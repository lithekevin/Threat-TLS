import asyncio
import json
import queue
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from typing import Dict, Optional, Set, Tuple
from utility.util import *

import requests
from cpe import CPE
from packaging import version

from attacks import *
from certificate import validate_certificate
from db import SessionLocal
from models import AttackCPE, Server
from single_attack import *

# Configuration Constants
MAX_QUEUE_SIZE = 100
DEFAULT_MAX_WORKERS = 10
DEFAULT_IDS = 'Suricata'
scanner = None

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

attack_cve_mapping = {
    'BLEICHENBACHER': 'CVE-2012-0884',
    'CCSINJECTION': 'CVE-2014-0224',
    'POODLE': 'CVE-2014-3566',
    'HEARTBEAT EXTENSION': 'CVE-2014-0160',
    'LUCKY13': 'CVE-2013-0169',
    'PADDING ORACLE ATTACK': 'CVE-2016-2107',
    'SWEET32': 'CVE-2016-2183',
    'DROWN': 'CVE-2016-0800',
    'TICKETBLEED': 'CVE-2016-9244',
    'CRIME': 'CVE-2012-4929',
    'LOGJAM': 'CVE-2015-4000',
    'ROCA': 'CVE-2017-15361',
    'BEAST': 'CVE-2011-3389',
    'RC4': 'CVE-2013-2566',
    'FREAK': 'CVE-2015-0204'
}


def extract_all_vulnerable_cpes(configurations) -> Set[frozenset]:
    """
    Recursively parse the CVE configurations field to extract all vulnerable CPE matches.

    Returns a set of frozensets, each frozenset representing a dict of CPE details:
    {
        'cpe_name': <CPE URI>,
        'version_start_including': <version or None>,
        'version_end_including': <version or None>,
        'version_start_excluding': <version or None>,
        'version_end_excluding': <version or None>
    }
    """

    if isinstance(configurations, list):
        # If there are multiple top-level configurations, treat them as OR
        combined = set()
        for config in configurations:
            combined = combined.union(extract_all_vulnerable_cpes(config))
        return combined

    operator = configurations.get('operator', 'OR')
    nodes = configurations.get('nodes', [])
    if not nodes:
        return set()

    result_sets = []
    for node in nodes:
        result_sets.append(parse_node(node))

    if operator == 'AND':
        if not result_sets:
            return set()
        combined = result_sets[0]
        for s in result_sets[1:]:
            combined = combined.intersection(s)
        return combined
    else:
        # OR logic
        combined = set()
        for s in result_sets:
            combined = combined.union(s)
        return combined


def parse_node(node: dict) -> Set[frozenset]:
    operator = node.get('operator', 'OR')
    cpe_matches = node.get('cpeMatch', [])
    children = node.get('children', [])
    subnodes = node.get('nodes', [])

    cpe_set = set()
    for cpe_match in cpe_matches:
        if cpe_match.get('vulnerable', False):
            cpe_set.add((
                cpe_match.get('criteria'),
                cpe_match.get('versionStartIncluding'),
                cpe_match.get('versionEndIncluding'),
                cpe_match.get('versionStartExcluding'),
                cpe_match.get('versionEndExcluding')
            ))

    child_sets = []
    for child in children:
        child_sets.append(parse_node(child))
    for sn in subnodes:
        child_sets.append(parse_node(sn))

    if child_sets:
        if operator == 'AND':
            if cpe_set:
                base = convert_tuple_set_to_dict_set(cpe_set)
            else:
                if child_sets:
                    base = child_sets[0]
                    child_sets = child_sets[1:]
                else:
                    base = set()
            for s in child_sets:
                base = base.intersection(s)
            return base
        else:
            # OR logic
            base = convert_tuple_set_to_dict_set(cpe_set)
            for s in child_sets:
                base = base.union(s)
            return base
    else:
        return convert_tuple_set_to_dict_set(cpe_set)


def convert_tuple_set_to_dict_set(cpe_set: Set[tuple]) -> Set[frozenset]:
    dict_set = set()
    for t in cpe_set:
        dict_set.add(
            frozenset({
                'cpe_name': t[0],
                'version_start_including': t[1],
                'version_end_including': t[2],
                'version_start_excluding': t[3],
                'version_end_excluding': t[4]
            }.items())
        )
    return dict_set


def frozenset_dict_to_dict(dict_fs: frozenset) -> dict:
    return dict(dict_fs)


class Vulnerability(Enum):
    HEARTBLEED = 'HEARTBEAT EXTENSION'
    CRIME = 'CRIME'
    PADDING_ORACLE_ATTACK = 'PADDING ORACLE ATTACK'
    LUCKY13 = 'LUCKY13'
    DROWN = 'DROWN'
    SWEET32 = 'SWEET32'
    LOGJAM = 'LOGJAM'
    ROCA = 'ROCA'
    BLEICHENBACHER = 'BLEICHENBACHER'
    TICKETBLEED = 'TICKETBLEED'
    CCS_INJECTION = 'CCSINJECTION'
    CERTIFICATE = 'CERTIFICATE'
    SELF_SIGNED = 'SELF SIGNED'
    EXPIRED = 'EXPIRED'
    POODLE = 'POODLE'
    RC4 = 'RC4'
    BEAST = 'BEAST'
    FREAK = 'FREAK'


class VulnerabilityScanner:
    def __init__(self,
                 max_workers: int = DEFAULT_MAX_WORKERS,
                 ids: str = DEFAULT_IDS,
                 versions_config: Optional[Set[str]] = None,
                 ciphers_config: Optional[Set[str]] = None,
                 certificate_fingerprint_config: Optional[Set[str]] = None,
                 verbose: bool = False):

        if verbose:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
        else:
            logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(levelname)s %(message)s')

        self.max_workers = max_workers
        self.ids = ids
        self.versions_config = versions_config or set()
        self.ciphers_config = ciphers_config or set()
        self.certificate_fingerprint_config = certificate_fingerprint_config or set()

        # Internal State
        self.processed_vulnerabilities: Set[Tuple[str, str]] = set()
        self.processed_vulnerabilities_lock = threading.Lock()
        self.servers_tested: Set[str] = set()
        self.zeek_field_names = []
        self.zeek_field_indices = {}
        self.servers_tested_lock = threading.Lock()
        self.vuln_queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.server_versions_cache: Dict[str, Dict[str, str]] = {}
        self.cache_lock = threading.Lock()
        self.executed_attacks_per_server = {}
        self.executed_attacks_lock = threading.Lock()
        self.server_locks: Dict[str, threading.Lock] = {}
        self.server_locks_lock = threading.Lock()
        self.cve_details_cache: Dict[Tuple[str, Tuple[str, ...]], Dict] = {}
        self.session = SessionLocal()
        self.api_key = os.environ.get('NVD_API_KEY', '')
        if not self.api_key:
            logging.error("NVD API Key not found in environment variable 'NVD_API_KEY'.")
            sys.exit(1)
        self.fetch_attack_cpes()

    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch CVE details from the NVD API.
        Implements caching to avoid redundant API calls.
        """
        cache_key = cve_id
        with self.cache_lock:
            if cache_key in self.cve_details_cache:
                return self.cve_details_cache[cache_key]

        url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        headers = {'apiKey': self.api_key}
        params = {'cveId': cve_id}

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            cve_data = response.json()
            with self.cache_lock:
                self.cve_details_cache[cache_key] = cve_data
            return cve_data
        except requests.HTTPError as http_err:
            logging.error(f"HTTP error occurred while fetching CVE details: {http_err}")
        except Exception as err:
            logging.error(f"An error occurred while fetching CVE details: {err}")
        return None

    def fetch_attack_cpes(self):
        """
        Fetch and store CPEs associated with each attack's CVE.
        Uses the new recursive logic to handle complex AND/OR configurations.
        """
        for attack_name, cve_ids in attack_cve_mapping.items():
            if isinstance(cve_ids, str):
                cve_ids_list = re.findall(r'CVE-\d{4}-\d{4,7}', cve_ids)
            else:
                cve_ids_list = cve_ids

            for cve_id in cve_ids_list:
                existing_cpes = self.session.query(AttackCPE).filter_by(attack_name=attack_name, cve_id=cve_id).first()
                if existing_cpes:
                    continue

                cve_data = self.get_cve_details(cve_id)
                if not cve_data or 'vulnerabilities' not in cve_data or not cve_data['vulnerabilities']:
                    logging.warning(f"No CVE data found for {cve_id}")
                    continue

                cpes = []
                for vuln in cve_data['vulnerabilities']:
                    cve_item = vuln.get('cve')
                    if cve_item and 'configurations' in cve_item:
                        configs = cve_item['configurations']
                        vuln_cpes = extract_all_vulnerable_cpes(configs)
                        for fc in vuln_cpes:
                            cpe_info = frozenset_dict_to_dict(fc)
                            cpes.append(cpe_info)

                for cpe_info in cpes:
                    attack_cpe = AttackCPE(
                        attack_name=attack_name,
                        cve_id=cve_id,
                        cpe_name=cpe_info.get('cpe_name'),
                        version_start_including=cpe_info.get('version_start_including'),
                        version_end_including=cpe_info.get('version_end_including'),
                        version_start_excluding=cpe_info.get('version_start_excluding'),
                        version_end_excluding=cpe_info.get('version_end_excluding')
                    )
                    self.session.add(attack_cpe)
                self.session.commit()
                logging.info(f"Stored {len(cpes)} CPEs for attack {attack_name} and CVE {cve_id}")

    def process_vulnerability(self, task: Dict):
        connection = task['connection']
        vulnerability = task['vulnerability']
        extra_data = task.get('extra_data', {})
        detection_time = task.get('detection_time', time.time())
        source = connection.split("->")[0].strip()
        dest = connection.split("->")[1].strip()
        ip_source = source.split(":")[0]
        port_source = source.split(":")[1]

        server = self.session.query(Server).filter_by(ip=ip_source, port=port_source).first()
        if not server:
            logging.info(f"Server {ip_source}:{port_source} not found in database. Skipping {vulnerability}")
            return

        # Skip applicability checks for CERTIFICATE vulnerability
        if vulnerability != Vulnerability.CERTIFICATE.value:
            openssl_cpe = None
            for cpe_entry in server.cpes:
                cpe_name = cpe_entry.cpe_name
                if cpe_name and 'openssl:openssl' in cpe_name:
                    openssl_cpe = cpe_name
                    break

            if not openssl_cpe:
                logging.info(f"No CPE found for server {ip_source}:{port_source}. Skipping {vulnerability}")
                return

            openssl_major_version = extract_openssl_version(openssl_cpe)
            if not openssl_major_version:
                logging.info(f"Cannot determine CPE {openssl_cpe}. Skipping {vulnerability}")
                return

            if not is_vulnerability_applicable(vulnerability, openssl_major_version):
                logging.info(
                    f"{vulnerability} not applicable on {ip_source}:{port_source}")
                return

        logging.info(f"Starting tests for {ip_source}:{port_source} for {vulnerability} vulnerability")

        vulnerability_tests = {
            Vulnerability.HEARTBLEED.value: [
                lambda: heartbleed_testssl(ip_source, port_source, detection_time),
                lambda: metasploit_heartbleed_process(ip_source, port_source, extra_data.get('tls_version', ''),
                                                      detection_time),
                lambda: nmap_heartbleed_process(ip_source, port_source, detection_time),
                lambda: heartbleed_osaft(ip_source, port_source, detection_time),
            ],
            Vulnerability.CRIME.value: [
                lambda: crime_testssl(ip_source, port_source, detection_time),
                lambda: crime_osaft(ip_source, port_source, detection_time),
            ],
            Vulnerability.PADDING_ORACLE_ATTACK.value: [
                lambda: poodle_nmap_process(ip_source, port_source, detection_time),
                lambda: poodle_testssl(ip_source, port_source, detection_time),
            ],
            Vulnerability.LUCKY13.value: [
                lambda: lucky13_testssl(ip_source, port_source, detection_time),
            ],
            Vulnerability.DROWN.value: [
                lambda: drown_testssl(ip_source, port_source, detection_time),
            ],
            Vulnerability.SWEET32.value: [
                lambda: sweet32_testssl(ip_source, port_source, detection_time),
            ],
            Vulnerability.BEAST.value: [
                lambda: beast_testssl(ip_source, port_source, detection_time),
                lambda: beast_osaft(ip_source, port_source, detection_time),
            ],
            Vulnerability.RC4.value: [
                lambda: rc4_testssl(ip_source, port_source, detection_time),
                lambda: rc4_osaft(ip_source, port_source, detection_time),
            ],
            Vulnerability.LOGJAM.value: [
                lambda: logjam_testssl(ip_source, port_source, detection_time),
                lambda: logjam_process_nmap(ip_source, port_source, detection_time),
            ],
            Vulnerability.BLEICHENBACHER.value: [
                lambda: robot_testssl(ip_source, port_source, detection_time),
                lambda: robot_metasploit(ip_source, port_source, detection_time),
            ],
            Vulnerability.ROCA.value: [
                lambda: roca_testssl(ip_source, port_source, detection_time),
                lambda: roca_nmap(ip_source, port_source, detection_time),
            ],
            Vulnerability.TICKETBLEED.value: [
                lambda: ticketbleed_testssl(ip_source, port_source, detection_time),
                lambda: ticketbleed_nmap(ip_source, port_source, detection_time),
            ],
            Vulnerability.CCS_INJECTION.value: [
                lambda: ccs_injection_testssl(ip_source, port_source, detection_time),
                lambda: ccs_injection_process_nmap(ip_source, port_source, detection_time),
                lambda: ccs_injection_process_metasploit(ip_source, port_source, detection_time),
            ],
            Vulnerability.FREAK.value: [
                lambda: freak_testssl(ip_source, port_source, detection_time),
                lambda: freak_osaft(ip_source, port_source, detection_time),
            ],
            Vulnerability.POODLE.value: [
                lambda: poodle_testssl(ip_source, port_source, detection_time),
                lambda: poodle_osaft(ip_source, port_source, detection_time),
            ],
            Vulnerability.CERTIFICATE.value: [
                lambda: self.process_certificate(ip_source, port_source),
            ],
        }

        tests = vulnerability_tests.get(vulnerability, [])
        if not tests:
            logging.info(f"No tests defined for vulnerability {vulnerability}. Skipping.")
            return

        with ThreadPoolExecutor(max_workers=DEFAULT_MAX_WORKERS) as executor:
            future_to_test = {executor.submit(test_func): test_func for test_func in tests}
            for future in as_completed(future_to_test):
                test_func = future_to_test[future]
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error during {vulnerability} test on {ip_source}:{port_source}: {e}")

    def reset_cache(self):
        with self.executed_attacks_lock:
            self.executed_attacks_per_server.clear()
        logging.info("Executed attacks cache has been reset due to OpenVAS alert")

    def get_server_openssl_version(self, server):
        for cpe_entry in server.cpes:
            cpe_str = cpe_entry.cpe_name
            parts = cpe_str.split(':')
            if len(parts) > 5 and parts[3] == 'openssl' and parts[4] == 'openssl':
                return parts[5]
        return None

    def check_cpes(self, server, attack_cpe_entries):
        server_cpes = [cpe.cpe_name for cpe in server.cpes]
        for server_cpe_str in server_cpes:
            try:
                server_cpe_obj = CPE(server_cpe_str)
            except Exception as e:
                logging.error(f"Error parsing server CPE {server_cpe_str}: {e}")
                continue

            for attack_cpe_entry in attack_cpe_entries:
                if not attack_cpe_entry.cpe_name:
                    continue

                try:
                    attack_cpe_obj = CPE(attack_cpe_entry.cpe_name)
                except Exception as e:
                    logging.error(f"Error parsing attack CPE {attack_cpe_entry.cpe_name}: {e}")
                    continue

                if self.compare_cpes(server_cpe_obj, attack_cpe_obj, attack_cpe_entry):
                    return True
        return False

    def compare_cpes(self, server_cpe: CPE, attack_cpe: CPE, attack_cpe_entry: AttackCPE) -> bool:
        if server_cpe.get_part() != attack_cpe.get_part():
            return False
        if server_cpe.get_vendor() != attack_cpe.get_vendor():
            return False
        if server_cpe.get_product() != attack_cpe.get_product():
            return False


        server_versions = server_cpe.get_version()
        if isinstance(server_versions, str):
            server_versions = [server_versions]


        attack_versions = attack_cpe.get_version()
        if isinstance(attack_versions, str):
            attack_versions = [attack_versions]

        has_wildcard = any(av in ('*', '-') for av in attack_versions)

        start_incl = attack_cpe_entry.version_start_including
        end_incl = attack_cpe_entry.version_end_including
        start_excl = attack_cpe_entry.version_start_excluding
        end_excl = attack_cpe_entry.version_end_excluding


        def version_meets_constraints(s_ver_str):
            try:
                s_ver = version.parse(s_ver_str)
            except:
                return False

            meets_start_including = True
            meets_end_including = True
            meets_start_excluding = True
            meets_end_excluding = True

            if start_incl:
                try:
                    si_ver = version.parse(start_incl)
                    meets_start_including = s_ver >= si_ver
                except:
                    pass

            if end_incl:
                try:
                    ei_ver = version.parse(end_incl)
                    meets_end_including = s_ver <= ei_ver
                except:
                    pass

            if start_excl:
                try:
                    se_ver = version.parse(start_excl)
                    meets_start_excluding = s_ver > se_ver
                except:
                    pass

            if end_excl:
                try:
                    ee_ver = version.parse(end_excl)
                    meets_end_excluding = s_ver < ee_ver
                except:
                    pass

            return all([meets_start_including, meets_end_including, meets_start_excluding, meets_end_excluding])



        if has_wildcard:
            for s_ver_str in server_versions:
                if version_meets_constraints(s_ver_str):
                    return True
            return False
        else:
            for s_ver_str in server_versions:
                if not version_meets_constraints(s_ver_str):
                    continue
                try:
                    s_ver_parsed = version.parse(s_ver_str)
                except:
                    continue

                for a_ver_str in attack_versions:
                    if a_ver_str in ('*', '-'):
                        continue
                    try:
                        a_ver = version.parse(a_ver_str)
                    except:
                        continue

                    if s_ver_parsed == a_ver:
                        return True
            return False

    def process_certificate(self, ip_source: str, port_source: str):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            cert_data = loop.run_until_complete(validate_certificate(ip_source, int(port_source)))
            loop.close()

            if cert_data:
                cert, cert_string, fingerprint = cert_data
                if fingerprint:
                    if fingerprint not in self.certificate_fingerprint_config:
                        logging.info(f'Certificate fingerprint for {ip_source}:{port_source} is {fingerprint}')
                    else:
                        logging.info(
                            f'Certificate fingerprint for {ip_source}:{port_source} is known and in the config.')
                else:
                    logging.error(f"Could not retrieve fingerprint for {ip_source}:{port_source}")
            else:
                logging.error(f"Validation failed for {ip_source}:{port_source}")
        except Exception as e:
            logging.error(f"Error during certificate validation for {ip_source}:{port_source} - {e}")

    def scheduler(self):
        logging.info("Vulnerability test thread is started...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while True:
                try:
                    task = self.vuln_queue.get(timeout=1)
                    if task is None:
                        break
                    executor.submit(self.process_vulnerability, task)
                    self.vuln_queue.task_done()
                except queue.Empty:
                    continue

    def parser_suricata(self, line: bytes):
        cipher_suite_found = ''
        tls_version_found = ''
        decoded_line = line.decode(errors='ignore')
        source_dest = decoded_line.partition("{TCP}")[2].strip()
        vuln = decoded_line.partition("|VULNERABILITY|")
        tls_version = vuln[0].split("+")
        if len(tls_version) > 1:
            tls_version_found = tls_version[1]
        if vuln[1]:
            cipher_suite = vuln[2].split("%")
            if len(cipher_suite) > 1:
                cipher_suite_found = cipher_suite[1]
            vulnerabilities = vuln[2].split("#")
            new_vulnerability = vulnerabilities[1]
            flag = False
            if new_vulnerability in {'CERTIFICATE', 'SELF SIGNED', 'EXPIRED', 'CRIME', 'HEARTBEAT EXTENSION'}:
                flag = True
            if tls_version_found not in self.versions_config and tls_version_found:
                flag = True
            if cipher_suite_found not in self.ciphers_config and cipher_suite_found:
                flag = True
            if flag:
                task_identifier = (source_dest, new_vulnerability)
                with self.processed_vulnerabilities_lock:
                    if task_identifier not in self.processed_vulnerabilities:
                        self.processed_vulnerabilities.add(task_identifier)
                        detection_time = time.time()
                        task = {
                            'connection': source_dest,
                            'vulnerability': new_vulnerability,
                            'detection_time': detection_time,
                            'extra_data': {
                                'tls_version': version,
                                'cipher_suite': cipher_suite_found,
                            }
                        }
                        self.vuln_queue.put(task)

    def extract_vulnerability(self, note: str, msg: str) -> Optional[str]:
        vulnerability_patterns = {
            'BEAST': r'BEAST',
            'LUCKY13': r'Lucky13',
            'PADDING ORACLE ATTACK': r'PaddingOracle',
            'BLEICHENBACHER': r'ROBOT',
            'POODLE': r'POODLE',
            'RC4': r'RC4',
            'HEARTBLEED': r'Heartbleed',
            'TICKETBLEED': r'TicketBleed',
            'CCSINJECTION': r'CCS',
            'LOGJAM': r'Logjam',
            'SWEET32': r'SWEET32',
            'DROWN': r'DROWN',
        }

        for vuln, pattern in vulnerability_patterns.items():
            if re.search(pattern, note, re.IGNORECASE) or re.search(pattern, msg, re.IGNORECASE):
                return vuln
        return None

    def extract_tls_version(self, msg: str) -> str:
        tls_version_mapping = {
            'SSLv3': 'SSLv3',
            'TLSv1.0': '1.0',
            'TLSv1.1': '1.1',
            'TLSv1.2': '1.2',
            'TLSv1.3': '1.3',
        }
        for key, value in tls_version_mapping.items():
            if key in msg:
                return value
        return ''

    def parser_zeek(self, line: bytes):
        decoded_line = line.decode('utf-8', errors='ignore').strip()
        if not decoded_line:
            return

        if decoded_line.startswith('#'):
            if decoded_line.startswith('#fields'):
                self.zeek_field_names = decoded_line.split()[1:]
                self.zeek_field_indices = {name: idx for idx, name in enumerate(self.zeek_field_names)}
            return

        if not self.zeek_field_indices:
            logging.error("Zeek field indices not initialized.")
            return

        fields = decoded_line.split()
        try:
            ip_src = fields[self.zeek_field_indices['id.orig_h']]
            port_src = fields[self.zeek_field_indices['id.orig_p']]
            ip_dest = fields[self.zeek_field_indices['id.resp_h']]
            port_dest = fields[self.zeek_field_indices['id.resp_p']]
            note = fields[self.zeek_field_indices['note']]
            msg = fields[self.zeek_field_indices['msg']]
            compression = fields[self.zeek_field_indices['compression']] if 'compression' in self.zeek_field_indices else ''
            validation_status = fields[self.zeek_field_indices['validation_status']] if 'validation_status' in self.zeek_field_indices else ''
        except IndexError as e:
            logging.error(f"Error parsing Zeek log line: {e}")
            return

        vulnerability = self.extract_vulnerability(note, msg)
        if not vulnerability:
            return

        src_dest = f"{ip_dest}:{port_dest} -> {ip_src}:{port_src}"

        extra_data = {}
        if vulnerability == 'HEARTBLEED':
            extra_data['tls_version'] = self.extract_tls_version(msg)

        detection_time = time.time()
        task = {
            'connection': src_dest,
            'vulnerability': vulnerability,
            'detection_time': detection_time,
            'extra_data': extra_data,
        }


        task_identifier = (src_dest, vulnerability)
        with self.processed_vulnerabilities_lock:
            if task_identifier not in self.processed_vulnerabilities:
                self.processed_vulnerabilities.add(task_identifier)
                logging.info(f'Zeek detected vulnerability {vulnerability} for {src_dest}')
                self.vuln_queue.put(task)

    def run(self):
        try:
            if self.ids.upper() == 'SURICATA':
                threading.Thread(
                    target=log_reader,
                    args=('/var/log/suricata/mio_fast.log', self.parser_suricata, True),
                    daemon=True
                ).start()
            elif self.ids.upper() == 'ZEEK':
                threading.Thread(
                    target=log_reader,
                    args=('/usr/local/zeek/logs/current/notice.log', self.parser_zeek, False),
                    daemon=True
                ).start()
            else:
                logging.error(f"Unsupported IDS: {self.ids}")
                sys.exit(1)
            logging.info('Vulnerability scanner started...')
            self.scheduler()
        except (KeyboardInterrupt, SystemExit):
            logging.info("Vulnerability scanner terminated.")
            sys.exit(0)

    @staticmethod
    def help_message():
        out = '''run_monitoring
            ▁ ▂ ▃ ▅ ▆ ▇ █ Monitor for TLS attacks █ ▇ ▆ ▅ ▃ ▂ ▁

    usage: monitor_for_tls_attacks [-h] [--IDS=Suricata/Zeek] [--json /pathToConfigJSONFile]

    Monitor your network traffic with Suricata or Zeek IDS and check if the found vulnerabilities are TP or FP. Before starting this tool you must execute Suricata/Zeek.

    NOTE: If you have changed the default path of log file for the IDS you have to change it also in this tool.

    Suricata log path variable: src_path = r"/var/log/suricata/fast.log"

    Zeek log path variable:  src_path = r"/usr/local/zeek/logs/current/notice.log"

    optional arguments:

      -h, --help            show this help message and exit

      --IDS=Suricata        use Suricata as IDS. This is the default setting

      --IDS=Zeek, --zeek    use Zeek as IDS

      --json                use a network config file in json format

    It is possible to use the attacks of this tool without the IDS in the following way:

        usage: monitor_for_tls_attacks [--attack attack_name] [--host ip:port]

    The attack_name can be:

        - heartbleed
        - crime
        - drown
        - bleichenbacher
        - robot
        - padding_oracle_attack
        - sweet32
        - logjam
        - lucky13
        - poodle
        - ticketbleed
        - ccs_injection
        - roca
        - beast
        - rc4
        - freak
      '''
        print(out)


def log_reader(src_path: str, parser, start_at_end: bool):
    with open(src_path, "rb") as fp:
        if start_at_end:
            fp.seek(0, os.SEEK_END)
        else:
            fp.seek(0, os.SEEK_SET)

        while True:
            line = fp.readline()
            if not line:
                time.sleep(0.1)
                continue
            parser(line)


def parse_args(args=None):
    import argparse

    parser = argparse.ArgumentParser(description='Monitor for TLS attacks.')
    parser.add_argument('--IDS', choices=['Suricata', 'Zeek'], default='Suricata', help='Use Suricata or Zeek as IDS')
    parser.add_argument('--zeek', action='store_const', const='Zeek', dest='IDS', help='Use Zeek as IDS')
    parser.add_argument('--json', type=str, help='Use a network config file in JSON format')
    parser.add_argument('--attack', type=str,
                        help='Specify an attack to perform (use "all" to test all vulnerabilities)')
    parser.add_argument('--host', type=str, help='Specify the host (ip:port) to attack')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    return parser.parse_args(args)


def main(args=None):
    args = parse_args(args)

    if args.host:
        if args.verbose:
            logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
        else:
            logging.basicConfig(level=logging.WARNING, format='%(asctime)s %(message)s')

        if args.attack and args.attack.lower() != 'all':
            logging.info(f"Performing attack '{args.attack}' on host '{args.host}'")
            single_attack(args.attack, args.host)
        else:
            start_time = time.time()
            logging.info(f"Performing all attacks on host '{args.host}' using multithreading")
            with ThreadPoolExecutor(max_workers=DEFAULT_MAX_WORKERS) as executor:
                futures = []
                for vuln in Vulnerability:
                    attack_name = vuln.name.lower()
                    logging.info(f"Queuing attack '{attack_name}' on host '{args.host}'")
                    futures.append(executor.submit(single_attack, attack_name, args.host))

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logging.error(f"Error executing an attack: {e}")

            end_time = time.time()
            total_time = end_time - start_time
            logging.info(f"All attacks completed in {total_time:.2f} seconds")

        sys.exit(0)

    versions_config = set()
    ciphers_config = set()
    certificate_fingerprint_config = set()

    if args.json:
        try:
            with open(args.json, 'r') as f:
                config_data = json.load(f)
                versions_config = set(config_data.get('versions', []))
                ciphers_config = set(config_data.get('ciphers', []))
                certificate_fingerprint_config = set(
                    fp.replace(':', '').lower() for fp in config_data.get('certificate_fingerprint', [])
                )
        except Exception as e:
            logging.error(f"Failed to load configuration from {args.json}: {e}")
            sys.exit(1)

    scanner = VulnerabilityScanner(
        ids=args.IDS,
        versions_config=versions_config,
        ciphers_config=ciphers_config,
        certificate_fingerprint_config=certificate_fingerprint_config,
        verbose=args.verbose
    )

    scanner.run()


if __name__ == "__main__":
    main()
