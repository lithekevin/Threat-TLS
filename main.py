import asyncio
import json
import queue
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from typing import Dict, Optional, List, Set, Tuple

import paramiko
import requests
from paramiko import SSHException, AuthenticationException

from attacks import *
from certificate import validate_certificate
from single_attack import *

# Configuration Constants
MAX_QUEUE_SIZE = 100
DEFAULT_MAX_WORKERS = 12
DEFAULT_IDS = 'Suricata'
DEFAULT_FULL_VERSION = False

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
    'RC4': 'CVE-2013-2566'
}


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


class VulnerabilityScanner:
    def __init__(self,
                 max_workers: int = DEFAULT_MAX_WORKERS,
                 full_version: bool = DEFAULT_FULL_VERSION,
                 ids: str = DEFAULT_IDS,
                 versions_config: Optional[Set[str]] = None,
                 ciphers_config: Optional[Set[str]] = None,
                 certificate_fingerprint_config: Optional[Set[str]] = None):
        self.max_workers = max_workers
        self.full_version = full_version
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
        self.server_locks: Dict[str, threading.Lock] = {}
        self.server_locks_lock = threading.Lock()
        self.cve_details_cache: Dict[Tuple[str, Tuple[str, ...]], Dict] = {}

        # API Key from environment variable
        self.api_key = os.environ.get('NVD_API_KEY', '')
        if not self.api_key:
            logging.error("NVD API Key not found in environment variable 'NVD_API_KEY'.")
            sys.exit(1)

    def get_cve_details(self, cve_id: str, cpes: List[str]) -> Optional[Dict]:
        """
        Fetch CVE details from the NVD API.
        Implements caching to avoid redundant API calls.
        """

        cache_key = (cve_id, tuple(cpes))
        with self.cache_lock:
            if cache_key in self.cve_details_cache:
                return self.cve_details_cache[cache_key]

        url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        headers = {'apiKey': self.api_key}
        params = [('cveId', cve_id)] + [('cpeName', cpe) for cpe in cpes]

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

    def parse_openssl_version(self, output: str) -> Optional[str]:
        """
        Parses the OpenSSL version from command output.
        """
        logging.debug(f"Parsing OpenSSL output: {output}")
        match = re.search(r'OpenSSL\s+(\S+)', output)
        if match:
            version = match.group(1)
            logging.debug(f"Found OpenSSL version: {version}")
            return version
        return None

    def parse_apache_version(self, output: str) -> Optional[str]:
        """
        Parses the Apache version from command output.
        """
        logging.debug(f"Parsing Apache output: {output}")
        match = re.search(r'Server version:\s*Apache/(\S+)', output)
        if match:
            version = match.group(1)
            logging.debug(f"Found Apache version: {version}")
            return version
        return None

    def get_server_versions(self, ip: str, username: str = 'server', password: str = 'server') -> Optional[
        Dict[str, str]]:
        """
        Fetches server versions for OpenSSL and Apache via SSH.
        Implements caching to avoid redundant SSH connections.
        """
        with self.cache_lock:
            if ip in self.server_versions_cache:
                return self.server_versions_cache[ip]

        with threading.Lock():
            if ip not in self.server_locks:
                self.server_locks[ip] = threading.Lock()
            server_lock = self.server_locks[ip]

        with server_lock:
            with self.cache_lock:
                if ip in self.server_versions_cache:
                    return self.server_versions_cache[ip]

            versions = {}
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port=22, username=username, password=password, timeout=10)

                # Get OpenSSL version
                stdin, stdout, stderr = ssh.exec_command('openssl version')
                openssl_output = stdout.read().decode().strip()
                versions['openssl'] = self.parse_openssl_version(openssl_output)

                # Get Apache version
                stdin, stdout, stderr = ssh.exec_command('apache2 -v')
                apache_output = stdout.read().decode().strip()
                versions['apache'] = self.parse_apache_version(apache_output)
                ssh.close()

                with self.cache_lock:
                    self.server_versions_cache[ip] = versions

                return versions
            except AuthenticationException as auth_exc:
                logging.error(f"Authentication failed when connecting to {ip}: {auth_exc}")
            except SSHException as ssh_exc:
                logging.error(f"Could not establish SSH connection to {ip}: {ssh_exc}")
            except Exception as e:
                logging.error(f"Error getting server versions for {ip}: {e}")
            return None

    def build_cpes(self, versions: Dict[str, str]) -> List[str]:
        """
        Builds a list of CPEs from the server versions.
        """
        cpes = []
        if 'openssl' in versions and versions['openssl']:
            openssl_version = versions['openssl']
            cpe_openssl = f"cpe:2.3:a:openssl:openssl:{openssl_version}"
            cpes.append(cpe_openssl)
        if 'apache' in versions and versions['apache']:
            apache_version = versions['apache']
            cpe_apache = f"cpe:2.3:a:apache:http_server:{apache_version}"
            cpes.append(cpe_apache)
        logging.debug(f"Built CPEs: {cpes}")
        return cpes

    def process_vulnerability(self, task: Dict):
        """
        Processes a vulnerability task from the queue.
        """
        connection = task['connection']
        vulnerability = task['vulnerability']
        extra_data = task.get('extra_data', {})
        source = connection.split("->")[0].strip()
        dest = connection.split("->")[1].strip()
        ip_source = source.split(":")[0]
        port_source = source.split(":")[1]

        if vulnerability in {Vulnerability.CERTIFICATE.value, Vulnerability.EXPIRED.value,
                             Vulnerability.SELF_SIGNED.value}:
            logging.info(f"Start certificate test for {ip_source}:{port_source} for {vulnerability} vulnerability")
            self.process_certificate(ip_source, port_source)
            logging.info(f"Finished processing {vulnerability} for {connection}")
            return

        # versions = self.get_server_versions(ip_source)
        # if not versions:
        #    logging.info(f"Could not get server versions for {ip_source}. Skipping vulnerability {vulnerability}")
        #    return
        #
        # cpes = self.build_cpes(versions)
        # if not cpes:
        #    logging.info(f"No CPEs built for {ip_source}. Skipping vulnerability {vulnerability}")
        #    return
        #
        # cve_id = attack_cve_mapping.get(vulnerability)
        # if not cve_id:
        #    logging.info(f"No CVE mapping for vulnerability {vulnerability}. Skipping")
        #    return
        #
        # cve_data = self.get_cve_details(cve_id, cpes)
        # if not cve_data or 'vulnerabilities' not in cve_data or not cve_data['vulnerabilities']:
        #    logging.info(f"No matching CPEs for vulnerability {vulnerability} on {ip_source}. Skipping")
        #    return

        logging.info(f"Start test for {ip_source}:{port_source} for {vulnerability} vulnerability")

        # Define the mapping of vulnerabilities to their respective test functions
        vulnerability_tests = {
            Vulnerability.HEARTBLEED.value: [
                lambda: heartbleed_testssl(ip_source, port_source),
                lambda: metasploit_heartbleed_process(ip_source, port_source, extra_data.get('tls_version', '')),
                lambda: nmap_heartbleed_process(ip_source, port_source),
                lambda: heartbleed_tls_attacker(ip_source, port_source),
            ],
            Vulnerability.CRIME.value: [
                lambda: crime_testssl(ip_source, port_source),
            ],
            Vulnerability.PADDING_ORACLE_ATTACK.value: [
                lambda: padding_attack_process_tls_attacker(ip_source, port_source),
                lambda: poodle_nmap_process(ip_source, port_source),
                lambda: poodle_testssl(ip_source, port_source),
                lambda: poodle_tls_attacker(ip_source, port_source),
            ],
            Vulnerability.LUCKY13.value: [
                lambda: lucky13_testssl(ip_source, port_source),
            ],
            Vulnerability.DROWN.value: [
                lambda: drown_testssl(ip_source, port_source),
                lambda: drown_tls_attacker(ip_source, port_source),
            ],
            Vulnerability.SWEET32.value: [
                lambda: sweet32_testssl(ip_source, port_source),
            ],
            Vulnerability.BEAST.value: [
                lambda: beast_testssl(ip_source, port_source),
            ],
            Vulnerability.RC4.value: [
                lambda: rc4_testssl(ip_source, port_source),
            ],
            Vulnerability.LOGJAM.value: [
                lambda: logjam_testssl(ip_source, port_source),
                lambda: logjam_process_nmap(ip_source, port_source),
            ],
            Vulnerability.BLEICHENBACHER.value: [
                lambda: bleichenbachers_process(ip_source, port_source),
                lambda: robot_testssl(ip_source, port_source),
                lambda: robot_metasploit(ip_source, port_source),
            ],
            Vulnerability.ROCA.value: [
                lambda: roca_testssl(ip_source, port_source),
                lambda: roca_nmap(ip_source, port_source),
            ],
            Vulnerability.TICKETBLEED.value: [
                lambda: ticketbleed_testssl(ip_source, port_source),
                lambda: ticketbleed_nmap(ip_source, port_source),
            ],
            Vulnerability.CCS_INJECTION.value: [
                lambda: ccs_injection_testssl(ip_source, port_source),
                lambda: ccs_injection_process_nmap(ip_source, port_source),
                lambda: ccs_injection_process_metasploit(ip_source, port_source),
            ],
            Vulnerability.CERTIFICATE.value: [
                lambda: self.process_certificate(ip_source, port_source),
            ],
        }

        tests = vulnerability_tests.get(vulnerability, [])
        if not tests:
            logging.info(f"No tests defined for vulnerability {vulnerability}. Skipping.")
            return

        # Limit the number of concurrent tests per vulnerability
        max_concurrent_tests = min(len(tests), 3)  # Adjust as needed
        with ThreadPoolExecutor(max_workers=max_concurrent_tests) as executor:
            future_to_test = {executor.submit(test_func): test_func for test_func in tests}
            for future in as_completed(future_to_test):
                test_func = future_to_test[future]
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error during {vulnerability} test on {ip_source}:{port_source}: {e}")

    def process_certificate(self, ip_source: str, port_source: str):
        """
        Processes certificate-related vulnerabilities.
        """
        try:
            # Since validate_certificate is an async function, we need to run it in an event loop.
            # We'll use a separate event loop for each thread to avoid conflicts.
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            cert_data = loop.run_until_complete(validate_certificate(ip_source, int(port_source)))
            loop.close()

            if cert_data:
                cert, cert_string, fingerprint = cert_data
                if fingerprint:
                    if fingerprint not in self.certificate_fingerprint_config:
                        logging.info(f'Certificate fingerprint for {ip_source}:{port_source} is {fingerprint}')
                        # Additional processing as needed
                    else:
                        logging.info(
                            f'Certificate fingerprint for {ip_source}:{port_source} is known and in the config.')
                else:
                    logging.error(f"Could not retrieve fingerprint for {ip_source}:{port_source}")
            else:
                logging.error(f"Validation failed for {ip_source}:{port_source}")
        except Exception as e:
            logging.error(f"Error during certificate validation for {ip_source}:{port_source} - {e}")

    def check_vulnerabilities(self):
        """
        Main loop to check vulnerabilities from the queue using a ThreadPoolExecutor.
        """
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
                    continue  # Continue if the queue is empty

    def file_reader_suricata(self, line: bytes):
        """
        Processes a line from the Suricata log file.
        """
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
                        version = ""
                        if new_vulnerability == 'HEARTBEAT EXTENSION':
                            version = vuln[2].split("$")[1]
                        logging.info(f'Suricata detected vulnerability {new_vulnerability} for {source_dest}')
                        task = {
                            'connection': source_dest,
                            'vulnerability': new_vulnerability,
                            'extra_data': {
                                'tls_version': version,
                                'cipher_suite': cipher_suite_found,
                            }
                        }
                        self.vuln_queue.put(task)
            if self.full_version:
                source = source_dest.split("->")[0]
                ip_source = source.split(":")[0].split(" ")[1]
                port_source = source.split(":")[1].split(" ")[0]
                with self.servers_tested_lock:
                    if ip_source not in self.servers_tested:
                        self.servers_tested.add(ip_source)
                        testssl_full(ip_source, port_source)

    def extract_vulnerability(self, note: str, msg: str) -> Optional[str]:
        """
        Extracts the vulnerability name from the 'note' or 'msg' fields.
        """
        # Define mappings or patterns to identify vulnerabilities
        vulnerability_patterns = {
            'BEAST': r'BEAST',
            'LUCKY13': r'Lucky13',
            'PADDING ORACLE ATTACK': r'PaddingOracle',
            'BLEICHENBACHER': r'ROBOT',
            'POODLE': r'POODLE',
            'RC4': r'RC4',
            'HEARTBLEED': r'Heartbleed',
            'TICKETBLEED': r'TicketBleed',
            'CCS_INJECTION': r'CCS_Injection',
            'LOGJAM': r'Logjam',
            'SWEET32': r'SWEET32',
            'DROWN': r'DROWN',
        }

        for vuln, pattern in vulnerability_patterns.items():
            if re.search(pattern, note, re.IGNORECASE) or re.search(pattern, msg, re.IGNORECASE):
                return vuln
        return None

    def extract_tls_version(self, msg: str) -> str:
        """
        Extracts TLS version from the 'msg' field.
        """
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

    def file_reader_zeek(self, line: bytes):
        """
        Processes a line from the Zeek notice.log file.
        Handles multiple #fields lines and updates field indices accordingly.
        """
        decoded_line = line.decode('utf-8', errors='ignore').strip()

        # Skip empty lines
        if not decoded_line:
            return

        # Handle header lines
        if decoded_line.startswith('#'):
            if decoded_line.startswith('#fields'):
                # Split by any whitespace (tabs or spaces)
                self.zeek_field_names = decoded_line.split()[1:]  # Exclude '#fields'
                self.zeek_field_indices = {name: idx for idx, name in enumerate(self.zeek_field_names)}
                logging.debug(f"Parsed Zeek fields: {self.zeek_field_indices}")
            return  # Skip other header lines like #types

        # Ensure that field indices are parsed
        if not self.zeek_field_indices:
            logging.error("Zeek field indices not initialized. Ensure that the #fields line is present in the log.")
            return

        # Split by any whitespace
        fields = decoded_line.split()

        # Extract necessary fields using field indices
        try:
            ip_src = fields[self.zeek_field_indices['id.orig_h']]
            port_src = fields[self.zeek_field_indices['id.orig_p']]
            ip_dest = fields[self.zeek_field_indices['id.resp_h']]
            port_dest = fields[self.zeek_field_indices['id.resp_p']]
            note = fields[self.zeek_field_indices['note']]
            msg = fields[self.zeek_field_indices['msg']]
            compression = fields[
                self.zeek_field_indices['compression']] if 'compression' in self.zeek_field_indices else ''
            validation_status = fields[
                self.zeek_field_indices['validation_status']] if 'validation_status' in self.zeek_field_indices else ''
        except IndexError as e:
            logging.error(f"Error parsing Zeek log line: {e}")
            return

        # Extract vulnerability name from 'note' or 'msg'
        vulnerability = self.extract_vulnerability(note, msg)
        if not vulnerability:
            return  # No recognized vulnerability found

        # Construct source-destination string
        src_dest = f"{ip_dest}:{port_dest} -> {ip_src}:{port_src}"

        # Prepare extra_data if needed
        extra_data = {}
        if vulnerability == 'HEARTBLEED':
            # Example: Extract TLS version from msg or other fields if available
            extra_data['tls_version'] = self.extract_tls_version(msg)

        # Create task
        task = {
            'connection': src_dest,
            'vulnerability': vulnerability,
            'extra_data': extra_data,
        }

        # Enqueue task if not already processed
        task_identifier = (src_dest, vulnerability)
        with self.processed_vulnerabilities_lock:
            if task_identifier not in self.processed_vulnerabilities:
                self.processed_vulnerabilities.add(task_identifier)
                logging.info(f'Zeek detected vulnerability {vulnerability} for {src_dest}')
                self.vuln_queue.put(task)

        # If full_version is enabled, run full testssl
        if self.full_version:
            with self.servers_tested_lock:
                if ip_src not in self.servers_tested:
                    self.servers_tested.add(ip_src)
                    testssl_full(ip_src, port_src)

    def run(self):
        """
        Starts the vulnerability scanner.
        """
        try:
            if self.ids.upper() == 'SURICATA':
                threading.Thread(target=tail_file, args=('/var/log/suricata/fast.log', self.file_reader_suricata),
                                 daemon=True).start()
            elif self.ids.upper() == 'ZEEK':
                threading.Thread(target=tail_file,
                                 args=('/usr/local/zeek/logs/current/notice.log', self.file_reader_zeek),
                                 daemon=True).start()
            else:
                logging.error(f"Unsupported IDS: {self.ids}")
                sys.exit(1)
            logging.info('Vulnerability scanner started...')
            self.check_vulnerabilities()
        except (KeyboardInterrupt, SystemExit):
            logging.info("Vulnerability scanner terminated.")
            sys.exit(0)

    @staticmethod
    def help_message():
        """
        Displays the help message.
        """
        out = '''run_monitoring
            ▁ ▂ ▃ ▅ ▆ ▇ █ Monitor for TLS attacks █ ▇ ▆ ▅ ▃ ▂ ▁

    usage: monitor_for_tls_attacks [-h] [--full] [--IDS=Suricata/Zeek] [--json /pathToConfigJSONFile]

    Monitor your network traffic with Suricata or Zeek IDS and check if the found vulnerabilities are TP or FP. Before starting this tool you must execute Suricata/Zeek.

    NOTE: If you have changed the default path of log file for the IDS you have to change it also in this tool.

    Suricata log path variable: src_path = r"/var/log/suricata/fast.log"

    Zeek log path variable:  src_path = r"/usr/local/zeek/logs/current/notice.log"

    optional arguments:

      -h, --help            show this help message and exit

      --full                use testssl to make a TLS configuration screenshot of the tested server

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
      '''
        print(out)


def tail_file(src_path: str, file_reader):
    """
    Tails a file and processes each new line using the provided file_reader function.
    """
    with open(src_path, "rb") as fp:
        fp.seek(0, os.SEEK_END)
        while True:
            line = fp.readline()
            if not line:
                time.sleep(0.1)
                continue
            file_reader(line)


def testssl_full(ip: str, port: str):
    """
    Runs a full testssl scan on the specified IP and port.
    """
    logging.info(f'Starting testssl full scan for {ip}:{port}')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = Path(f"./Logs/testssl_{ip}_{port}_{timestamp}.log")
    addr = f"{ip}:{port}"
    try:
        testssl = subprocess.run(
            [
                'testssl',
                '-U',
                '--full',
                '--severity',
                'LOW',
                '--json',
                '--parallel',
                '-n',
                'none',
                '--logfile',
                str(filename),
                addr,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        with open(f"color_{filename}.html", 'w') as color_file:
            subprocess.run(['aha', '-f', str(filename)], stdout=color_file)
        logging.info(f'Testssl full scan completed for {ip}:{port}, results in {filename}')
    except subprocess.CalledProcessError as e:
        logging.error(f"Testssl full scan failed for {ip}:{port}: {e.stderr}")
    except Exception as e:
        logging.error(f"Error during testssl full scan for {ip}:{port}: {e}")


def parse_args():
    """
    Parses command-line arguments.
    """
    import argparse

    parser = argparse.ArgumentParser(description='Monitor for TLS attacks.')
    parser.add_argument('--full', action='store_true',
                        help='Use testssl to make a TLS configuration screenshot of the tested server')
    parser.add_argument('--IDS', choices=['Suricata', 'Zeek'], default='Suricata', help='Use Suricata or Zeek as IDS')
    parser.add_argument('--zeek', action='store_const', const='Zeek', dest='IDS', help='Use Zeek as IDS')
    parser.add_argument('--json', type=str, help='Use a network config file in JSON format')
    parser.add_argument('--attack', type=str, help='Specify an attack to perform')
    parser.add_argument('--host', type=str, help='Specify the host (ip:port) to attack')
    return parser.parse_args()


def delete_old_logs(log_dir, max_age_days=1):
    """
    Deletes log files older than `max_age_days` from the specified directory.

    Args:
        log_dir (str or Path): The directory containing the log files.
        max_age_days (int): The maximum age of log files in days. Older files will be deleted.
    """
    log_dir = Path(log_dir)
    if not log_dir.exists():
        log_message(f"Log directory {log_dir} does not exist. Skipping cleanup.", "WARNING")
        return

    now = datetime.now()
    max_age_seconds = max_age_days * 24 * 60 * 60

    for log_file in log_dir.glob("**/*"):  # Recursively find all log files
        if log_file.is_file():
            file_age_seconds = (now - datetime.fromtimestamp(log_file.stat().st_mtime)).total_seconds()
            if file_age_seconds > max_age_seconds:
                try:
                    log_file.unlink()  # Deletes the file
                    log_message(f"Deleted old log file: {log_file}", "SUCCESS")
                except Exception as e:
                    log_message(f"Error deleting log file {log_file}: {e}", "ERROR")


def main():
    args = parse_args()
    log_dir = "./Logs"
    delete_old_logs(log_dir, max_age_days=1)

    if args.attack and args.host:
        logging.info(f"Performing attack '{args.attack}' on host '{args.host}'")
        single_attack(args.attack, args.host)
        sys.exit(0)

    # Load configurations from JSON if provided
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
        full_version=args.full,
        ids=args.IDS,
        versions_config=versions_config,
        ciphers_config=ciphers_config,
        certificate_fingerprint_config=certificate_fingerprint_config
    )

    scanner.run()


if __name__ == "__main__":
    main()
