import json
import time
from datetime import datetime
import threading
import sys
import subprocess
import os
import queue
import logging
import paramiko
from paramiko import SSHException, AuthenticationException
from threading import Lock
from concurrent.futures import ThreadPoolExecutor
from ciphers import cbc_ciphers, rsa_ciphers, export_ciphers, des_ciphers
from certificate import (
    get_cert_for_hostname,
    get_cert_status_for_host,
    get_certificate_fingerprint,
)
from single_attack import single_attack
import requests
from cveMap import attack_cve_mapping
from attacks import (metasploit_process, nmap_process, testssl_heartbleed_process, heartbleed_tls_attacker,
                     crime_process,
                     padding_attack_process_tls_attacker, poodle_nmap_process, poodle_testssl, poodle_tls_attacker,
                     lucky13_process, drown_attack, drown_tls_attacker, sweet32_process, logjam_process,
                     logjam_process_nmap,
                     bleichenbachers_process,
                     robot_process, robot_metasploit, roca_process, ticketbleed_process, ccs_injection_process_nmap,
                     ccs_injection_process_metasploit, COLOR)

MAX_QUEUE_SIZE = 100
MAX_WORKERS = 20
api_key = "59389710-bfb2-49bf-b933-3d286c183616"
full_version = 0
IDS = 'Suricata'
ciphers_config = []
versions_config = []
certificate_fingerprint_config = []
config_input = False
processed_vulnerabilities = set()
processed_vulnerabilities_lock = Lock()
vulnerability_results = {}
servers_tested = set()
servers_tested_lock = Lock()
vuln_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
cve_cache = {}
server_versions_cache = {}
cache_lock = threading.Lock()
server_locks = {}
server_locks_lock = threading.Lock()

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')


def get_cve_details(cve_id, cpes):
    if cve_id in cve_cache:
        return cve_cache[cve_id]

    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    headers = {
        'apiKey': api_key
    }

    params = [('cveId', cve_id)]
    for cpe in cpes:
        params.append(('cpeName', cpe))

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            cve_data = response.json()
            cve_cache[cve_id] = cve_data
            return cve_data
        else:
            logging.error(f"Failed to get CVE details for {cve_id}. HTTP Status: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error fetching CVE details: {e}")
        return None


def parse_openssl_version(output):
    logging.info(f"OpenSSL output: {output}")
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("OpenSSL"):
            parts = line.split()
            if len(parts) >= 2:
                version = parts[1]
                return clean_openssl_version(version)
    return None


def clean_openssl_version(version):
    if version == "1.0.2o":
        return "1.0.2"
    return version


def parse_apache_version(output):
    logging.info(f"Apache output: {output}")
    for line in output.splitlines():
        line = line.strip()
        if "Server version" in line:
            parts = line.split("Server version:")
            if len(parts) > 1:
                version_line = parts[1].strip()
                version = version_line.split()[0].replace("Apache/", "")
                return version
        elif line.startswith("Apache/"):
            version = line.split()[0].replace("Apache/", "")
            return version
    return None


def get_server_versions(ip, username='server', password='server'):
    with cache_lock:
        if ip in server_versions_cache:
            return server_versions_cache[ip]

    with server_locks_lock:
        if ip not in server_locks:
            server_locks[ip] = threading.Lock()
        server_lock = server_locks[ip]

    with server_lock:
        with cache_lock:
            if ip in server_versions_cache:
                return server_versions_cache[ip]

        versions = {}
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=22, username=username, password=password, timeout=10)
            stdin, stdout, stderr = ssh.exec_command('openssl version')
            openssl_output = stdout.read().decode().strip()
            versions['openssl'] = parse_openssl_version(openssl_output)
            stdin, stdout, stderr = ssh.exec_command('apache2 -v')
            apache_output = stdout.read().decode().strip()
            versions['apache'] = parse_apache_version(apache_output)
            ssh.close()

            with cache_lock:
                server_versions_cache[ip] = versions

            return versions
        except AuthenticationException as auth_exc:
            logging.error(f"Authentication failed when connecting to {ip}: {auth_exc}")
            return None
        except SSHException as ssh_exc:
            logging.error(f"Could not establish SSH connection to {ip}: {ssh_exc}")
            return None
        except Exception as e:
            logging.error(f"Error getting server versions for {ip}: {e}")
            return None


def build_cpes(versions):
    cpes = []
    if 'openssl' in versions and versions['openssl']:
        openssl_version = versions['openssl']
        cpe_openssl = f"cpe:2.3:a:openssl:openssl:{openssl_version}"
        cpes.append(cpe_openssl)
    if 'apache' in versions and versions['apache']:
        apache_version = versions['apache']
        cpe_apache = f"cpe:2.3:a:apache:http_server:{apache_version}"
        cpes.append(cpe_apache)
    return cpes


def process_vulnerability(task):
    connection = task['connection']
    vulnerability = task['vulnerability']
    extra_data = task.get('extra_data', {})
    source = connection.split("->")[0]
    dest = connection.split("->")[1]
    ip_source = source.split(":")[0].strip()
    port_source = source.split(":")[1].strip()

    certificate_vulnerabilities = {'CERTIFICATE', 'EXPIRED', 'SELF SIGNED'}

    if vulnerability in certificate_vulnerabilities:
        logging.info(
            f"{COLOR['YELLOW']}Start certificate test for {ip_source}:{port_source} for {vulnerability} vulnerability{COLOR['ENDC']}"
        )
        process_certificate(ip_source, port_source)
        logging.info(f"Finished processing {vulnerability} for {connection}")
        return

    versions = get_server_versions(ip_source)
    if not versions:
        logging.info(f"Could not get server versions for {ip_source}. Skipping vulnerability {vulnerability}")
        return

    cpes = build_cpes(versions)
    if not cpes:
        logging.info(f"No CPEs built for {ip_source}. Skipping vulnerability {vulnerability}")
        return

    cve_id = attack_cve_mapping.get(vulnerability)
    if not cve_id:
        logging.info(f"No CVE mapping for vulnerability {vulnerability}. Skipping")
        return

    cve_data = get_cve_details(cve_id, cpes)
    if not cve_data or 'vulnerabilities' not in cve_data or not cve_data['vulnerabilities']:
        logging.info(f"Could not get CVE details for {cve_id}. Skipping vulnerability {vulnerability} or "
                     f"No matching CPEs for vulnerability {vulnerability} on {ip_source}. Skipping")
        return

    logging.info(
        f"{COLOR['YELLOW']}Start test for {ip_source}:{port_source} for {vulnerability} vulnerability{COLOR['ENDC']}"
    )

    vulnerability_tests = {
        'HEARTBEAT EXTENSION': [
            lambda: metasploit_process(ip_source, port_source, extra_data.get('tls_version', '')),
            lambda: nmap_process(ip_source, port_source),
            lambda: testssl_heartbleed_process(ip_source, port_source),
            lambda: heartbleed_tls_attacker(ip_source, port_source),
        ],
        'CRIME': [
            lambda: crime_process(ip_source, port_source),
        ],
        'PADDING ORACLE ATTACK': [
            lambda: padding_attack_process_tls_attacker(ip_source, port_source),
            lambda: poodle_nmap_process(ip_source, port_source),
            lambda: poodle_testssl(ip_source, port_source),
            lambda: poodle_tls_attacker(ip_source, port_source),
        ],
        'LUCKY13': [
            lambda: lucky13_process(ip_source, port_source),
        ],
        'DROWN': [
            lambda: drown_attack(ip_source, port_source),
            lambda: drown_tls_attacker(ip_source, port_source),
        ],
        'SWEET32': [
            lambda: sweet32_process(ip_source, port_source),
        ],
        'LOGJAM': [
            lambda: logjam_process(ip_source, port_source),
            lambda: logjam_process_nmap(ip_source, port_source),
        ],
        'BLEICHENBACHER': [
            lambda: bleichenbachers_process(ip_source, port_source),
            lambda: robot_process(ip_source, port_source),
            lambda: robot_metasploit(ip_source, port_source),
            lambda: roca_process(ip_source, port_source),
        ],
        'TICKETBLEED': [
            lambda: ticketbleed_process(ip_source, port_source),
        ],
        'CCSINJECTION': [
            lambda: ccs_injection_process_nmap(ip_source, port_source),
            lambda: ccs_injection_process_metasploit(ip_source, port_source),
        ],
        'CERTIFICATE': [
            lambda: process_certificate(ip_source, port_source),
        ],
    }
    tests = vulnerability_tests.get(vulnerability, [])
    for test_func in tests:
        test_func()

    logging.info(f"Finished processing {vulnerability} for {connection}")


def process_certificate(ip_source, port_source):
    cert, cert_string = get_cert_for_hostname(ip_source, port_source)
    certificate_monitored_fingerprint = get_certificate_fingerprint(cert, ip_source, port_source)
    if certificate_monitored_fingerprint not in certificate_fingerprint_config:
        get_cert_status_for_host(ip_source, port_source, cert, cert_string)
        logging.info(f'Started certificate test for {ip_source}:{port_source}')


def check_vulnerabilities():
    logging.info("Vulnerability test thread is started...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        while True:
            task = vuln_queue.get()
            if task is None:
                break
            executor.submit(process_vulnerability, task)
            vuln_queue.task_done()


def tail_file_suricata():
    src_path = r"/var/log/suricata/mio_fast.log"
    with open(src_path, "rb") as fp:
        fp.seek(0, os.SEEK_END)
        while True:
            line = fp.readline()
            if not line:
                time.sleep(0.1)
                continue
            file_reader_suricata(line)


def tail_file_zeek():
    src_path = r"/usr/local/zeek/logs/current/ssl.log"
    with open(src_path, "rb") as fp:
        fp.seek(0, os.SEEK_END)
        while True:
            line = fp.readline()
            if not line:
                time.sleep(0.1)
                continue
            file_reader_zeek(line.decode())


def file_reader_suricata(line):
    cipher_suite_found = ''
    tls_version_found = ''
    source_dest = line.decode().partition("{TCP}")[2].strip()
    vuln = line.decode().partition("|VULNERABILITY|")
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
        if tls_version_found not in versions_config and tls_version_found:
            flag = True
        if cipher_suite_found not in ciphers_config and cipher_suite_found:
            flag = True
        if flag:
            task_identifier = (source_dest, new_vulnerability)
            with processed_vulnerabilities_lock:
                if task_identifier not in processed_vulnerabilities:
                    processed_vulnerabilities.add(task_identifier)
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
                    vuln_queue.put(task)
        if full_version == 1:
            source = source_dest.split("->")[0]
            ip_source = source.split(":")[0].split(" ")[1]
            port_source = source.split(":")[1].split(" ")[0]
            with servers_tested_lock:
                if ip_source not in servers_tested:
                    servers_tested.add(ip_source)
                    testssl_full(ip_source, port_source)


def file_reader_zeek(line):
    line_array = line.strip().split('\x09')
    if len(line_array) > 3 and line_array[2] not in {'uid', 'string'}:
        ip_src = line_array[2]
        port_src = line_array[3]
        ip_dest = line_array[4]
        port_dest = line_array[5]
        tls_version = line_array[6]
        cipher_suite = line_array[7]
        msg = line_array[15]
        compression = line_array[16]
        validation_status = line_array[20]
        zeek_produce(
            ip_src,
            ip_dest,
            port_dest,
            port_src,
            msg,
            compression,
            validation_status,
            cipher_suite,
            tls_version,
        )


def zeek_produce(
        ip_src, ip_dest, port_dest, port_src, msg, compression, validation_status, cipher_suite, tls_version
):
    exception_ip = '10.0.2.9'
    if ip_dest != exception_ip and ip_src != exception_ip:
        src_dest = f"{ip_dest}:{port_dest} -> {ip_src}:{port_src}"
        vulnerabilities = []
        extra_data = {}
        if tls_version != 'TLSv1.3':
            vulnerabilities.extend(['TICKETBLEED', 'CCSINJECTION'])
        if cipher_suite in export_ciphers:
            vulnerabilities.append('LOGJAM')
        if cipher_suite in des_ciphers:
            vulnerabilities.append('SWEET32')
        if cipher_suite in cbc_ciphers:
            vulnerabilities.extend(['PADDING ORACLE ATTACK', 'POODLE', 'LUCKY13'])
        if cipher_suite in rsa_ciphers:
            vulnerabilities.append('BLEICHENBACHER')
        if compression == 'COMPRESSION':
            vulnerabilities.append('CRIME')
        if tls_version == 'SSLv3':
            if 'POODLE' not in vulnerabilities:
                vulnerabilities.append('POODLE')
        if tls_version == 'SSLv2':
            vulnerabilities.append('DROWN')
        if msg == 'HEARTBEAT':
            vulnerabilities.append('HEARTBEAT EXTENSION')
            extra_data['tls_version'] = {
                'SSLv3': 'SSLv3',
                'TLSv10': '1.0',
                'TLSv11': '1.1',
                'TLSv12': '1.2',
                '-': '1.0',
            }.get(tls_version, '')
        if validation_status == 'self signed certificate\n':
            vulnerabilities.append('SELF SIGNED')
        vulnerabilities.append('CERTIFICATE')
        for vulnerability in vulnerabilities:
            task_identifier = (src_dest, vulnerability)
            with processed_vulnerabilities_lock:
                if task_identifier not in processed_vulnerabilities:
                    processed_vulnerabilities.add(task_identifier)
                    task = {
                        'connection': src_dest,
                        'vulnerability': vulnerability,
                        'extra_data': extra_data,
                    }
                    vuln_queue.put(task)
        if full_version == 1:
            with servers_tested_lock:
                if ip_src not in servers_tested:
                    servers_tested.add(ip_src)
                    testssl_full(ip_src, port_src)


def testssl_full(ip, port):
    logging.info(f'Starting testssl full scan for {ip}:{port}')
    filename = f"./Logs/testssl_{ip}_{port}.log"
    addr = f"{ip}:{port}"
    try:
        testssl = subprocess.Popen(
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
                filename,
                addr,
            ],
            stdout=subprocess.PIPE,
        )
        testssl.wait()
        with open(f"color_{filename}.html", 'w') as color:
            subprocess.run(['aha', '-f', filename], stdout=color)
        logging.info(f'Testssl full scan completed for {ip}:{port}, results in {filename}')
    except (SystemExit, KeyboardInterrupt):
        logging.info("TestSSL Process interrupted")


def main():
    global full_version, IDS, versions_config, ciphers_config, certificate_fingerprint_config
    if "-h" in sys.argv or "--help" in sys.argv:
        help_message()
    else:
        if "--attack" in sys.argv:
            i = sys.argv.index("--attack")
            attack = sys.argv.pop(i + 1)
            j = sys.argv.index("--host")
            host = sys.argv.pop(j + 1)
            single_attack(attack, host)
        else:
            logging.info('Starting Monitor for TLS Attacks...')
            if "--full" in sys.argv:
                logging.info("FULL VERSION enabled")
                full_version = 1
            if any(arg in sys.argv for arg in ["--IDS=Zeek", "--IDS=zeek", '--zeek', '--Zeek']):
                logging.info("Using ZEEK as IDS")
                IDS = "ZEEK"
            if "--json" in sys.argv:
                i = sys.argv.index("--json")
                with open(sys.argv.pop(i + 1)) as file:
                    json_format = json.load(file)
                    versions_config = json_format['versions']
                    ciphers_config = json_format['ciphers']
                    certificate_fingerprint_config = json_format.get('certificate_fingerprint', [])
                    for idx in range(len(certificate_fingerprint_config)):
                        certificate_fingerprint_config[idx] = certificate_fingerprint_config[idx].replace(':',
                                                                                                          '').lower()
                    _ = True
            try:
                if IDS == 'Suricata':
                    threading.Thread(target=tail_file_suricata, daemon=True).start()
                else:
                    threading.Thread(target=tail_file_zeek, daemon=True).start()
                logging.info('Program started...')
                check_vulnerabilities()
            except (KeyboardInterrupt, SystemExit):
                logging.info("End of the program")
                sys.exit()


def help_message():
    out = '''run_monitoring
        ▁ ▂ ▃ ▅ ▆ ▇ █ Monitor for TLS attacks █ ▇ ▆ ▅ ▃ ▂ ▁

usage: monitor_for_tls_attacks [-h] [--full] [--IDS=Suricata/Zeek] [--json /pathToConfigJSONFile]

Monitor your network traffic with Suricata or Zeek IDS and check if the found vulnerabilities are TP or FP. Before starting this tool you must execute Suricata/Zeek.

NOTE: If you have changed the default path of log file for the IDS you have to change it also in this tool.

Suricata log path variable: src_path = r"/var/log/suricata/fast.log"

Zeek log path variable:  src_path = r"/usr/local/zeek/logs/current/ssl.log"

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
  '''
    print(out)


if __name__ == "__main__":
    main()
