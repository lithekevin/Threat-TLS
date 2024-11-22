import os
import logging
import threading
from datetime import datetime
import subprocess
from pathlib import Path
from colorama import init, Fore, Style
from shutil import which

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

# Color definitions for logging
COLOR = {
    "INFO": Fore.CYAN,
    "START": Fore.YELLOW,
    "SUCCESS": Fore.GREEN,
    "WARNING": Fore.YELLOW,
    "ERROR": Fore.RED,
    "ENDC": Style.RESET_ALL,
}

# Maximum number of concurrent external processes (configurable via environment variable)
MAX_CONCURRENT_PROCESSES = int(os.environ.get('MAX_CONCURRENT_PROCESSES', 6))
external_process_semaphore = threading.Semaphore(MAX_CONCURRENT_PROCESSES)


def log_message(message, level="INFO"):
    """
    Logs a message with the specified color and level.
    """
    color = COLOR.get(level, COLOR["INFO"])
    logging.info(f"{color}{message}{COLOR['ENDC']}")


def is_tool_available(tool_name):
    """
    Checks if a tool is available in the system PATH.
    """
    return which(tool_name) is not None


def write_file(ip, port, stdout, attack):
    """
    Writes the output of an attack to a log file.
    """
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    header = f'---------START {attack}---------\nWrite at: {current_time}\n\n'
    footer = f'\n---------END {attack}---------\n\n'
    src_path = Path(f"./Logs/{ip}_{port}")
    src_path.mkdir(parents=True, exist_ok=True)
    current_time = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
    filename = src_path / f"{attack} {current_time}.log"
    try:
        with filename.open('w') as fp:
            fp.write(header)
            fp.write(stdout)
            fp.write(footer)
        log_message(f"Result of {attack} on {ip}:{port} written to file {filename}", "SUCCESS")
    except Exception as e:
        log_message(f"Error writing to file {filename}: {e}", "ERROR")


def run_subprocess(command_list, ip, port, attack, timeout=None):
    """
    Runs a subprocess with the given command list, capturing the output and errors.
    """
    with external_process_semaphore:
        try:
            log_message(f"Starting {attack} on {ip}:{port}", "START")
            process = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(timeout=timeout)
            stdout = stdout.decode()
            stderr = stderr.decode()
            write_file(ip, port, stdout + stderr, attack)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            stdout = stdout.decode()
            stderr = stderr.decode()
            log_message(f"{attack} on {ip}:{port} timed out after {timeout} seconds", "WARNING")
            write_file(ip, port, stdout + stderr, attack)
        except Exception as e:
            log_message(f"Error running subprocess for {attack} on {ip}:{port}: {e}", "ERROR")


def run_testssl(ip, port, options, attack_name, timeout=None):
    """
    Runs a testssl scan with the specified options.
    """
    if not is_tool_available('testssl'):
        log_message("testssl is not installed or not in PATH", "ERROR")
        return
    host = f"{ip}:{port}"
    command_list = [
        'testssl',
        *options,
        '--color', '0',
        '--parallel',
        '--warnings', 'off',
        host
    ]
    run_subprocess(command_list, ip, port, attack_name, timeout)


def run_tls_attacker(ip, port, attack_type, attack_name, timeout=None):
    """
    Runs a TLS-Attacker attack.
    """
    if not is_tool_available('java'):
        log_message("Java is not installed or not in PATH", "ERROR")
        return
    tls_attacker_path = os.environ.get('TLS_ATTACKER_PATH', '/home/kali/Desktop/TLS-Attacker/apps/Attacks.jar')
    if not os.path.exists(tls_attacker_path):
        log_message(f"TLS-Attacker JAR not found at {tls_attacker_path}", "ERROR")
        return
    host = f"{ip}:{port}"
    command_list = [
        'java', '-jar', tls_attacker_path, attack_type, '-connect', host
    ]
    run_subprocess(command_list, ip, port, attack_name, timeout)


def run_nmap(ip, port, script_name, attack_name, timeout=None):
    """
    Runs an nmap scan with the specified script.
    """
    if not is_tool_available('nmap'):
        log_message("nmap is not installed or not in PATH", "ERROR")
        return
    command_list = ['nmap', '-T4', '-p', port, f'--script={script_name}', ip]
    run_subprocess(command_list, ip, port, attack_name, timeout)


def run_metasploit(ip, port, module, settings, attack_name, timeout=None):
    """
    Runs a Metasploit module with specified settings.
    """
    if not is_tool_available('msfconsole'):
        log_message("Metasploit msfconsole is not installed or not in PATH", "ERROR")
        return
    commands = f"use {module};"
    for key, value in settings.items():
        commands += f"set {key} {value};"
    commands += "run; exit"
    command_list = ['msfconsole', '-q', '-x', commands]
    run_subprocess(command_list, ip, port, attack_name, timeout)


# Attack Functions
def metasploit_heartbleed_process(ip, port, tls_version):
    settings = {
        'RHOSTS': ip,
        'RPORT': port,
        'TLS_VERSION': tls_version
    }
    run_metasploit(ip, port, 'auxiliary/scanner/ssl/openssl_heartbleed', settings, 'Heartbleed by Metasploit')


def nmap_heartbleed_process(ip, port):
    run_nmap(ip, port, 'ssl-heartbleed', 'Heartbleed by Nmap', timeout=120)


def heartbleed_testssl(ip, port):
    options = ['--heartbleed']
    run_testssl(ip, port, options, 'Heartbleed by TestSSL')


def heartbleed_tls_attacker(ip, port):
    run_tls_attacker(ip, port, 'heartbleed', 'Heartbleed by TLS-Attacker', timeout=80)


def crime_testssl(ip, port):
    options = ['--crime']
    run_testssl(ip, port, options, 'CRIME by TestSSL')


def breach_testssl(ip, port):
    options = ['--breach']
    run_testssl(ip, port, options, 'BREACH by TestSSL')


def padding_attack_process_tls_attacker(ip, port):
    run_tls_attacker(ip, port, 'padding_oracle', 'Padding Oracle attack by TLS-Attacker', timeout=80)


def poodle_nmap_process(ip, port):
    run_nmap(ip, port, 'ssl-poodle', 'POODLE by Nmap')


def poodle_testssl(ip, port):
    options = ['--poodle']
    run_testssl(ip, port, options, 'POODLE by TestSSL')


def poodle_tls_attacker(ip, port):
    run_tls_attacker(ip, port, 'poodle', 'POODLE by TLS-Attacker', timeout=80)


def lucky13_testssl(ip, port):
    options = ['--lucky13']
    run_testssl(ip, port, options, 'Lucky13 by TestSSL')


def drown_testssl(ip, port):
    options = ['--drown']
    run_testssl(ip, port, options, 'DROWN by TestSSL')


def drown_tls_attacker(ip, port):
    run_tls_attacker(ip, port, 'generalDrown', 'DROWN by TLS-Attacker', timeout=80)


def sweet32_testssl(ip, port):
    options = ['--sweet32']
    run_testssl(ip, port, options, 'Sweet32 by TestSSL')


def logjam_testssl(ip, port):
    options = ['--logjam']
    run_testssl(ip, port, options, 'Logjam by TestSSL')


def logjam_process_nmap(ip, port):
    run_nmap(ip, port, 'ssl-dh-params.nse', 'Logjam by Nmap')


def bleichenbachers_process(ip, port):
    run_tls_attacker(ip, port, 'bleichenbacher', 'Bleichenbacher\'s by TLS-Attacker', timeout=80)


def robot_testssl(ip, port):
    options = ['--robot']
    run_testssl(ip, port, options, 'ROBOT by TestSSL')


def robot_metasploit(ip, port):
    settings = {
        'RHOST': ip,
        'RPORT': port
    }
    run_metasploit(ip, port, 'auxiliary/scanner/ssl/bleichenbacher_oracle', settings, 'ROBOT by Metasploit')


def roca_testssl(ip, port):
    options = ['--roca']
    run_testssl(ip, port, options, 'ROCA by TestSSL')


def roca_nmap(ip, port):
    run_nmap(ip, port, 'rsa-vuln-roca', 'ROCA by Nmap')


def ticketbleed_testssl(ip, port):
    options = ['--ticketbleed']
    run_testssl(ip, port, options, 'Ticketbleed by TestSSL')


def ticketbleed_nmap(ip, port):
    run_nmap(ip, port, 'tls-ticketbleed', 'Ticketbleed by Nmap')


def ccs_injection_testssl(ip, port):
    options = ['--ccs']
    run_testssl(ip, port, options, 'CCS Injection by TestSSL')


def ccs_injection_process_nmap(ip, port):
    run_nmap(ip, port, 'ssl-ccs-injection', 'CCS Injection by Nmap')


def ccs_injection_process_metasploit(ip, port):
    settings = {
        'RHOST': ip,
        'RPORT': port
    }
    run_metasploit(ip, port, 'auxiliary/scanner/ssl/openssl_ccs', settings, 'CCS Injection by Metasploit')


def beast_testssl(ip, port):
    options = ['--beast']
    run_testssl(ip, port, options, 'BEAST by TestSSL')


def rc4_testssl(ip, port):
    options = ['--rc4']
    run_testssl(ip, port, options, 'RC4 by TestSSL')

