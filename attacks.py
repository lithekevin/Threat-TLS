import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from shutil import which

from colorama import init, Fore, Style
from sqlalchemy.orm import sessionmaker
from socketio_manager import socketio

from db import engine
from models import Server, AttackResult

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

COLOR = {
    "INFO": Fore.CYAN,
    "START": Fore.YELLOW,
    "SUCCESS": Fore.GREEN,
    "WARNING": Fore.YELLOW,
    "ERROR": Fore.RED,
    "ENDC": Style.RESET_ALL,
}



Session = sessionmaker(bind=engine)
thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, 'session'):
        thread_local.session = Session()
    return thread_local.session

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

def save_attack_result(ip, port, stdout, attack, tool, vulnerable, detection_time):
    """
    Saves the attack result to the database and updates server information if necessary.
    """
    session = get_session()

    # Find or create the server
    server = session.query(Server).filter_by(ip=ip).first()  # Search by IP only
    if not server:
        server = Server(ip=ip, port=port)
        session.add(server)
        session.commit()
    elif server.port == '':
        server.port = port
        session.commit()

    completion_time = time.time()
    processing_time = completion_time - detection_time  # Time in seconds

    attack_result = AttackResult(
        server_id=server.id,
        attack_name=attack,
        tool=tool,
        vulnerable=vulnerable,
        log_content=stdout,
        timestamp=datetime.fromtimestamp(completion_time),
        processing_time=processing_time
    )
    session.add(attack_result)
    session.commit()
    log_message(f"Result of {attack} ({tool}) on {ip}:{port} saved to the database", "SUCCESS")

    all_results = session.query(AttackResult).filter_by(server_id=server.id).all()
    server.overall_status = 'Secure' if all(not result.vulnerable for result in all_results) else 'Vulnerable'
    session.commit()

    socketio.emit('update', {'message': 'New attack result', 'ip': ip, 'port': port})

    session.close()




def check_vulnerability(log_content, tool):
    """
    Checks if the log content indicates a vulnerability, specific to the tool used.
    """
    tool_keywords = {
        "TestSSL": [
            r'VULNERABLE --',
            r'potentially VULNERABLE',
            r'VULNERABLE \(NOT ok\)',
            r'potentially NOT ok',
            r'uses 64 bit block ciphers',
            r'sslv3.*poodle',
            r'sslv2 offered with \d+ ciphers',
        ],
        "OSAFT": [
            r'no \(.*\)',
            r'not safe against .*attack',
        ],
        "Nmap": [
            r'VULNERABLE',
        ],
        "Metasploit": [
            r'response with leak',
            r'probably vulnerable',
            r'vulnerable:'
        ]
    }


    if tool in tool_keywords:
        for keyword in tool_keywords[tool]:
            if re.search(keyword, log_content):
                return True

    return False

def run_subprocess(command_list, ip, port, attack, tool, detection_time, timeout=None):
    """
    Runs a subprocess with the given command list, capturing the output and errors.
    """

    try:
        log_message(f"Starting {attack} ({tool}) on {ip}:{port}", "START")
        process = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(timeout=timeout)
        stdout = stdout.decode()
        stderr = stderr.decode()
        combined_output = stdout + stderr

        # Determine if the output indicates a vulnerability
        vulnerable = check_vulnerability(combined_output,tool)

        # Save the result to the database
        save_attack_result(ip, port, combined_output, attack, tool, vulnerable, detection_time)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        stdout = stdout.decode()
        stderr = stderr.decode()
        combined_output = stdout + stderr
        log_message(f"{attack} ({tool}) on {ip}:{port} timed out after {timeout} seconds", "WARNING")

        # Save the result to the database, mark as not vulnerable due to timeout
        save_attack_result(ip, port, combined_output, attack, tool, vulnerable=False, detection_time=detection_time)
    except Exception as e:
        log_message(f"Error running subprocess for {attack} ({tool}) on {ip}:{port}: {e}", "ERROR")



def run_testssl(ip, port, options, attack_name, tool, detection_time, timeout=None):
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
    run_subprocess(command_list, ip, port, attack_name, tool, detection_time, timeout)


def run_tls_attacker(ip, port, attack_type, attack_name, tool, detection_time, timeout=None):
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
    run_subprocess(command_list, ip, port, attack_name, tool, detection_time, timeout)


def run_nmap(ip, port, script_name, attack_name, tool, detection_time, timeout=None):
    if not is_tool_available('nmap'):
        log_message("nmap is not installed or not in PATH", "ERROR")
        return
    command_list = ['nmap', '-T4', '-p', port, f'--script={script_name}', ip]
    run_subprocess(command_list, ip, port, attack_name, tool, detection_time, timeout)


def run_metasploit(ip, port, module, settings, attack_name, tool, detection_time, timeout=None):
    if not is_tool_available('msfconsole'):
        log_message("Metasploit msfconsole is not installed or not in PATH", "ERROR")
        return
    commands = f"use {module};"
    for key, value in settings.items():
        commands += f"set {key} {value};"
    commands += "run; exit"
    command_list = ['msfconsole', '-q', '-x', commands]
    run_subprocess(command_list, ip, port, attack_name, tool, detection_time, timeout)




# Attack Functions
def metasploit_heartbleed_process(ip, port, tls_version, detection_time):
    settings = {
        'RHOSTS': ip,
        'RPORT': port,
        'TLS_VERSION': tls_version
    }
    run_metasploit(ip, port, 'auxiliary/scanner/ssl/openssl_heartbleed', settings, 'Heartbleed', 'Metasploit', detection_time=detection_time)


def nmap_heartbleed_process(ip, port, detection_time):
    run_nmap(ip, port, 'ssl-heartbleed', 'Heartbleed', 'Nmap', detection_time=detection_time)


def heartbleed_testssl(ip, port, detection_time):
    options = ['--heartbleed']
    run_testssl(ip, port, options, 'Heartbleed', 'TestSSL', detection_time=detection_time)


def heartbleed_tls_attacker(ip, port, detection_time):
    run_tls_attacker(ip, port, 'heartbleed', 'Heartbleed', 'TLS-Attacker', detection_time=detection_time)


def crime_testssl(ip, port, detection_time):
    options = ['--crime']
    run_testssl(ip, port, options, 'CRIME', 'TestSSL', detection_time=detection_time)


def padding_attack_process_tls_attacker(ip, port, detection_time):
    run_tls_attacker(ip, port, 'padding_oracle', 'Padding Oracle', 'TLS-Attacker', detection_time=detection_time)


def poodle_nmap_process(ip, port, detection_time):
    run_nmap(ip, port, 'ssl-poodle', 'POODLE', 'Nmap', detection_time=detection_time)


def poodle_testssl(ip, port, detection_time):
    options = ['--poodle']
    run_testssl(ip, port, options, 'POODLE', 'TestSSL', detection_time=detection_time)


def poodle_tls_attacker(ip, port, detection_time):
    run_tls_attacker(ip, port, 'POODLE', 'POODLE', 'TLS-Attacker', detection_time=detection_time)

def poodle_osaft(ip, port, detection_time):
    """
    Runs the POODLE vulnerability test using OSAFT.
    """
    if not is_tool_available('o-saft'):
        log_message("OSAFT is not installed or not in PATH", "ERROR")
        return
    host = f"{ip}:{port}"
    command_list = ['o-saft', '+poodle', host]
    run_subprocess(command_list, ip, port, 'POODLE', 'OSAFT', detection_time=detection_time)


def lucky13_testssl(ip, port, detection_time):
    options = ['--lucky13']
    run_testssl(ip, port, options, 'Lucky13', 'TestSSL', detection_time=detection_time)


def drown_testssl(ip, port, detection_time):
    options = ['--drown']
    run_testssl(ip, port, options, 'DROWN', 'TestSSL', detection_time=detection_time)


def drown_tls_attacker(ip, port, detection_time):
    run_tls_attacker(ip, port, 'generalDrown', 'DROWN', 'TLS-Attacker', detection_time=detection_time)


def sweet32_testssl(ip, port, detection_time):
    options = ['--sweet32']
    run_testssl(ip, port, options, 'Sweet32', 'TestSSL', detection_time=detection_time)


def logjam_testssl(ip, port, detection_time):
    options = ['--logjam']
    run_testssl(ip, port, options, 'Logjam', 'TestSSL', detection_time=detection_time)


def logjam_process_nmap(ip, port, detection_time):
    run_nmap(ip, port, 'ssl-dh-params.nse', 'Logjam', 'Nmap', detection_time=detection_time)


def bleichenbachers_tls_attacker(ip, port, detection_time):
    run_tls_attacker(ip, port, 'bleichenbacher', 'Bleichenbacher', 'TLS-Attacker', detection_time=detection_time)


def roca_testssl(ip, port, detection_time):
    options = ['--roca']
    run_testssl(ip, port, options, 'ROCA', 'TestSSL', detection_time=detection_time)


def roca_nmap(ip, port, detection_time):
    run_nmap(ip, port, 'rsa-vuln-roca', 'ROCA', 'Nmap', detection_time=detection_time)


def ticketbleed_testssl(ip, port, detection_time):
    options = ['--ticketbleed']
    run_testssl(ip, port, options, 'Ticketbleed', 'TestSSL', detection_time=detection_time)


def ticketbleed_nmap(ip, port, detection_time):
    run_nmap(ip, port, 'tls-ticketbleed', 'Ticketbleed', 'Nmap', detection_time=detection_time)


def ccs_injection_testssl(ip, port, detection_time):
    options = ['--ccs']
    run_testssl(ip, port, options, 'CCS Injection', 'TestSSL', detection_time=detection_time)


def ccs_injection_process_nmap(ip, port, detection_time):
    run_nmap(ip, port, 'ssl-ccs-injection', 'CCS Injection', 'Nmap', detection_time=detection_time)

def ccs_injection_process_metasploit(ip, port, detection_time):
    settings = {
        'RHOST': ip,
        'RPORT': port
    }
    run_metasploit(ip, port, 'auxiliary/scanner/ssl/openssl_ccs', settings, 'CCS Injection', 'Metasploit', detection_time=detection_time)


def beast_testssl(ip, port, detection_time):
    options = ['--beast']
    run_testssl(ip, port, options, 'BEAST', 'TestSSL', detection_time=detection_time)


def rc4_testssl(ip, port, detection_time):
    options = ['--rc4']
    run_testssl(ip, port, options, 'RC4', 'TestSSL', detection_time=detection_time)

def robot_testssl(ip, port, detection_time):
    options = ['--robot']
    run_testssl(ip, port, options, 'ROBOT', 'TestSSL', detection_time=detection_time)

def robot_metasploit(ip, port, detection_time):
    settings = {
        'RHOST': ip,
        'RPORT': port
    }
    run_metasploit(ip, port, 'auxiliary/scanner/ssl/bleichenbacher_oracle', settings, 'ROBOT', 'Metasploit', detection_time=detection_time)

def heartbleed_osaft(ip, port, detection_time):
    """
    Runs the Heartbleed vulnerability test using OSAFT.
    """
    if not is_tool_available('o-saft'):
        log_message("OSAFT is not installed or not in PATH", "ERROR")
        return
    host = f"{ip}:{port}"
    command_list = ['o-saft', '+heartbleed', host]
    run_subprocess(command_list, ip, port, 'Heartbleed', 'OSAFT', detection_time=detection_time)

def crime_osaft(ip, port, detection_time):
    """
    Runs the CRIME vulnerability test using OSAFT.
    """
    if not is_tool_available('o-saft'):
        log_message("OSAFT is not installed or not in PATH", "ERROR")
        return
    host = f"{ip}:{port}"
    command_list = ['o-saft', '+crime', host]
    run_subprocess(command_list, ip, port, 'CRIME', 'OSAFT', detection_time=detection_time)


def beast_osaft(ip, port, detection_time):
    """
    Runs the BEAST vulnerability test using OSAFT.
    """
    if not is_tool_available('o-saft'):
        log_message("OSAFT is not installed or not in PATH", "ERROR")
        return
    host = f"{ip}:{port}"
    command_list = ['o-saft', '+beast', host]
    run_subprocess(command_list, ip, port, 'BEAST', 'OSAFT', detection_time=detection_time)


def freak_testssl(ip, port, detection_time):
    """
    Runs the FREAK vulnerability test using TestSSL.
    """
    if not is_tool_available('testssl'):
        log_message("TestSSL is not installed or not in PATH", "ERROR")
        return
    options = ['--freak']
    run_testssl(ip, port, options, 'FREAK', 'TestSSL', detection_time=detection_time)

def rc4_osaft(ip, port, detection_time):
    """
    Runs the RC4 vulnerability test using OSAFT.
    """
    if not is_tool_available('o-saft'):
        log_message("OSAFT is not installed or not in PATH", "ERROR")
        return
    host = f"{ip}:{port}"
    command_list = ['o-saft', '+rc4', host]
    run_subprocess(command_list, ip, port, 'RC4', 'OSAFT', detection_time=detection_time)

def freak_osaft(ip, port, detection_time):
    """
    Runs the FREAK vulnerability test using OSAFT.
    """
    if not is_tool_available('o-saft'):
        log_message("OSAFT is not installed or not in PATH", "ERROR")
        return
    host = f"{ip}:{port}"
    command_list = ['o-saft', '+freak', host]
    run_subprocess(command_list, ip, port, 'FREAK', 'OSAFT', detection_time=detection_time)