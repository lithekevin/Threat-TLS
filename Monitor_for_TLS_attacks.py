import json
import re
import time
from datetime import datetime
from multiprocessing import Process
import multiprocessing
import threading
from queue import Queue
import sys
import watchdog.events
import watchdog.observers
import subprocess
import os.path
from ciphers import cbc_ciphers, rsa_ciphers, export_ciphers, des_ciphers
from certificate import get_cert_for_hostname, get_ocsp_cert_status, get_cert_status_for_host

connessioni_attive = dict()
server_tested = []
vuln_conn = dict()
tls_version_conn = dict()
cv = threading.Condition()
MAX_NUM = 20
full_version = 0
IDS = 'Suricata'
nmap = False
ciphers_config = []
versions_config = []
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
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print(f'{current_time} --- {action}')


def log_print_attack(ip_source, port_source, attack):
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print(
        f"{current_time} --- {COLOR['YELLOW']}Start test for {ip_source}:{port_source} for {attack} vulnerability{COLOR['ENDC']}")


# ---------Scrittura su File ---------
def pulizia_output(string):
    s = string.split("Further")
    if s.__len__() == 1:
        s = s[0].split("<<--")[1]
    else:
        s = s[1]
    s2 = s.split("Done")[0]
    return s2


def write_file(ip, port, stdout, attacco):
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    if attacco == 'CRIME' or attacco == 'ROBOT' or attacco == 'LOGJAM' or attacco == 'SWEET32' or attacco == 'LUCKY13':
        stdout = pulizia_output(stdout)
    if attacco == 'BLEICHENBACHERS':
        stdout = escape_ansi(stdout)
    stringa_inizio = f'---------START {attacco}---------\nWrite at: {current_time}\n'
    stringa_fine = f'\n---------FINE {attacco}---------\n'
    try:
        fp = open(
            f'./Logs/{ip}_{port}.log',
            'a')
        fp.seek(0, 0)
        fp.write(stringa_inizio)
        # fp.write(s_fine)
        fp.write(stdout)
        fp.write(stringa_fine)
        fp.close()
        print(f"{current_time} --- {COLOR['BLUE']}Esito {attacco} su {ip}:{port} scritto su file{COLOR['ENDC']}")
    except (SystemExit, KeyboardInterrupt):
        print("END writing file")


# ----------SCRIPT ATTACCHI---------
def metasploit_prosess(ip, port, tls_version):
    command = f"use auxiliary/scanner/ssl/openssl_heartbleed;set RHOST {ip};set RPORT {port};set TLS_VERSION {tls_version};check;exit"
    try:
        metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)

        stout = metasploit.communicate()[0].decode().rpartition("-")
        # print(f'STOUT: {stout[2].removeprefix(" ")}')
        if stout[2].removeprefix(" ").__contains__('The target appears to be vulnerable.'):
            # print('--------DENTROOOO')
            commandKey = f"use auxiliary/scanner/ssl/openssl_heartbleed;set RHOST {ip};set RPORT {port};set TLS_VERSION {tls_version};keys;exit"
            metasploitKey = subprocess.Popen(['msfconsole', '-x', commandKey], stdout=subprocess.PIPE)
            keyout = metasploitKey.communicate()[0].decode()
            privateKey = keyout.rpartition('-----BEGIN RSA PRIVATE KEY-----')
            if privateKey[2] != '':
                privateKey = privateKey[2].rpartition('-----END RSA PRIVATE KEY-----')[0]
                privateKey = f'-----BEGIN RSA PRIVATE KEY-----{privateKey}-----END RSA PRIVATE KEY-----'
                # print(privateKey)
                write_file(ip, port, keyout, 'PRIVATE KEY RETRIEVED BY METASPLOIT')
                log_print(
                    f'The {ip}:{port} is vulnerable to Heartbleed. The private key is stolen and it is in the log file')
        # print("----MetaSploit Process:")
        # print(stout)
        write_file(ip, port, stout[2].removeprefix(" "), 'HEARTBLEED BY METASPLOIT')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Metasploit Process for KeyInterrupt")


def nmap_process(ip, port):
    heartbleed_script = "--script=ssl-heartbleed.nse"
    show_all = "--script-args=vulns.showall"
    command = f"nmap -A -p {port} --script=ssl-heartbleed.nse --script-args=vulns.showall {ip}"
    try:
        nmap = subprocess.Popen(['timeout', '120', 'nmap', '-A', '-p', port, heartbleed_script, show_all, ip],
                                stdout=subprocess.PIPE)
        # nmap = subprocess.Popen([command], stdout=subprocess.PIPE)

        stdout = nmap.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("|")
        # print(f"Output NMAP PROCESS: ${output}")
        if output[0] != '':
            o2 = output[1] + " " + output[2]
            # print("----NMAP Process:")
            # print(o2)
            s_finale = o2
        else:
            # print("Timeout for heartbleed attack in NMAP Process")
            s_finale = "Timeout for heartbleed attack in NMAP Process"

        write_file(ip, port, s_finale, 'HEARTBLEED BY NMAP')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP Process Heartbleed for KeyInterrupt")


def poodle_nmap_process(ip, port):
    poodle_script = "--script=ssl-poodle"
    show_all = "--script-args=vulns.showall"
    try:
        poodle = subprocess.Popen(['nmap', '-A', '-p', port, poodle_script, show_all, ip], stdout=subprocess.PIPE)

        stdout = poodle.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("|")
        o2 = output[1] + " " + output[2]
        # print("----POODLE Process:")
        # print(o2)
        write_file(ip, port, o2, 'POODLE BY NMAP')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP POODLE Process for KeyInterrupt")


def padding_attack_process(ip, port):
    path = "/home/kali/Desktop/TLS_Attack_Tools/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(['timeout', '35', 'java', '-jar', path, 'padding_oracle', '-connect', host],
                                  stdout=subprocess.PIPE)
        stdout = attack.communicate()[0].decode()
        # print("----Padding Oracle Attack Process:")
        # print(stdout)
        vulnerable = stdout.partition("Vulnerable:")
        # print("----Vulnerable-----")
        # print(vulnerable)
        if vulnerable[1] == "":
            # print("UNDEFINED")
            o2 = 'UNDEFINED'
        else:
            # print(f"{vulnerable[1]} {vulnerable[2]}")
            o2 = f"{vulnerable[1]} {vulnerable[2]}"

        write_file(ip, port, o2, 'Padding Oracle Attack')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt TLS ATTACKER Padding Oracle Attack process for KeyInterrupt")


def bleichenbachers_process(ip, port):
    path = "/home/kali/Desktop/TLS_Attack_Tools/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(['timeout', '35', 'java', '-jar', path, 'bleichenbacher', '-connect', host],
                                  stdout=subprocess.PIPE)
        stdout = attack.communicate()[0].decode()
        # print("----Bleichenbacher Process:")
        # print(stdout)
        write_file(ip, port, stdout, 'BLEICHENBACHERS')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Bleinchebachers Process for KeyInterrupt")


def robot_process(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--robot', '--color', '0', '--parallel', '--ssl-native', '--fast', host],
            stdout=subprocess.PIPE)
        stdout = attack.communicate()[0].decode()
        # print("----ROBOT Process:")
        # print(stdout)
        write_file(ip, port, stdout, 'ROBOT')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt ROBOT Process for KeyInterrupt")


def drownAttack(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--drown', '--color', '0', '--parallel', '--ssl-native', '--fast', host],
            stdout=subprocess.PIPE)
        stdout = attack.communicate()[0].decode()
        # print("----DROWN Process:")
        # print(stdout)
        write_file(ip, port, stdout, 'DROWN')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt DROWN Process for KeyInterrupt")


def sweet32Process(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--sweet32', '--color', '0', '--parallel', '--ssl-native', '--fast', host],
            stdout=subprocess.PIPE)
        stdout = attack.communicate()[0].decode()
        # print("----Sweet32 Process:")
        # print(stdout)
        write_file(ip, port, stdout, 'SWEET32')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Sweet32 Process for KeyInterrupt")


def lucky13Process(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--lucky13', '--color', '0', '--parallel', '--ssl-native', '--fast', host],
            stdout=subprocess.PIPE)
        stdout = attack.communicate()[0].decode()
        # print("----Lucky13 Process:")
        # print(stdout)
        write_file(ip, port, stdout, 'LUCKY13')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Lucky13 Process for KeyInterrupt")


def logJamProcess(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--logjam', '--color', '0', '--parallel', '--ssl-native', '--fast', host],
            stdout=subprocess.PIPE)
        stdout = attack.communicate()[0].decode()
        # print("----LOGJAM Process:")
        # print(stdout)
        write_file(ip, port, stdout, 'LOGJAM')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt LOGJAM Process for KeyInterrupt")


def crimeProcess(ip, port):
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(
            ['testssl', '--crime', '--color', '0', '--parallel', '--ssl-native', '--fast', host],
            stdout=subprocess.PIPE)
        stdout = attack.communicate()[0].decode()
        # print("----CRIME Process:")
        # print(stdout)
        write_file(ip, port, stdout, 'CRIME')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt CRIME Process for KeyInterrupt")


def ticketBleedProcess(ip, port):
    'nmap -A -p 443 --script=tls-ticketbleed --script-args=vulns.showall 10.0.2.7'
    ticketBleed_script = "--script=tls-ticketbleed"
    show_all = "--script-args=vulns.showall"
    try:
        poodle = subprocess.Popen(['nmap', '-A', '-p', port, ticketBleed_script, show_all, ip], stdout=subprocess.PIPE)

        stdout = poodle.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("|")
        if output.__len__() > 1:
            o2 = output[1] + " " + output[2]
        else:
            o2 = stdout.partition("NSE: ")[2].split("Nmap")[0]

        write_file(ip, port, o2, 'TICKETBLEED BY NMAP')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP POODLE Process for KeyInterrupt")


def CCSInjectionProcess_nmap(ip, port):
    CCSInjection_script = "--script=ssl-ccs-injection"
    show_all = "--script-args=vulns.showall"
    stdout = ''
    try:
        poodle = subprocess.Popen(['nmap', '-A', '-p', port, CCSInjection_script, show_all, ip],
                                  stdout=subprocess.PIPE)

        stdout = poodle.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("ssl-ccs-injection:")
        if output.__len__() > 1:
            o = output[1].split('|_')
            if o.__len__() <= 1:
                write_file(ip, port, stdout, 'CCS Injection BY NMAP')
            else:
                o2 = 'ssl-ccs-injection:' + o[0] + o[1]
                write_file(ip, port, o2, 'CCS Injection BY NMAP')
        else:
            write_file(ip, port, stdout, 'CCS Injection BY NMAP')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP CCS Injection Process for KeyInterrupt")
    except (IndexError):
        write_file(ip, port, f"Server responds in unexpected way:\n RESPONSE:{stdout}", 'CCS Injection BY NMAP')


def CCSInjectionProcess_metasploit(ip, port, tls_version):
    command = f"use auxiliary/scanner/ssl/openssl_ccs;set RHOST {ip};set RPORT {port};set TLS_VERSION {tls_version};exploit;exit"
    try:
        metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)

        stout = metasploit.communicate()[0].decode().rpartition('Starting persistent handler(s)...')

        write_file(ip, port, stout[2], 'CCS Injection BY METASPLOIT')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt Metasploit Process for KeyInterrupt")


def rocaProcess(ip, port):
    roca_script = "--script=rsa-vuln-roca"
    show_all = "--script-args=vulns.showall"
    stdout = ''
    try:
        poodle = subprocess.Popen(['nmap', '-A', '-p', port, roca_script, show_all, ip],
                                  stdout=subprocess.PIPE)

        stdout = poodle.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("rsa-vuln-roca:")
        if output.__len__() > 1:
            o = output[1].split('|_')
            if o.__len__() <= 1:
                write_file(ip, port, stdout, 'ROCA Vulnerability')
            else:
                o2 = 'ssl-ccs-injection:' + o[0] + o[1]
                write_file(ip, port, o2, 'ROCA Vulnerability')
        else:
            write_file(ip, port, stdout, 'ROCA Vulnerability')
    except (SystemExit, KeyboardInterrupt):
        print("Interrupt NMAP ROCA Process for KeyInterrupt")
    except (IndexError):
        write_file(ip, port, f"Server responds in unexpected way:\n RESPONSE:{stdout}", 'ROCA Vulnerability')


# ---------------------------------
# --------------------------------
# TESTSSL
def testssl_lab(ip, port):
    nomefile = f"./Logs/testssl_{ip}:{port}.log"
    addr = f"{ip}:{port}"
    try:
        testssl = subprocess.Popen(
            ['testssl', '-U', '--full', '--severity', 'LOW', '--json', '--parallel', '-n', 'none', '--logfile',
             nomefile,
             addr],
            stdout=subprocess.PIPE)

        testssl.wait()
        # print("BEFORE AHA")
        color = open(f"color_{nomefile}.html", 'w')
        subprocess.run(['aha', '-f', nomefile], stdout=color)
        log_print(f'Testssl in full mode has produced the results for {ip}:{port} in file {nomefile}')
        # print("AFTER AHA")
    except (SystemExit, KeyboardInterrupt):
        print("END TestSSL Process for KeyInterrupt")


# ---------------------------------


class Handler(watchdog.events.PatternMatchingEventHandler):
    def __init__(self):
        # Set the patterns for PatternMatchingEventHandler
        watchdog.events.PatternMatchingEventHandler.__init__(self,
                                                             ignore_directories=True, case_sensitive=False)
        if IDS == "Suricata":
            logfile = open(r"/var/log/suricata/mio_fast.log", "rb")
        else:
            logfile = open(r"/usr/local/zeek/logs/current/ssl.log")
        self.logfile = logfile
        # self.logfile.seek(0, 0)

    def on_created(self, event):
        # print("Watchdog received created event - % s." % event.src_path)
        # Event is created, you can process it now
        log_print(f'The log file is created. Now we can start!')

    def on_modified(self, event):
        # print("Watchdog received modified event - % s." % event.src_path)
        # Event is modified, you can process it now
        # ------PRIMA-------
        if IDS == "Suricata":
            f = threading.Thread(target=file_reader_suricata, args=(self.logfile,), daemon=True)
        else:
            f = threading.Thread(target=file_reader_zeek, args=(self.logfile,), daemon=True)
        try:
            f.start()
        # f.join()
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
            # for i in range(1,15):
            #     print(i)
            #     time.sleep(1)
            cv.acquire()
            # print(vuln_conn.keys())
            # print(connessioni_attive)
            # job = []
            while len(vuln_conn.keys()) < 1:
                log_print("Empty Queue. It's time to sleep...")
                cv.wait()
                log_print(f"Someone knocks. WAKE UP!")

            keys = vuln_conn.keys()
            # print(keys)
            # print('-----')
            # print(vuln_conn)
            [connessioni, all_vuln_for_conn] = vuln_conn.popitem()
            # print(connessioni)
            # print(all_vuln_for_conn)

            # for connessioni in keys:
            # In caso si voglia distinguere sorgente e destinazione
            log_print(f"{COLOR['CIANO']}Found new connection: {connessioni}{COLOR['ENDC']}")
            source = connessioni.split("->")[0]
            dest = connessioni.split("->")[1]
            # print(f"SRC: {source}")
            # print(f"DEST: {dest}")
            if (IDS == 'Suricata'):
                ip_source = source.split(":")[0].split(" ")[1]

            else:
                ip_source = source.split(":")[0]

            ip_dest = dest.split(":")[0]

            # print(f"IP SRC: -{ip_source}-")
            # print(f"IP DEST: -{ip_dest}-")
            port_source = source.split(":")[1].split(" ")[0]
            port_dest = dest.split(":")[1]
            # print(f"PORT SRC: {port_source}")
            # print(f"PORT DEST: {port_dest}")
            # print(f"NUMERO VULN CONN: {vuln_conn}")
            # all_vuln_for_conn=vuln_conn.pop(connessioni)
            # print(f"NUMERO VULN CONN DOPO POP: {vuln_conn}")
            for test_vuln in all_vuln_for_conn:
                # print("Vulnerabilita TEST")
                # print(test_vuln)
                if test_vuln == "HEARTBEAT EXTENSION":
                    # print(connessioni_attive)
                    # connessioni_attive[connessioni].append(test_vuln)
                    # print("HEARTBLEED METASPLOIT")
                    # print(f"TLS_VERSION_CONN: {tls_version_conn}")
                    tls_version = tls_version_conn.pop(connessioni)
                    # print(f"TLS_VERSION: {tls_version} ")
                    heartbleed_metasploit = threading.Thread(target=metasploit_prosess,
                                                             args=(ip_source, port_source, tls_version))
                    heartbleed_metasploit.start()
                    # log_print(f'Start test for {ip_source}:{port_source} for HEARTBLEED vulnerability with Metasploit')
                    log_print_attack(ip_source, port_source, 'HEARTBEED WITH METASPLOIT')
                    job.append(heartbleed_metasploit)

                    if nmap:
                        # print("HEARTBLEED NMAP")
                        heartbleed_nmap = threading.Thread(target=nmap_process, args=(ip_source, port_source,))
                        heartbleed_nmap.start()
                        log_print(f'Start test for {ip_source}:{port_source} for HEARTBLEED vulnerability with NMAP')
                        job.append(heartbleed_nmap)

                if test_vuln == "CRIME":
                    # print("CRIME DOPO IF")
                    crime = threading.Thread(target=crimeProcess, args=(ip_source, port_source))
                    crime.start()
                    # log_print(f'Start test for {ip_source}:{port_source} for CRIME vulnerability')
                    job.append(crime)
                    # log_print(f'Server {ip_source}:{port_source} is vunerable to CRIME')
                    log_print_attack(ip_source, port_source, 'CRIME')

                if test_vuln == "PADDING ORACLE ATTACK":
                    # print("PADDING ORACLE ATTACK ---> DOPO IF")
                    padding_oracle = threading.Thread(target=padding_attack_process, args=(ip_source, port_source))
                    padding_oracle.start()
                    # log_print(f'Start test for {ip_source}:{port_source} for Padding Oracle Attack vulnerability')
                    log_print_attack(ip_source, ip_dest, 'PADDING ORACLE ATTACK')
                    job.append(padding_oracle)
                    # Lancio anche POODLE-----------
                    poodle = threading.Thread(target=poodle_nmap_process, args=(ip_source, port_source,))
                    poodle.start()
                    # log_print(f'Start test for {ip_source}:{port_source} for POODLE vulnerability')
                    log_print_attack(ip_source, ip_dest, 'POODLE')
                    job.append(poodle)
                    #Tolgo if di Luky13 perchè dovrebbe essere anche quello con CBC
                #if test_vuln == 'LUCKY13':
                    lucky13 = threading.Thread(target=lucky13Process, args=(ip_source, port_source))
                    lucky13.start()
                    log_print_attack(ip_source, port_source, 'LUCKY13 ATTACK')
                    job.append(lucky13)

                if test_vuln == 'DROWN':
                    drown = threading.Thread(target=drownAttack, args=(ip_source, port_source))
                    drown.start()
                    log_print_attack(ip_source, port_source, 'DROWN ATTACK')
                    job.append(drown)

                if test_vuln == 'SWEET32':
                    sweet32 = threading.Thread(target=sweet32Process, args=(ip_source, port_source))
                    sweet32.start()
                    log_print_attack(ip_source, port_source, 'SWEET32 ATTACK')
                    job.append(sweet32)



                if test_vuln == 'LOGJAM':
                    logjam = threading.Thread(target=logJamProcess, args=(ip_source, port_source))
                    logjam.start()
                    log_print_attack(ip_source, port_source, 'LOGJAM ATTACK')
                    job.append(logjam)

                if test_vuln == "BLEICHENBACHER":
                    # print("BLEICHENBACHER")
                    bleichenbachers = threading.Thread(target=bleichenbachers_process,
                                                       args=(ip_source, port_source,))
                    bleichenbachers.start()
                    # log_print(f'Start test for {ip_source}:{port_source} for BLEICHENBACHER vulnerability')
                    log_print_attack(ip_source, ip_dest, 'BLEICHENBACHER')
                    job.append(bleichenbachers)

                    # print("ROBOT")
                    # ------Lacnio anche ROBOT
                    robot = threading.Thread(target=robot_process,
                                             args=(ip_source, port_source,))
                    robot.start()
                    # log_print(f'Start test for {ip_source}:{port_source} for ROBOT vulnerability')
                    log_print_attack(ip_source, ip_dest, 'ROBOT')
                    job.append(robot)
                    # ------Lancio anche ROCA
                    roca = threading.Thread(target=rocaProcess,
                                            args=(ip_source, port_source,))
                    roca.start()
                    log_print_attack(ip_source, ip_dest, 'ROCA')
                    job.append(roca)

                if test_vuln == "TICKETBLEED":
                    ticketbleed = threading.Thread(target=ticketBleedProcess,
                                                   args=(ip_source, port_source,))
                    ticketbleed.start()
                    log_print_attack(ip_source, ip_dest, 'TICKETBLEED')
                    job.append(ticketbleed)

                if test_vuln == "CCSINJECTION":
                    ccsinjection_nmap = threading.Thread(target=CCSInjectionProcess_nmap,
                                                         args=(ip_source, port_source,))
                    ccsinjection_nmap.start()
                    log_print_attack(ip_source, ip_dest, 'CCS INJECTION BY NMAP')
                    job.append(ccsinjection_nmap)

                if test_vuln == 'SELF SIGNED':
                    # print(f"THE CERTIFICATE FOR CONNECTION: {connessioni} IS SELF SIGNED")
                    log_print(
                        f"{COLOR['RED']} THE CERTIFICATE FOR CONNECTION: {connessioni} IS SELF SIGNED {COLOR['ENDC']}")
                    write_file(ip_source, port_source, f"THE CERTIFICATE FOR CONNECTION: {connessioni} IS SELF SIGNED",
                               "Certificate Self Signed")

                if test_vuln == 'EXPIRED':
                    # print(f"THE CERTIFICATE FOR CONNECTION: {connessioni} IS EXPIRED")
                    write_file(ip_source, port_source, f"THE CERTIFICATE FOR CONNECTION: {connessioni} IS SELF EXPIRED",
                               "Certificate Expired")
                # RIATTIVARE:
                if test_vuln == 'CERTIFICATE':
                    test_certificate = threading.Thread(target=get_cert_status_for_host, args=(ip_source, port_source,),
                                                        daemon=True)
                    test_certificate.start()
                    log_print(f'Start test the certificate of connection {connessioni}')
                    job.append(test_certificate)
                # -------
                # get_cert_status_for_host(ip_source,port_source)

            # vuln_conn.clear()
            # tls_version_conn.clear()
            # print(f"NUMERO VULN CONN DOPO CLEAR: {vuln_conn}")
            # for test in job:
            #     print("----TORNO A CASA-----")
            #     test.join()
            #     print(f'Numero JOB ATTIVI: {job.__len__()}')
            # print("---------FINE VERIFICA----------")
            while job.__len__() > 0:
                # print("----TORNO A CASA-----")
                # print(
                #     f'{time.localtime().tm_hour}:{time.localtime().tm_min}:{time.localtime().tm_sec} --- LEN: {job.__len__()}')
                test = job.pop()
                if test.is_alive():
                    test.join()
            #     print(f'Lunghezza coda: {job.__len__()}')
            # print("---------FINE VERIFICA----------")

            cv.notify()
            cv.release()

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
    global connessioni_attive

    for line in fp:
        cipher_suite_found = ''
        tls_version_found = ''
        # print("------LINE------")
        # print(line.decode())
        source_dest = line.decode().partition("{TCP}")[2].removesuffix("\n")

        # print(f"SRC_DEST: {source_dest}")

        #  a vuln va messo il separatore che identifica la vulnerabilità
        vuln = line.decode().partition("|VULNERABILITY|")
        tls_version = vuln[0].split("+")
        if len(tls_version) > 1:
            tls_version_found = tls_version[1]
        # print("---Vulnerabilita----")
        # print(f"VULN: {vuln[1]}")
        if vuln[1] != '':
            cv.acquire()

            # Controllo cipersuite per config file
            cipher_suite = vuln[2].split("%")
            if len(cipher_suite) > 1:
                cipher_suite_found = cipher_suite[1]

            # print(f'TLS VERSION:{tls_version} - {tls_version_found}')
            # print(f'cipher suite: {cipher_suite} - {cipher_suite_found}')
            # print(f'CONFIG CIPHER: {ciphers_config}')
            # print(f'VERSION CONFIG: {versions_config}')
            #
            # print(f'First Condition: {cipher_suite_found not in ciphers_config}')
            # print(f'Second Condition: {tls_version_found not in versions_config}')

            vulnerabilities = vuln[2].split("#")
            new_vulnerability = vulnerabilities[1]
            flag = False
            if new_vulnerability == 'CERTIFICATE' or new_vulnerability == 'SELF SIGNED' or new_vulnerability == 'EXPIRED' or new_vulnerability == 'CRIME':
                flag = True
            if tls_version_found not in versions_config and tls_version_found != '':
                flag = True
            if cipher_suite_found not in ciphers_config and cipher_suite_found != '':
                flag = True
            # MODIFICARE--------
            if flag:
                if source_dest not in vuln_conn.keys():
                    # print(f'Prima----> {vuln_conn}')
                    vuln_conn[source_dest] = []
                    # tls_version_conn[source_dest] = []
                    # connessioni_attive[source_dest]=[]
                    # print(f'Dopo----> {vuln_conn}')

                # Controllo che la lista

                if new_vulnerability not in vuln_conn[source_dest]:
                    version = ""
                    if new_vulnerability == 'HEARTBEAT EXTENSION':
                        version = vuln[2].split("$")[1]
                    # print(f"NUOVAAAAA: {new_vulnerability}")
                    log_print(
                        f'Suricata has found a new vulnerability is found for {source_dest}: -> {new_vulnerability}<-')
                    vuln_conn[source_dest].append(new_vulnerability)
                    if version != "":
                        tls_version_conn[source_dest] = version
                    #     print(f"TLS VERSION SURICATA: {tls_version_conn}")
                    # print(f"VULM_CONN: {vuln_conn}")

                if len(vuln_conn) == MAX_NUM:
                    log_print(f'The queue is full. Producer Thread waits.')
                    cv.wait()
                    log_print(f'The queue is no longer full. Producer Thread wakes up.')
                # print('NOTIFYYYYY')
                cv.notify()
            cv.release()

        if full_version == 1:
            log_print(f'Start testssl in full mode')
            source = source_dest.split("->")[0]
            ip_source = source.split(":")[0].split(" ")[1]
            port_source = source.split(":")[1].split(" ")[0]
            # print(f"IP SRC: {ip_source} ---- PORT SRC: {port_source}")
            if ip_source not in server_tested:
                # print("SERVER NOT TESTED -----> TEST IT!")
                server_tested.append(ip_source)
                test = threading.Thread(target=testssl_lab, args=(ip_source, port_source,))
                test.start()


# ---------------ZEEK-------------------
def file_reader_zeek(fp):
    global vuln_conn
    for line in fp:

        lineArray = line.split('\x09')
        if lineArray.__len__() > 3 and lineArray[2] != 'uid' and lineArray[2] != 'string':

            cv.acquire()

            if len(vuln_conn) == MAX_NUM:
                # print("PIENO QUINDI MI FERMO")
                log_print(f'The queue is full. Producer Thread waits.')
                cv.wait()
                log_print(f'The queue is no longer full. Producer Thread wakes up.')

            ip_src = lineArray[2]
            port_src = lineArray[3]
            ip_dest = lineArray[4]
            port_dest = lineArray[5]
            tls_version = lineArray[6]
            cipher_suite = lineArray[7]
            msg = lineArray[15]
            compression = lineArray[16]
            validation_status = lineArray[20]  # 'self signed certificate\n'
            # print(f'VALIDATION: {validation_status}')
            # print(f'CAMPI SALVATI:')
            # print(f'IP_SRC: {ip_src}')
            # print(f'IP_DEST: {ip_dest}')
            # print(f'PORT_SRC: {port_src}')
            # print(f'PORT_DEST: {port_dest}')

            # print(f'-------> TLS_VERSION: {tls_version}')
            # print(f'CIPHER: {cipher_suite}')
            # print(f'MSG: {msg}')

            # print('DENTRO CONFIG')
            # print(versions_config)
            # print(ciphers_config)
            if tls_version not in versions_config or cipher_suite not in ciphers_config:
                # print(tls_version not in versions_config)
                # print(cipher_suite not in ciphers_config)
                zeek_produce(ip_src, ip_dest, port_dest, port_src, msg, compression, validation_status,
                             cipher_suite, tls_version)

            cv.release()
            # print('DOPO RELEASE')


def zeek_produce(ip_src, ip_dest, port_dest, port_src, msg, compression, validation_status, cipher_suite, tls_version):
    exception_ip = '10.0.2.15'
    if ip_dest != exception_ip and ip_src != exception_ip:
        log_print(f'The log file is changed. The Zeek has found something...')
        # print("------LINE------")
        # print(line)
        src_dest = f"{ip_dest}:{port_dest} -> {ip_src}:{port_src}"
        vuln_conn[src_dest] = []

        # if validation_status == 'self signed certificate\n':
        #     print("SELF SIGNED CERTIFICATE ----> ZEEK")

        if tls_version != 'TLSv1.3':
            vuln_conn[src_dest].append('TICKETBLEED')
            vuln_conn[src_dest].append('CCSINJECTION')

        if cipher_suite in export_ciphers:
            vuln_conn[src_dest].append('LOGJAM')

        if cipher_suite in des_ciphers:
            vuln_conn[src_dest].append('SWEET32')

        if cipher_suite in cbc_ciphers:
            vuln_conn[src_dest].append('PADDING ORACLE ATTACK')
            vuln_conn[src_dest].append('POODLE')
            vuln_conn[src_dest].append('LUCKY13')

        if cipher_suite in rsa_ciphers:
            vuln_conn[src_dest].append('BLEICHENBACHER')
            vuln_conn[src_dest].append('ROBOT')

        if compression == 'COMPRESSION':
            vuln_conn[src_dest].append('CRIME')

        if tls_version == 'SSLv3':
            if 'POODLE' not in vuln_conn[src_dest]:
                vuln_conn[src_dest].append('POODLE')

        if tls_version == 'SSLv2':
            vuln_conn[src_dest].append('DROWN')

        if msg == 'HEARTBEAT':
            vuln_conn[src_dest].append('HEARTBEAT EXTENSION')
            if tls_version == 'SSLv3':
                tls_version_conn[src_dest] = 'SSLv3'

            if tls_version == 'TLSv10':
                tls_version_conn[src_dest] = 1.0

            if tls_version == 'TLSv11':
                tls_version_conn[src_dest] = 1.1

            if tls_version == 'TLSv12':
                tls_version_conn[src_dest] = 1.2

            if tls_version == '-':
                tls_version_conn[src_dest] = 1.0

        if validation_status == 'self signed certificate\n':
            vuln_conn[src_dest].append('SELF SIGNED')

        else:
            vuln_conn[src_dest].append('CERTIFICATE')

        if full_version == 1:
            print("FULL MODE ZEEK")
            if ip_src not in server_tested:
                print("SERVER NOT TESTED -----> TEST IT!")
                server_tested.append(ip_src)
                test = threading.Thread(target=testssl_lab, args=(ip_src, port_src,))
                test.start()

        # print('NOTIFYYYYY')
        # print(vuln_conn)
        cv.notify()
        # print('DOPO NOTIFYYYYY')


def producer():
    if IDS == "Suricata":
        src_path = r"/var/log/suricata/mio_fast.log"
    else:
        src_path = r"/usr/local/zeek/logs/current/ssl.log"
        file_exists = os.path.exists(src_path)

        if not file_exists:
            with open(src_path, 'x') as fp:
                fp.close()

    event_handler = Handler()
    observer = watchdog.observers.Observer()
    observer.schedule(event_handler, path=src_path, recursive=False)
    observer.start()



def help():
    out = '''
                ▁ ▂ ▃ ▅ ▆ ▇ █ Monitor for TLS attacks █ ▇ ▆ ▅ ▃ ▂ ▁

usage: monitor_for_tls_attacks [-h] [--full] [--IDS=Suricata/Zeek] [--nmap, --nmap=true] [--json /pathToConfigJSONFle]

Monitor your network traffic with Suricata or Zeek IDS and check if the found vulnerabilities are TP or FP. Before starting this tool you must execute Suricata/Zeek.

NOTE: If you have changed the default path of log file for the IDS you have to change it also in this tool.
Suricata log path variable: src_path = r"/var/log/suricata/fast.log"
Zeek log path variable:  src_path = r"/usr/local/zeek/logs/current/ssl.log"

optional arguments:
  -h, --help            show this help message and exit
  --full                use testssl to make a TLS configuration screenshot of the tested server
  --IDS=Suricata        use Suricata as IDS. This is the default setting
  --IDS=Zeek, --zeek    use Zeek as IDS
  --nmap, --nmap=true   use nmap to test the server against heartbleed. The default setting is to use only metasploit
  --json                use a network config file in json format
  '''
    print(out)


if __name__ == "__main__":
    if sys.argv.__contains__("-h") or sys.argv.__contains__("--help"):
        help()
    else:
        # producer = threading.Thread(target=process_handler, daemon=True)
        print('Start Monitor for TLS Attacks...')
        # verify = threading.Thread(target=verifica_vulnerabilita, daemon=True)

        if sys.argv.__contains__("--full"):
            print("FULL VERSION")
            full_version = 1

        if sys.argv.__contains__("--IDS=Zeek") or sys.argv.__contains__("--IDS=zeek") \
                or sys.argv.__contains__('--zeek') or sys.argv.__contains__('--Zeek'):
            print("ZEEK IDS")
            IDS = "ZEEK"

        if sys.argv.__contains__("--nmap") or sys.argv.__contains__("--nmap=true"):
            print("NMAP")
            nmap = True

        if sys.argv.__contains__("--json"):
            print("JSON")
            i = sys.argv.index("--json")
            file = open(sys.argv.pop(i + 1))
            json_format = json.load(file)
            versions_config = json_format['versions']
            ciphers_config = json_format['ciphers']
            config_input = True
            # exit(2)

        try:

            # producer.start()
            producer()
            log_print('Producer thread is started...')

            # verify.start()
            # producer.join()
            # verify.join()
            verifica_vulnerabilita()


        except (KeyboardInterrupt, SystemExit):
            print("End of the program")
            sys.exit()
