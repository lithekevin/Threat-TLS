import time
from multiprocessing import Process
import multiprocessing
import threading
from queue import Queue
import sys
import watchdog.events
import watchdog.observers
import subprocess
import os.path
from ciphers import cbc_ciphers,rsa_ciphers

connessioni_attive = dict()
server_tested = []
vuln_conn = dict()
tls_version_conn = dict()
cv = threading.Condition()
MAX_NUM = 2
full_version = 0
IDS = 'Suricata'
nmap=False

# ----------SCRIPT ATTACCHI---------
def metasploit_prosess(ip, port, tls_version):
    command = f"use auxiliary/scanner/ssl/openssl_heartbleed;set RHOST {ip};set RPORT {port};set TLS_VERSION {tls_version};check;exit"
    print(command)
    try:
        metasploit = subprocess.Popen(['msfconsole', '-x', command], stdout=subprocess.PIPE)

        stout = metasploit.communicate()[0].decode().rpartition("-")
        print("----MetaSploit Process:")
        print(stout[2].removeprefix(" "))
    except (SystemExit, KeyboardInterrupt):
        print("END Metasploit Process for KeyInterrupt")


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
        print(f"Output NMAP PROCESS: ${output}")
        if output[0] != '':
            o2 = output[1] + " " + output[2]
            print("----NMAP Process:")
            print(o2)
        else:
            print("Timeout for heartbleed attack in NMAP Process")
    except (SystemExit, KeyboardInterrupt):
        print("END NMAP Process Heartbleed for KeyInterrupt")


def poodle_nmap_process(ip, port):
    poodle_script = "--script=ssl-poodle"
    show_all = "--script-args=vulns.showall"
    try:
        poodle = subprocess.Popen(['nmap', '-A', '-p', port, poodle_script, show_all, ip], stdout=subprocess.PIPE)

        stdout = poodle.communicate()[0].decode()
        index = stdout.partition("|")
        output = index[2].split("|")
        o2 = output[1] + " " + output[2]
        print("----POODLE Process:")
        print(o2)
    except (SystemExit, KeyboardInterrupt):
        print("END NMAP POODLE Process for KeyInterrupt")


def padding_attack_process(ip, port):
    path = "/home/kali/Desktop/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(['timeout', '35', 'java', '-jar', path, 'padding_oracle', '-connect', host],
                                  stdout=subprocess.PIPE)
        stdout = attack.communicate()[0].decode()
        print("----Padding Oracle Attack Process:")
        print(stdout)
        vulnerable = stdout.partition("Vulnerable:")
        # print("----Vulnerable-----")
        print(vulnerable)
        if vulnerable[1] == "":
            print("UNDEFINED")
        else:
            print(f"{vulnerable[1]} {vulnerable[2]}")
    except (SystemExit, KeyboardInterrupt):
        print("END TLS ATTACKER Padding Oracle Attack process for KeyInterrupt")


def bleichenbachers_process(ip, port):
    path = "/home/kali/Desktop/TLS-Attacker/apps/Attacks.jar"
    host = f"{ip}:{port}"
    try:
        attack = subprocess.Popen(['timeout', '35', 'java', '-jar', path, 'bleichenbacher', '-connect', host],
                                  stdout=subprocess.PIPE)
        stdout = attack.communicate()[0].decode()
        print("----Bleichenbacher Process:")
        print(stdout)
    except (SystemExit, KeyboardInterrupt):
        print("END Bleinchebachers Process for KeyInterrupt")


# ---------------------------------
# --------------------------------
# TESTSSL
def testssl_lab(ip, port):
    nomefile = f"testssl_{ip}:{port}.log"
    try:
        testssl = subprocess.Popen(
            ['testssl', '-U', '--full', '--severity', 'LOW', '--json', '--parallel', '-n', 'none', '--logfile',
             nomefile,
             'https://10.0.2.7:443'],
            stdout=subprocess.PIPE)

        testssl.wait()
        print("BEFORE AHA")
        color = open(f"color_{nomefile}.html", 'w')
        subprocess.run(['aha', '-f', nomefile], stdout=color)

        print("AFTER AHA")
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
        print("Watchdog received created event - % s." % event.src_path)
        # Event is created, you can process it now

    def on_modified(self, event):
        print("Watchdog received modified event - % s." % event.src_path)
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
            print("FINITO")
            sys.exit(2)


def verifica_vulnerabilità():
    print("----> Verifica Vulnerabilità<-----")
    print(f'{time.localtime()}')
    global vuln_conn
    global connessioni_attive
    try:
        while True:
            # for i in range(1,15):
            #     print(i)
            #     time.sleep(1)
            cv.acquire()
            print(vuln_conn.keys())
            print(connessioni_attive)
            while len(vuln_conn.keys()) < 1:
                print(f'PRIMA WAIT ---> {len(vuln_conn)}')
                cv.wait()

            print("Consumer Thread")
            print(f'DOPO WAIT ---> {len(vuln_conn)}')
            keys = vuln_conn.keys()
            print(keys)
            print('-----')
            print(vuln_conn)
            job = []

            for connessioni in keys:
                # In caso si voglia distinguere sorgente e destinazione
                source = connessioni.split("->")[0]
                dest = connessioni.split("->")[1]
                print(f"SRC: {source}")
                print(f"DEST: {dest}")
                if (IDS == 'Suricata'):
                    ip_source = source.split(":")[0].split(" ")[1]

                else:
                    ip_source = source.split(":")[0]

                ip_dest = dest.split(":")[0]

                print(f"IP SRC: -{ip_source}-")
                print(f"IP DEST: -{ip_dest}-")
                port_source = source.split(":")[1].split(" ")[0]
                port_dest = dest.split(":")[1]
                print(f"PORT SRC: {port_source}")
                print(f"PORT DEST: {port_dest}")

                for test_vuln in vuln_conn[connessioni]:
                    print("Vulnerabilita TEST")
                    print(test_vuln)
                    if test_vuln == "HEARTBEAT EXTENSION":
                        # print(connessioni_attive)
                        # connessioni_attive[connessioni].append(test_vuln)
                        print("HEARTBLEED METASPLOIT")
                        print(f"TLS_VERSION_CONN: {tls_version_conn}")
                        tls_version = tls_version_conn[connessioni]
                        print(f"TLS_VERSION: {tls_version} ")
                        heartbleed_metasploit = threading.Thread(target=metasploit_prosess,
                                                                 args=(ip_source, port_source, tls_version))
                        heartbleed_metasploit.start()
                        job.append(heartbleed_metasploit)

                        if nmap:
                            print("HEARTBLEED NMAP")
                            heartbleed_nmap = threading.Thread(target=nmap_process, args=(ip_source, port_source,))
                            heartbleed_nmap.start()
                            job.append(heartbleed_nmap)

                    if test_vuln == "CRIME":
                        print("CRIME DOPO IF")

                    if test_vuln == "PADDING ORACLE ATTACK":
                        print("PADDING ORACLE ATTACK ---> DOPO IF")
                        padding_oracle = threading.Thread(target=padding_attack_process, args=(ip_source, port_source))
                        padding_oracle.start()
                        job.append(padding_oracle)

                    if test_vuln == "POODLE":
                        print("POODLE ATTACK IF")
                        poodle = threading.Thread(target=poodle_nmap_process, args=(ip_source, port_source,))
                        poodle.start()
                        job.append(poodle)

                    if test_vuln == "BLEICHENBACHER":
                        print("BLEICHENBACHER")
                        bleichenbachers = threading.Thread(target=bleichenbachers_process,
                                                           args=(ip_source, port_source,))
                        bleichenbachers.start()
                        job.append(bleichenbachers)

            print(f"NUMERO VULN CONN: {vuln_conn}")
            vuln_conn.clear()
            print(f"NUMERO VULN CONN DOPO CLEAR: {vuln_conn}")
            cv.notify()
            cv.release()

            for test in job:
                print("----TORNO A CASA-----")
                test.join()
            print("---------FINE VERIFICA----------")

    except (KeyboardInterrupt, SystemExit):
        cv.notify()
        cv.release()
        for test in job:
            print("----TORNO A CASA -> KEYBOARD INTERRUPT-----")
            test.join()
        print("END of verifica")
        sys.exit(3)


def file_reader_suricata(fp):
    global vuln_conn
    global connessioni_attive
    for line in fp:
        print("------LINE------")
        print(line.decode())
        source_dest = line.decode().partition("{TCP}")[2].removesuffix("\n")

        print(f"SRC_DEST: {source_dest}")

        #  a vuln va messo il separatore che identifica la vulnerabilità
        vuln = line.decode().partition("|VULNERABILITY|")
        print("---Vulnerabilita----")
        print(f"VULN: {vuln[1]}")
        if vuln[1] != '':
            cv.acquire()

            if source_dest not in vuln_conn.keys():
                print(f'Prima----> {vuln_conn}')
                vuln_conn[source_dest] = []
                # tls_version_conn[source_dest] = []
                # connessioni_attive[source_dest]=[]
                print(f'Dopo----> {vuln_conn}')

            # Controllo che la lista

            if vuln[2] not in vuln_conn[source_dest]:
                new_vulnerability = vuln[2].split("#")[1]
                version = ""
                if new_vulnerability == 'HEARTBEAT EXTENSION':
                    version = vuln[2].split("$")[1]
                print(f"NUOVAAAAA: {new_vulnerability}")
                vuln_conn[source_dest].append(new_vulnerability)
                if version != "":
                    tls_version_conn[source_dest] = version
                    print(f"TLS VERSION SURICATA: {tls_version_conn}")
                print(f"VULM_CONN: {vuln_conn}")

            if len(vuln_conn) == MAX_NUM:
                cv.wait()
            print('NOTIFYYYYY')
            cv.notify()
            cv.release()

        if full_version == 1:
            print("FULL MODE")
            source = source_dest.split("->")[0]
            ip_source = source.split(":")[0].split(" ")[1]
            port_source = source.split(":")[1].split(" ")[0]
            print(f"IP SRC: {ip_source} ---- PORT SRC: {port_source}")
            if ip_source not in server_tested:
                print("SERVER NOT TESTED -----> TEST IT!")
                server_tested.append(ip_source)
                test = threading.Thread(target=testssl_lab, args=(ip_source, port_source,))
                test.start()


# ---------------ZEEK-------------------
def file_reader_zeek(fp):
    global vuln_conn
    for line in fp:
        print("------LINE------")
        print(line)
        lineArray = line.split('\x09')
        j = 0
        if lineArray.__len__() > 3 and lineArray[2] != 'uid' and lineArray[2] != 'string':
            cv.acquire()

            ip_src = lineArray[2]
            port_src = lineArray[3]
            ip_dest = lineArray[4]
            port_dest = lineArray[5]
            tls_version = lineArray[6]
            cipher_suite = lineArray[7]
            msg = lineArray[15]
            validation_status = lineArray[19]  # 'self signed certificate\n'
            print(f'VALIDATION: {validation_status}')
            print(f'CAMPI SALVATI:')
            print(f'IP_SRC: {ip_src}')
            print(f'IP_DEST: {ip_dest}')
            print(f'PORT_SRC: {port_src}')
            print(f'PORT_DEST: {port_dest}')
            print(f'TLS_VERSION: {tls_version}')
            print(f'CIPHER: {cipher_suite}')
            print(f'MSG: {msg}')

            exception_ip = '10.0.2.15'
            if ip_dest != exception_ip:
                src_dest = f"{ip_dest}:{port_dest} -> {ip_src}:{port_src}"
                vuln_conn[src_dest] = []

                if validation_status == 'self signed certificate\n':
                    print("SELF SIGNED CERTIFICATE ----> ZEEK")

                if cipher_suite in cbc_ciphers:
                    vuln_conn[src_dest].append('PADDING ORACLE ATTACK')

                if cipher_suite in rsa_ciphers:
                    vuln_conn[src_dest].append('BLEICHENBACHER')

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

                if len(vuln_conn) == MAX_NUM:
                    cv.wait()
                print('NOTIFYYYYY')
                cv.notify()
                cv.release()

                if full_version == 1:
                    print("FULL MODE ZEEK")
                    if ip_src not in server_tested:
                        print("SERVER NOT TESTED -----> TEST IT!")
                        server_tested.append(ip_src)
                        test = threading.Thread(target=testssl_lab, args=(ip_src, port_src,))
                        test.start()


def process_handler():
    if IDS == "Suricata":
        src_path = r"/var/log/suricata/fast.log"
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
    try:
        while True:
            time.sleep(1)

    except (KeyboardInterrupt, SystemExit):
        observer.stop()
    observer.join()


if __name__ == "__main__":

    producer = threading.Thread(target=process_handler, daemon=True)
    print("---------->>>>SECONDO")
    verify = threading.Thread(target=verifica_vulnerabilità, daemon=True)

    if sys.argv.__contains__("--full"):
        print("FULL VERSION")
        full_version = 1

    if sys.argv.__contains__("--IDS=Zeek") or sys.argv.__contains__("--IDS=zeek"):
        print("ZEEK")
        IDS = "ZEEK"

    if sys.argv.__contains__("--nmap") or sys.argv.__contains__("--nmap=true"):
        print("NMAP")
        nmap = True

    try:

        producer.start()

        verify.start()
        producer.join()
        verify.join()


    except (KeyboardInterrupt, SystemExit):
        print("End of the program")
        sys.exit()
