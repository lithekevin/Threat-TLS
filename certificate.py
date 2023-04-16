import base64
import ssl
import subprocess
import socket

import OpenSSL
import cryptography
import requests
from urllib.parse import urljoin
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from crl_checker import check_revoked, Revoked, Error, check_revoked_crypto_cert
from ctutlz.ctlog import download_log_list
from ctutlz.scripts.verify_scts import verify_scts_by_cert, verify_scts_by_ocsp, verify_scts_by_tls
from ctutlz.tls.handshake import do_handshake, create_context
from datetime import datetime
from Monitor_for_TLS_attacks import certificate_fingerprint_config

COLOR = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "GREEN": "\033[92m",
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "CIANO":"\033[36m",
    "ENDC": "\033[0m",
}

def log_print(action):
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print(f'{current_time} --- {action}')


def write_file(ip, port, stdout, attacco):
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    stringa_inizio = f'---------START {attacco}---------\nWrite at: {current_time}\n'
    stringa_fine = f'\n---------FINE {attacco}---------\n'
    try:
        # fp = open(
        #     f'./Logs/{ip}_{port}.log',
        #     'a')
        src_path = f"./Logs/{ip}_{port}"
        file_exists = os.path.exists(src_path)

        if not file_exists:
            os.makedirs(src_path)

        fp = open(
            f'{src_path}/{attacco}.log', 'a')
        fp.seek(0, 0)
        fp.write(stringa_inizio)
        # fp.write(s_fine)
        fp.write(stdout)
        fp.write(stringa_fine)
        fp.close()
        print(f'{current_time} --- {COLOR["BLUE"]}Esito {attacco} su {ip}:{port} scritto su file{COLOR["ENDC"]}')
    except (SystemExit, KeyboardInterrupt):
        print("END writing file")


def sct_web(hostname, port, sct_cert):
    try:
        ctlogs = download_log_list()
        # print(f"HOST: {hostname} - PORT: {port}")
        handshake = do_handshake(hostname, int(port))
        # print('HANDSHAKE---------------------')
        # print(handshake.__getattribute__('err'))
        if handshake.__getattribute__('err')!='':
            log_print(f"{COLOR['RED']} SCT Found for connection {hostname}:{port} but Octect is not correct.{COLOR['ENDC']}")
            write_file(hostname,port,f'SCT Found for connection {hostname}:{port} but Octect is not correct.','SCT Error')
        else:
            if sct_cert.__len__() > 0:
                log_print(f"{COLOR['YELLOW']}Start Test to verify Certificate Transparency by SCT extension into the certificate")
                verification_cert = verify_scts_by_cert(handshake, ctlogs)
                verify_sct = ''
                for ver in verification_cert:
                    if ver.verified:
                        description = ver.log["description"]
                        verify_sct = f"{COLOR['GREEN']}For {hostname}:{port} -> {ver.verified}: {description}{COLOR['ENDC']}"
                        verify_sct_file=f'For {hostname}:{port} -> {ver.verified}: {description}'
                    else:
                        verify_sct = f"{COLOR['RED']}SCT NOT VERIFIED for {hostname}:{port}{COLOR['ENDC']}"
                        verify_sct_file=f'SCT NOT VERIFIED for {hostname}:{port}'

                    log_print(verify_sct)
                    write_file(hostname, port, verify_sct_file, 'Certificate Transparency by SCT')
            else:
                log_print(f"{COLOR['YELLOW']}Start Test to verify Certificate Transparency by OCSP{COLOR['ENDC']}")
                verification_ocsp = verify_scts_by_ocsp(handshake, ctlogs)
                if verification_ocsp.__len__() == 0:
                    log_print(f"{COLOR['RED']}NO SCT FOUND BY OCSP for {hostname}:{port}{COLOR['ENDC']}")
                    write_file(hostname, port, f"NO SCT FOUND BY OCSP for {hostname}:{port}",
                               'Certificate Transparency by OCSP')
                else:
                    for ver in verification_ocsp:
                        ocsp_verify = ''
                        if ver.verified:
                            description = ver.log["description"]
                            ocsp_verify = f"For {hostname}:{port} -> {ver.verified}: {description} - {ver}"
                        else:
                            ocsp_verify = f"{COLOR['RED']}For {hostname}:{port} -> SCT NOT VERIFIED{COLOR['ENDC']}"

                        log_print(ocsp_verify)
                        write_file(hostname, port, ocsp_verify, 'Certificate Transparency by OCSP')

                log_print(f'{COLOR["YELLOW"]} Verify Certificate Transparency through TLS Extension{COLOR["ENDC"]}')
                verification_tls = verify_scts_by_tls(handshake, ctlogs)
                final_tls_string = ''
                if verification_tls.__len__() == 0:
                    action = f"For {hostname}:{port} -> NO SCT FOUND IN TLS EXTENSION"
                    log_print(f'{COLOR["RED"]}{action}{COLOR["ENDC"]}')
                    final_tls_string = action
                else:
                    for ver in verification_tls:
                        description = ver.log["description"]
                        action = f"For connection {hostname}:{port} -> {ver.verified}: {description} - {ver}"
                        if ver.verified:
                            log_print(f'For connection {hostname}:{port} TLS Extension is verified and writted in file')
                        else:
                            # log_print(action)
                            log_print(
                                f"{COLOR['RED']}For connection {hostname}:{port} -> TLS Extension NOT VERIFIED. For more detail read the log file.{COLOR['ENDC']}")
                            # log_print(action)
                        final_tls_string = f'{final_tls_string}\n{action}'

                write_file(hostname, port, final_tls_string, 'Certificate Transparency through TLS Extension')

    except (SystemExit, KeyboardInterrupt):
        print("END SCT Verify for KeyInterrupt")


def sct_cmd(hostname):
    try:
        sct = subprocess.Popen(['verify-scts', hostname, '--cert-only'], stdout=subprocess.PIPE)

        stout = sct.communicate()[0].decode()
        print("----SCT Process:")
        print(stout)
    except (SystemExit, KeyboardInterrupt):
        print("END Metasploit Process for KeyInterrupt")


def sct_extension(cert, hostname, port):
    try:
        ct = cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        # print(f"CT EXTENSION: {ct}")
        ct_value = ct.value

        # print(ct_value[0])

        # print("SCT SOTTO")
        sct = [ia for ia in ct_value]
        log_print(f"{COLOR['BLUE']}PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS FOUND INTO CERTIFICATE for connection {hostname}:{port}{COLOR['ENDC']}")
        logs_id = []
        # print(Logs.logs)
        # for s in sct:
        #     print(
        #         f"VERSION: {s.version} - LOGID: {s.log_id.hex()} - TIMESTAMP: {s.timestamp} - ENTRYTIPE: {s.entry_type}")

        return sct
    except cryptography.x509.extensions.ExtensionNotFound:
        log_print(f"{COLOR['RED']}NO PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS FOUND INTO CERTIFICATE for connection {hostname}:{port}{COLOR['ENDC']}")
        return []


def get_cert_for_hostname(hostname, port):
    try:
        conn = ssl.create_connection((hostname, port))
        # # mettere TLSv1.3
        # print(f"CONNESSIONE SSL: {hostname}: {port}")
        log_print(f'{COLOR["YELLOW"]} Start TLS connection with {hostname}:{port} to retrieve the certificate{COLOR["ENDC"]}')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        sock = context.wrap_socket(conn, server_hostname=hostname)

        certDER = sock.getpeercert(True)
        certPEM = ssl.DER_cert_to_PEM_cert(certDER)
        certificate = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
        return x509.load_pem_x509_certificate(certPEM.encode('ascii'), default_backend()), certificate
    except ssl.SSLError as e:
        log_print(f"{COLOR['RED']}Error Connection for {hostname}:{port} --- REASON: {e.reason}{COLOR['ENDC']}")
        write_file(hostname,port,f"Error Connection for {hostname}:{port} --- REASON: {e.reason}",'Get cert for hostname connection')
        return "err", ""


def get_issuer(cert):
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    issuers = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
    if not issuers:
        raise Exception(f'no issuers entry in AIA')
    return issuers[0].access_location.value


def get_ocsp_server(cert):
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    # OCSP è il nome dell'estensione che prende
    ocsps = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
    if not ocsps:
        raise Exception(f'no ocsp server entry in AIA')
    return ocsps[0].access_location.value


def get_issuer_cert(ca_issuer):
    issuer_response = requests.get(ca_issuer)
    if issuer_response.ok:
        issuerDER = issuer_response.content
        issuerPEM = ssl.DER_cert_to_PEM_cert(issuerDER)
        return x509.load_pem_x509_certificate(issuerPEM.encode('ascii'), default_backend())
    raise Exception(f'fetching issuer cert  failed with response status: {issuer_response.status_code}')


def get_oscp_request(ocsp_server, cert, issuer_cert):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, SHA256())
    req = builder.build()
    req_path = base64.b64encode(req.public_bytes(serialization.Encoding.DER))
    return urljoin(ocsp_server + '/', req_path.decode('ascii'))


def get_ocsp_cert_status(ocsp_server, cert, issuer_cert):
    # print("-----STATUS------")
    ocsp_resp = requests.get(get_oscp_request(ocsp_server, cert, issuer_cert))
    # print(ocsp_resp)
    if ocsp_resp.ok:
        ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp.content)

        if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
            # print(
            #     f"OCSP DECODED STATUS: {ocsp_decoded.certificate_status} - OCSP RESPONSE: {ocsp_decoded.response_status}")
            # print(f"---RESPONSES: {ocsp_decoded.responses}")
            return ocsp_decoded.response_status, ocsp_decoded.certificate_status
        else:
            # raise Exception(f'decoding ocsp response failed: {ocsp_decoded.response_status}')
            return ocsp_decoded.response_status, ''
    # log_print(f'fetching ocsp cert status failed with response status: {ocsp_resp.status_code}')
    return ocsp_resp.status_code, 'err'


def get_cert_status_for_host(hostname, port):
    # print('   hostname:', hostname, "port:", port)
    [cert, cert_string] = get_cert_for_hostname(hostname, port)
    # print(f"CERTIFICATE: {cert_string}")
    # print(f"ISSUER: {cert.issuer} - SUBJECT: {cert.subject} - VERSION: {cert.version} - PK: {cert.public_key()}")
    array = []
    crl = ''
    ocsp = ''
    if cert == "err":
        log_print(f"{COLOR['RED']}Error occurred during connection. No certificate found. {COLOR['ENDC']}")
    else:

        try:
            log_print(f'{COLOR["GREEN"]} Certificate for {hostname}:{port} retrieved successfully{COLOR["ENDC"]}')
            write_file(hostname,port,cert_string,'CERTIFICATE')
            crl = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            # print("-----------CRLDISTRIBUTIONPOINTS-------------")
            # print(cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS))
            # print(f"CRL VALUE: {crl.value}")
            array.append('CRL')
        except:
            log_print(f'{COLOR["RED"]}CRLDISTRIBUTIONPOINTS NOT FOUND for {hostname}:{port}{COLOR["ENDC"]}')

        try:
            # print('---------------OCSP---------------')
            e = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            # print(e.value)
            am = e.value
            ocsp = [ia for ia in am if ia.access_method == AuthorityInformationAccessOID.OCSP]
            # print(ocsp)
            array.append('OCSP')
        except:
            log_print(f'{COLOR["RED"]}OCSP EXTENSION NOT FOUND for {hostname}:{port}{COLOR["ENDC"]}')

        # try:
        # print("---------CERTIFICATE TRANSPARENCY-----------")
        sct_cert = sct_extension(cert, hostname, port)

        sct_web(hostname, port, sct_cert)
        # sct_cmd(hostname)

        # except:
        #     print("PRE-CERTIFICATE FOR CERTIFICATE TRANSPARENCY NOT FOUND")

        try:
            ca_issuer = get_issuer(cert)
            log_print(f'Found certificate issuer of {hostname}:{port} -> {ca_issuer}')
        except:
            log_print(f"Issuer extension not found for certificate owned by {hostname}:{port}")
            ca_issuer = ""

        try:
            issuer_cert = get_issuer_cert(ca_issuer)
            log_print(f'certificate for the issuer of {hostname}:{port} is retrieved')
        except:
            # print("Exception for issuer certification")
            log_print(f"Issuer certificate not found")
            issuer_cert = ""

        try:
            ocsp_server = get_ocsp_server(cert)
            # print('   ocsp_server ->', ocsp_server)
            log_print(f'OCSP Server found for {hostname}:{port}')
        except:
            # print("Exception for ocsp SERVER")
            log_print(f'OCSP Server not found for {hostname}:{port}')
            ocsp_server = ""

        if array.__len__() == 0:
            log_print(f"{COLOR['RED']}NO CRL AND OCSP EXTENSIONS FOUND in connection {hostname}:{port}. THIS IS DANGEROUS{COLOR['ENDC']}")
            write_file(hostname, port, 'NO CRL AND OCSP EXTENSIONS FOUND. THIS IS DANGEROUS', 'Certificate')
        else:
            if array.__contains__('CRL'):
                log_print(f'CRL EXTENSION FOUND for {hostname}:{port}. CRL Extension is written in log file.')
                try:
                    # print("PROVO CRL")
                    status_crl = check_revoked(cert_string)
                    # print(status)
                    # print(status_crl)
                    status_f = f'STATUS CERTIFICATE for {hostname}:{port} -> {status_crl}'
                    if status_crl is None:
                        status_f = "THE CERTIFICATE IS NOT FOUND IN THE CRL LIST. The certificate is CRL Valid"

                    final_string_crl = f'{crl}\n\n{status_f}\n\n'
                    write_file(hostname, port, final_string_crl, 'CRL')

                except Revoked as e:
                    log_print(f"{COLOR['RED']}Certificate revoked for {hostname}:{port}: {e}{COLOR['ENDC']}")
                    write_file(hostname, port, f"Certificate revoked for {hostname}:{port} : {e}", 'CRL')
                except Error as e:
                    log_print(f"{COLOR['RED']}Revocation check failed for {hostname}:{port}. Error: {e}{COLOR['ENDC']}")
                    write_file(hostname, port, f"Revocation check failed for {hostname}:{port}. Error: {e}", 'CRL')
                except:
                    log_print(f"{COLOR['RED']}CAN'T CHECK THE STATUS OF THE CERTIFICATE ON THE CRL SERVER for {hostname}:{port}{COLOR['ENDC']}")
                    write_file(hostname, port,
                               f"CAN'T CHECK THE STATUS OF THE CERTIFICATE ON THE CRL SERVER for {hostname}:{port}",
                               'CRL')

            if array.__contains__('OCSP'):
                log_print(f'OCSP EXTENSION FOUND for {hostname}:{port}. OCSP Extension is written in log file.')
                #print('----------OCSP----------')
                o=ocsp.pop()
                string_ocsp=f'OCSP with OID:{o.access_method.dotted_string} ---- {o.access_location.value}'
                write_file(hostname, port, string_ocsp, 'OCSP')


        if issuer_cert == "" or cert == "" or ocsp_server == "":
            log_print(
                f"OCSP Status can't be retrieved for {hostname}:{port} because ISSUER, ISSUER CERTIFICATE AND OCSP NOT FOUND")
            write_file(hostname, port,
                       f"OCSP Status can't be retrieved for {hostname}:{port} because ISSUER, ISSUER CERTIFICATE AND OCSP NOT FOUND",
                       'OCSP')
        else:
            # print("----CERCO LO STATUS DEL CERTIFICATO------")
            file_status = ''
            status_resp, status_ocsp = get_ocsp_cert_status(ocsp_server, cert, issuer_cert)
            if status_ocsp == 'err':
                log_print(f'{COLOR["RED"]}Error for communication {hostname}:{port} in OCSP Response{COLOR["ENDC"]}')
                file_status = f'Error for communication {hostname}:{port} in OCSP Response\nStatus Response: {status_resp}'
            else:
                if status_ocsp == '':
                    log_print(f'{COLOR["RED"]}In communication {hostname}:{port} decoding ocsp response failed: {status_resp}{COLOR["ENDC"]}')
                    file_status=f'In communication {hostname}:{port} decoding ocsp response failed: {status_resp}'
                else:
                    log_print(f'OCSP Status retrieved for {hostname}:{port}. The status is written in log file')
                    file_status = f'OCSP STATUS: {status_ocsp} - OCSP RESPONSE:{status_resp}'
            write_file(hostname, port, file_status, 'OCSP')
