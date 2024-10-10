import base64
import ssl
import subprocess
import os
from datetime import datetime
import requests
from urllib.parse import urljoin
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from crl_checker import check_revoked, Revoked, Error
from ctutlz.ctlog import download_log_list
from ctutlz.scripts.verify_scts import verify_scts_by_cert, verify_scts_by_ocsp, verify_scts_by_tls
from ctutlz.tls.handshake import do_handshake

COLOR = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "GREEN": "\033[92m",
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "CIANO": "\033[36m",
    "ENDC": "\033[0m",
}

def log_print(message):
    current_time = datetime.now().strftime("%H:%M:%S")
    print(f'{current_time} --- {message}')

def write_file(ip, port, content, attack_name):
    current_time = datetime.now().strftime("%H:%M:%S")
    header = f'---------START {attack_name}---------\nWrite at: {current_time}\n\n'
    footer = f'\n---------END {attack_name}---------\n\n'
    src_path = f"./Logs/{ip}_{port}"
    os.makedirs(src_path, exist_ok=True)
    file_path = os.path.join(src_path, f"{attack_name}.log")
    try:
        with open(file_path, 'a') as fp:
            fp.write(header)
            fp.write(content)
            fp.write(footer)
        print(f'{current_time} --- {COLOR["BLUE"]}Result of {attack_name} on {ip}:{port} written to file{COLOR["ENDC"]}')
    except Exception as e:
        print(f"Error writing to file {file_path}: {e}")

def sct_web(hostname, port, sct_cert):
    try:
        ctlogs = download_log_list()
        handshake = do_handshake(hostname, int(port))
        if getattr(handshake, 'err', '') != '':
            log_print(f"{COLOR['RED']}SCT found for connection {hostname}:{port} but octet is not correct.{COLOR['ENDC']}")
            write_file(hostname, port, f'SCT found for connection {hostname}:{port} but octet is not correct.', 'SCT Error')
            return
        if len(sct_cert) > 0:
            log_print(f"{COLOR['YELLOW']}Starting verification of Certificate Transparency via SCT extension in the certificate{COLOR['ENDC']}")
            verification_cert = verify_scts_by_cert(handshake, ctlogs)
            for ver in verification_cert:
                description = ver.log["description"]
                if ver.verified:
                    message = f"{COLOR['GREEN']}For {hostname}:{port} -> Verified: {description}{COLOR['ENDC']}"
                    file_message = f'For {hostname}:{port} -> Verified: {description}'
                else:
                    message = f"{COLOR['RED']}SCT NOT VERIFIED for {hostname}:{port}{COLOR['ENDC']}"
                    file_message = f'SCT NOT VERIFIED for {hostname}:{port}'
                log_print(message)
                write_file(hostname, port, file_message, 'Certificate Transparency by SCT')
        else:
            log_print(f"{COLOR['YELLOW']}Starting verification of Certificate Transparency via OCSP{COLOR['ENDC']}")
            verification_ocsp = verify_scts_by_ocsp(handshake, ctlogs)
            if not verification_ocsp:
                log_print(f"{COLOR['RED']}NO SCT FOUND VIA OCSP for {hostname}:{port}{COLOR['ENDC']}")
                write_file(hostname, port, f"NO SCT FOUND VIA OCSP for {hostname}:{port}", 'Certificate Transparency by OCSP')
            else:
                for ver in verification_ocsp:
                    description = ver.log["description"]
                    if ver.verified:
                        message = f"For {hostname}:{port} -> Verified: {description} - {ver}"
                    else:
                        message = f"{COLOR['RED']}For {hostname}:{port} -> SCT NOT VERIFIED{COLOR['ENDC']}"
                    log_print(message)
                    write_file(hostname, port, message, 'Certificate Transparency by OCSP')

            log_print(f'{COLOR["YELLOW"]}Verifying Certificate Transparency through TLS Extension{COLOR["ENDC"]}')
            verification_tls = verify_scts_by_tls(handshake, ctlogs)
            if not verification_tls:
                message = f"For {hostname}:{port} -> NO SCT FOUND IN TLS EXTENSION"
                log_print(f'{COLOR["RED"]}{message}{COLOR["ENDC"]}')
                write_file(hostname, port, message, 'Certificate Transparency via TLS Extension')
            else:
                for ver in verification_tls:
                    description = ver.log["description"]
                    if ver.verified:
                        message = f"For connection {hostname}:{port} -> Verified: {description} - {ver}"
                        log_print(f"For connection {hostname}:{port} TLS Extension is verified and written in file")
                    else:
                        message = f"{COLOR['RED']}For connection {hostname}:{port} -> TLS Extension NOT VERIFIED. See log file for details.{COLOR['ENDC']}"
                        log_print(message)
                    write_file(hostname, port, message, 'Certificate Transparency via TLS Extension')

    except Exception as e:
        log_print(f"Error verifying SCT for {hostname}:{port}: {e}")

def sct_extension(cert, hostname, port):
    try:
        ct = cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        sct_list = list(ct.value)
        log_print(f"{COLOR['BLUE']}PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS found in certificate for {hostname}:{port}{COLOR['ENDC']}")
        return sct_list
    except x509.ExtensionNotFound:
        log_print(f"{COLOR['RED']}NO PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS found in certificate for {hostname}:{port}{COLOR['ENDC']}")
        return []

def get_cert_for_hostname(hostname, port):
    try:
        conn = ssl.create_connection((hostname, port))
        log_print(f'{COLOR["YELLOW"]}Starting TLS connection with {hostname}:{port} to retrieve the certificate{COLOR["ENDC"]}')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        sock = context.wrap_socket(conn, server_hostname=hostname)
        cert_der = sock.getpeercert(True)
        cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
        cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'), default_backend())
        return cert, cert_pem
    except ssl.SSLError as e:
        log_print(f"{COLOR['RED']}Error connecting to {hostname}:{port} --- REASON: {e.reason}{COLOR['ENDC']}")
        write_file(hostname, port, f"Error connecting to {hostname}:{port} --- REASON: {e.reason}", 'Get cert for hostname connection')
        return None, ""

def get_issuer(cert):
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        issuers = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
        if not issuers:
            raise Exception('No issuers entry in AIA')
        return issuers[0].access_location.value
    except x509.ExtensionNotFound:
        raise Exception('AuthorityInformationAccess extension not found')

def get_ocsp_server(cert):
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsps = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
        if not ocsps:
            raise Exception('No OCSP server entry in AIA')
        return ocsps[0].access_location.value
    except x509.ExtensionNotFound:
        raise Exception('AuthorityInformationAccess extension not found')

def get_issuer_cert(ca_issuer):
    try:
        issuer_response = requests.get(ca_issuer)
        issuer_response.raise_for_status()
        issuer_der = issuer_response.content
        issuer_pem = ssl.DER_cert_to_PEM_cert(issuer_der)
        issuer_cert = x509.load_pem_x509_certificate(issuer_pem.encode('ascii'), default_backend())
        return issuer_cert
    except Exception as e:
        raise Exception(f'Fetching issuer cert failed: {e}')

def get_ocsp_request_url(ocsp_server, cert, issuer_cert):
    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
    req = builder.build()
    req_der = req.public_bytes(serialization.Encoding.DER)
    req_b64 = base64.b64encode(req_der).decode('ascii')
    return urljoin(ocsp_server + '/', req_b64)

def get_ocsp_cert_status(ocsp_server, cert, issuer_cert):
    try:
        ocsp_url = get_ocsp_request_url(ocsp_server, cert, issuer_cert)
        ocsp_resp = requests.get(ocsp_url)
        ocsp_resp.raise_for_status()
        ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp.content)
        if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
            return ocsp_decoded.response_status, ocsp_decoded.certificate_status
        else:
            return ocsp_decoded.response_status, None
    except Exception as e:
        log_print(f'Error fetching OCSP status: {e}')
        return None, None

def get_certificate_fingerprint(cert, hostname, port):
    try:
        return cert.fingerprint(cert.signature_hash_algorithm).hex()
    except Exception:
        log_print(f'{COLOR["RED"]}No fingerprint can be retrieved for {hostname}:{port}{COLOR["ENDC"]}')
        return None

def get_cert_status_for_host(hostname, port, cert, cert_pem):
    if cert is None:
        log_print(f"{COLOR['RED']}Error occurred during connection. No certificate found for {hostname}:{port}{COLOR['ENDC']}")
        return

    log_print(f'{COLOR["GREEN"]}Certificate for {hostname}:{port} retrieved successfully{COLOR["ENDC"]}')
    write_file(hostname, port, cert_pem, 'CERTIFICATE')

    has_crl = False
    has_ocsp = False

    try:
        crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        has_crl = True
        log_print(f'CRL Extension found for {hostname}:{port}')
    except x509.ExtensionNotFound:
        log_print(f'{COLOR["RED"]}CRL Distribution Points extension not found for {hostname}:{port}{COLOR["ENDC"]}')

    try:
        aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        has_ocsp = any(ia.access_method == AuthorityInformationAccessOID.OCSP for ia in aia_ext.value)
        if has_ocsp:
            log_print(f'OCSP Extension found for {hostname}:{port}')
        else:
            log_print(f'{COLOR["RED"]}OCSP Extension not found for {hostname}:{port}{COLOR["ENDC"]}')
    except x509.ExtensionNotFound:
        log_print(f'{COLOR["RED"]}Authority Information Access extension not found for {hostname}:{port}{COLOR["ENDC"]}')

    sct_cert = sct_extension(cert, hostname, port)
    sct_web(hostname, port, sct_cert)

    ca_issuer = ''
    try:
        ca_issuer = get_issuer(cert)
        log_print(f'Found certificate issuer for {hostname}:{port} -> {ca_issuer}')
    except Exception as e:
        log_print(f"Issuer extension not found for certificate owned by {hostname}:{port}: {e}")

    issuer_cert = None
    if ca_issuer:
        try:
            issuer_cert = get_issuer_cert(ca_issuer)
            log_print(f'Certificate for the issuer of {hostname}:{port} retrieved')
        except Exception as e:
            log_print(f"Issuer certificate not found: {e}")

    ocsp_server = ''
    try:
        ocsp_server = get_ocsp_server(cert)
        log_print(f'OCSP Server found for {hostname}:{port}')
    except Exception as e:
        log_print(f'OCSP Server not found for {hostname}:{port}: {e}')

    if not has_crl and not has_ocsp:
        log_print(f"{COLOR['RED']}NO CRL AND OCSP EXTENSIONS FOUND in certificate for {hostname}:{port}. THIS IS DANGEROUS{COLOR['ENDC']}")
        write_file(hostname, port, 'NO CRL AND OCSP EXTENSIONS FOUND. THIS IS DANGEROUS', 'Certificate')
    else:
        if has_crl:
            log_print(f'Attempting CRL check for {hostname}:{port}')
            try:
                status_crl = check_revoked(cert_pem)
                if status_crl is None:
                    status_msg = "The certificate is not found in the CRL list. The certificate is CRL valid."
                else:
                    status_msg = f'Status: {status_crl}'
                write_file(hostname, port, status_msg, 'CRL')
            except Revoked as e:
                log_print(f"{COLOR['RED']}Certificate revoked for {hostname}:{port}: {e}{COLOR['ENDC']}")
                write_file(hostname, port, f"Certificate revoked: {e}", 'CRL')
            except Error as e:
                log_print(f"{COLOR['RED']}Revocation check failed for {hostname}:{port}: {e}{COLOR['ENDC']}")
                write_file(hostname, port, f"Revocation check failed: {e}", 'CRL')
            except Exception as e:
                log_print(f"{COLOR['RED']}Cannot check the status of the certificate on the CRL server for {hostname}:{port}: {e}{COLOR['ENDC']}")
                write_file(hostname, port, f"Cannot check CRL status: {e}", 'CRL')

        if has_ocsp and issuer_cert and ocsp_server:
            log_print(f'Attempting OCSP check for {hostname}:{port}')
            status_resp, status_ocsp = get_ocsp_cert_status(ocsp_server, cert, issuer_cert)
            if status_ocsp is None:
                log_print(f'{COLOR["RED"]}Error fetching OCSP status for {hostname}:{port}{COLOR["ENDC"]}')
                file_status = f'Error fetching OCSP status for {hostname}:{port}'
            else:
                log_print(f'OCSP status retrieved for {hostname}:{port}')
                file_status = f'OCSP STATUS: {status_ocsp} - OCSP RESPONSE: {status_resp}'
            write_file(hostname, port, file_status, 'OCSP')
        else:
            log_print(f"OCSP status can't be retrieved for {hostname}:{port} because issuer cert or OCSP server not found")
            write_file(hostname, port, "OCSP status can't be retrieved because issuer cert or OCSP server not found", 'OCSP')
