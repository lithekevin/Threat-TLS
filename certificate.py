import base64
import ssl
import requests
from urllib.parse import urljoin

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID


def get_cert_for_hostname(hostname, port):
    conn = ssl.create_connection((hostname, port))
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    sock = context.wrap_socket(conn, server_hostname=hostname)
    certDER = sock.getpeercert(True)
    certPEM = ssl.DER_cert_to_PEM_cert(certDER)
    return x509.load_pem_x509_certificate(certPEM.encode('ascii'), default_backend())


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
    ocsp_resp = requests.get(get_oscp_request(ocsp_server, cert, issuer_cert))
    if ocsp_resp.ok:
        ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp.content)
        if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
            return ocsp_decoded.certificate_status
        else:
            # raise Exception(f'decoding ocsp response failed: {ocsp_decoded.response_status}')
            return ocsp_decoded.response_status
    raise Exception(f'fetching ocsp cert status failed with response status: {ocsp_resp.status_code}')


def get_cert_status_for_host(hostname, port):
    print('   hostname:', hostname, "port:", port)
    cert = get_cert_for_hostname(hostname, port)
    # print("CERTIFICATE:")
    # print(f"ISSUER: {cert.issuer} - SUBJECT: {cert.subject} - VERSION: {cert.version} - PK: {cert.public_key()}")
    array = []
    crl = ''
    ocsp = ''

    try:
        crl = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        # print("-----------CRLDISTRIBUTIONPOINTS-------------")
        # print(cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS))
        array.append('CRL')
    except:
        print("CRLDISTRIBUTIONPOINTS NOT FOUND")

    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        print('---------------OCSP---------------')
        e = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        print(e.value)
        am = e.value
        ocsp = [ia for ia in am if ia.access_method == AuthorityInformationAccessOID.OCSP]
        print(ocsp)
        array.append('OCSP')
    except:
        print("CRL EXTENSION NOT FOUND")

    try:
        ca_issuer = get_issuer(cert)
        print('   issuer ->', ca_issuer)
    except:
        print("Exception for issuer extension")
        ca_issuer = ""

    try:
        issuer_cert = get_issuer_cert(ca_issuer)
    except:
        print("Exception for issuer certification")
        issuer_cert = ""

    try:
        ocsp_server = get_ocsp_server(cert)
        print('   ocsp_server ->', ocsp_server)
    except:
        print("Exception for ocsp SERVER")
        ocsp_server = ""

    if array.__len__() == 0:
        print("NO CRL AND OCSP EXTENSIONS FOUND. THIS IS DANGEROUS")
    else:
        if array.__contains__('CRL'):
            print('CRL EXTENSION FOUND')
            print(crl)
        if array.__contains__('OCSP'):
            print('OCSP EXTENSION FOUND')
            print(ocsp)

    if issuer_cert == "" or cert == "" or ocsp_server == "":
        print("ISSUER, CERT AND OCSP NOT FOUND")
    else:
        get_ocsp_cert_status(ocsp_server, cert, issuer_cert)