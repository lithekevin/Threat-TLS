import base64
import hashlib
import logging
import socket
import ssl
import struct
import subprocess
from typing import Optional, List, Tuple

import aiohttp
import requests
from certvalidator import CertificateValidator as CV, ValidationContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from asn1crypto import x509 as asn1x509

from db import SessionLocal
from models import Server, CertificateResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CertificateValidationError(Exception):
    """Custom exception for certificate validation errors."""
    pass

class CertificateValidator:
    """
    A class to validate SSL/TLS certificates, including checking the chain of trust,
    revocation status (via OCSP and CRL), and Certificate Transparency (SCTs).
    """

    def __init__(self, hostname: str, port: int = 443, timeout: int = 5):
        """
        Initializes the CertificateValidator.

        Args:
            hostname (str): The hostname to validate.
            port (int, optional): The port number to connect to. Defaults to 443.
            timeout (int, optional): Connection timeout in seconds. Defaults to 5.
        """
        self.hostname = hostname
        self.port = port
        self.timeout = timeout
        self.cert: Optional[x509.Certificate] = None
        self.der_cert: Optional[bytes] = None
        self.cert_pem: Optional[str] = None
        self.context = ssl.create_default_context()
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.set_ciphers('HIGH:!aNULL:!eNULL')
        self.ocsp_urls: List[str] = []
        self.crl_urls: List[str] = []
        self.session = SessionLocal()  # Database session

    def get_cert_for_hostname(self) -> Tuple[Optional[x509.Certificate], Optional[str]]:
        """
        Fetches the certificate from the server.

        Returns:
            Tuple[Optional[x509.Certificate], Optional[str]]: The certificate object and PEM string.
        """
        try:
            logger.info(f"Fetching certificate from {self.hostname}:{self.port}")
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout) as sock:
                with self.context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    self.der_cert = ssock.getpeercert(True)
                    self.cert_pem = ssl.DER_cert_to_PEM_cert(self.der_cert)
                    self.cert = x509.load_pem_x509_certificate(self.cert_pem.encode('ascii'), default_backend())
            logger.info(f"Certificate fetched successfully for {self.hostname}:{self.port}")
            return self.cert, self.cert_pem
        except ssl.SSLCertVerificationError as e:
            logger.error(f"Certificate verification failed for {self.hostname}:{self.port} - {e}")
            if "self signed certificate" in str(e).lower():
                self.handle_self_signed_certificate()
            return None, None
        except Exception as e:
            logger.error(f"Error fetching certificate from {self.hostname}:{self.port} - {e}")
            return None, None

    def handle_self_signed_certificate(self):
        """
        Handles the case when a self-signed certificate is encountered.
        """
        logger.warning(f"Self-signed certificate detected for {self.hostname}:{self.port}")
        self.save_certificate_result(
            is_valid=False,
            reason="Self-signed certificate detected. Possible MITM attack."
        )

    def fetch_intermediate_certs(self) -> List[asn1x509.Certificate]:
        """
        Fetches intermediate certificates from the AIA extension.
        """
        intermediates = []
        issuer_urls = self.get_aia_ca_issuers()
        for url in issuer_urls:
            try:
                logger.info(f"Fetching intermediate certificate from {url}")
                response = requests.get(url, timeout=self.timeout)
                response.raise_for_status()
                intermediate_cert = asn1x509.Certificate.load(response.content)
                logger.info(
                    f"Fetched intermediate certificate with subject: {intermediate_cert.subject.human_friendly}")
                intermediates.append(intermediate_cert)
            except Exception as e:
                logger.error(f"Error fetching intermediate certificate from {url}: {e}")
        return intermediates

    def get_certificate_fingerprint(self) -> Optional[str]:
        """
        Retrieves the certificate's fingerprint.

        Returns:
            Optional[str]: The fingerprint as a hexadecimal string.
        """
        if self.cert:
            fingerprint = self.cert.fingerprint(self.cert.signature_hash_algorithm).hex()
            logger.info(f"Certificate fingerprint: {fingerprint}")
            return fingerprint
        else:
            logger.warning("Certificate not loaded; cannot get fingerprint.")
            return None

    async def get_cert_status_for_host(self):
        """
        Performs comprehensive validation of the certificate, including chain validation,
        revocation checks (OCSP and CRL), and SCT verification.
        """
        try:
            if not self.cert:
                logger.error("Certificate not loaded; cannot perform validation.")
                return

            self.extract_revocation_info()
            self.validate_certificate_chain()
            await self.check_ocsp_revocation()
            await self.check_crl_revocation()
            await self.check_scts()
            await self.check_certificate_in_ct_logs()
            logger.info(f"Certificate validation completed successfully for {self.hostname}:{self.port}")
            # Save successful validation result
            self.save_certificate_result(
                is_valid=True,
                reason="Certificate is valid."
            )
        except CertificateValidationError as e:
            logger.error(f"Certificate validation failed for {self.hostname}:{self.port} - {e}")
            # Save the result indicating validation failure
            self.save_certificate_result(
                is_valid=False,
                reason=str(e)
            )
        except Exception as e:
            logger.error(f"An unexpected error occurred during validation: {e}")
            self.save_certificate_result(
                is_valid=False,
                reason=f"Unexpected error: {e}"
            )

    def extract_revocation_info(self):
        """
        Extracts OCSP and CRL URLs from the certificate.
        """
        if not self.cert:
            raise CertificateValidationError("Certificate not loaded.")

        try:
            aia = self.cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            self.ocsp_urls = [
                desc.access_location.value
                for desc in aia
                if desc.access_method == AuthorityInformationAccessOID.OCSP
            ]
            logger.info(f"OCSP URLs extracted: {self.ocsp_urls}")
        except x509.ExtensionNotFound:
            logger.warning("No OCSP URLs found in the certificate.")

        try:
            crl_distribution_points = self.cert.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            ).value
            for point in crl_distribution_points:
                for url in point.full_name:
                    self.crl_urls.append(url.value)
            logger.info(f"CRL URLs extracted: {self.crl_urls}")
        except x509.ExtensionNotFound:
            logger.warning("No CRL URLs found in the certificate.")

    def validate_certificate_chain(self):
        """
        Validates the certificate chain using certvalidator.
        """
        try:
            logger.info(f"Validating certificate chain for {self.hostname}")
            cert = asn1x509.Certificate.load(self.der_cert)

            intermediates = self.fetch_intermediate_certs()

            context = ValidationContext()

            validator = CV(cert, intermediate_certs=intermediates, validation_context=context)
            validator.validate_tls(self.hostname)
            logger.info(f"Certificate chain is valid for {self.hostname}")
        except Exception as e:
            logger.error(f"Certificate chain validation failed for {self.hostname} - {e}")
            raise CertificateValidationError(f"Certificate chain validation failed: {e}")

    async def check_ocsp_revocation(self):
        """
        Checks the revocation status of the certificate using OCSP.
        """
        if not self.ocsp_urls:
            logger.warning("No OCSP URLs to check.")
            return

        for ocsp_url in self.ocsp_urls:
            try:
                logger.info(f"Checking OCSP revocation status with {ocsp_url}")
                issuer = self.get_issuer_certificate()
                if not issuer:
                    logger.warning("Issuer certificate not found. Skipping OCSP check.")
                    continue

                # Build the OCSP request
                builder = ocsp.OCSPRequestBuilder()
                builder = builder.add_certificate(self.cert, issuer, hashes.SHA1())
                req = builder.build()
                data = req.public_bytes(serialization.Encoding.DER)

                async with aiohttp.ClientSession() as session:
                    async with session.post(
                            ocsp_url,
                            data=data,
                            headers={'Content-Type': 'application/ocsp-request'},
                            timeout=self.timeout
                    ) as response:
                        if response.status != 200:
                            logger.error(f"OCSP server returned status {response.status}")
                            continue
                        content = await response.read()
                        ocsp_resp = ocsp.load_der_ocsp_response(content)
                        if ocsp_resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                            status = ocsp_resp.certificate_status
                            logger.info(f"OCSP revocation status: {status}")
                            if status != ocsp.OCSPCertStatus.GOOD:
                                raise CertificateValidationError(f"Certificate is revoked according to OCSP: {status}")
                        else:
                            logger.error(f"OCSP response unsuccessful: {ocsp_resp.response_status}")
            except Exception as e:
                logger.error(f"Error checking OCSP revocation status: {e}")
                raise

    def get_issuer_certificate(self) -> Optional[x509.Certificate]:
        """
        Retrieves the issuer's certificate.

        Returns:
            Optional[x509.Certificate]: The issuer's certificate, or None if not found.
        """
        try:
            issuer_urls = self.get_aia_ca_issuers()
            for url in issuer_urls:
                logger.info(f"Fetching issuer certificate from {url}")
                response = requests.get(url, timeout=self.timeout)
                response.raise_for_status()
                issuer_cert = x509.load_der_x509_certificate(response.content, default_backend())
                logger.info("Issuer certificate fetched successfully.")
                return issuer_cert
        except Exception as e:
            logger.error(f"Error fetching issuer certificate: {e}")
            return None

    def get_aia_ca_issuers(self) -> List[str]:
        """
        Extracts CA Issuers URLs from the certificate's AIA extension.
        """
        try:
            aia = self.cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            ca_issuers_urls = [
                desc.access_location.value
                for desc in aia
                if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS
            ]
            logger.info(f"CA Issuers URLs extracted: {ca_issuers_urls}")
            return ca_issuers_urls
        except x509.ExtensionNotFound:
            logger.warning("No CA Issuers URLs found in the certificate.")
            return []

    async def check_crl_revocation(self):
        """
        Checks the revocation status of the certificate using CRL.
        """
        if not self.crl_urls:
            logger.warning("No CRL URLs to check.")
            return

        for crl_url in self.crl_urls:
            try:
                logger.info(f"Checking CRL revocation status with {crl_url}")
                async with aiohttp.ClientSession() as session:
                    async with session.get(crl_url, timeout=self.timeout) as response:
                        if response.status != 200:
                            logger.error(f"CRL server returned status {response.status}")
                            continue
                        content = await response.read()
                        crl = x509.load_der_x509_crl(content, default_backend())
                        for revoked_cert in crl:
                            if revoked_cert.serial_number == self.cert.serial_number:
                                logger.error(f"Certificate is revoked according to CRL at {crl_url}")
                                raise CertificateValidationError("Certificate is revoked according to CRL")
                        logger.info(f"Certificate is not revoked according to CRL at {crl_url}")
            except Exception as e:
                logger.error(f"Error checking CRL revocation status: {e}")
                raise

    #async def check_scts(self):
    #    """
    #    Checks for SCTs in the certificate, TLS handshake, and OCSP response.
    #    """
    #    scts_found = False
    #
    #    try:
    #        scts = self.cert.extensions.get_extension_for_oid(
    #            ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS
    #        ).value
    #        if scts:
    #            logger.info(f"SCTs found in certificate for {self.hostname}")
    #            scts_found = True
    #            await self.verify_scts(scts)
    #    except x509.ExtensionNotFound:
    #        logger.warning("No SCTs found in the certificate.")
    #
    #    if not scts_found:
    #        scts = self.get_scts_from_tls_handshake()
    #        if scts:
    #            scts_found = True
    #            await self.verify_scts(scts)
    #
    #    if not scts_found:
    #        scts = await self.get_scts_from_ocsp()
    #        if scts:
    #            scts_found = True
    #            await self.verify_scts(scts)
    #
    #    if not scts_found:
    #        logger.error(f"No SCTs found for {self.hostname}. Certificate may not be compliant with CT requirements.")
    #        raise CertificateValidationError("No SCTs found via certificate, TLS handshake, or OCSP response.")

    def get_scts_from_tls_handshake(self) -> List[bytes]:
        """
        Performs a TLS handshake and extracts SCTs from the ServerHello message.
        """
        try:
            logger.info(f"Attempting to extract SCTs from TLS handshake for {self.hostname}:{self.port}")
            command = [
                'openssl', 's_client',
                '-connect', f'{self.hostname}:{self.port}',
                '-tlsextdebug', '-status', '-ign_eof'
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout)
            output = result.stdout

            scts = self.parse_scts_from_openssl_output(output)
            if scts:
                logger.info(f"SCTs extracted from TLS handshake for {self.hostname}:{self.port}")
                return scts
            else:
                logger.warning(f"No SCTs found in TLS handshake for {self.hostname}:{self.port}")
                return []
        except Exception as e:
            logger.error(f"Error extracting SCTs from TLS handshake: {e}")
            return []

    def parse_scts_from_openssl_output(self, output: str) -> List[bytes]:
        """
        Parses SCTs from the output of 'openssl s_client'.
        """
        scts = []
        lines = output.split('\n')
        sct_data = ''
        capture = False
        for line in lines:
            if 'TLS server extension "status request"' in line:
                capture = False
            elif 'TLS server extension "signed certificate timestamp"' in line:
                capture = True
                continue
            if capture:
                if '---' in line:
                    capture = False
                    continue
                sct_data += line.strip()
        if sct_data:
            try:
                sct_bytes = base64.b64decode(sct_data)
                scts.append(sct_bytes)
            except Exception as e:
                logger.error(f"Error decoding SCT data: {e}")
        return scts

    async def get_scts_from_ocsp(self) -> List[bytes]:
        """
        Fetches the OCSP response and extracts SCTs if present.
        """

        return []

    async def verify_scts(self, scts):
        """
        Verifies SCTs using the fetched CT logs.
        """
        ct_logs = self.fetch_known_ct_logs()
        for sct in scts:
            # Extract log_id from SCT
            log_id = sct.log_id if hasattr(sct, 'log_id') else sct[:32]
            log_id_b64 = base64.b64encode(log_id).decode("ascii")
            public_key_pem = ct_logs.get(log_id_b64)
            if not public_key_pem:
                logger.warning(f"LogID {log_id_b64} not found in known logs.")
                continue
            if not self.verify_sct(sct, public_key_pem, self.der_cert):
                raise CertificateValidationError(f"SCT verification failed for log {log_id_b64}.")
        logger.info("All SCTs verified successfully.")

    def fetch_known_ct_logs(self) -> dict:
        """
        Fetches the list of known CT logs from a reliable source.
        Returns a dictionary mapping log IDs to their public keys.
        """
        ct_logs = {}
        try:
            response = requests.get('https://www.gstatic.com/ct/log_list/v3/log_list.json')
            response.raise_for_status()
            log_list = response.json()

            for log in log_list.get('logs', []):
                key = log.get('key')
                log_id = log.get('log_id')
                if key and log_id:
                    public_key_der = base64.b64decode(key)
                    public_key = serialization.load_der_public_key(public_key_der, backend=default_backend())
                    public_key_pem = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('ascii')
                    ct_logs[log_id] = public_key_pem
            logger.info("Fetched known CT logs successfully.")
        except Exception as e:
            logger.error(f"Error fetching known CT logs: {e}")
        return ct_logs

    def verify_sct(self, sct, public_key_pem, ee_cert_der):
        """
        Verifies a single SCT using cryptography library.

        Args:
            sct (bytes): The SCT to verify.
            public_key_pem (str): PEM-encoded public key of the log.
            ee_cert_der (bytes): DER-encoded end-entity certificate.

        Returns:
            bool: True if verification is successful, False otherwise.
        """
        try:
            # Parse SCT
            if isinstance(sct, x509.SignedCertificateTimestamp):
                sct_data = sct
            else:
                sct_data = x509.SignedCertificateTimestamp.from_der(sct)

            tbs_data = b'\x00' + struct.pack('>Q', sct_data.timestamp)
            cert_length_bytes = struct.pack('>I', len(ee_cert_der))
            tbs_data += cert_length_bytes[1:] + ee_cert_der + struct.pack('>H', 0)  # Empty extensions

            public_key = serialization.load_pem_public_key(public_key_pem.encode('ascii'), backend=default_backend())

            hash_alg = sct_data.signature_hash_algorithm
            if hash_alg == x509.SignatureHashAlgorithm.sha256:
                chosen_hash = hashes.SHA256()
            elif hash_alg == x509.SignatureHashAlgorithm.sha384:
                chosen_hash = hashes.SHA384()
            else:
                logger.error(f"Unsupported hash algorithm: {hash_alg}")
                return False

            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    sct_data.signature,
                    tbs_data,
                    asym_padding.PKCS1v15(),
                    chosen_hash
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    sct_data.signature,
                    tbs_data,
                    ec.ECDSA(chosen_hash)
                )
            else:
                logger.error("Unsupported public key type for SCT verification.")
                return False

            logger.info("SCT verification successful.")
            return True
        except Exception as e:
            logger.error(f"SCT verification failed: {e}")
            return False

    async def check_certificate_in_ct_logs(self):
        """
        Checks if the certificate is present in known CT logs by querying them.
        """
        try:
            logger.info(f"Checking if certificate is present in CT logs for {self.hostname}")
            cert_der = self.cert.public_bytes(serialization.Encoding.DER)
            cert_sha256 = hashlib.sha256(cert_der).hexdigest()

            ct_logs = [
                'https://ct.googleapis.com/logs/xenon2023',
                'https://ct.googleapis.com/logs/argon2023',
                # Add more known CT log URLs
            ]

            found_in_ct = False
            for log_url in ct_logs:
                query_url = f"https://crt.sh/?q={cert_sha256}&output=json"
                response = requests.get(query_url)
                if response.status_code == 200 and response.json():
                    logger.info(f"Certificate found in CT log {log_url}")
                    found_in_ct = True
                    break
            if not found_in_ct:
                logger.error("Certificate not found in any known CT logs.")
                raise CertificateValidationError("Certificate not found in any known CT logs.")
        except Exception as e:
            logger.error(f"Error checking certificate in CT logs: {e}")
            raise CertificateValidationError(f"Error checking certificate in CT logs: {e}")

    def save_certificate_result(self, is_valid: bool, reason: str):
        """
        Saves the certificate validation result to the database.

        Args:
            is_valid (bool): Whether the certificate is valid.
            reason (str): The reason for the validation result.
        """
        # Find or create the server
        server = self.session.query(Server).filter_by(ip=self.hostname, port=str(self.port)).first()
        if not server:
            server = Server(ip=self.hostname, port=str(self.port))
            self.session.add(server)
            self.session.commit()

        # Create the certificate result
        cert_result = CertificateResult(
            server_id=server.id,
            is_valid=is_valid,
            reason=reason,
            certificate_pem=self.cert_pem if self.cert_pem else '',
            fingerprint=self.get_certificate_fingerprint() if self.cert else ''
        )
        self.session.add(cert_result)
        self.session.commit()
        logger.info(f"Certificate validation result saved for {self.hostname}:{self.port}")

async def validate_certificate(hostname: str, port: int = 443):
    """
    Performs the entire certificate validation process for the given hostname and port.

    Args:
        hostname (str): The hostname to validate.
        port (int, optional): The port number. Defaults to 443.
    """
    validator = CertificateValidator(hostname, port)
    cert, cert_pem = validator.get_cert_for_hostname()
    if cert is None:
        logger.error(f"Failed to retrieve certificate for {hostname}:{port}")
        return
    await validator.get_cert_status_for_host()
    return cert, cert_pem, validator.get_certificate_fingerprint()
