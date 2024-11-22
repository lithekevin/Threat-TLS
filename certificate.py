import base64
import logging
import os
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

from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from asn1crypto import x509 as asn1x509

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

LOGS = [
    { "Name": "Aviator - FROZEN",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1J\n"
    "YP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=" },

    { "Name": "Digicert Log",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCF\n"
    "RkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=" },

    { "Name": "Pilot",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHT\n"
    "DM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=" },

    { "Name": "Icarus",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETtK8v7MICve56qTHHDhhBOuV4IlU\n"
    "aESxZryCfk9QbG9co/CqPvTsgPDbCpp6oFtyAHwlDhnvr7JijXRD9Cb2FA==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=" },

    { "Name": "Rocketeer",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1\n"
    "aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=" },

    { "Name": "Skydiver",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2x\n"
    "zb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=" },

    { "Name": "Comodo Dodo",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELPXCMfVjQ2oWSgrewu4fIW4Sfh3lco90CwKZ061p\n"
    "vAI1eflh6c8ACE90pKM0muBDHCN+j0HV7scco4KKQPqq4A==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "23b9raxl59CVCIhuIVm9i5A1L1/q0+PcXiLrNQrMe5g=" },

    { "Name": "Symantec log",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY\n"
    "4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=" },

    { "Name": "Venafi log",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OC\n"
    "dpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym\n"
    "97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWt\n"
    "gnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB\n"
    "8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauC\n"
    "Fx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5\n"
    "wQIDAQAB\n"
    "-----END PUBLIC KEY-----",
    "LogID": "rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=" },

    { "Name": "WoSign log",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzBGIey1my66PTTBmJxklIpMhRrQv\n"
    "AdPG+SvVyLpzmwai8IoCnNBrRhgwhbrpJIsO0VtwKAx+8TpFf1rzgkJgMQ==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM=" },

    { "Name": "Symantec Vega",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6pWeAv/u8TNtS4e8zf0ZF2L/lNPQ\n"
    "WQc/Ai0ckP7IRzA78d0NuBEMXR2G3avTK0Zm+25ltzv9WWis36b4ztIYTQ==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU=" },

    { "Name": "CNNIC",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv7UIYZopMgTTJWPp2IXh\n"
    "huAf1l6a9zM7gBvntj5fLaFm9pVKhKYhVnno94XuXeN8EsDgiSIJIj66FpUGvai5\n"
    "samyetZhLocRuXhAiXXbDNyQ4KR51tVebtEq2zT0mT9liTtGwiksFQccyUsaVPhs\n"
    "Hq9gJ2IKZdWauVA2Fm5x9h8B9xKn/L/2IaMpkIYtd967TNTP/dLPgixN1PLCLayp\n"
    "vurDGSVDsuWabA3FHKWL9z8wr7kBkbdpEhLlg2H+NAC+9nGKx+tQkuhZ/hWR65aX\n"
    "+CNUPy2OB9/u2rNPyDydb988LENXoUcMkQT0dU3aiYGkFAY0uZjD2vH97TM20xYt\n"
    "NQIDAQAB\n"
    "-----END PUBLIC KEY-----",
    "LogID": "pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg=" },

    { "Name": "StartSSL",
    "Key": "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESPNZ8/YFGNPbsu1Gfs/IEbVXsajW\n"
    "TOaft0oaFIZDqUiwy1o/PErK38SCFFWa+PeOQFXc9NKv6nV0+05/YIYuUQ==\n"
    "-----END PUBLIC KEY-----",
    "LogID": "NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8=" },

    ]

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
        except Exception as e:
            logger.error(f"Error fetching certificate from {self.hostname}:{self.port} - {e}")
            return None, None

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
            self.check_scts()
            logger.info(f"Certificate validation completed successfully for {self.hostname}:{self.port}")
        except CertificateValidationError as e:
            logger.error(f"Certificate validation failed for {self.hostname}:{self.port} - {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred during validation: {e}")

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
            # Load the end-entity certificate
            cert = asn1x509.Certificate.load(self.der_cert)

            # Fetch intermediate certificates
            intermediates = self.fetch_intermediate_certs()

            # Create ValidationContext (using system trust roots)
            context = ValidationContext()

            # Instantiate the validator with intermediates
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

    def verify_sct(self, sct, public_key_pem, ee_cert_der):
        """
        Verifies a single SCT using OpenSSL.

        Args:
            sct (bytes): The SCT to verify.
            public_key_pem (str): PEM-encoded public key of the log.
            ee_cert_der (bytes): DER-encoded end-entity certificate.

        Returns:
            bool: True if verification is successful, False otherwise.
        """
        try:
            # Parse SCT fields
            offset = 0
            version = sct[offset]
            offset += 1
            log_id = sct[offset:offset + 32]
            offset += 32
            timestamp, = struct.unpack("!Q", sct[offset:offset + 8])
            offset += 8
            extensions_len, = struct.unpack("!H", sct[offset:offset + 2])
            offset += 2 + extensions_len
            sig_alg_hash = sct[offset]
            sig_alg_sign = sct[offset + 1]
            offset += 2
            signature_len, = struct.unpack("!H", sct[offset:offset + 2])
            offset += 2
            signature = sct[offset:offset + signature_len]

            # Prepare signed data
            cert_len_bytes = struct.pack("!I", len(ee_cert_der))[1:]  # 3 bytes for length
            signed_data = (
                    struct.pack("!BBQh", version, 0, timestamp, 0) +  # Version, type, timestamp
                    cert_len_bytes + ee_cert_der +  # Length and cert
                    struct.pack("!H", 0)  # Extensions length
            )

            # Write public key, signature, and signed data to temporary files
            with open("tmp-pubkey.pem", "w") as pubkey_file:
                pubkey_file.write(public_key_pem)
            with open("tmp-signature.bin", "wb") as sig_file:
                sig_file.write(signature)
            with open("tmp-signeddata.bin", "wb") as signed_data_file:
                signed_data_file.write(signed_data)

            # Use OpenSSL to verify
            args = [
                "openssl", "dgst", "-sha256", "-verify", "tmp-pubkey.pem",
                "-signature", "tmp-signature.bin", "tmp-signeddata.bin"
            ]
            result = subprocess.run(args, capture_output=True)
            if result.returncode == 0:
                logger.info("SCT verification successful.")
                return True
            else:
                logger.error("SCT verification failed.")
                return False
        finally:
            # Clean up temporary files
            for tmp_file in ["tmp-pubkey.pem", "tmp-signature.bin", "tmp-signeddata.bin"]:
                try:
                    os.remove(tmp_file)
                except FileNotFoundError:
                    pass

    def check_scts(self):
        """
        Verifies Signed Certificate Timestamps (SCTs) for Certificate Transparency.
        """
        try:
            scts = self.cert.extensions.get_extension_for_oid(
                ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS
            ).value
            if scts:
                logger.info(f"SCTs found in certificate for {self.hostname}")
                for sct in scts:
                    log_id_b64 = base64.b64encode(sct.log_id).decode("ascii")
                    public_key_pem = next(
                        (log["Key"] for log in LOGS if log["LogID"] == log_id_b64),
                        None
                    )
                    if not public_key_pem:
                        logger.warning(f"LogID {log_id_b64} not found in known logs.")
                        continue
                    if not self.verify_sct(sct.encode(), public_key_pem, self.der_cert):
                        raise CertificateValidationError(f"SCT verification failed for log {log_id_b64}.")
                logger.info("All SCTs verified successfully.")
            else:
                logger.warning(f"No SCTs found in certificate for {self.hostname}")
        except x509.ExtensionNotFound:
            logger.warning("No SCTs found in the certificate.")
        except Exception as e:
            logger.error(f"Error during SCT verification: {e}")


# Expose the necessary functions for main.py
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
    fingerprint = validator.get_certificate_fingerprint()
    await validator.get_cert_status_for_host()
    return cert, cert_pem, fingerprint
