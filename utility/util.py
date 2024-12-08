import logging


def extract_openssl_version(openssl_cpe: str) -> str:
    """
    Extract the OpenSSL version from a CPE string by splitting on ':' and
    stripping the trailing letter from the fifth element.

    Args:
        openssl_cpe (str): The CPE string, e.g., "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*"

    Returns:
        str: The normalized OpenSSL version, e.g., "1.0.1", or an empty string if invalid.
    """
    try:
        parts = openssl_cpe.split(":")

        raw_version = parts[5]
        normalized_version = ''.join([c for c in raw_version if c.isdigit() or c == '.'])  # Remove trailing letters

        logging.debug(f"Extracted OpenSSL version: {normalized_version} from CPE {openssl_cpe}")
        return normalized_version
    except Exception as e:
        logging.error(f"Error processing CPE: {openssl_cpe}, Error: {e}")
        return ""


def is_vulnerability_applicable(vulnerability: str, openssl_major_version: str) -> bool:
    vulnerability_openssl_support = {
        'BLEICHENBACHER': {'1.0.1': False, '1.0.2': False},
        'CCSINJECTION': {'1.0.1': True, '1.0.2': False},
        'POODLE': {'1.0.1': True, '1.0.2': False},
        'HEARTBEAT EXTENSION': {'1.0.1': True, '1.0.2': False},
        'LUCKY13': {'1.0.1': True, '1.0.2': False},
        'PADDING ORACLE ATTACK': {'1.0.1': True, '1.0.2': True},
        'SWEET32': {'1.0.1': True, '1.0.2': True},
        'DROWN': {'1.0.1': True, '1.0.2': True},
        'CRIME': {'1.0.1': True, '1.0.2': True},
        'LOGJAM': {'1.0.1': True, '1.0.2': True},
        'BEAST': {'1.0.1': True, '1.0.2': True},
        'RC4': {'1.0.1': True, '1.0.2': True},
        'FREAK': {'1.0.1': True, '1.0.2': False}
    }

    if vulnerability not in vulnerability_openssl_support:
        return False

    return vulnerability_openssl_support[vulnerability].get(openssl_major_version, False)
