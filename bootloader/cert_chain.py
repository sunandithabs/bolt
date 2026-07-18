import datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey


class ChainValidationError(Exception):
    pass


def load_cert(path: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def validate_chain(oem_cert_path: str, root_cert_path: str) -> RSAPublicKey:
    oem_cert = load_cert(oem_cert_path)
    root_cert = load_cert(root_cert_path)

    if oem_cert.issuer != root_cert.subject:
        raise ChainValidationError("OEM cert issuer does not match root subject")

    root_pub = root_cert.public_key()
    assert isinstance(root_pub, RSAPublicKey)

    try:
        assert oem_cert.signature_hash_algorithm is not None
        root_pub.verify(
            oem_cert.signature,
            oem_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            oem_cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        raise ChainValidationError("OEM cert signature not valid under root CA key")

    now = datetime.datetime.now(datetime.timezone.utc)
    if now < oem_cert.not_valid_before_utc or now > oem_cert.not_valid_after_utc:
        raise ChainValidationError("OEM cert not within validity period")
    if now < root_cert.not_valid_before_utc or now > root_cert.not_valid_after_utc:
        raise ChainValidationError("root cert not within validity period")

    oem_pub = oem_cert.public_key()
    assert isinstance(oem_pub, RSAPublicKey)
    return oem_pub
