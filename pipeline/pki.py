import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def _write_pem(path: Path, obj, is_private: bool):
    if is_private:
        data = obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        data = obj.public_bytes(encoding=serialization.Encoding.PEM)
    path.write_bytes(data)


def generate_ca_chain(out_dir: str, oem_name: str = "BOLT OEM"):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    root_key, root_pub = _keypair()
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BOLT Root CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    oem_key, oem_pub = _keypair()
    oem_name_attr = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, oem_name)])
    oem_cert = (
        x509.CertificateBuilder()
        .subject_name(oem_name_attr)
        .issuer_name(root_name)
        .public_key(oem_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    _write_pem(out / "root_key.pem", root_key, True)
    _write_pem(out / "root_cert.pem", root_cert, False)
    _write_pem(out / "oem_key.pem", oem_key, True)
    _write_pem(out / "oem_cert.pem", oem_cert, False)

    return {
        "root_key": out / "root_key.pem",
        "root_cert": out / "root_cert.pem",
        "oem_key": out / "oem_key.pem",
        "oem_cert": out / "oem_cert.pem",
    }
