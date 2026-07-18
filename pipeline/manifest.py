import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


class ManifestError(Exception):
    pass


def build_manifest(
    ecu_id: str,
    version: int,
    rollback_index: int,
    targets: list[dict],
    private_key_path: str,
) -> dict:
    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(), password=None
    )
    assert isinstance(private_key, RSAPrivateKey)

    body = {
        "ecu_id": ecu_id,
        "version": version,
        "rollback_index": rollback_index,
        "targets": targets,
    }
    body_bytes = json.dumps(body, sort_keys=True).encode("utf-8")

    signature = private_key.sign(
        body_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    return {"body": body, "sig": signature.hex()}


def target_entry(name: str, payload: bytes) -> dict:
    return {
        "name": name,
        "length": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def verify_manifest(manifest: dict, public_key: RSAPublicKey) -> dict:
    body_bytes = json.dumps(manifest["body"], sort_keys=True).encode("utf-8")
    signature = bytes.fromhex(manifest["sig"])

    try:
        public_key.verify(
            signature,
            body_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise ManifestError("manifest signature invalid")

    return manifest["body"]


def verify_target(payload: bytes, entry: dict) -> bool:
    if len(payload) != entry["length"]:
        return False
    return hashlib.sha256(payload).hexdigest() == entry["sha256"]
