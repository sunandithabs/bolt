import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


class MetadataError(Exception):
    pass


def _sign_body(body: dict, private_key_path: str) -> dict:
    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(), password=None
    )
    assert isinstance(private_key, RSAPrivateKey)
    body_bytes = json.dumps(body, sort_keys=True).encode("utf-8")
    signature = private_key.sign(
        body_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {"body": body, "sig": signature.hex()}


def _verify_body(metadata: dict, public_key: RSAPublicKey) -> dict:
    body_bytes = json.dumps(metadata["body"], sort_keys=True).encode("utf-8")
    signature = bytes.fromhex(metadata["sig"])
    try:
        public_key.verify(
            signature,
            body_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise MetadataError("metadata signature invalid")
    return metadata["body"]


def build_director_metadata(ecu_id: str, assigned_target: str, private_key_path: str) -> dict:
    body = {"role": "director", "ecu_id": ecu_id, "assigned_target": assigned_target}
    return _sign_body(body, private_key_path)


def build_image_repo_metadata(targets: dict, private_key_path: str) -> dict:
    body = {"role": "image_repository", "targets": targets}
    return _sign_body(body, private_key_path)


def resolve_target(
    director_metadata: dict,
    image_repo_metadata: dict,
    public_key: RSAPublicKey,
) -> dict:
    director_body = _verify_body(director_metadata, public_key)
    image_repo_body = _verify_body(image_repo_metadata, public_key)

    assigned = director_body["assigned_target"]
    targets = image_repo_body["targets"]

    if assigned not in targets:
        raise MetadataError(
            f"director assigned target '{assigned}' not present in image repository"
        )

    return targets[assigned]
