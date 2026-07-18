import struct
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from pipeline.image_builder import build_signed_image, parse_image
from pipeline.keygen import generate_keypair


@pytest.fixture
def keypair(tmp_path):
    priv, pub = generate_keypair(str(tmp_path), "test_key")
    return priv, pub


def _verify(image_bytes, pub_key_path):
    header, payload = parse_image(image_bytes)
    pub_key = serialization.load_pem_public_key(Path(pub_key_path).read_bytes())
    blob = struct.pack(">II", header["version"], header["rollback_index"]) + payload
    sig = bytes.fromhex(header["sig"])
    pub_key.verify(
        sig,
        blob,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def test_valid_image_verifies(keypair):
    priv, pub = keypair
    payload = b"dummy firmware bytes v1"
    image = build_signed_image(payload, version=1, rollback_index=1, private_key_path=str(priv))
    _verify(image, pub)  # should not raise


def test_header_roundtrip(keypair):
    priv, pub = keypair
    payload = b"dummy firmware bytes"
    image = build_signed_image(payload, version=3, rollback_index=2, private_key_path=str(priv))
    header, parsed_payload = parse_image(image)
    assert header["version"] == 3
    assert header["rollback_index"] == 2
    assert parsed_payload == payload


def test_tampered_payload_fails_verification(keypair):
    priv, pub = keypair
    payload = b"dummy firmware bytes"
    image = build_signed_image(payload, version=1, rollback_index=1, private_key_path=str(priv))

    tampered = bytearray(image)
    tampered[-1] ^= 0xFF
    tampered = bytes(tampered)

    with pytest.raises(InvalidSignature):
        _verify(tampered, pub)


def test_tampered_version_fails_verification(keypair):
    priv, pub = keypair
    payload = b"dummy firmware bytes"
    image = build_signed_image(payload, version=1, rollback_index=1, private_key_path=str(priv))

    header, parsed_payload = parse_image(image)
    header["version"] = 99  # attacker bumps version in header without re-signing
    import json
    new_header_bytes = json.dumps(header).encode("utf-8")
    tampered = struct.pack(">I", len(new_header_bytes)) + new_header_bytes + parsed_payload

    with pytest.raises(InvalidSignature):
        _verify(tampered, pub)
