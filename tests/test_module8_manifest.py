import pytest
from cryptography.hazmat.primitives import serialization

from pipeline.keygen import generate_keypair
from pipeline.manifest import (
    ManifestError,
    build_manifest,
    target_entry,
    verify_manifest,
    verify_target,
)


@pytest.fixture
def keypair(tmp_path):
    priv, pub = generate_keypair(str(tmp_path), "key")
    pub_key = serialization.load_pem_public_key(pub.read_bytes())
    return priv, pub_key


def test_manifest_round_trip(keypair):
    priv, pub_key = keypair
    payload = b"firmware bytes"
    entry = target_entry("main_ecu_fw", payload)
    manifest = build_manifest("ecu-01", 2, 2, [entry], str(priv))

    body = verify_manifest(manifest, pub_key)
    assert body["version"] == 2
    assert body["targets"][0]["name"] == "main_ecu_fw"
    assert verify_target(payload, body["targets"][0]) is True


def test_manifest_tamper_detected(keypair):
    priv, pub_key = keypair
    entry = target_entry("main_ecu_fw", b"firmware bytes")
    manifest = build_manifest("ecu-01", 1, 1, [entry], str(priv))
    manifest["body"]["version"] = 99

    with pytest.raises(ManifestError):
        verify_manifest(manifest, pub_key)


def test_target_hash_mismatch_detected(keypair):
    priv, pub_key = keypair
    entry = target_entry("main_ecu_fw", b"firmware bytes")
    manifest = build_manifest("ecu-01", 1, 1, [entry], str(priv))
    body = verify_manifest(manifest, pub_key)
    assert verify_target(b"different bytes", body["targets"][0]) is False
