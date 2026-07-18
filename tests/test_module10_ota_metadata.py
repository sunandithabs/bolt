import pytest
from cryptography.hazmat.primitives import serialization

from pipeline.keygen import generate_keypair
from pipeline.ota_metadata import (
    MetadataError,
    build_director_metadata,
    build_image_repo_metadata,
    resolve_target,
)


@pytest.fixture
def keypair(tmp_path):
    priv, pub = generate_keypair(str(tmp_path), "key")
    pub_key = serialization.load_pem_public_key(pub.read_bytes())
    return priv, pub_key


def test_resolve_target_matches_director_assignment(keypair):
    priv, pub_key = keypair
    director = build_director_metadata("ecu-01", "fw_v2", str(priv))
    image_repo = build_image_repo_metadata(
        {"fw_v1": {"sha256": "aaa"}, "fw_v2": {"sha256": "bbb"}}, str(priv)
    )
    resolved = resolve_target(director, image_repo, pub_key)
    assert resolved["sha256"] == "bbb"


def test_resolve_target_missing_from_image_repo_rejected(keypair):
    priv, pub_key = keypair
    director = build_director_metadata("ecu-01", "fw_v3", str(priv))
    image_repo = build_image_repo_metadata({"fw_v1": {"sha256": "aaa"}}, str(priv))

    with pytest.raises(MetadataError):
        resolve_target(director, image_repo, pub_key)


def test_tampered_director_assignment_rejected(keypair):
    priv, pub_key = keypair
    director = build_director_metadata("ecu-01", "fw_v1", str(priv))
    director["body"]["assigned_target"] = "fw_v2"
    image_repo = build_image_repo_metadata({"fw_v1": {}, "fw_v2": {}}, str(priv))

    with pytest.raises(MetadataError):
        resolve_target(director, image_repo, pub_key)
