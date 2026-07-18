import pytest

from bootloader.rollback_store import RollbackStore
from bootloader.verifier import VerificationError, Verifier
from pipeline.image_builder import build_signed_image
from pipeline.keygen import generate_keypair


@pytest.fixture
def env(tmp_path):
    priv, pub = generate_keypair(str(tmp_path), "key")
    store = RollbackStore(str(tmp_path / "rollback.state"))
    verifier = Verifier(str(pub), store)
    return priv, pub, store, verifier


def test_valid_image_boots(env):
    priv, pub, store, verifier = env
    image = build_signed_image(b"fw v1", version=1, rollback_index=1, private_key_path=str(priv))
    payload = verifier.verify_and_boot(image)
    assert payload == b"fw v1"
    assert store.get() == 1


def test_tampered_image_rejected(env):
    priv, pub, store, verifier = env
    image = bytearray(
        build_signed_image(b"fw v1", version=1, rollback_index=1, private_key_path=str(priv))
    )
    image[-1] ^= 0xFF
    with pytest.raises(VerificationError):
        verifier.verify_and_boot(bytes(image))


def test_rollback_attack_rejected(env):
    priv, pub, store, verifier = env
    old_image = build_signed_image(
        b"fw v1", version=1, rollback_index=1, private_key_path=str(priv)
    )
    new_image = build_signed_image(
        b"fw v2", version=2, rollback_index=2, private_key_path=str(priv)
    )

    verifier.verify_and_boot(new_image)
    with pytest.raises(VerificationError):
        verifier.verify_and_boot(old_image)


def test_equal_rollback_index_allowed(env):
    priv, pub, store, verifier = env
    image1 = build_signed_image(b"fw v1", version=1, rollback_index=1, private_key_path=str(priv))
    image2 = build_signed_image(b"fw v1b", version=1, rollback_index=1, private_key_path=str(priv))

    verifier.verify_and_boot(image1)
    verifier.verify_and_boot(image2)
    assert store.get() == 1
