import pytest

from attacks import downgrade_attack, mitm_channel, power_loss_sim, strip_signature
from bootloader.rollback_store import RollbackStore
from bootloader.verifier import Verifier
from pipeline.image_builder import build_signed_image
from pipeline.keygen import generate_keypair


@pytest.fixture
def env(tmp_path):
    priv, pub = generate_keypair(str(tmp_path), "key")
    store = RollbackStore(str(tmp_path / "rollback.state"))
    verifier = Verifier(str(pub), store)
    return priv, pub, store, verifier


def test_downgrade_attack_blocked(env):
    priv, pub, store, verifier = env
    old = build_signed_image(b"v1", version=1, rollback_index=1, private_key_path=str(priv))
    new = build_signed_image(b"v2", version=2, rollback_index=2, private_key_path=str(priv))
    verifier.verify_and_boot(new)
    assert downgrade_attack.run(verifier, old) is False


def test_strip_signature_blocked(env):
    priv, pub, store, verifier = env
    image = build_signed_image(b"v1", version=1, rollback_index=1, private_key_path=str(priv))
    assert strip_signature.run(verifier, image) is False


def test_mitm_tamper_blocked(env):
    priv, pub, store, verifier = env
    image = build_signed_image(b"v1", version=1, rollback_index=1, private_key_path=str(priv))
    assert mitm_channel.run(verifier, image) is False


def test_power_loss_blocked(env):
    priv, pub, store, verifier = env
    image = build_signed_image(b"v1", version=1, rollback_index=1, private_key_path=str(priv))
    assert power_loss_sim.run(verifier, image) is False
