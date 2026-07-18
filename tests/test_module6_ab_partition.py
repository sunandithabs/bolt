import pytest

from bootloader.ab_partition import ABPartitionManager, PartitionError
from bootloader.rollback_store import RollbackStore
from bootloader.verifier import VerificationError, Verifier
from pipeline.image_builder import build_signed_image
from pipeline.keygen import generate_keypair


@pytest.fixture
def env(tmp_path):
    priv, pub = generate_keypair(str(tmp_path), "key")
    store = RollbackStore(str(tmp_path / "rollback.state"))
    partitions = ABPartitionManager(str(tmp_path / "partitions.state"))
    verifier = Verifier(str(pub), store, partitions)
    return priv, pub, store, partitions, verifier


def test_flash_ab_switches_active_slot(env):
    priv, pub, store, partitions, verifier = env
    v1 = build_signed_image(b"fw v1", version=1, rollback_index=1, private_key_path=str(priv))
    verifier.flash_ab(v1)
    assert partitions.read_active() == v1
    assert partitions.active_slot() == "B"


def test_power_loss_before_commit_leaves_active_slot_intact(env):
    priv, pub, store, partitions, verifier = env
    v1 = build_signed_image(b"fw v1", version=1, rollback_index=1, private_key_path=str(priv))
    verifier.flash_ab(v1)

    v2 = build_signed_image(b"fw v2", version=2, rollback_index=2, private_key_path=str(priv))
    partitions.stage(v2)

    assert partitions.read_active() == v1


def test_second_update_flips_slot_back(env):
    priv, pub, store, partitions, verifier = env
    v1 = build_signed_image(b"fw v1", version=1, rollback_index=1, private_key_path=str(priv))
    v2 = build_signed_image(b"fw v2", version=2, rollback_index=2, private_key_path=str(priv))

    verifier.flash_ab(v1)
    verifier.flash_ab(v2)

    assert partitions.read_active() == v2
    assert partitions.active_slot() == "A"


def test_read_active_before_any_flash_raises(env):
    priv, pub, store, partitions, verifier = env
    with pytest.raises(PartitionError):
        partitions.read_active()


def test_invalid_image_never_reaches_active_slot(env):
    priv, pub, store, partitions, verifier = env
    v1 = build_signed_image(b"fw v1", version=1, rollback_index=1, private_key_path=str(priv))
    verifier.flash_ab(v1)

    corrupt = bytearray(
        build_signed_image(b"fw v2", version=2, rollback_index=2, private_key_path=str(priv))
    )
    corrupt[-1] ^= 0xFF

    with pytest.raises(VerificationError):
        verifier.flash_ab(bytes(corrupt))

    assert partitions.read_active() == v1
