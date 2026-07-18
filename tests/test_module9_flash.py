import pytest

from bootloader.flash import FlashError, VirtualFlash
from bootloader.flash_ecu import FlashECU


def test_write_read_region(tmp_path):
    flash = VirtualFlash(str(tmp_path / "flash.bin"))
    flash.write("slot_a", b"firmware payload")
    assert flash.read("slot_a") == b"firmware payload"


def test_oversized_write_rejected(tmp_path):
    flash = VirtualFlash(str(tmp_path / "flash.bin"))
    with pytest.raises(FlashError):
        flash.write("bootloader", b"\x00" * 100000)


def test_unknown_region_rejected(tmp_path):
    flash = VirtualFlash(str(tmp_path / "flash.bin"))
    with pytest.raises(FlashError):
        flash.write("nonexistent_region", b"data")


def test_flash_ecu_stage_and_commit_flips_slot(tmp_path):
    ecu = FlashECU(str(tmp_path / "ecu.bin"))
    assert ecu.active_slot() == "slot_a"

    slot = ecu.stage(b"fw v1")
    assert slot == "slot_b"
    ecu.commit(slot, rollback_index=1)

    assert ecu.active_slot() == "slot_b"
    assert ecu.read_active_image() == b"fw v1"
    assert ecu.rollback_index() == 1


def test_flash_ecu_uncommitted_stage_does_not_change_active(tmp_path):
    ecu = FlashECU(str(tmp_path / "ecu.bin"))
    ecu.stage(b"fw v1")
    assert ecu.active_slot() == "slot_a"
    assert ecu.read_active_image() == b""
