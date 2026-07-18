import struct

from bootloader.flash import VirtualFlash


class FlashECU:
    def __init__(self, flash_path: str):
        self.flash = VirtualFlash(flash_path)
        counter = self.flash.read("rollback_counter")
        if not counter:
            self.flash.write("rollback_counter", struct.pack(">I", 0))

    def active_slot(self) -> str:
        state = self.flash.read("slot_state")
        if not state:
            return "slot_a"
        return "slot_a" if state[:1] == b"A" else "slot_b"

    def inactive_slot(self) -> str:
        return "slot_b" if self.active_slot() == "slot_a" else "slot_a"

    def rollback_index(self) -> int:
        return struct.unpack(">I", self.flash.read("rollback_counter").ljust(4, b"\x00"))[0]

    def stage(self, image_bytes: bytes) -> str:
        slot = self.inactive_slot()
        self.flash.write(slot, image_bytes)
        return slot

    def commit(self, slot: str, rollback_index: int):
        marker = b"A" if slot == "slot_a" else b"B"
        self.flash.write("slot_state", marker)
        self.flash.write("rollback_counter", struct.pack(">I", rollback_index))

    def read_active_image(self) -> bytes:
        return self.flash.read(self.active_slot())
