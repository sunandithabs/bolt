import json
from pathlib import Path


class PartitionError(Exception):
    pass


class ABPartitionManager:
    def __init__(self, state_path: str):
        self.state_path = Path(state_path)
        if not self.state_path.exists():
            self._write_state({"active": "A", "A": None, "B": None})

    def _read_state(self) -> dict:
        return json.loads(self.state_path.read_text())

    def _write_state(self, state: dict):
        self.state_path.write_text(json.dumps(state))

    def active_slot(self) -> str:
        return self._read_state()["active"]

    def inactive_slot(self) -> str:
        return "B" if self.active_slot() == "A" else "A"

    def stage(self, image_bytes: bytes) -> str:
        slot = self.inactive_slot()
        state = self._read_state()
        state[slot] = image_bytes.hex()
        self._write_state(state)
        return slot

    def commit(self, slot: str):
        state = self._read_state()
        if state.get(slot) is None:
            raise PartitionError(f"slot {slot} has no staged image")
        state["active"] = slot
        self._write_state(state)

    def read_active(self) -> bytes:
        state = self._read_state()
        active_hex = state.get(state["active"])
        if active_hex is None:
            raise PartitionError("no image in active slot")
        return bytes.fromhex(active_hex)
