from pathlib import Path

REGIONS = {
    "bootloader": (0x0000, 0x1000),
    "slot_a": (0x1000, 0x9000),
    "slot_b": (0x9000, 0x11000),
    "rollback_counter": (0x11000, 0x11010),
    "slot_state": (0x11010, 0x11020),
    "manifest": (0x11020, 0x12020),
}

FLASH_SIZE = 0x12020


class FlashError(Exception):
    pass


class VirtualFlash:
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.exists() or self.path.stat().st_size != FLASH_SIZE:
            self.path.write_bytes(b"\xff" * FLASH_SIZE)

    def _bounds(self, region: str, data_len: int):
        if region not in REGIONS:
            raise FlashError(f"unknown region: {region}")
        start, end = REGIONS[region]
        if data_len > (end - start):
            raise FlashError(f"data too large for region {region}: {data_len} > {end - start}")
        return start, end

    def write(self, region: str, data: bytes):
        start, end = self._bounds(region, len(data))
        with open(self.path, "r+b") as f:
            f.seek(start)
            f.write(data.ljust(end - start, b"\xff"))

    def read(self, region: str) -> bytes:
        if region not in REGIONS:
            raise FlashError(f"unknown region: {region}")
        start, end = REGIONS[region]
        with open(self.path, "rb") as f:
            f.seek(start)
            return f.read(end - start).rstrip(b"\xff")

    def layout(self) -> dict:
        return dict(REGIONS)
