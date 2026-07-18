import json
import struct

from bootloader.verifier import VerificationError, Verifier
from pipeline.image_builder import parse_image


def strip(image_bytes: bytes) -> bytes:
    header, payload = parse_image(image_bytes)
    header["sig"] = "00" * 256
    header_bytes = json.dumps(header).encode("utf-8")
    return struct.pack(">I", len(header_bytes)) + header_bytes + payload


def run(verifier: Verifier, signed_image: bytes) -> bool:
    stripped = strip(signed_image)
    try:
        verifier.verify_and_boot(stripped)
        return True
    except VerificationError:
        return False
