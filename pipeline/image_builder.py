import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey


def _signing_blob(version: int, rollback_index: int, payload: bytes) -> bytes:
    return struct.pack(">II", version, rollback_index) + payload


def build_signed_image(
    payload: bytes,
    version: int,
    rollback_index: int,
    private_key_path: str,
) -> bytes:
    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(), password=None
    )
    assert isinstance(private_key, RSAPrivateKey)

    blob = _signing_blob(version, rollback_index, payload)
    signature = private_key.sign(
        blob,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    header = json.dumps(
        {
            "version": version,
            "rollback_index": rollback_index,
            "sig": signature.hex(),
        }
    ).encode("utf-8")

    return struct.pack(">I", len(header)) + header + payload


def parse_image(image_bytes: bytes):
    header_len = struct.unpack(">I", image_bytes[:4])[0]
    header_bytes = image_bytes[4 : 4 + header_len]
    payload = image_bytes[4 + header_len :]
    header = json.loads(header_bytes.decode("utf-8"))
    return header, payload


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 5:
        print("Usage: image_builder.py <payload_file> <version> <rollback_index> <private_key.pem>")
        sys.exit(1)

    payload_file, version, rollback_index, key_path = sys.argv[1:5]
    payload = Path(payload_file).read_bytes()
    image = build_signed_image(payload, int(version), int(rollback_index), key_path)

    out_path = Path(payload_file).with_suffix(".fwimg")
    out_path.write_bytes(image)
    print(f"Signed image written: {out_path} ({len(image)} bytes)")
