import struct
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from bootloader.ab_partition import ABPartitionManager
from bootloader.cert_chain import validate_chain
from bootloader.rollback_store import RollbackStore
from pipeline.image_builder import parse_image


class VerificationError(Exception):
    pass


class Verifier:
    def __init__(
        self,
        public_key_path: str,
        rollback_store: RollbackStore,
        partitions: Optional[ABPartitionManager] = None,
    ):
        public_key = serialization.load_pem_public_key(
            Path(public_key_path).read_bytes()
        )
        assert isinstance(public_key, RSAPublicKey)
        self.public_key = public_key
        self.rollback_store = rollback_store
        self.partitions = partitions

    @classmethod
    def from_cert_chain(
        cls,
        oem_cert_path: str,
        root_cert_path: str,
        rollback_store: RollbackStore,
        partitions: Optional[ABPartitionManager] = None,
    ) -> "Verifier":
        oem_pub = validate_chain(oem_cert_path, root_cert_path)
        instance = cls.__new__(cls)
        instance.public_key = oem_pub
        instance.rollback_store = rollback_store
        instance.partitions = partitions
        return instance

    def verify(self, image_bytes: bytes) -> dict:
        header, payload = parse_image(image_bytes)
        blob = struct.pack(">II", header["version"], header["rollback_index"]) + payload
        signature = bytes.fromhex(header["sig"])

        try:
            self.public_key.verify(
                signature,
                blob,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except InvalidSignature:
            raise VerificationError("signature invalid")

        if header["rollback_index"] < self.rollback_store.get():
            raise VerificationError("rollback index too low")

        return header

    def verify_and_boot(self, image_bytes: bytes) -> bytes:
        header = self.verify(image_bytes)
        _, payload = parse_image(image_bytes)
        self.rollback_store.commit(header["rollback_index"])
        return payload

    def flash_ab(self, image_bytes: bytes) -> bytes:
        if self.partitions is None:
            raise VerificationError("no partition manager configured")

        header = self.verify(image_bytes)
        _, payload = parse_image(image_bytes)
        slot = self.partitions.stage(image_bytes)
        self.rollback_store.commit(header["rollback_index"])
        self.partitions.commit(slot)
        return payload
