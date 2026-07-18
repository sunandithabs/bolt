from bootloader.verifier import VerificationError, Verifier


def tamper_in_transit(image_bytes: bytes) -> bytes:
    tampered = bytearray(image_bytes)
    tampered[-1] ^= 0xFF
    return bytes(tampered)


def run(verifier: Verifier, signed_image: bytes) -> bool:
    delivered = tamper_in_transit(signed_image)
    try:
        verifier.verify_and_boot(delivered)
        return True
    except VerificationError:
        return False
