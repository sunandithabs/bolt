from bootloader.verifier import VerificationError, Verifier


def run(verifier: Verifier, old_signed_image: bytes) -> bool:
    try:
        verifier.verify_and_boot(old_signed_image)
        return True
    except VerificationError:
        return False
