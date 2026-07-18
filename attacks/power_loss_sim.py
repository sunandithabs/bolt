from bootloader.verifier import Verifier


def truncate_mid_write(image_bytes: bytes, fraction: float = 0.6) -> bytes:
    cutoff = int(len(image_bytes) * fraction)
    return image_bytes[:cutoff]


def run(verifier: Verifier, signed_image: bytes, fraction: float = 0.6) -> bool:
    partial = truncate_mid_write(signed_image, fraction)
    flash = verifier.flash_ab if verifier.partitions is not None else verifier.verify_and_boot
    try:
        flash(partial)
        return True
    except Exception:
        return False
