import argparse
import tempfile

from attacks import downgrade_attack, mitm_channel, power_loss_sim, strip_signature
from bootloader.ab_partition import ABPartitionManager
from bootloader.rollback_store import RollbackStore
from bootloader.verifier import Verifier
from detector.dashboard import render
from detector.event_log import EventLog
from pipeline.image_builder import build_signed_image
from pipeline.pki import generate_ca_chain


def run_suite():
    log = EventLog()

    with tempfile.TemporaryDirectory() as tmp:
        chain = generate_ca_chain(tmp)
        store = RollbackStore(f"{tmp}/rollback.state")
        partitions = ABPartitionManager(f"{tmp}/partitions.state")
        verifier = Verifier.from_cert_chain(
            str(chain["oem_cert"]), str(chain["root_cert"]), store, partitions
        )

        v1 = build_signed_image(
            b"fw v1", version=1, rollback_index=1, private_key_path=str(chain["oem_key"])
        )
        v2 = build_signed_image(
            b"fw v2", version=2, rollback_index=2, private_key_path=str(chain["oem_key"])
        )
        verifier.flash_ab(v2)

        succeeded = downgrade_attack.run(verifier, v1)
        log.record(
            "downgrade_attack", 1, blocked=not succeeded, detail="replay of old signed image"
        )

        succeeded = strip_signature.run(verifier, v1)
        log.record("strip_signature", 1, blocked=not succeeded, detail="signature zeroed out")

        succeeded = mitm_channel.run(verifier, v1)
        log.record("mitm_channel", 1, blocked=not succeeded, detail="tampered in transit")

        succeeded = power_loss_sim.run(verifier, v1)
        log.record("power_loss_sim", 1, blocked=not succeeded, detail="truncated mid-write")

    render(log)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.parse_args()
    run_suite()
