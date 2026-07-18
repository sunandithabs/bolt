import pytest

from bootloader.cert_chain import validate_chain
from bootloader.rollback_store import RollbackStore
from bootloader.verifier import Verifier
from pipeline.image_builder import build_signed_image
from pipeline.pki import generate_ca_chain


@pytest.fixture
def chain(tmp_path):
    return generate_ca_chain(str(tmp_path))


def test_valid_chain_resolves_oem_key(chain):
    pub = validate_chain(str(chain["oem_cert"]), str(chain["root_cert"]))
    assert pub is not None


def test_tampered_oem_cert_rejected(chain, tmp_path):
    tampered = tmp_path / "tampered_cert.pem"
    data = bytearray(chain["oem_cert"].read_bytes())
    data[-5] ^= 0xFF
    tampered.write_bytes(bytes(data))

    with pytest.raises(Exception):
        validate_chain(str(tampered), str(chain["root_cert"]))


def test_verifier_from_cert_chain_boots_valid_image(chain, tmp_path):
    store = RollbackStore(str(tmp_path / "rollback.state"))
    verifier = Verifier.from_cert_chain(
        str(chain["oem_cert"]), str(chain["root_cert"]), store
    )
    image = build_signed_image(
        b"fw v1", version=1, rollback_index=1, private_key_path=str(chain["oem_key"])
    )
    payload = verifier.verify_and_boot(image)
    assert payload == b"fw v1"


def test_image_signed_by_wrong_key_rejected_under_chain_trust(chain, tmp_path):
    other_chain = generate_ca_chain(str(tmp_path / "other"), oem_name="Rogue OEM")
    store = RollbackStore(str(tmp_path / "rollback.state"))
    verifier = Verifier.from_cert_chain(
        str(chain["oem_cert"]), str(chain["root_cert"]), store
    )
    image = build_signed_image(
        b"fw v1", version=1, rollback_index=1, private_key_path=str(other_chain["oem_key"])
    )
    with pytest.raises(Exception):
        verifier.verify_and_boot(image)
