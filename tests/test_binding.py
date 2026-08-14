"""Clone-detection tests: the PUF identity is bound to the device's certified public key.

The binding couples the PUF-derived secret with the device public key:
only the physical PUF can recover the secret, and only the certified key
reproduces the registered binding. A certificate or public key copied
onto different hardware must fail.
"""

from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto.utils import serialize_public_key
from app.puf import PUFEnrollment, SRAMPUF


def _pub(private_key) -> bytes:
    """DER SubjectPublicKeyInfo for a private key."""
    return serialize_public_key(private_key.public_key())


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def test_binding_present_and_matches_for_same_device(service, provisioned_device):
    enrollment = service.db.get_enrollment("dev-0001")
    assert enrollment.puf_binding is not None
    result = service.test_puf("dev-0001", num_captures=5)
    assert result["puf_binding_match"] is True
    assert result["matched"] is True


def test_binding_requires_the_registered_key(service, provisioned_device):
    """Same physical PUF but a different public key must fail the binding."""
    enrollment = service.db.get_enrollment("dev-0001")
    puf = service.puf_for("dev-0001")
    result = PUFEnrollment.test(puf, enrollment, num_captures=5, device_public_key=_pub(_key()))
    assert result["puf_binding_match"] is False
    assert result["matched"] is False


def test_binding_rejects_copied_certificate_on_other_hardware(service, provisioned_device):
    """The core clone attack: the real certificate copied onto different hardware."""
    enrollment = service.db.get_enrollment("dev-0001")
    cert = service.pki.get_device_certificate("dev-0001")
    clone = SRAMPUF("dev-0001", bit_size=256, seed=b"impostor-seed", noise_rate=0.01)
    result = PUFEnrollment.test(clone, enrollment, num_captures=5, device_public_key=serialize_public_key(cert.public_key()))
    assert result["puf_binding_match"] is False
    assert result["matched"] is False


def test_binding_optional_when_no_key_supplied():
    puf = SRAMPUF("dev-opt", bit_size=256, seed=b"opt-seed")
    enrollment = PUFEnrollment.enroll(puf, num_captures=10)
    assert enrollment.puf_binding is None
    result = PUFEnrollment.test(puf, enrollment, num_captures=10)
    assert result["puf_binding_match"] is None
    assert result["matched"] is True


def test_enroll_with_foreign_key_mismatches_and_registered_key_matches():
    puf = SRAMPUF("dev-bind", bit_size=256, seed=b"bind-seed", noise_rate=0.01)
    registered = _key()
    foreign = _key()
    enrollment = PUFEnrollment.enroll(puf, num_captures=20, device_public_key=_pub(registered))
    assert enrollment.puf_binding is not None

    result = PUFEnrollment.test(puf, enrollment, num_captures=10, device_public_key=_pub(foreign))
    assert result["puf_binding_match"] is False
    assert result["matched"] is False

    result = PUFEnrollment.test(puf, enrollment, num_captures=10, device_public_key=_pub(registered))
    assert result["puf_binding_match"] is True
    assert result["matched"] is True


def test_binding_survives_database_roundtrip(service, provisioned_device):
    enrollment = service.db.get_enrollment("dev-0001")
    assert enrollment.puf_binding is not None
    restored = service.db.get_enrollment("dev-0001")
    assert restored.puf_binding == enrollment.puf_binding


def test_clone_attack_rejected_by_binding_at_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("clone_device", "dev-0001")
    assert result["status"] == "puf_mismatch"
    assert result["expected_failure"] is True
    assert result["checks"]["puf_binding_match"] is False
