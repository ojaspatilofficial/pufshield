"""Tests for firmware signing and secure boot verification."""

from cryptography.hazmat.primitives.asymmetric import ec

from app.attacks import AttackSimulator
from app.firmware import FirmwareImage
from app.secureboot import BootStatus


def test_firmware_roundtrip():
    private_key = ec.generate_private_key(ec.SECP256R1())
    image = FirmwareImage(version="1.0.0", device_id="dev-1", payload=b"bootloader")
    signed = image.sign_manifest(private_key)
    bundle = signed.to_bundle()
    restored = FirmwareImage.from_bundle(bundle)
    assert restored.verify_manifest(private_key.public_key())
    assert restored.payload == b"bootloader"
    assert restored.version == "1.0.0"


def test_firmware_tamper_detected():
    private_key = ec.generate_private_key(ec.SECP256R1())
    signed = FirmwareImage(version="1.0.0", device_id="dev-1", payload=b"bootloader").sign_manifest(private_key)
    tampered = FirmwareImage(version="1.0.0", device_id="dev-1", payload=b"BOOTLOADER!", manufacturer_signature=signed.manufacturer_signature)
    assert not tampered.verify_manifest(private_key.public_key())


def test_bundle_digest_guard():
    private_key = ec.generate_private_key(ec.SECP256R1())
    signed = FirmwareImage(version="1.0.0", device_id="dev-1", payload=b"bootloader").sign_manifest(private_key)
    bundle = signed.to_bundle()
    bundle["payload_b64"] = __import__("app.crypto.utils", fromlist=["b64encode"]).b64encode(b"evil")
    try:
        FirmwareImage.from_bundle(bundle)
        raise AssertionError("expected ValueError for payload digest mismatch")
    except ValueError:
        pass


def test_secureboot_success(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_boot("dev-0001", "1.0.0")
    assert result["status"] == BootStatus.SUCCESS.value
    assert result["checks"]["puf_binding_match"] is True
    assert result["checks"]["puf_binding_match"] is True
    assert result["checks"]["firmware_authentic"] is True
    assert result["checks"]["firmware_authentic"] is True


def test_secureboot_fails_for_clone(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("clone_device", "dev-0001")
    assert result["status"] == BootStatus.PUF_MISMATCH.value
    assert result["expected_failure"] is True
    assert result["checks"]["puf_binding_match"] is False


def test_secureboot_fails_for_tampered_firmware(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("tamper_firmware", "dev-0001")
    assert result["status"] == BootStatus.SIGNATURE_INVALID.value
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["expected_failure"] is True
    assert result["stages"]["firmware_verification"]["passed"] is False


def test_secureboot_fails_for_wrong_signer(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("wrong_signer", "dev-0001")
    assert result["status"] == BootStatus.SIGNATURE_INVALID.value
    assert result["expected_failure"] is True
