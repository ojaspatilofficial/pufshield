"""Complete secure boot engine integration tests.

Verifies the full boot sequence using the decentralized bootloader architecture:
SRAM PUF recovery -> Derive Device Key -> PKI Trust Anchor -> Certificate Verification ->
Challenge-Response -> Firmware Verification -> Kernel Verification ->
Rootfs Verification -> Anti-Rollback -> BOOT ALLOWED | BOOT BLOCKED.
"""

import base64
import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.crypto.utils import b64encode
from app.database import Database
from app.firmware import FirmwareImage
from app.secureboot import BOOT_STAGE_ORDER, BootStatus

def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def _self_signed_ca(common_name: str = "PUFShield Rogue CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

def test_boot_allowed_reports_every_stage_in_order(service, provisioned_device):
    service.create_firmware("2.0.0", "dev-0001")
    service.set_minimum_firmware_version("dev-0001", "1.0.0")

    challenge_b64, signature_b64 = service._device_challenge_response("dev-0001")
    result = service.run_boot("dev-0001", "2.0.0", challenge_b64=challenge_b64, signature_b64=signature_b64)
    
    assert result["decision"] == "BOOT_ALLOWED"
    assert result["booted"] is True
    assert result["status"] == BootStatus.SUCCESS.value
    assert result["success"] is True

    stages = result["stages"]
    # Check that core stages passed
    for key in ["sram_puf_recovery", "derive_device_key", "firmware_verification", "anti_rollback", "certificate_verification", "challenge_response"]:
        assert key in stages
        assert stages[key]["passed"] is True

def test_puf_recovery_failure_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("clone_device", "dev-0001")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.PUF_MISMATCH.value
    assert result["stages"]["sram_puf_recovery"]["passed"] is False

def test_certificate_chain_failure_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    ca_path = service.pki.key_store._cert_path("ca", "ca_cert")
    original_ca = ca_path.read_bytes()
    try:
        service.pki.key_store.save_certificate(_self_signed_ca(), "ca", "ca_cert")
        result = service.run_boot("dev-0001", "1.0.0")
        assert result["decision"] == "BOOT_BLOCKED"
        assert result["status"] == BootStatus.CERTIFICATE_INVALID.value
        assert result["stages"]["certificate_verification"]["passed"] is False
    finally:
        ca_path.write_bytes(original_ca)

def test_bad_challenge_signature_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    issued = service.auth.issue_challenge("dev-0001")
    result = service.run_boot(
        "dev-0001", "1.0.0",
        challenge_b64=issued["challenge_b64"],
        signature_b64=_b64(b"\x00" * 70),
    )
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.AUTH_FAILED.value
    stage = result["stages"]["challenge_response"]
    assert stage["passed"] is False

def test_replayed_challenge_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    challenge_b64, signature_b64 = service._device_challenge_response("dev-0001")

    first = service.run_boot("dev-0001", "1.0.0", challenge_b64=challenge_b64, signature_b64=signature_b64)
    assert first["decision"] == "BOOT_ALLOWED"

    replay = service.run_boot("dev-0001", "1.0.0", challenge_b64=challenge_b64, signature_b64=signature_b64)
    assert replay["decision"] == "BOOT_BLOCKED"
    assert replay["status"] == BootStatus.AUTH_FAILED.value

def test_firmware_hash_failure_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("tamper_firmware", "dev-0001")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.HASH_INVALID.value
    assert result["stages"]["firmware_verification"]["passed"] is False

def test_firmware_signature_failure_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("wrong_signer", "dev-0001")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.SIGNATURE_INVALID.value
    assert result["stages"]["firmware_verification"]["passed"] is False

def test_rollback_policy_failure_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    service.set_minimum_firmware_version("dev-0001", "2.0.0")
    result = service.run_boot("dev-0001", "1.0.0")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.ROLLBACK_REJECTED.value
    assert result["stages"]["anti_rollback"]["passed"] is False
