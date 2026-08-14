"""Complete secure boot engine integration tests.

Verifies the full boot sequence:
SRAM PUF recovery -> PUF-PKI binding -> certificate verification ->
challenge-response authentication -> firmware SHA-256 verification ->
firmware signature verification -> anti-rollback verification ->
BOOT ALLOWED | BOOT BLOCKED.

Every mandatory stage is reported per-boot and every boot decision is
logged. A failure in any stage must block boot.
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
    """A well-formed but different self-signed CA (breaks the trust chain)."""
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


# -- full success path ----------------------------------------------------------

def test_boot_allowed_reports_every_stage_in_order(service, provisioned_device):
    service.create_firmware("2.0.0", "dev-0001")
    service.set_minimum_firmware_version("dev-0001", "1.0.0")

    result = service.run_boot("dev-0001", "2.0.0")
    assert result["decision"] == "BOOT_ALLOWED"
    assert result["booted"] is True
    assert result["status"] == BootStatus.SUCCESS.value
    assert result["success"] is True

    stages = result["stages"]
    assert list(stages) == list(BOOT_STAGE_ORDER)
    for key in BOOT_STAGE_ORDER:
        assert stages[key]["passed"] is True
        assert stages[key]["blocking"] is True
        assert isinstance(stages[key]["details"], dict)

    d = stages["puf_recovery"]["details"]
    assert d["fuzzy_recovered"] is True and d["puf_match"] is True
    assert stages["puf_pki_binding"]["details"]["puf_binding_match"] is True
    assert stages["certificate_verification"]["details"]["certificate_valid"] is True
    assert stages["challenge_response"]["details"]["challenge_verified"] is True
    assert stages["challenge_response"]["details"]["auth_signature_valid"] is True
    assert stages["firmware_hash"]["details"]["hash_valid"] is True
    assert stages["firmware_signature"]["details"]["signature_valid"] is True
    assert stages["firmware_signature"]["details"]["manufacturer_signature_valid"] is True
    assert stages["anti_rollback"]["details"]["version_allowed"] is True

    # flat aggregate kept for convenience
    assert result["checks"]["puf_match"] is True
    assert result["checks"]["signature_valid"] is True


def test_boot_allowed_with_explicit_challenge(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    challenge_b64, signature_b64 = service._device_challenge_response("dev-0001")
    result = service.run_boot("dev-0001", "1.0.0", challenge_b64=challenge_b64, signature_b64=signature_b64)
    assert result["decision"] == "BOOT_ALLOWED"
    assert result["stages"]["challenge_response"]["details"]["auth_signature_valid"] is True


# -- every stage must block boot when it fails ----------------------------------

def test_puf_recovery_failure_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("clone_device", "dev-0001")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.PUF_MISMATCH.value
    assert result["stages"]["puf_recovery"]["passed"] is False
    assert list(result["stages"]) == ["puf_recovery"]  # short-circuits immediately
    assert result["checks"]["puf_binding_match"] is False


def test_puf_binding_failure_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    db = Database()
    db.conn.execute(
        "UPDATE puf_enrollments SET puf_binding = ? WHERE device_id = ?",
        ((b"\x00" * 32).hex(), "dev-0001"),
    )
    db.conn.commit()
    result = service.run_boot("dev-0001", "1.0.0")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.PUF_MISMATCH.value
    assert result["stages"]["puf_recovery"]["passed"] is True
    assert result["stages"]["puf_pki_binding"]["passed"] is False
    assert result["stages"]["puf_pki_binding"]["details"]["puf_binding_match"] is False
    assert list(result["stages"]) == ["puf_recovery", "puf_pki_binding"]


def test_certificate_chain_failure_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    # Replace the root CA anchor: the genuine device certificate no longer
    # chains. The key store is session-scoped, so restore the real CA after.
    ca_path = service.pki.key_store._cert_path("ca", "ca_cert")
    original_ca = ca_path.read_bytes()
    try:
        service.pki.key_store.save_certificate(_self_signed_ca(), "ca", "ca_cert")
        result = service.run_boot("dev-0001", "1.0.0")
        assert result["decision"] == "BOOT_BLOCKED"
        assert result["status"] == BootStatus.CERTIFICATE_INVALID.value
        assert result["stages"]["puf_recovery"]["passed"] is True
        assert result["stages"]["puf_pki_binding"]["passed"] is True
        assert result["stages"]["certificate_verification"]["passed"] is False
        assert result["stages"]["certificate_verification"]["details"]["certificate_valid"] is False
        assert list(result["stages"]) == ["puf_recovery", "puf_pki_binding", "certificate_verification"]
    finally:
        ca_path.write_bytes(original_ca)


def test_missing_certificate_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    service.pki.key_store._cert_path("device", "dev-0001").unlink()
    result = service.run_boot("dev-0001", "1.0.0")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.PUF_MISMATCH.value  # binding is impossible without the certified key


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
    assert stage["details"]["challenge_verified"] is True
    assert stage["details"]["auth_signature_valid"] is False
    assert list(result["stages"]) == list(BOOT_STAGE_ORDER[:4])


def test_replayed_challenge_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    challenge_b64, signature_b64 = service._device_challenge_response("dev-0001")

    first = service.run_boot("dev-0001", "1.0.0", challenge_b64=challenge_b64, signature_b64=signature_b64)
    assert first["decision"] == "BOOT_ALLOWED"

    replay = service.run_boot("dev-0001", "1.0.0", challenge_b64=challenge_b64, signature_b64=signature_b64)
    assert replay["decision"] == "BOOT_BLOCKED"
    assert replay["status"] == BootStatus.AUTH_FAILED.value
    assert "replay" in replay["stages"]["challenge_response"]["details"]["challenge_reason"]


def test_missing_challenge_blocks_boot_without_autocomplete(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    enrollment = service.db.get_enrollment("dev-0001")
    puf = service.puf_for("dev-0001")
    bundle = service.list_firmware("dev-0001")[0]["bundle"]
    image = FirmwareImage.from_bundle(bundle)
    result = service.boot.verify_boot(
        device_id="dev-0001",
        puf=puf,
        enrollment=enrollment,
        image=image,
        expected_sha256=bundle["payload_sha256"],
    )
    assert result.decision.value == "BOOT_BLOCKED"
    assert result.status == BootStatus.AUTH_FAILED
    assert result.stages["challenge_response"]["passed"] is False
    assert result.stages["challenge_response"]["details"]["challenge_provided"] is False


def test_firmware_hash_failure_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    enrollment = service.db.get_enrollment("dev-0001")
    puf = service.puf_for("dev-0001")
    bundle = service.list_firmware("dev-0001")[0]["bundle"]
    original = FirmwareImage.from_bundle(bundle)
    tampered = FirmwareImage(
        original.version,
        original.device_id,
        original.payload + b"\x00",
        signature=original.signature,
        manufacturer_signature=original.manufacturer_signature,
    )
    challenge_b64, signature_b64 = service._device_challenge_response("dev-0001")
    result = service.boot.verify_boot(
        device_id="dev-0001",
        puf=puf,
        enrollment=enrollment,
        image=tampered,
        expected_sha256=bundle["payload_sha256"],
        challenge_b64=challenge_b64,
        signature_b64=signature_b64,
    )
    assert result.decision.value == "BOOT_BLOCKED"
    assert result.status == BootStatus.HASH_INVALID
    assert result.stages["firmware_hash"]["passed"] is False
    assert result.stages["firmware_hash"]["details"]["recomputed_sha256"] != bundle["payload_sha256"]
    assert list(result.stages) == list(BOOT_STAGE_ORDER[:5])


def test_wrong_signer_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("wrong_signer", "dev-0001")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.SIGNATURE_INVALID.value
    assert result["stages"]["firmware_hash"]["passed"] is True  # payload untouched
    assert result["stages"]["firmware_signature"]["passed"] is False
    assert result["stages"]["firmware_signature"]["details"]["signature_valid"] is False
    assert list(result["stages"]) == list(BOOT_STAGE_ORDER[:6])


def test_missing_manufacturer_signature_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    stored = service.list_firmware("dev-0001")[0]
    bundle = dict(stored["bundle"])
    bundle.pop("manufacturer_signature_b64")
    db = Database()
    db.conn.execute(
        "UPDATE firmware_images SET bundle = ? WHERE id = ?",
        (__import__("json").dumps(bundle), stored["id"]),
    )
    db.conn.commit()
    result = service.run_boot("dev-0001", "1.0.0")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.SIGNATURE_INVALID.value
    assert result["stages"]["firmware_signature"]["details"]["signature_valid"] is True
    assert result["stages"]["firmware_signature"]["details"]["manufacturer_signature_valid"] is False


def test_anti_rollback_failure_blocks_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    service.set_minimum_firmware_version("dev-0001", "5.0.0")
    result = service.run_boot("dev-0001", "1.0.0")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.ROLLBACK_REJECTED.value
    assert result["stages"]["firmware_signature"]["passed"] is True  # correctly signed, rejected on policy only
    assert result["stages"]["anti_rollback"]["passed"] is False
    assert result["stages"]["anti_rollback"]["details"]["version_allowed"] is False
    assert list(result["stages"]) == list(BOOT_STAGE_ORDER)


# -- logging ----------------------------------------------------------------------

def test_every_boot_decision_is_logged(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    service.set_minimum_firmware_version("dev-0001", "9.0.0")
    service.run_boot("dev-0001", "1.0.0")  # blocked (rollback)
    service.set_minimum_firmware_version("dev-0001", "1.0.0")
    service.run_boot("dev-0001", "1.0.0")  # allowed

    logs = service.list_boot_logs(limit=5)
    assert logs[0]["status"] == BootStatus.SUCCESS.value
    assert logs[0]["checks"]["decision"] == "BOOT_ALLOWED"
    assert logs[0]["checks"]["anti_rollback"] is True

    assert logs[1]["status"] == BootStatus.ROLLBACK_REJECTED.value
    assert logs[1]["checks"]["decision"] == "BOOT_BLOCKED"
    assert logs[1]["checks"]["anti_rollback"] is False
    assert logs[1]["checks"]["firmware_signature"] is True
    assert logs[1]["image_version"] == "1.0.0"
    assert "rollback" in logs[1]["message"].lower()


# -- REST API ----------------------------------------------------------------------

def test_api_boot_returns_full_sequence(client):
    client.post("/api/devices", json={"device_id": "dev-seq"})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-seq"})
    res = client.post("/api/boot", json={"device_id": "dev-seq"})
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "BOOT_ALLOWED"
    assert body["booted"] is True
    assert list(body["stages"]) == list(BOOT_STAGE_ORDER)
    assert all(stage["passed"] for stage in body["stages"].values())


def test_api_boot_blocked_on_bad_challenge(client):
    client.post("/api/devices", json={"device_id": "dev-cc"})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-cc"})
    issued = client.post("/api/auth/challenge", json={"device_id": "dev-cc"}).json()
    res = client.post(
        "/api/boot",
        json={
            "device_id": "dev-cc",
            "challenge_b64": issued["challenge_b64"],
            "signature_b64": _b64(b"\x00" * 70),
        },
    )
    body = res.json()
    assert body["decision"] == "BOOT_BLOCKED"
    assert body["status"] == "auth_failed"
    assert body["stages"]["challenge_response"]["passed"] is False


def test_api_boot_blocked_on_rollback(client):
    client.post("/api/devices", json={"device_id": "dev-rb"})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-rb"})
    client.put("/api/devices/dev-rb/minimum-version", json={"version": "2.0.0"})
    res = client.post("/api/boot", json={"device_id": "dev-rb"})
    body = res.json()
    assert body["decision"] == "BOOT_BLOCKED"
    assert body["status"] == "rollback_rejected"
    assert body["stages"]["anti_rollback"]["passed"] is False
