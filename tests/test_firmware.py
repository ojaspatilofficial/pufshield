"""Tests for firmware management: registration, hashing, manufacturer signing, verification, tamper detection."""

import base64
import json

from cryptography.hazmat.primitives.asymmetric import ec

from app.crypto.utils import sha256
from app.database import Database
from app.firmware import FirmwareImage, ensure_manufacturer_key, load_manufacturer_public_key
from app.secureboot import BootStatus


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# -- manufacturer key pair ----------------------------------------------------

def test_manufacturer_key_pair_generated_once(service):
    first = ensure_manufacturer_key(service.pki.key_store)
    second = ensure_manufacturer_key(service.pki.key_store)
    assert first.public_key().public_numbers() == second.public_key().public_numbers()
    public = load_manufacturer_public_key(service.pki.key_store)
    assert public.public_numbers() == first.public_key().public_numbers()


def test_manufacturer_public_key_endpoint_is_public_only(client):
    res = client.get("/api/manufacturer/key")
    assert res.status_code == 200
    body = res.json()
    assert body["algorithm"] == "ECDSA"
    assert body["curve"] == "secp256r1"
    assert "PRIVATE KEY" not in body["public_key_b64"]
    der = base64.b64decode(body["public_key_b64"])
    assert der.startswith(b"\x30")  # DER SEQUENCE (SubjectPublicKeyInfo)


# -- registration + hashing ----------------------------------------------------

def test_firmware_registered_with_version_and_hash(service, provisioned_device):
    payload = b"\x00\x01 binary firmware v1 \xff\xfe"
    bundle = service.create_firmware("1.0.0", "dev-0001", payload)
    assert bundle["payload_sha256"] == sha256(payload).hex()
    assert "signature_b64" in bundle
    assert "manufacturer_signature_b64" in bundle
    assert "PRIVATE KEY" not in json.dumps(bundle)
    stored = service.list_firmware("dev-0001")
    assert any(i["bundle"]["version"] == "1.0.0" for i in stored)


# -- verification ----------------------------------------------------------------

def test_verify_firmware_valid(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.verify_firmware("dev-0001", "1.0.0")
    assert result["hash_valid"] is True
    assert result["device_signature_valid"] is True
    assert result["manufacturer_signature_valid"] is True
    assert result["verified"] is True


def test_verify_firmware_detects_tampered_payload(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    stored = service.list_firmware("dev-0001")[0]
    bundle = dict(stored["bundle"])
    bundle["payload_b64"] = _b64(b"EVIL PAYLOAD")
    db = Database()
    db.conn.execute(
        "UPDATE firmware_images SET bundle = ? WHERE id = ?",
        (json.dumps(bundle), stored["id"]),
    )
    db.conn.commit()
    result = service.verify_firmware("dev-0001", "1.0.0")
    assert result["hash_valid"] is False
    assert result["verified"] is False


# -- manifest signature primitives ----------------------------------------------

def test_firmware_manifest_roundtrip():
    key = ec.generate_private_key(ec.SECP256R1())
    image = FirmwareImage("2.0.0", "dev-x", b"payload").sign_manifest(key)
    assert image.verify_manifest(key.public_key())
    assert image.manifest_bytes() == FirmwareImage("2.0.0", "dev-x", b"payload").manifest_bytes()


def test_firmware_modified_payload_detected_by_manifest():
    key = ec.generate_private_key(ec.SECP256R1())
    image = FirmwareImage("2.0.0", "dev-x", b"ORIGINAL").sign_manifest(key)
    tampered = FirmwareImage(
        "2.0.0",
        "dev-x",
        b"MODIFIED",
        manufacturer_signature=image.manufacturer_signature,
    )
    assert tampered.verify_manifest(key.public_key()) is False
    assert tampered.payload_digest != image.payload_digest


def test_firmware_manifest_rejects_wrong_public_key():
    signer = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    image = FirmwareImage("1.0.0", "dev-x", b"payload").sign_manifest(signer)
    assert not image.verify_manifest(other.public_key())


def test_unsigned_image_fails_manifest_verification():
    key = ec.generate_private_key(ec.SECP256R1())
    assert FirmwareImage("1.0.0", "dev-x", b"payload").verify_manifest(key.public_key()) is False


# -- secure boot integration ------------------------------------------------------

def test_secureboot_success_checks_manufacturer_signature(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_boot("dev-0001", "1.0.0")
    assert result["status"] == BootStatus.SUCCESS.value
    assert result["checks"]["signature_valid"] is True
    assert result["checks"]["manufacturer_signature_valid"] is True


def test_boot_rejects_firmware_without_manufacturer_signature(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    stored = service.list_firmware("dev-0001")[0]
    bundle = dict(stored["bundle"])
    bundle.pop("manufacturer_signature_b64")
    db = Database()
    db.conn.execute(
        "UPDATE firmware_images SET bundle = ? WHERE id = ?",
        (json.dumps(bundle), stored["id"]),
    )
    db.conn.commit()
    result = service.run_boot("dev-0001", "1.0.0")
    assert result["status"] == BootStatus.SIGNATURE_INVALID.value
    assert result["checks"]["manufacturer_signature_valid"] is False


def test_tamper_attack_detected_by_boot(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("tamper_firmware", "dev-0001")
    assert result["status"] == BootStatus.HASH_INVALID.value
    assert result["expected_failure"] is True
    assert result["decision"] == "BOOT_BLOCKED"


# -- REST API -----------------------------------------------------------------------

def test_firmware_api_binary_registration_and_verify(client):
    client.post("/api/devices", json={"device_id": "dev-fw-api"})
    payload = b"\x1f\x8b binary firmware payload \x00\xff"
    res = client.post(
        "/api/firmware",
        json={"version": "3.1.4", "device_id": "dev-fw-api", "payload_b64": _b64(payload)},
    )
    assert res.status_code == 201
    body = res.json()
    assert body["payload_sha256"] == sha256(payload).hex()
    assert "manufacturer_signature_b64" in body
    assert "PRIVATE KEY" not in res.text

    vres = client.post(
        "/api/firmware/verify",
        json={"device_id": "dev-fw-api", "firmware_version": "3.1.4"},
    )
    assert vres.status_code == 200
    assert vres.json()["verified"] is True
    assert vres.json()["manufacturer_signature_valid"] is True


def test_firmware_api_detects_tampered_binary(client):
    client.post("/api/devices", json={"device_id": "dev-fw-tamper"})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-fw-tamper"})

    stored = Database().list_firmware("dev-fw-tamper")[0]
    bundle = dict(stored["bundle"])
    bundle["payload_b64"] = _b64(b"pwned binary")
    db = Database()
    db.conn.execute(
        "UPDATE firmware_images SET bundle = ? WHERE id = ?",
        (json.dumps(bundle), stored["id"]),
    )
    db.conn.commit()

    vres = client.post(
        "/api/firmware/verify",
        json={"device_id": "dev-fw-tamper", "firmware_version": "1.0.0"},
    )
    assert vres.status_code == 200
    assert vres.json()["hash_valid"] is False
    assert vres.json()["verified"] is False


def test_firmware_api_verify_unknown_version(client):
    client.post("/api/devices", json={"device_id": "dev-fw-miss"})
    res = client.post(
        "/api/firmware/verify",
        json={"device_id": "dev-fw-miss", "firmware_version": "9.9.9"},
    )
    assert res.status_code == 400
