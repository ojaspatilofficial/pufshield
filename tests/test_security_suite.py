"""Complete security test suite: the eight requested threat scenarios.

Every scenario drives the REAL secure-boot / authentication pipeline
(no mocks, no hardcoded outcomes) and asserts that the genuine defence
produced the decision:

    1. genuine device + genuine firmware   -> BOOT ALLOWED
    2. genuine device + tampered firmware  -> BLOCKED (firmware_hash)
    3. clone device + copied certificate   -> BLOCKED (puf_recovery)
    4. replay authentication               -> BLOCKED (challenge_response)
    5. fake certificate                    -> BLOCKED (certificate_verification)
    6. signed old firmware (rollback)      -> BLOCKED (anti_rollback)
    7. wrong device PUF                    -> BLOCKED (puf_recovery)
    8. invalid firmware signature          -> BLOCKED (firmware_signature)

Where an attack mutates real data (payload bytes, signer key, stored
certificate, one-time challenge state) the test also asserts the mutation
is visible, so the outcome is proven to come from the pipeline and not
from a stubbed stage.
"""

import pytest

from app.auth.auth import AuthenticationError
from app.secureboot import BOOT_STAGE_ORDER, BootStatus


def _provision_firmware(service, device_id: str, versions: tuple[str, ...] = ("1.0.0",)) -> None:
    for version in versions:
        service.create_firmware(version, device_id)


def _details(result: dict, stage: str) -> dict:
    return result["stages"][stage]["details"]


def _first_failed_stage(result: dict):
    for key in BOOT_STAGE_ORDER:
        if result["stages"].get(key) and not result["stages"][key]["passed"]:
            return key
    return None


# -- 1. genuine device + genuine firmware -> BOOT ALLOWED -----------------------

def test_genuine_device_and_firmware_boot_is_allowed(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_boot("dev-0001")

    assert result["decision"] == "BOOT_ALLOWED"
    assert result["booted"] is True
    assert result["status"] == BootStatus.SUCCESS.value
    # every mandatory stage passed on the real pipeline
    assert all(result["stages"][stage]["passed"] for stage in BOOT_STAGE_ORDER)
    # the audit trail records the allowed boot
    assert service.list_boot_logs()[-1]["status"] == "success"


# -- 2. genuine device + tampered firmware -> BLOCKED ---------------------------

def test_tampered_firmware_is_blocked(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("tamper_firmware", "dev-0001")

    # the payload really changed: recomputed digest differs from the registered one
    hash_stage = _details(result, "firmware_hash")
    assert hash_stage["recomputed_sha256"] != hash_stage["registered_sha256"]
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["booted"] is False
    assert result["status"] == BootStatus.HASH_INVALID.value
    assert result["detection_point"] == "firmware_hash"
    assert result["expected_failure"] is True


# -- 3. clone device + copied certificate -> BLOCKED ----------------------------

def test_clone_with_copied_certificate_is_blocked(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")

    # the clone boots with the genuine device's certificate copied onto it
    copied_cert = service.pki.get_device_certificate("dev-0001")
    assert service.pki.verify_certificate_chain(copied_cert) is True  # cert itself is valid

    result = service.run_attack("clone_device", "dev-0001")

    # a different physical PUF fails to reproduce the enrolled credential,
    # so the copied certificate alone cannot authenticate the clone
    assert _details(result, "puf_recovery")["puf_match"] is False
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.PUF_MISMATCH.value
    assert result["detection_point"] == "puf_recovery"
    assert result["expected_failure"] is True
    assert service.pki.verify_certificate_chain(service.pki.get_device_certificate("dev-0001")) is True


# -- 4. replay authentication -> BLOCKED ----------------------------------------

def test_replay_authentication_is_blocked(service, provisioned_device):
    issued = service.issue_auth_challenge("dev-0001")
    challenge_b64 = issued["challenge_b64"]
    signature_b64 = service._sign_challenge_b64("dev-0001", challenge_b64)

    first = service.authenticate_device("dev-0001", challenge_b64, signature_b64)
    assert first["authenticated"] is True

    # replaying the same (challenge, signature) is rejected
    with pytest.raises(AuthenticationError) as exc:
        service.authenticate_device("dev-0001", challenge_b64, signature_b64)
    assert exc.value.reason == "challenge_invalid"
    assert "replay" in exc.value.message.lower()

    # a fresh challenge still authenticates: the block is replay-specific
    fresh_challenge, fresh_signature = service._device_challenge_response("dev-0001")
    assert service.authenticate_device("dev-0001", fresh_challenge, fresh_signature)["authenticated"] is True


def test_replay_boot_challenge_is_blocked(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("replay_challenge", "dev-0001")

    challenge_stage = _details(result, "challenge_response")
    assert challenge_stage["challenge_provided"] is True
    assert challenge_stage["challenge_verified"] is False
    assert "replay" in challenge_stage["challenge_reason"].lower()
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.AUTH_FAILED.value
    assert result["detection_point"] == "challenge_response"


# -- 5. fake certificate -> BLOCKED ---------------------------------------------

def test_fake_certificate_is_blocked(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    root_subject = service.pki.get_root_ca().subject

    result = service.run_attack("certificate_forgery", "dev-0001")

    # the stored certificate really was replaced by a rogue-CA credential
    stored = service.pki.get_device_certificate("dev-0001")
    assert stored.issuer != root_subject
    assert "Rogue CA" in stored.issuer.rfc4514_string()
    assert _details(result, "certificate_verification")["certificate_valid"] is False
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.CERTIFICATE_INVALID.value
    assert result["detection_point"] == "certificate_verification"


# -- 6. signed old firmware (rollback) -> BLOCKED -------------------------------

def test_signed_old_firmware_is_blocked(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    service.create_firmware("2.0.0", "dev-0001")
    service.set_minimum_firmware_version("dev-0001", "2.0.0")

    result = service.run_attack("firmware_rollback", "dev-0001", firmware_version="1.0.0")

    # the older image is legitimately signed (both signature layers pass) ...
    signature_stage = _details(result, "firmware_signature")
    assert signature_stage["signature_valid"] is True
    assert signature_stage["manufacturer_signature_valid"] is True
    # ... so blocking is purely the anti-rollback policy
    rollback_stage = _details(result, "anti_rollback")
    assert rollback_stage["image_version"] == "1.0.0"
    assert rollback_stage["minimum_version"] == "2.0.0"
    assert rollback_stage["version_allowed"] is False
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.ROLLBACK_REJECTED.value
    assert result["detection_point"] == "anti_rollback"


# -- 7. wrong device PUF -> BLOCKED ---------------------------------------------

def test_wrong_device_puf_is_blocked(service, provisioned_device):
    service.provision_device("dev-other")
    service.create_firmware("1.0.0", "dev-0001")

    # dev-0001's genuine assets, but dev-other's physical PUF
    enrollment, image, expected_sha256 = service._boot_assets("dev-0001", None)
    challenge_b64, signature_b64 = service._device_challenge_response("dev-0001")
    wrong_puf = service.puf_for("dev-other")

    result = service.boot.verify_boot(
        device_id="dev-0001",
        puf=wrong_puf,
        enrollment=enrollment,
        image=image,
        minimum_version=service.db.get_min_firmware_version("dev-0001"),
        expected_sha256=expected_sha256,
        challenge_b64=challenge_b64,
        signature_b64=signature_b64,
    ).to_dict()

    assert _details(result, "puf_recovery")["puf_match"] is False
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.PUF_MISMATCH.value
    assert _first_failed_stage(result) == "puf_recovery"

    # control: the genuine device PUF boots the same image successfully
    control = service.run_boot("dev-0001")
    assert control["decision"] == "BOOT_ALLOWED"
    assert control["status"] == BootStatus.SUCCESS.value


# -- 8. invalid firmware signature -> BLOCKED -----------------------------------

def test_invalid_firmware_signature_is_blocked(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_attack("wrong_signer", "dev-0001")

    assert _details(result, "firmware_signature")["signature_valid"] is False
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.SIGNATURE_INVALID.value
    assert result["detection_point"] == "firmware_signature"
    assert result["expected_failure"] is True


def test_tampered_signature_bytes_are_blocked(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    enrollment, image, expected_sha256 = service._boot_assets("dev-0001", None)
    challenge_b64, signature_b64 = service._device_challenge_response("dev-0001")

    # corrupt the device signature on an otherwise genuine image
    image.signature = bytes([b ^ 0xFF for b in image.signature[:8]]) + image.signature[8:]

    result = service.boot.verify_boot(
        device_id="dev-0001",
        puf=service.puf_for("dev-0001"),
        enrollment=enrollment,
        image=image,
        minimum_version=service.db.get_min_firmware_version("dev-0001"),
        expected_sha256=expected_sha256,
        challenge_b64=challenge_b64,
        signature_b64=signature_b64,
    ).to_dict()

    # the untouched payload still passes the hash stage, isolating the signature stage
    assert _details(result, "firmware_hash")["hash_valid"] is True
    assert _details(result, "firmware_signature")["signature_valid"] is False
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.SIGNATURE_INVALID.value
    assert _first_failed_stage(result) == "firmware_signature"


# -- integration: the whole threat model through the REST API -------------------

def test_full_threat_sweep_via_rest_api(client):
    from app.services import Service

    # 1. provision a genuine device + two signed firmware images
    assert client.post("/api/devices", json={"device_id": "dev-0001", "bit_size": 256}).status_code == 201
    for version in ("1.0.0", "2.0.0"):
        assert client.post("/api/firmware", json={"version": version, "device_id": "dev-0001"}).status_code == 201

    # genuine device + genuine firmware -> allowed
    boot = client.post("/api/boot", json={"device_id": "dev-0001"}).json()
    assert boot["decision"] == "BOOT_ALLOWED"
    assert boot["booted"] is True

    # 4. replay authentication -> 401 (before the forged-cert step, which persists)
    service = Service()
    challenge = client.post("/api/auth/challenge", json={"device_id": "dev-0001"}).json()
    signature = service._sign_challenge_b64("dev-0001", challenge["challenge_b64"])
    auth_ok = client.post(
        "/api/auth/authenticate",
        json={"device_id": "dev-0001", "challenge_b64": challenge["challenge_b64"], "signature_b64": signature},
    )
    assert auth_ok.status_code == 200 and auth_ok.json()["authenticated"] is True
    replay = client.post(
        "/api/auth/authenticate",
        json={"device_id": "dev-0001", "challenge_b64": challenge["challenge_b64"], "signature_b64": signature},
    )
    assert replay.status_code == 401
    assert replay.json()["detail"]
    assert replay.headers["X-Auth-Reason"] == "challenge_invalid"

    # 2/8. tampered payload + invalid signer -> blocked
    for attack, detection in (
        ("clone_device", "puf_recovery"),
        ("tamper_firmware", "firmware_hash"),
        ("wrong_signer", "firmware_signature"),
        ("replay_challenge", "challenge_response"),
    ):
        body = client.post(f"/api/attacks/{attack}", json={"device_id": "dev-0001"}).json()
        assert body["decision"] == "BOOT_BLOCKED", attack
        assert body["detection_point"] == detection, attack

    # 6. signed old firmware -> blocked by policy
    assert client.put("/api/devices/dev-0001/minimum-version", json={"version": "2.0.0"}).status_code == 200
    rollback = client.post(
        "/api/attacks/firmware_rollback",
        json={"device_id": "dev-0001", "firmware_version": "1.0.0"},
    ).json()
    assert rollback["decision"] == "BOOT_BLOCKED"
    assert rollback["detection_point"] == "anti_rollback"

    # 5. fake certificate -> blocked (must run last: it persists the forged cert)
    forgery = client.post("/api/attacks/certificate_forgery", json={"device_id": "dev-0001"}).json()
    assert forgery["decision"] == "BOOT_BLOCKED"
    assert forgery["detection_point"] == "certificate_verification"

    # audit trail: every blocked attempt was recorded with its real detection point
    attacks = {record["attack"]: record for record in client.get("/api/attacks/logs").json()}
    for attack in (
        "clone_device",
        "tamper_firmware",
        "wrong_signer",
        "replay_challenge",
        "firmware_rollback",
        "certificate_forgery",
    ):
        assert attack in attacks, attack
        assert attacks[attack]["result"] == "BOOT_BLOCKED", attack
        assert attacks[attack]["detection_point"]

    # dashboard aggregates: 1 allowed boot, 5 blocked boots (the replayed
    # challenge is logged as an auth failure, not a boot), 6 blocked attacks,
    # and 1 + 1 auth results from the API replay and the replay attack.
    stats = client.get("/api/dashboard/stats").json()
    assert stats["boots"]["allowed"] == 1
    assert stats["boots"]["blocked"] == 5
    assert stats["attacks"]["total"] == 6
    assert stats["attacks"]["blocked"] == 6
    assert stats["attacks"]["allowed"] == 0
    assert stats["auth"]["successes"] == 1
    assert stats["auth"]["failures"] == 2
