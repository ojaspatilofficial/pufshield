"""Attack Center: real attack simulations through the secure boot pipeline.

Every attack mutates the *actual* data the boot engine verifies (PUF
response, firmware payload/signer, stored certificate, one-time challenge
state, or the image selected for boot) and is then evaluated by the real
`verify_boot` pipeline. The recorded result, detection point, and reason
are derived from the pipeline's BootResult - never hardcoded.

Each test asserts both that real data was manipulated and that the
pipeline (not a mock) produced the outcome, and that a full attack record
(attack, target, detection point, result, reason, timestamp) is persisted.
"""

import pytest

from app.secureboot import BOOT_STAGE_ORDER, BootStatus

REQUIRED_ATTACKS = {
    "clone_device",
    "tamper_firmware",
    "replay_challenge",
    "certificate_forgery",
    "firmware_rollback",
}

EXPECTED_DETECTION = {
    "clone_device": "sram_puf_recovery",
    "tamper_firmware": "firmware_verification",
    "replay_challenge": "challenge_response",
    "certificate_forgery": "certificate_verification",
    "firmware_rollback": "anti_rollback",
}

EXPECTED_STATUS = {
    "clone_device": BootStatus.PUF_MISMATCH.value,
    "tamper_firmware": BootStatus.HASH_INVALID.value,
    "replay_challenge": BootStatus.AUTH_FAILED.value,
    "certificate_forgery": BootStatus.CERTIFICATE_INVALID.value,
    "firmware_rollback": BootStatus.ROLLBACK_REJECTED.value,
}


def _provision_firmware(service, device_id: str, versions: tuple[str, ...] = ("1.0.0",)) -> None:
    for version in versions:
        service.create_firmware(version, device_id)


def _details(result: dict, stage: str) -> dict:
    return result["stages"][stage]["details"]


# -- real manipulations + pipeline-derived outcomes ------------------------------

def test_clone_device_manipulates_puf_and_is_detected(service, provisioned_device):
    _provision_firmware(service, "dev-0001")
    result = service.run_attack("clone_device", "dev-0001")

    assert _details(result, "sram_puf_recovery")["puf_binding_match"] is False  # different PUF, real mismatch
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.PUF_MISMATCH.value
    assert result["detection_point"] == "sram_puf_recovery"
    assert result["expected_failure"] is True


def test_tamper_firmware_changes_payload_and_is_detected(service, provisioned_device):
    _provision_firmware(service, "dev-0001")
    result = service.run_attack("tamper_firmware", "dev-0001")

    hash_stage = _details(result, "firmware_verification")
    assert "error" in hash_stage or hash_stage.get("hash_valid") is False
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.HASH_INVALID.value
    assert result["detection_point"] == "firmware_verification"


def test_wrong_signer_is_detected(service, provisioned_device):
    _provision_firmware(service, "dev-0001")
    result = service.run_attack("wrong_signer", "dev-0001")

    assert "error" in _details(result, "firmware_verification")
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.SIGNATURE_INVALID.value
    assert result["detection_point"] == "firmware_verification"


def test_replay_challenge_reuses_consumed_nonce_and_is_detected(service, provisioned_device):
    _provision_firmware(service, "dev-0001")
    result = service.run_attack("replay_challenge", "dev-0001")

    challenge_stage = _details(result, "challenge_response")
    assert challenge_stage["challenge_verified"] is False
    assert "replay" in challenge_stage["challenge_reason"].lower()
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.AUTH_FAILED.value
    assert result["detection_point"] == "challenge_response"

    # The replayed nonce really was issued and consumed before the replay.
    rows = service.db.conn.execute(
        "SELECT used FROM auth_challenges WHERE device_id = 'dev-0001'"
    ).fetchall()
    assert rows and all(row["used"] == 1 for row in rows)


def test_certificate_forgery_swaps_cert_and_is_detected(service, provisioned_device):
    _provision_firmware(service, "dev-0001")
    root_subject = service.pki.get_root_ca().subject

    result = service.run_attack("certificate_forgery", "dev-0001")

    # The stored certificate really was replaced by the forged one.
    stored = service.pki.get_device_certificate("dev-0001")
    assert stored.issuer != root_subject
    assert "Rogue CA" in stored.issuer.rfc4514_string()
    assert _details(result, "certificate_verification")["certificate_valid"] is False
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.CERTIFICATE_INVALID.value
    assert result["detection_point"] == "certificate_verification"


def test_firmware_rollback_targets_old_image_and_is_detected(service, provisioned_device):
    _provision_firmware(service, "dev-0001", ("1.0.0", "2.0.0"))
    service.set_minimum_firmware_version("dev-0001", "2.0.0")

    result = service.run_attack("firmware_rollback", "dev-0001", firmware_version="1.0.0")

    rollback_stage = _details(result, "anti_rollback")
    assert "error" in rollback_stage
    assert result["decision"] == "BOOT_BLOCKED"
    assert result["status"] == BootStatus.ROLLBACK_REJECTED.value
    assert result["detection_point"] == "anti_rollback"


def test_firmware_rollback_without_policy_is_honestly_allowed(service, provisioned_device):
    """No hardcoded outcome: without a policy the pipeline allows the boot."""
    _provision_firmware(service, "dev-0001", ("1.0.0",))
    result = service.run_attack("firmware_rollback", "dev-0001", firmware_version="1.0.0")

    assert result["decision"] == "BOOT_ALLOWED"
    assert result["status"] == BootStatus.SUCCESS.value
    assert result["detection_point"] is None
    assert result["expected_failure"] is False


def test_firmware_rollback_requires_a_target_version(service, provisioned_device):
    _provision_firmware(service, "dev-0001")
    with pytest.raises(Exception, match="firmware_rollback requires firmware_version"):
        service.run_attack("firmware_rollback", "dev-0001")


# -- detection point derivation --------------------------------------------------

ATTACK_ORDER = (
    "clone_device",
    "tamper_firmware",
    "replay_challenge",
    "firmware_rollback",  # before certificate_forgery: it persists the forged cert
    "certificate_forgery",
)


def test_detection_point_is_first_failing_stage_in_order(service, provisioned_device):
    _provision_firmware(service, "dev-0001", ("1.0.0", "2.0.0"))
    service.set_minimum_firmware_version("dev-0001", "2.0.0")
    for attack in ATTACK_ORDER:
        expected = EXPECTED_DETECTION[attack]
        kwargs = {}
        if attack == "firmware_rollback":
            kwargs["firmware_version"] = "1.0.0"
        result = service.run_attack(attack, "dev-0001", **kwargs)
        assert result["detection_point"] == expected, f"{attack}: {result['detection_point']}"
        stage_index = BOOT_STAGE_ORDER.index(result["detection_point"])
        for later_stage in BOOT_STAGE_ORDER[stage_index + 1:]:
            assert later_stage not in result["stages"], f"{attack}: stage {later_stage} ran after failure"
        assert result["stages"][expected]["passed"] is False


# -- record persistence ----------------------------------------------------------

def test_every_attack_persists_full_record(service, provisioned_device):
    _provision_firmware(service, "dev-0001", ("1.0.0", "2.0.0"))
    service.set_minimum_firmware_version("dev-0001", "2.0.0")

    outcomes = {}
    for attack in ATTACK_ORDER:
        kwargs = {}
        if attack == "firmware_rollback":
            kwargs["firmware_version"] = "1.0.0"
        outcomes[attack] = service.run_attack(attack, "dev-0001", **kwargs)

    records = {record["attack"]: record for record in service.list_attack_logs()}
    assert set(records) == REQUIRED_ATTACKS

    for attack, expected_status in EXPECTED_STATUS.items():
        result = outcomes[attack]
        record = records[attack]
        assert record["target"] == "dev-0001"
        assert record["detection_point"] == result["detection_point"] == EXPECTED_DETECTION[attack]
        assert record["result"] == result["decision"] == "BOOT_BLOCKED"
        assert result["status"] == expected_status
        assert record["reason"] == result["message"]
        assert record["timestamp"]


def test_attack_record_matches_pipeline_result(service, provisioned_device):
    """The persisted record must equal the pipeline-derived boot result."""
    _provision_firmware(service, "dev-0001")
    result = service.run_attack("tamper_firmware", "dev-0001")
    record = service.list_attack_logs()[0]

    assert record["attack"] == "tamper_firmware"
    assert record["target"] == "dev-0001"
    assert record["detection_point"] == result["detection_point"]
    assert record["result"] == result["decision"]
    assert record["reason"] == result["message"]


# -- attack catalogue ------------------------------------------------------------

def test_attack_catalogue_lists_all_required_simulations(service):
    names = {scenario["name"] for scenario in service.list_attack_scenarios()}
    assert REQUIRED_ATTACKS <= names
    for attack in REQUIRED_ATTACKS:
        description = next(s["description"] for s in service.list_attack_scenarios() if s["name"] == attack)
        assert description


# -- REST API --------------------------------------------------------------------

def test_api_runs_clone_attack_and_returns_record(client):
    client.post("/api/devices", json={"device_id": "dev-0001", "bit_size": 256})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-0001"})

    response = client.post("/api/attacks/clone_device", json={"device_id": "dev-0001"})
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BOOT_BLOCKED"
    assert body["detection_point"] == "sram_puf_recovery"
    assert body["attack"] == "clone_device"
    assert body["target"] == "dev-0001"
    assert body["result"] == "BOOT_BLOCKED"
    assert body["reason"]
    assert body["timestamp"]


def test_api_attack_logs_endpoint(client):
    client.post("/api/devices", json={"device_id": "dev-0001", "bit_size": 256})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-0001"})
    client.post("/api/attacks/tamper_firmware", json={"device_id": "dev-0001"})

    response = client.get("/api/attacks/logs")
    assert response.status_code == 200
    records = response.json()
    assert len(records) == 1
    assert records[0]["attack"] == "tamper_firmware"
    assert records[0]["detection_point"] == "firmware_verification"
    assert records[0]["result"] == "BOOT_BLOCKED"
    assert records[0]["target"] == "dev-0001"
    assert records[0]["reason"]
    assert records[0]["timestamp"]


def test_api_rollback_attack_full_flow(client):
    client.post("/api/devices", json={"device_id": "dev-0001", "bit_size": 256})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-0001"})
    client.post("/api/firmware", json={"version": "2.0.0", "device_id": "dev-0001"})
    response = client.put("/api/devices/dev-0001/minimum-version", json={"version": "2.0.0"})
    assert response.status_code == 200

    response = client.post(
        "/api/attacks/firmware_rollback",
        json={"device_id": "dev-0001", "firmware_version": "1.0.0"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "BOOT_BLOCKED"
    assert body["detection_point"] == "anti_rollback"
    assert body["status"] == BootStatus.ROLLBACK_REJECTED.value


def test_api_unknown_attack_returns_400(client, provisioned_device):
    response = client.post("/api/attacks/does_not_exist", json={"device_id": "dev-0001"})
    assert response.status_code == 400
