"""SQLite persistence + retrieval tests for every backend table.

Covers devices, PUF enrollments, certificates, firmware, boot events,
authentication events, security events, and attacks - plus the rule that
every authentication, secure boot, and attack attempt produces a
timestamped security event, and the REST endpoints that read them back.
"""

import base64

import pytest

from app.auth.auth import AuthenticationError
from app.auth.challenge import sign_challenge
from app.crypto.utils import b64decode, b64encode
from app.database.db import Database
from app.services import DeviceNotFound, Service

TABLES = (
    "devices",
    "puf_enrollments",
    "certificates",
    "firmware_images",
    "boot_logs",
    "authentication_events",
    "security_events",
    "attack_logs",
)

EXPECTED_SCHEMA_COLUMNS = {
    "devices": {"device_id", "bit_size", "puf_seed", "min_firmware_version", "created_at"},
    "puf_enrollments": {"device_id", "stable_bit_count", "reference", "credential_tag", "reliability", "fuzzy_helper"},
    "certificates": {"device_id", "subject", "issuer", "serial_number", "pem", "not_valid_before", "not_valid_after"},
    "firmware_images": {"version", "device_id", "bundle"},
    "boot_logs": {"device_id", "image_version", "status", "message", "checks"},
    "authentication_events": {"device_id", "success", "reason", "checks", "created_at"},
    "security_events": {"event_type", "device_id", "severity", "result", "summary", "created_at"},
    "attack_logs": {"attack", "target", "detection_point", "result", "reason", "created_at"},
}


def _sign_b64(service: Service, device_id: str, challenge_b64: str) -> str:
    return service._sign_challenge_b64(device_id, challenge_b64)


def _auth_success(service: Service, device_id: str) -> None:
    challenge = service.issue_auth_challenge(device_id)
    service.authenticate_device(device_id, challenge["challenge_b64"], _sign_b64(service, device_id, challenge["challenge_b64"]))


# -- schema ---------------------------------------------------------------------

def test_all_required_tables_exist(service):
    tables = {row[0] for row in service.db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()}
    assert set(TABLES) <= tables


def test_required_columns_exist(service):
    for table, expected in EXPECTED_SCHEMA_COLUMNS.items():
        columns = {row[1] for row in service.db.conn.execute(f"PRAGMA table_info({table})").fetchall()}
        assert expected <= columns, table


def test_database_supports_threaded_requests(service):
    import threading

    results = []

    def worker() -> None:
        service.db.log_security_event(
            event_type="boot",
            device_id="dev-thread",
            severity="info",
            result="ok",
            summary="thread-safe access",
        )
        rows = service.db.list_security_events(limit=1)
        results.append(rows[0]["device_id"])

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()

    assert results == ["dev-thread"]


# -- devices --------------------------------------------------------------------

def test_device_persistence_roundtrip(service):
    service.provision_device("dev-db-1", bit_size=256)
    row = service.db.get_device("dev-db-1")
    assert row is not None
    assert row["device_id"] == "dev-db-1"
    assert row["bit_size"] == 256
    assert len(bytes.fromhex(row["puf_seed"])) == 32
    assert row["created_at"]

    service.db.set_min_firmware_version("dev-db-1", "2.1.0")
    assert service.db.get_min_firmware_version("dev-db-1") == "2.1.0"

    assert {d["device_id"] for d in service.db.list_devices()} == {"dev-db-1"}

    fresh = Database()
    try:
        reloaded = fresh.get_device("dev-db-1")
        assert reloaded["min_firmware_version"] == "2.1.0"
    finally:
        fresh.close()


def test_device_unique(service):
    service.provision_device("dev-db-uniq")
    service.provision_device("dev-db-other")
    assert len(service.db.list_devices()) == 2


def test_delete_device_cascades_state_and_keeps_audit(service):
    """Deleting a device removes its operational state but preserves audit logs."""
    service.provision_device("dev-del")
    service.create_firmware("1.0.0", "dev-del")
    service.run_boot("dev-del")  # produces a boot log + security event

    key_path = service.pki.key_store._key_path("device", "dev-del")
    cert_path = service.pki.key_store._cert_path("device", "dev-del")
    assert cert_path.exists()

    result = service.delete_device("dev-del")
    assert result == {"device_id": "dev-del", "deleted": True}

    # Operational state is gone...
    assert service.db.get_device("dev-del") is None
    assert service.db.get_enrollment("dev-del") is None
    assert service.db.get_certificate("dev-del") is None
    assert service.db.list_firmware("dev-del") == []
    assert service.pki.key_store.load_private_key("device", "dev-del") is None
    assert service.pki.key_store.load_certificate("device", "dev-del") is None
    assert not cert_path.exists()
    assert service._pufs.get("dev-del") is None

    # ...but audit history survives for forensics.
    assert service.list_boot_logs()
    assert service.list_security_events()

    # The same id can be re-provisioned and boots again.
    service.provision_device("dev-del")
    service.create_firmware("1.0.0", "dev-del")
    assert service.run_boot("dev-del")["decision"] == "BOOT_ALLOWED"


def test_delete_missing_device_raises(service):
    with pytest.raises(DeviceNotFound):
        service.delete_device("dev-missing")


def test_delete_device_ignores_other_devices(service):
    service.provision_device("dev-keep")
    service.provision_device("dev-drop")
    service.delete_device("dev-drop")
    assert service.db.get_device("dev-keep") is not None
    assert service.db.get_device("dev-drop") is None


# -- PUF enrollment -------------------------------------------------------------

def test_puf_enrollment_persistence_roundtrip(service):
    service.provision_device("dev-puf-db")
    enrollment = service.db.get_enrollment("dev-puf-db")
    assert enrollment is not None
    assert enrollment.device_id == "dev-puf-db"
    assert enrollment.bit_size == 256
    assert enrollment.reliability > 0.9
    assert enrollment.fuzzy_helper is not None

    persisted = service.db.get_enrollment("dev-puf-db")
    assert persisted.reference == enrollment.reference
    assert persisted.credential_tag == enrollment.credential_tag
    assert persisted.stability_mask == enrollment.stability_mask
    assert persisted.fuzzy_helper.to_dict() == enrollment.fuzzy_helper.to_dict()

    assert service.db.list_enrollments()[0].device_id == "dev-puf-db"


# -- certificates ---------------------------------------------------------------

def test_certificate_persistence(service):
    provisioned = service.provision_device("dev-cert-db")
    row = service.db.get_certificate("dev-cert-db")
    assert row is not None
    assert row["device_id"] == "dev-cert-db"
    assert str(provisioned["certificate_serial"]) == row["serial_number"]
    assert row["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert "PUFShield Root CA" in row["issuer"]
    assert len(row["public_key_fingerprint"]) == 64
    assert row["not_valid_before"] <= row["not_valid_after"]

    assert {c["device_id"] for c in service.db.list_certificates()} == {"dev-cert-db"}


def test_certificate_refreshed_on_read(service):
    service.provision_device("dev-cert-refresh")
    info = service.get_device_certificate_info("dev-cert-refresh")
    stored = service.db.get_certificate("dev-cert-refresh")
    assert stored["pem"] == info["pem"]
    assert stored["serial_number"] == info["serial_number"]


# -- firmware -------------------------------------------------------------------

def test_firmware_persistence_roundtrip(service):
    service.provision_device("dev-fw-db")
    service.provision_device("dev-fw-other")
    service.create_firmware("1.0.0", "dev-fw-db")
    service.create_firmware("2.0.0", "dev-fw-db")
    service.create_firmware("1.0.0", "dev-fw-other")

    images = service.db.list_firmware("dev-fw-db")
    assert {i["version"] for i in images} == {"1.0.0", "2.0.0"}
    assert images[0]["bundle"]["signature_b64"]
    assert images[0]["bundle"]["manufacturer_signature_b64"]

    all_images = service.db.list_firmware()
    assert len(all_images) == 3
    assert all("bundle" in i and "version" in i for i in all_images)


# -- boot events ----------------------------------------------------------------

def test_boot_events_persisted(service):
    service.provision_device("dev-boot-db")
    service.create_firmware("1.0.0", "dev-boot-db")
    service.run_boot("dev-boot-db", "1.0.0")

    logs = service.db.list_boot_logs()
    assert len(logs) == 1
    assert logs[0]["device_id"] == "dev-boot-db"
    assert logs[0]["status"] == "success"
    assert logs[0]["checks"]["decision"] == "BOOT_ALLOWED"

    fresh = Database()
    try:
        assert len(fresh.list_boot_logs()) == 1
    finally:
        fresh.close()


# -- authentication events ------------------------------------------------------

def test_authentication_events_persisted(service):
    service.provision_device("dev-auth-db")
    _auth_success(service, "dev-auth-db")

    events = service.db.list_authentication_events()
    assert len(events) == 1
    assert events[0]["device_id"] == "dev-auth-db"
    assert events[0]["success"] is True
    assert events[0]["reason"] == "ok"
    assert events[0]["checks"]["signature_valid"] is True
    assert events[0]["timestamp"]

    challenge = service.issue_auth_challenge("dev-auth-db")
    try:
        service.authenticate_device("dev-auth-db", challenge["challenge_b64"], b64encode(b"\x00" * 70))
    except AuthenticationError:
        pass
    events = service.db.list_authentication_events()
    assert len(events) == 2
    assert events[0]["success"] is False
    assert events[0]["reason"] == "signature_invalid"

    counts = service.db.count_authentication_events_by_result()
    assert counts == {"successes": 1, "failures": 1}


def test_authentication_events_filters(service):
    service.provision_device("dev-auth-f1")
    service.provision_device("dev-auth-f2")
    _auth_success(service, "dev-auth-f1")
    _auth_success(service, "dev-auth-f2")

    filtered = service.db.list_authentication_events(device_id="dev-auth-f1")
    assert len(filtered) == 1 and filtered[0]["device_id"] == "dev-auth-f1"


# -- attacks --------------------------------------------------------------------

def test_attack_logs_persisted(service):
    service.provision_device("dev-att-db")
    service.create_firmware("1.0.0", "dev-att-db")
    result = service.run_attack("clone_device", "dev-att-db", "1.0.0")
    assert result["decision"] == "BOOT_BLOCKED"

    logs = service.db.list_attack_logs()
    assert len(logs) == 1
    assert logs[0]["attack"] == "clone_device"
    assert logs[0]["target"] == "dev-att-db"
    assert logs[0]["result"] == "BOOT_BLOCKED"
    assert logs[0]["detection_point"] == "sram_puf_recovery"
    assert logs[0]["timestamp"]

    counts = service.db.count_attack_logs_by_result()
    assert counts["BOOT_BLOCKED"] == 1


# -- security events ------------------------------------------------------------

def test_every_boot_attempt_writes_timestamped_security_event(service):
    service.provision_device("dev-ev-boot")
    service.create_firmware("1.0.0", "dev-ev-boot")
    service.run_boot("dev-ev-boot", "1.0.0")
    service.set_minimum_firmware_version("dev-ev-boot", "9.0.0")
    service.run_boot("dev-ev-boot", "1.0.0")  # blocked

    events = service.db.list_security_events()
    assert len(events) == 2
    assert {e["result"] for e in events} == {"success", "rollback_rejected"}
    assert all(e["event_type"] == "boot" for e in events)
    assert all(e["device_id"] == "dev-ev-boot" for e in events)
    assert all(e["timestamp"] for e in events)
    severities = {e["severity"] for e in events}
    assert "info" in severities and "critical" in severities
    assert all("checks" in e for e in events)


def test_every_auth_attempt_writes_timestamped_security_event(service):
    service.provision_device("dev-ev-auth")
    _auth_success(service, "dev-ev-auth")

    challenge = service.issue_auth_challenge("dev-ev-auth")
    try:
        service.authenticate_device("dev-ev-auth", challenge["challenge_b64"], b64encode(b"\x00" * 70))
    except AuthenticationError:
        pass

    events = [e for e in service.db.list_security_events() if e["event_type"] == "auth"]
    assert len(events) == 2
    results = {e["result"] for e in events}
    assert results == {"success", "failed"}
    assert all(e["timestamp"] for e in events)
    assert any(e["severity"] == "info" for e in events)
    assert any(e["severity"] == "high" for e in events)


def test_every_attack_attempt_writes_timestamped_security_event(service):
    service.provision_device("dev-ev-att")
    service.create_firmware("1.0.0", "dev-ev-att")
    service.run_attack("tamper_firmware", "dev-ev-att", "1.0.0")

    events = service.db.list_security_events()
    assert len(events) == 2  # the attack event + the boot it ran through
    attack_events = [e for e in events if e["event_type"] == "attack"]
    boot_events = [e for e in events if e["event_type"] == "boot"]
    assert len(attack_events) == 1
    assert len(boot_events) == 1
    assert attack_events[0]["attack"] == "tamper_firmware"
    assert attack_events[0]["detection_point"] == "firmware_verification"
    assert attack_events[0]["severity"] == "critical"
    assert boot_events[0]["severity"] == "critical"
    assert all(e["timestamp"] for e in events)


def test_security_event_retrieval_filters(service):
    service.provision_device("dev-sr-1")
    service.provision_device("dev-sr-2")
    service.create_firmware("1.0.0", "dev-sr-1")
    service.run_boot("dev-sr-1", "1.0.0")
    _auth_success(service, "dev-sr-2")

    boots = service.db.list_security_events(event_type="boot")
    auths = service.db.list_security_events(event_type="auth")
    by_device = service.db.list_security_events(device_id="dev-sr-2")
    assert len(boots) == 1 and boots[0]["event_type"] == "boot"
    assert len(auths) == 1 and auths[0]["event_type"] == "auth"
    assert len(by_device) == 1 and by_device[0]["device_id"] == "dev-sr-2"

    assert service.db.count_security_events_by_severity().get("info", 0) == 2


def test_security_event_ordering_newest_first(service):
    service.provision_device("dev-ord")
    service.create_firmware("1.0.0", "dev-ord")
    service.run_boot("dev-ord", "1.0.0")
    _auth_success(service, "dev-ord")
    events = service.db.list_security_events()
    assert events[0]["event_type"] == "auth"
    assert events[-1]["event_type"] == "boot"


# -- REST API retrieval ---------------------------------------------------------

def test_api_retrieves_security_logs(client):
    client.post("/api/devices", json={"device_id": "dev-log-api"})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-log-api"})
    client.post("/api/boot", json={"device_id": "dev-log-api"})
    challenge = client.post("/api/auth/challenge", json={"device_id": "dev-log-api"}).json()
    client.post(
        "/api/auth/authenticate",
        json={"device_id": "dev-log-api", "challenge_b64": challenge["challenge_b64"], "signature_b64": "AAAA"},
    )

    events = client.get("/api/security/events").json()
    assert len(events) >= 2
    assert all({"event_type", "device_id", "severity", "result", "summary", "timestamp"} <= set(e) for e in events)

    auth_logs = client.get("/api/auth/logs").json()
    assert len(auth_logs) == 1
    assert auth_logs[0]["success"] is False
    assert auth_logs[0]["reason"] == "signature_invalid"

    assert client.get("/api/boot/logs").json()
    assert client.get("/api/auth/logs", params={"device_id": "dev-log-api"}).json()


def test_api_auth_logs_validation(client):
    assert client.get("/api/auth/logs", params={"device_id": "bad id!"}).status_code == 422
    assert client.get("/api/auth/logs", params={"limit": 0}).status_code == 422
    assert client.get("/api/security/events", params={"event_type": "auth"}).status_code == 200


def test_firmware_payload_persisted_and_retrievable(client):
    client.post("/api/devices", json={"device_id": "dev-payload"})
    payload = b"persist me"
    client.post(
        "/api/firmware",
        json={"version": "1.0.0", "device_id": "dev-payload", "payload_b64": base64.b64encode(payload).decode()},
    )
    rows = Database().list_firmware("dev-payload")
    assert rows[0]["bundle"]["payload_b64"] == base64.b64encode(payload).decode()
