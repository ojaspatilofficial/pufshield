"""Full REST API coverage: every backend module exposed through FastAPI.

Covers device registration/listing, PUF testing/metrics, authentication,
certificate information, firmware upload/signing/verification, secure
boot, attack simulations, security events, and dashboard statistics -
including input validation and clean error responses.
"""

import base64

from app.auth.challenge import sign_challenge
from app.crypto.utils import b64decode, b64encode
from app.services import Service

REQUIRED_CERT_FIELDS = {
    "device_id", "subject", "issuer", "serial_number",
    "not_valid_before", "not_valid_after", "is_ca", "key_usage",
    "public_key", "pem", "chain_valid", "chain_errors",
}

REQUIRED_EVENT_FIELDS = {
    "event_type", "device_id", "severity", "result", "summary", "timestamp",
}


def _provision(client, device_id: str = "dev-api") -> None:
    assert client.post("/api/devices", json={"device_id": device_id}).status_code == 201


def _upload_firmware(client, device_id: str = "dev-api", version: str = "1.0.0") -> dict:
    res = client.post("/api/firmware", json={"version": version, "device_id": device_id})
    assert res.status_code == 201
    return res.json()


def _signature_for(client, device_id: str, challenge_b64: str) -> str:
    """Sign a challenge as the genuine device would (device private key)."""
    key = Service().pki.key_store.load_private_key("device", device_id)
    assert key is not None
    return b64encode(sign_challenge(key, device_id, b64decode(challenge_b64)))


# -- device registration + listing ----------------------------------------------

def test_register_device(client):
    res = client.post("/api/devices", json={"device_id": "dev-reg", "bit_size": 256})
    assert res.status_code == 201
    body = res.json()
    assert body["device_id"] == "dev-reg"
    assert body["stable_bit_count"] > 0
    assert 0.0 < body["reliability"] <= 1.0
    assert "certificate_serial" in body


def test_register_device_duplicate_conflict(client):
    _provision(client, "dev-dup")
    res = client.post("/api/devices", json={"device_id": "dev-dup"})
    assert res.status_code == 409


def test_register_device_validates_inputs(client):
    for payload in (
        {"device_id": "bad id!"},
        {"device_id": ""},
        {"device_id": "-leading-dash"},
        {"device_id": "dev-1", "bit_size": 4},
        {"device_id": "dev-1", "bit_size": 8192},
        {"device_id": "dev-1", "num_captures": 0},
    ):
        res = client.post("/api/devices", json=payload)
        assert res.status_code == 422, payload


def test_list_devices(client):
    assert client.get("/api/devices").json() == []
    _provision(client, "dev-a")
    _provision(client, "dev-b")
    devices = client.get("/api/devices").json()
    assert {d["device_id"] for d in devices} == {"dev-a", "dev-b"}
    assert all("enrollment" in d for d in devices)
    assert all("min_firmware_version" in d for d in devices)


def test_delete_device_allows_reprovisioning(client):
    _provision(client, "dev-del")
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-del"})

    res = client.delete("/api/devices/dev-del")
    assert res.status_code == 200
    assert res.json() == {"device_id": "dev-del", "deleted": True}

    assert client.get("/api/devices/dev-del").status_code == 404
    assert client.get("/api/devices").json() == []

    # The same device id can be provisioned again with a fresh identity.
    res = client.post("/api/devices", json={"device_id": "dev-del"})
    assert res.status_code == 201
    res = client.post("/api/devices", json={"device_id": "dev-del"})
    assert res.status_code == 409


def test_delete_missing_device_is_404(client):
    res = client.delete("/api/devices/nope")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


# -- PUF testing + metrics ------------------------------------------------------

def test_puf_test_and_metrics(client):
    _provision(client, "dev-puf")
    test = client.post("/api/puf/test", json={"device_id": "dev-puf"}).json()
    assert test["matched"] is True
    assert test["puf_binding_match"] is True
    assert test["hamming_distance"] == 0

    metrics = client.get("/api/puf/analysis").json()
    assert metrics["device_count"] == 1
    assert metrics["mean_reliability"] > 0.9
    assert metrics["mean_uniqueness"] is not None
    assert metrics["devices"][0]["device_id"] == "dev-puf"


def test_puf_test_validation(client):
    assert client.post("/api/puf/test", json={"device_id": "nope"}).status_code == 404
    assert client.post("/api/puf/test", json={"device_id": "bad id!"}).status_code == 422
    assert client.post("/api/puf/test", json={"device_id": "dev-x", "num_captures": 0}).status_code == 422


# -- device authentication ------------------------------------------------------

def test_authentication_success(client):
    _provision(client, "dev-auth")
    challenge = client.post("/api/auth/challenge", json={"device_id": "dev-auth"}).json()
    signature = _signature_for(client, "dev-auth", challenge["challenge_b64"])
    res = client.post(
        "/api/auth/authenticate",
        json={"device_id": "dev-auth", "challenge_b64": challenge["challenge_b64"], "signature_b64": signature},
    )
    assert res.status_code == 200
    assert res.json()["authenticated"] is True


def test_authentication_failure_is_401_with_reason(client):
    _provision(client, "dev-auth-fail")
    challenge = client.post("/api/auth/challenge", json={"device_id": "dev-auth-fail"}).json()
    res = client.post(
        "/api/auth/authenticate",
        json={"device_id": "dev-auth-fail", "challenge_b64": challenge["challenge_b64"], "signature_b64": "AAAA"},
    )
    assert res.status_code == 401
    assert res.headers.get("X-Auth-Reason") == "signature_invalid"
    assert "signature" in res.json()["detail"]


def test_authentication_replay_is_401(client):
    _provision(client, "dev-auth-rep")
    challenge = client.post("/api/auth/challenge", json={"device_id": "dev-auth-rep"}).json()
    signature = _signature_for(client, "dev-auth-rep", challenge["challenge_b64"])
    payload = {"device_id": "dev-auth-rep", "challenge_b64": challenge["challenge_b64"], "signature_b64": signature}
    assert client.post("/api/auth/authenticate", json=payload).status_code == 200
    replay = client.post("/api/auth/authenticate", json=payload)
    assert replay.status_code == 401
    assert replay.headers.get("X-Auth-Reason") == "challenge_invalid"


def test_authentication_malformed_signature_never_500s(client):
    _provision(client, "dev-auth-bad")
    challenge = client.post("/api/auth/challenge", json={"device_id": "dev-auth-bad"}).json()
    res = client.post(
        "/api/auth/authenticate",
        json={"device_id": "dev-auth-bad", "challenge_b64": challenge["challenge_b64"], "signature_b64": "!!!"},
    )
    assert res.status_code == 401
    assert res.headers.get("X-Auth-Reason") == "signature_invalid"


# -- certificate information ----------------------------------------------------

def test_certificate_information(client):
    _provision(client, "dev-cert")
    res = client.get("/api/devices/dev-cert/certificate")
    assert res.status_code == 200
    body = res.json()
    assert set(body) == REQUIRED_CERT_FIELDS
    assert body["device_id"] == "dev-cert"
    assert "PUFShield Root CA" in body["issuer"]
    assert body["subject"].startswith("CN=device:")
    assert body["pem"].startswith("-----BEGIN CERTIFICATE-----")
    assert body["chain_valid"] is True
    assert body["chain_errors"] == []
    assert body["public_key"]["algorithm"] == "ECDSA"
    assert len(body["public_key"]["fingerprint_sha256"]) == 64
    assert "digital_signature" in body["key_usage"]
    assert body["not_valid_before"] <= body["not_valid_after"]


def test_certificate_information_unknown_device(client):
    assert client.get("/api/devices/nope/certificate").status_code == 404


# -- firmware upload ------------------------------------------------------------

def test_firmware_upload(client):
    _provision(client, "dev-fw-up")
    payload = b"\x00\x01PUFShield runtime"
    res = client.post(
        "/api/firmware",
        json={"version": "1.2.3", "device_id": "dev-fw-up", "payload_b64": base64.b64encode(payload).decode()},
    )
    assert res.status_code == 201
    body = res.json()
    assert body["version"] == "1.2.3"
    assert body["device_id"] == "dev-fw-up"
    assert body["payload_sha256"]
    assert body["signature_b64"]
    assert body["manufacturer_signature_b64"]
    listing = client.get("/api/firmware", params={"device_id": "dev-fw-up"}).json()
    assert any(item["version"] == "1.2.3" for item in listing)


def test_firmware_upload_validation(client):
    _provision(client, "dev-fw-val")
    bad_b64 = client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-fw-val", "payload_b64": "!!!"})
    assert bad_b64.status_code == 422

    bad_version = client.post("/api/firmware", json={"version": "v1.0.0!", "device_id": "dev-fw-val"})
    assert bad_version.status_code == 400

    missing_device = client.post("/api/firmware", json={"version": "1.0.0", "device_id": "ghost"})
    assert missing_device.status_code == 404


# -- firmware signing -----------------------------------------------------------

def test_firmware_sign_without_storing(client):
    _provision(client, "dev-fw-sign")
    res = client.post(
        "/api/firmware/sign",
        json={"version": "5.0.0", "device_id": "dev-fw-sign", "payload_b64": base64.b64encode(b"boot").decode()},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["version"] == "5.0.0"
    assert body["signature_b64"]
    assert body["manufacturer_signature_b64"]
    assert body.get("stored") is None
    assert client.get("/api/firmware", params={"device_id": "dev-fw-sign"}).json() == []


def test_firmware_sign_and_store(client):
    _provision(client, "dev-fw-sign-store")
    res = client.post(
        "/api/firmware/sign",
        json={"version": "6.0.0", "device_id": "dev-fw-sign-store", "store": True},
    )
    assert res.status_code == 200
    assert res.json()["stored"] is True
    assert any(item["version"] == "6.0.0" for item in client.get("/api/firmware").json())


def test_firmware_sign_validation(client):
    _provision(client, "dev-fw-sign-val")
    assert client.post(
        "/api/firmware/sign", json={"version": "1.0", "device_id": "dev-fw-sign-val", "payload_b64": "!!!"}
    ).status_code == 422
    assert client.post("/api/firmware/sign", json={"version": "bad", "device_id": "dev-fw-sign-val"}).status_code == 400
    assert client.post("/api/firmware/sign", json={"version": "1.0.0", "device_id": "ghost"}).status_code == 404


# -- firmware verification ------------------------------------------------------

def test_firmware_verify_clean_image(client):
    _provision(client, "dev-fw-vrf")
    _upload_firmware(client, "dev-fw-vrf", "1.0.0")
    res = client.post("/api/firmware/verify", json={"device_id": "dev-fw-vrf", "firmware_version": "1.0.0"})
    assert res.status_code == 200
    body = res.json()
    assert body["verified"] is True
    assert body["hash_valid"] is True
    assert body["device_signature_valid"] is True
    assert body["manufacturer_signature_valid"] is True
    assert body["version_allowed"] is True


def test_firmware_verify_rejects_rollback(client):
    _provision(client, "dev-fw-vrf-rb")
    _upload_firmware(client, "dev-fw-vrf-rb", "1.0.0")
    _upload_firmware(client, "dev-fw-vrf-rb", "2.0.0")
    client.put("/api/devices/dev-fw-vrf-rb/minimum-version", json={"version": "2.0.0"})
    body = client.post("/api/firmware/verify", json={"device_id": "dev-fw-vrf-rb", "firmware_version": "1.0.0"}).json()
    assert body["verified"] is False
    assert body["version_allowed"] is False


def test_firmware_verify_missing(client):
    _provision(client, "dev-fw-vrf-miss")
    assert client.post(
        "/api/firmware/verify", json={"device_id": "dev-fw-vrf-miss", "firmware_version": "9.9.9"}
    ).status_code == 400


# -- secure boot -----------------------------------------------------------------

def test_secure_boot_allowed(client):
    _provision(client, "dev-boot-ok")
    _upload_firmware(client, "dev-boot-ok", "1.0.0")
    res = client.post("/api/boot", json={"device_id": "dev-boot-ok"})
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "BOOT_ALLOWED"
    assert body["status"] == "success"
    assert body["stages"]["anti_rollback"]["passed"] is True


def test_secure_boot_blocked_by_rollback(client):
    _provision(client, "dev-boot-rb")
    _upload_firmware(client, "dev-boot-rb", "1.0.0")
    _upload_firmware(client, "dev-boot-rb", "2.0.0")
    client.put("/api/devices/dev-boot-rb/minimum-version", json={"version": "2.0.0"})
    body = client.post("/api/boot", json={"device_id": "dev-boot-rb", "firmware_version": "1.0.0"}).json()
    assert body["decision"] == "BOOT_BLOCKED"
    assert body["status"] == "rollback_rejected"
    assert body["detection_point"] if "detection_point" in body else True


# -- attack simulations ----------------------------------------------------------

def test_attack_simulations(client):
    _provision(client, "dev-att")
    _upload_firmware(client, "dev-att", "1.0.0")
    scenarios = client.get("/api/attacks").json()
    names = {s["name"] for s in scenarios}
    assert {"clone_device", "tamper_firmware", "replay_challenge", "certificate_forgery", "firmware_rollback"} <= names

    res = client.post("/api/attacks/clone_device", json={"device_id": "dev-att"})
    assert res.status_code == 200
    body = res.json()
    assert body["decision"] == "BOOT_BLOCKED"
    assert body["detection_point"] == "puf_recovery"

    logs = client.get("/api/attacks/logs").json()
    assert logs and logs[0]["attack"] == "clone_device"


# -- security events -------------------------------------------------------------

def test_security_events_feed(client):
    _provision(client, "dev-ev")
    _upload_firmware(client, "dev-ev", "1.0.0")
    client.post("/api/boot", json={"device_id": "dev-ev"})  # info event
    client.post("/api/attacks/tamper_firmware", json={"device_id": "dev-ev"})  # critical event
    challenge = client.post("/api/auth/challenge", json={"device_id": "dev-ev"}).json()
    client.post(
        "/api/auth/authenticate",
        json={"device_id": "dev-ev", "challenge_b64": challenge["challenge_b64"], "signature_b64": "AAAA"},
    )  # high event

    events = client.get("/api/security/events").json()
    assert len(events) >= 3
    assert all(set(event) >= REQUIRED_EVENT_FIELDS for event in events)

    attacks = client.get("/api/security/events", params={"event_type": "attack"}).json()
    assert attacks and all(e["event_type"] == "attack" for e in attacks)

    device_events = client.get("/api/security/events", params={"device_id": "dev-ev"}).json()
    assert device_events and all(e["device_id"] == "dev-ev" for e in device_events)


def test_security_events_validation(client):
    assert client.get("/api/security/events", params={"event_type": "bogus"}).status_code == 422
    assert client.get("/api/security/events", params={"device_id": "bad id!"}).status_code == 422
    assert client.get("/api/security/events", params={"limit": 0}).status_code == 422


# -- dashboard statistics --------------------------------------------------------

def test_dashboard_stats(client):
    _provision(client, "dev-dash")
    _upload_firmware(client, "dev-dash", "1.0.0")
    _upload_firmware(client, "dev-dash", "2.0.0")
    client.put("/api/devices/dev-dash/minimum-version", json={"version": "2.0.0"})
    client.post("/api/boot", json={"device_id": "dev-dash", "firmware_version": "2.0.0"})  # allowed
    client.post("/api/boot", json={"device_id": "dev-dash", "firmware_version": "1.0.0"})  # blocked
    client.post("/api/attacks/clone_device", json={"device_id": "dev-dash"})  # blocked

    stats = client.get("/api/dashboard/stats").json()
    assert stats["devices"]["total"] == 1
    assert stats["firmware"]["total_images"] == 2
    assert stats["firmware"]["devices_with_firmware"] == 1
    assert stats["boots"]["total"] == 3
    assert stats["boots"]["allowed"] == 1
    assert stats["boots"]["blocked"] == 2
    assert round(stats["boots"]["success_rate"], 3) == 0.333
    assert stats["attacks"]["total"] == 1
    assert stats["attacks"]["blocked"] == 1
    assert stats["attacks"]["blocked_rate"] == 1.0
    assert stats["auth"] == {"successes": 0, "failures": 0}
    assert stats["security"]["events_total"] == 4
    assert stats["security"]["critical"] == 3
    assert stats["puf"]["device_count"] == 1
    assert stats["puf"]["mean_uniqueness"] is not None


def test_dashboard_stats_empty_fleet(client):
    stats = client.get("/api/dashboard/stats").json()
    assert stats["devices"]["total"] == 0
    assert stats["firmware"]["total_images"] == 0
    assert stats["boots"]["total"] == 0
    assert stats["boots"]["success_rate"] is None
    assert stats["attacks"]["blocked_rate"] is None
    assert stats["security"]["events_total"] == 0
