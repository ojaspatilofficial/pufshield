"""End-to-end API tests using the FastAPI TestClient."""


def test_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_provision_and_boot_flow(client):
    provision = client.post("/api/devices", json={"device_id": "dev-api-1", "bit_size": 256})
    assert provision.status_code == 201
    body = provision.json()
    assert body["stable_bit_count"] > 0
    assert body["unstable_bit_count"] >= 0
    assert "reliability" in body
    assert "uniqueness" in body

    fw = client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-api-1"})
    assert fw.status_code == 201
    assert "signature_b64" in fw.json()

    boot = client.post("/api/boot", json={"device_id": "dev-api-1", "firmware_version": "1.0.0"})
    assert boot.status_code == 200
    assert boot.json()["status"] == "success"
    assert boot.json()["checks"]["puf_binding_match"] is True


def test_provision_duplicate_conflict(client):
    client.post("/api/devices", json={"device_id": "dev-api-dup"})
    res = client.post("/api/devices", json={"device_id": "dev-api-dup"})
    assert res.status_code == 409


def test_device_not_found(client):
    assert client.get("/api/devices/nope").status_code == 404
    assert client.post("/api/boot", json={"device_id": "nope"}).status_code == 404


def test_firmware_requires_provisioned_device(client):
    res = client.post("/api/firmware", json={"version": "1.0.0", "device_id": "not-provisioned"})
    assert res.status_code == 404


def test_boot_without_firmware(client):
    client.post("/api/devices", json={"device_id": "dev-no-fw"})
    res = client.post("/api/boot", json={"device_id": "dev-no-fw"})
    assert res.status_code == 400


def test_puf_test_endpoint(client):
    client.post("/api/devices", json={"device_id": "dev-puf-test", "bit_size": 256})
    res = client.post("/api/puf/test", json={"device_id": "dev-puf-test", "num_captures": 10})
    assert res.status_code == 200
    body = res.json()
    assert body["matched"] is True
    assert body["puf_binding_match"] is True
    assert body["hamming_distance"] == 0
    assert 0.0 < body["reliability"] <= 1.0


def test_puf_test_unknown_device(client):
    assert client.post("/api/puf/test", json={"device_id": "nope"}).status_code == 404


def test_puf_analysis_fleet(client):
    for i in range(3):
        client.post("/api/devices", json={"device_id": f"dev-an-{i}", "bit_size": 256})
    analysis = client.get("/api/puf/analysis").json()
    assert analysis["device_count"] == 3
    assert analysis["mean_uniqueness"] > 0.3
    assert analysis["mean_reliability"] > 0.9
    assert all(d["uniqueness"] is not None for d in analysis["devices"])


def test_puf_analysis_mixed_size_fleet_does_not_crash(client):
    """Regression: a fleet with different bit_sizes must not 500 on metrics."""
    client.post("/api/devices", json={"device_id": "dev-mix-small", "bit_size": 256})
    client.post("/api/devices", json={"device_id": "dev-mix-large", "bit_size": 512})
    analysis = client.get("/api/puf/analysis")
    assert analysis.status_code == 200
    body = analysis.json()
    assert body["device_count"] == 2
    assert all(d["uniqueness"] is not None for d in body["devices"])
    for device_id in ("dev-mix-small", "dev-mix-large"):
        client.post("/api/firmware", json={"version": "1.0.0", "device_id": device_id})
        boot = client.post("/api/boot", json={"device_id": device_id, "firmware_version": "1.0.0"})
        assert boot.status_code == 200
        assert boot.json()["status"] == "success"


def test_device_detail_includes_enrollment(client):
    client.post("/api/devices", json={"device_id": "dev-detail"})
    detail = client.get("/api/devices/dev-detail").json()
    assert "enrollment" in detail
    assert "stability_mask" in detail["enrollment"]
    assert "credential_tag" not in detail["enrollment"]


def test_attack_endpoint(client):
    client.post("/api/devices", json={"device_id": "dev-attack"})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-attack"})
    res = client.post("/api/attacks/tamper_firmware", json={"device_id": "dev-attack"})
    assert res.status_code == 200
    body = res.json()
    assert body["expected_failure"] is True
    assert body["status"] == "hash_invalid"


def test_clone_attack_fails_puf(client):
    client.post("/api/devices", json={"device_id": "dev-clone"})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-clone"})
    res = client.post("/api/attacks/clone_device", json={"device_id": "dev-clone"})
    body = res.json()
    assert body["status"] == "puf_mismatch"
    assert body["expected_failure"] is True
    assert body["checks"]["puf_binding_match"] is False


def test_boot_logs(client):
    client.post("/api/devices", json={"device_id": "dev-logs"})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-logs"})
    client.post("/api/boot", json={"device_id": "dev-logs"})
    logs = client.get("/api/boot/logs").json()
    assert any(log["device_id"] == "dev-logs" for log in logs)


def test_frontend_served(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "PUFShield" in res.text
