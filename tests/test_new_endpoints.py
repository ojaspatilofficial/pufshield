"""Tests for the new API endpoints:

- GET  /api/boot/report/{device_id}  — explainable boot report
- GET  /api/boot/metrics             — performance metrics
- GET  /api/security/timeline        — security event timeline
- GET  /api/twin/{device_id}         — digital twin (SRAM grid)
- POST /api/boot                     — extended response fields
"""

from app.services import Service


def _provision(client, device_id: str = "dev-t") -> None:
    assert client.post("/api/devices", json={"device_id": device_id}).status_code == 201


def _upload_firmware(client, device_id: str = "dev-t", version: str = "1.0.0") -> dict:
    res = client.post("/api/firmware", json={"version": version, "device_id": device_id})
    assert res.status_code == 201
    return res.json()


def _run_boot(client, device_id: str = "dev-t") -> dict:
    _provision(client, device_id)
    _upload_firmware(client, device_id)
    res = client.post("/api/boot", json={"device_id": device_id})
    assert res.status_code == 200
    return res.json()


# ── Boot response: timing and explanation fields ─────────────────────────────


def test_boot_response_has_timing_and_explanation_fields(client):
    body = _run_boot(client, "dev-boot-ext")
    assert "total_duration_ms" in body
    assert isinstance(body["total_duration_ms"], (int, float))
    assert body["total_duration_ms"] >= 0

    assert "stage_timings_ms" in body
    assert isinstance(body["stage_timings_ms"], dict)
    assert len(body["stage_timings_ms"]) > 0

    assert "explanations" in body
    assert isinstance(body["explanations"], dict)


# ── GET /api/boot/report/{device_id} ────────────────────────────────────────


def test_boot_report_happy_path(client):
    _run_boot(client, "dev-rpt")
    res = client.get("/api/boot/report/dev-rpt")
    assert res.status_code == 200
    body = res.json()

    assert body["device_id"] == "dev-rpt"
    assert body["decision"] in ("BOOT_ALLOWED", "BOOT_BLOCKED")

    assert "event_chain" in body
    assert isinstance(body["event_chain"], list)
    assert len(body["event_chain"]) > 0

    first_event = body["event_chain"][0]
    assert "stage" in first_event
    assert "passed" in first_event
    assert "duration_ms" in first_event
    assert "title" in first_event
    assert "description" in first_event

    assert "summary" in body
    assert isinstance(body["summary"], dict)
    assert "all_passed" in body["summary"]
    assert "boot_allowed" in body["summary"]
    assert "security_posture" in body["summary"]

    assert "first_failure_point" in body
    assert "total_duration_ms" in body
    assert "passed_stages" in body
    assert "total_stages" in body


def test_boot_report_404_for_unknown_device(client):
    res = client.get("/api/boot/report/dev-ghost")
    assert res.status_code == 404


def test_boot_report_no_boots_yet(client):
    _provision(client, "dev-rpt-empty")
    res = client.get("/api/boot/report/dev-rpt-empty")
    assert res.status_code == 200
    body = res.json()
    assert "error" in body


# ── GET /api/boot/metrics ───────────────────────────────────────────────────


def test_boot_metrics_happy_path(client):
    _run_boot(client, "dev-met")
    res = client.get("/api/boot/metrics")
    assert res.status_code == 200
    body = res.json()
    assert body["boots_analyzed"] >= 1
    assert "stage_pass_rates" in body
    assert isinstance(body["stage_pass_rates"], dict)
    assert len(body["stage_pass_rates"]) > 0
    for rate in body["stage_pass_rates"].values():
        assert 0.0 <= rate <= 1.0
    assert "allow_rate" in body
    assert "block_rate" in body


def test_boot_metrics_filtered_by_device(client):
    _run_boot(client, "dev-met-a")
    _run_boot(client, "dev-met-b")
    res = client.get("/api/boot/metrics", params={"device_id": "dev-met-a"})
    assert res.status_code == 200
    body = res.json()
    assert body["device_id"] == "dev-met-a"
    assert body["boots_analyzed"] >= 1


def test_boot_metrics_empty(client):
    res = client.get("/api/boot/metrics")
    assert res.status_code == 200
    body = res.json()
    assert body["boots_analyzed"] == 0
    assert body.get("stage_pass_rates") == {} or "stage_pass_rates" not in body


def test_boot_metrics_validation(client):
    res = client.get("/api/boot/metrics", params={"device_id": "bad id!"})
    assert res.status_code == 422


# ── GET /api/security/timeline ──────────────────────────────────────────────


def test_security_timeline_happy_path(client):
    _provision(client, "dev-tl")
    _upload_firmware(client, "dev-tl")
    client.post("/api/boot", json={"device_id": "dev-tl"})

    res = client.get("/api/security/timeline")
    assert res.status_code == 200
    body = res.json()
    assert body["event_count"] >= 1
    assert isinstance(body["timeline"], list)
    assert "severity_counts" in body
    assert isinstance(body["severity_counts"], dict)
    for key in ("info", "warning", "high", "critical"):
        assert key in body["severity_counts"]
        assert isinstance(body["severity_counts"][key], int)
    assert "device_id" in body


def test_security_timeline_filtered_by_device(client):
    _provision(client, "dev-tl-x")
    _upload_firmware(client, "dev-tl-x")
    client.post("/api/boot", json={"device_id": "dev-tl-x"})

    res = client.get("/api/security/timeline", params={"device_id": "dev-tl-x"})
    assert res.status_code == 200
    body = res.json()
    assert body["device_id"] == "dev-tl-x"
    assert body["event_count"] >= 1
    for ev in body["timeline"]:
        assert ev["device_id"] == "dev-tl-x"


def test_security_timeline_with_limit(client):
    _provision(client, "dev-tl-lim")
    _upload_firmware(client, "dev-tl-lim")
    client.post("/api/boot", json={"device_id": "dev-tl-lim"})

    res = client.get("/api/security/timeline", params={"limit": 1})
    assert res.status_code == 200
    body = res.json()
    assert body["event_count"] <= 1


def test_security_timeline_empty(client):
    res = client.get("/api/security/timeline")
    assert res.status_code == 200
    body = res.json()
    assert body["event_count"] == 0
    assert body["timeline"] == []
    assert all(v == 0 for v in body["severity_counts"].values())


def test_security_timeline_validation(client):
    assert client.get("/api/security/timeline", params={"limit": 0}).status_code == 422
    assert client.get("/api/security/timeline", params={"device_id": "bad id!"}).status_code == 422


# ── GET /api/twin/{device_id} ──────────────────────────────────────────────


def test_digital_twin_happy_path(client):
    _provision(client, "dev-tw")
    res = client.get("/api/twin/dev-tw")
    assert res.status_code == 200
    body = res.json()
    assert body["device_id"] == "dev-tw"

    assert "sram_grid" in body
    assert isinstance(body["sram_grid"], list)
    assert len(body["sram_grid"]) > 0
    for row in body["sram_grid"]:
        assert isinstance(row, list)
        assert len(row) == body["grid_size"]
        assert all(isinstance(v, (int, float)) for v in row)

    assert "grid_size" in body
    assert isinstance(body["grid_size"], int)
    assert body["grid_size"] > 0
    assert len(body["sram_grid"]) == body["grid_size"]

    assert "total_bits" in body
    assert body["total_bits"] > 0
    assert "bit_flip_rate" in body
    assert isinstance(body["bit_flip_rate"], (int, float))
    assert "stability" in body
    assert isinstance(body["stability"], (int, float))
    assert "entropy_bits" in body
    assert isinstance(body["entropy_bits"], (int, float))
    assert "conditions" in body
    assert isinstance(body["conditions"], dict)
    assert "temperature_c" in body["conditions"]
    assert "voltage_v" in body["conditions"]


def test_digital_twin_404_for_unknown_device(client):
    res = client.get("/api/twin/dev-ghost")
    assert res.status_code == 404


def test_deterministic_twin(client):
    _provision(client, "dev-det")
    r1 = client.get("/api/twin/dev-det").json()
    r2 = client.get("/api/twin/dev-det").json()
    assert r1["sram_grid"] == r2["sram_grid"]
    assert r1["bit_flip_rate"] == r2["bit_flip_rate"]
    assert r1["stability"] == r2["stability"]
