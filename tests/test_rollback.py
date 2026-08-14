"""Tests for firmware anti-rollback protection: secure version comparison, minimum version policy, boot rejection, and logging."""

import pytest

from app.database import Database
from app.firmware import VersionError, compare_versions, parse_version, version_allowed
from app.secureboot import BootStatus
from app.services import DeviceNotFound


# -- secure version comparison ------------------------------------------------

def test_compare_versions_numeric_not_lexicographic():
    assert compare_versions("1.10.0", "1.9.0") > 0
    assert compare_versions("2.0", "1.99.99") > 0
    assert compare_versions("0.9", "1.0") < 0
    assert compare_versions("1.10.0", "1.9.0") > 0
    assert compare_versions("10.0", "9.99") > 0


def test_compare_versions_missing_components_count_as_zero():
    assert compare_versions("1.0", "1.0.0") == 0
    assert compare_versions("2", "2.0.0.0") == 0
    assert compare_versions("1.0", "1.0.1") < 0


def test_parse_version_rejects_malformed():
    for bad in ("", " 1.0.0", "1.0.0 ", "v1", "1.0.0-alpha", "1..0", "1.0.", ".1", "01.0", "1.00", "1.-1", "1.0.0.0.0.0.0.0.0.0"):
        with pytest.raises(VersionError):
            parse_version(bad)


def test_version_allowed_no_policy():
    assert version_allowed("1.0.0", None) is True
    assert version_allowed("1.0.0", "") is True
    assert version_allowed("0.0.1", "") is True


def test_version_allowed_boundaries():
    assert version_allowed("2.0.0", "2.0.0") is True
    assert version_allowed("2.0.1", "2.0.0") is True
    assert version_allowed("1.9.9", "2.0.0") is False


def test_version_allowed_fails_closed_on_malformed_image_version():
    with pytest.raises(VersionError):
        version_allowed("1.0.0-alpha", "2.0.0")


# -- persistence ----------------------------------------------------------------

def test_default_minimum_version_is_unrestricted(service, provisioned_device):
    assert service.get_minimum_firmware_version("dev-0001") == ""
    info = service.get_device("dev-0001")
    assert info["min_firmware_version"] == ""


def test_set_get_minimum_version_roundtrip(service, provisioned_device):
    service.set_minimum_firmware_version("dev-0001", "2.0.0")
    assert service.get_minimum_firmware_version("dev-0001") == "2.0.0"
    info = service.get_device("dev-0001")
    assert info["min_firmware_version"] == "2.0.0"
    assert any(d["min_firmware_version"] == "2.0.0" for d in service.list_devices())


def test_set_minimum_version_rejects_malformed(service, provisioned_device):
    with pytest.raises(VersionError):
        service.set_minimum_firmware_version("dev-0001", "1..2")
    with pytest.raises(VersionError):
        service.set_minimum_firmware_version("dev-0001", "01.0")
    assert service.get_minimum_firmware_version("dev-0001") == ""


def test_minimum_version_unknown_device(service):
    with pytest.raises(DeviceNotFound):
        service.get_minimum_firmware_version("nope")
    with pytest.raises(DeviceNotFound):
        service.set_minimum_firmware_version("nope", "1.0.0")


# -- boot policy ------------------------------------------------------------------

def test_boot_without_policy_allows_old_and_new(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    service.create_firmware("2.0.0", "dev-0001")
    assert service.run_boot("dev-0001", "1.0.0")["status"] == BootStatus.SUCCESS.value
    assert service.run_boot("dev-0001", "2.0.0")["status"] == BootStatus.SUCCESS.value


def test_valid_latest_firmware_boots(service, provisioned_device):
    service.set_minimum_firmware_version("dev-0001", "1.0.0")
    service.create_firmware("1.0.0", "dev-0001")
    result = service.run_boot("dev-0001", "1.0.0")
    assert result["status"] == BootStatus.SUCCESS.value
    assert result["checks"]["version_allowed"] is True
    assert result["checks"]["minimum_version"] == "1.0.0"
    assert result["checks"]["image_version"] == "1.0.0"


def test_valid_upgrade_boots_after_raising_minimum(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    service.create_firmware("2.0.0", "dev-0001")
    service.set_minimum_firmware_version("dev-0001", "1.0.0")
    assert service.run_boot("dev-0001", "2.0.0")["status"] == BootStatus.SUCCESS.value
    service.set_minimum_firmware_version("dev-0001", "2.0.0")
    assert service.run_boot("dev-0001", "2.0.0")["status"] == BootStatus.SUCCESS.value


def test_signed_old_firmware_rollback_rejected(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    service.create_firmware("2.0.0", "dev-0001")
    service.set_minimum_firmware_version("dev-0001", "2.0.0")

    result = service.run_boot("dev-0001", "1.0.0")
    assert result["status"] == BootStatus.ROLLBACK_REJECTED.value
    assert result["success"] is False
    checks = result["checks"]
    # the old image is CORRECTLY signed - rejection is purely the version policy.
    assert checks["signature_valid"] is True
    assert checks["manufacturer_signature_valid"] is True
    assert checks["version_allowed"] is False
    assert checks["image_version"] == "1.0.0"
    assert checks["minimum_version"] == "2.0.0"
    assert "below the minimum" in result["message"]

    # the current version still boots fine.
    assert service.run_boot("dev-0001", "2.0.0")["status"] == BootStatus.SUCCESS.value


def test_rollback_comparison_is_numeric(service, provisioned_device):
    service.create_firmware("1.9.0", "dev-0001")
    service.create_firmware("1.10.0", "dev-0001")
    # numeric ordering: 1.10.0 is newer than 1.9.0 (string ordering would wrongly reject it).
    service.set_minimum_firmware_version("dev-0001", "1.9.0")
    assert service.run_boot("dev-0001", "1.10.0")["status"] == BootStatus.SUCCESS.value
    service.set_minimum_firmware_version("dev-0001", "1.10.0")
    result = service.run_boot("dev-0001", "1.9.0")
    assert result["status"] == BootStatus.ROLLBACK_REJECTED.value


def test_rollback_rejection_is_logged(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    service.create_firmware("2.0.0", "dev-0001")
    service.set_minimum_firmware_version("dev-0001", "2.0.0")
    service.run_boot("dev-0001", "1.0.0")

    logs = service.list_boot_logs()
    assert logs and logs[0]["status"] == BootStatus.ROLLBACK_REJECTED.value
    assert logs[0]["image_version"] == "1.0.0"
    assert "2.0.0" in logs[0]["message"]
    assert logs[0]["checks"]["version_allowed"] is False


def test_rollback_logged_via_database(service, provisioned_device):
    service.create_firmware("1.0.0", "dev-0001")
    service.set_minimum_firmware_version("dev-0001", "5.0.0")
    service.run_boot("dev-0001", "1.0.0")
    rows = Database().conn.execute("SELECT * FROM boot_logs ORDER BY id DESC LIMIT 1").fetchone()
    assert rows["status"] == BootStatus.ROLLBACK_REJECTED.value
    assert rows["image_version"] == "1.0.0"


# -- REST API -----------------------------------------------------------------------

def test_api_minimum_version_set_and_get(client):
    client.post("/api/devices", json={"device_id": "dev-api"})
    res = client.put("/api/devices/dev-api/minimum-version", json={"version": "3.2.1"})
    assert res.status_code == 200
    assert res.json()["min_firmware_version"] == "3.2.1"
    assert client.get("/api/devices/dev-api/minimum-version").json()["min_firmware_version"] == "3.2.1"
    assert client.get("/api/devices/dev-api").json()["min_firmware_version"] == "3.2.1"


def test_api_minimum_version_clears_policy(client):
    client.post("/api/devices", json={"device_id": "dev-api-clear"})
    client.put("/api/devices/dev-api-clear/minimum-version", json={"version": "3.0.0"})
    res = client.put("/api/devices/dev-api-clear/minimum-version", json={"version": ""})
    assert res.status_code == 200
    assert client.get("/api/devices/dev-api-clear/minimum-version").json()["min_firmware_version"] == ""


def test_api_minimum_version_rejects_malformed(client):
    client.post("/api/devices", json={"device_id": "dev-api-bad"})
    res = client.put("/api/devices/dev-api-bad/minimum-version", json={"version": "1..0"})
    assert res.status_code == 400


def test_api_minimum_version_unknown_device(client):
    res = client.put("/api/devices/nope/minimum-version", json={"version": "1.0.0"})
    assert res.status_code == 404
    assert client.get("/api/devices/nope/minimum-version").status_code == 404


def test_api_boot_rejects_old_firmware(client):
    client.post("/api/devices", json={"device_id": "dev-boot"})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-boot"})
    client.post("/api/firmware", json={"version": "2.0.0", "device_id": "dev-boot"})
    client.put("/api/devices/dev-boot/minimum-version", json={"version": "2.0.0"})

    res = client.post("/api/boot", json={"device_id": "dev-boot", "firmware_version": "1.0.0"})
    assert res.status_code == 200
    assert res.json()["status"] == BootStatus.ROLLBACK_REJECTED.value
    assert res.json()["success"] is False

    res = client.post("/api/boot", json={"device_id": "dev-boot", "firmware_version": "2.0.0"})
    assert res.status_code == 200
    assert res.json()["status"] == BootStatus.SUCCESS.value


def test_api_firmware_verify_reports_version_policy(client):
    client.post("/api/devices", json={"device_id": "dev-vrf"})
    client.post("/api/firmware", json={"version": "1.0.0", "device_id": "dev-vrf"})
    client.put("/api/devices/dev-vrf/minimum-version", json={"version": "2.0.0"})
    res = client.post(
        "/api/firmware/verify",
        json={"device_id": "dev-vrf", "firmware_version": "1.0.0"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["version_allowed"] is False
    assert body["minimum_version"] == "2.0.0"
    assert body["manufacturer_signature_valid"] is True
    assert body["verified"] is False
