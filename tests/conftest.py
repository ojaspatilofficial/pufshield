"""Test fixtures.

Environment variables are set before importing application modules so
tests use an isolated database and key store under a temp directory.
"""

import os
import tempfile

_TMP_ROOT = tempfile.mkdtemp(prefix="pufshield-tests-")
os.environ["DATABASE_PATH"] = os.path.join(_TMP_ROOT, "pufshield.db")
os.environ["PUF_CREDENTIAL_SECRET_PATH"] = os.path.join(_TMP_ROOT, "puf_secret.bin")
os.environ["APP_DEBUG"] = "false"
os.environ["PUFSHIELD_SIMULATE_HARDWARE"] = "1"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.services import Service  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_database():
    """Reset the shared test database between tests."""
    db = Service().db
    for table in (
        "security_events",
        "authentication_events",
        "certificates",
        "attack_logs",
        "boot_logs",
        "firmware_images",
        "puf_enrollments",
        "devices",
        "auth_challenges",
    ):
        db.conn.execute(f"DELETE FROM {table}")
    db.conn.commit()
    yield
    db.close()


@pytest.fixture
def service() -> Service:
    return Service()


@pytest.fixture
def provisioned_device(service: Service) -> dict:
    return service.provision_device("dev-0001", bit_size=256)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)
