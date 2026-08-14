"""Tests for challenge-response device authentication.

Covers: valid authentication, wrong-device rejection, replay/expired/
unknown/cross-device challenge rejection, cloned-hardware (PUF-to-key
binding) rejection, and the REST API endpoints.
"""

import time

import pytest

from app.auth import AuthenticationError, sign_challenge, verify_challenge_signature
from app.crypto.utils import b64decode, b64encode
from app.puf import SRAMPUF
from app.services import DeviceNotFound


def _sign_b64(service, device_id: str, challenge_b64: str) -> str:
    """Simulate the device signing the challenge with its private key."""
    key = service.pki.key_store.load_private_key("device", device_id)
    return b64encode(sign_challenge(key, device_id, b64decode(challenge_b64)))


def _tampered_signature(service, device_id: str, challenge_b64: str) -> str:
    """A signature that is guaranteed to differ from the real one."""
    signature = bytearray(b64decode(_sign_b64(service, device_id, challenge_b64)))
    signature[0] ^= 0xFF  # flip all bits of the first byte
    return b64encode(bytes(signature))


# -- unit: valid authentication ----------------------------------------------

def test_valid_authentication(service, provisioned_device):
    challenge = service.issue_auth_challenge("dev-0001")
    signature = _sign_b64(service, "dev-0001", challenge["challenge_b64"])
    result = service.authenticate_device("dev-0001", challenge["challenge_b64"], signature)
    assert result["authenticated"] is True
    assert result["checks"]["challenge_verified"] is True
    assert result["checks"]["certificate_valid"] is True
    assert result["checks"]["signature_valid"] is True
    assert result["checks"]["puf_match"] is True
    assert result["checks"]["puf_binding_match"] is True


def test_challenge_nonce_is_random_and_secure(service, provisioned_device):
    a = service.issue_auth_challenge("dev-0001")
    b = service.issue_auth_challenge("dev-0001")
    assert a["challenge_b64"] != b["challenge_b64"]
    assert len(b64decode(a["challenge_b64"])) == 32  # 256-bit nonce
    assert a["device_id"] == "dev-0001"
    assert a["expires_at"] > time.time()


def test_auth_attempts_are_logged(service, provisioned_device):
    challenge = service.issue_auth_challenge("dev-0001")
    signature = _sign_b64(service, "dev-0001", challenge["challenge_b64"])
    service.authenticate_device("dev-0001", challenge["challenge_b64"], signature)
    logs = service.list_boot_logs()
    assert logs[0]["status"] == "auth_success"


# -- unit: wrong device -------------------------------------------------------

def test_wrong_device_signature_rejected(service, provisioned_device):
    service.provision_device("dev-0002")
    challenge = service.issue_auth_challenge("dev-0001")
    signature = _sign_b64(service, "dev-0002", challenge["challenge_b64"])
    with pytest.raises(AuthenticationError) as exc:
        service.authenticate_device("dev-0001", challenge["challenge_b64"], signature)
    assert exc.value.reason == "signature_invalid"


def test_signature_tampering_detected(service, provisioned_device):
    challenge = service.issue_auth_challenge("dev-0001")
    signature = b64decode(_sign_b64(service, "dev-0001", challenge["challenge_b64"]))
    tampered = b64encode(signature[:-1] + b"\x00")
    with pytest.raises(AuthenticationError) as exc:
        service.authenticate_device("dev-0001", challenge["challenge_b64"], tampered)
    assert exc.value.reason == "signature_invalid"


# -- unit: replay and challenge misuse ----------------------------------------

def test_replay_attack_rejected(service, provisioned_device):
    challenge = service.issue_auth_challenge("dev-0001")
    signature = _sign_b64(service, "dev-0001", challenge["challenge_b64"])
    first = service.authenticate_device("dev-0001", challenge["challenge_b64"], signature)
    assert first["authenticated"] is True
    with pytest.raises(AuthenticationError) as exc:
        service.authenticate_device("dev-0001", challenge["challenge_b64"], signature)
    assert exc.value.reason == "challenge_invalid"


def test_unknown_challenge_rejected(service, provisioned_device):
    fake = b64encode(b"\x01" * 32)
    signature = _sign_b64(service, "dev-0001", fake)
    with pytest.raises(AuthenticationError) as exc:
        service.authenticate_device("dev-0001", fake, signature)
    assert exc.value.reason == "challenge_invalid"


def test_expired_challenge_rejected(service, provisioned_device):
    challenge = service.issue_auth_challenge("dev-0001")
    service.db.conn.execute(
        "UPDATE auth_challenges SET expires_at = ? WHERE challenge = ?",
        (time.time() - 1, challenge["challenge_b64"]),
    )
    service.db.conn.commit()
    signature = _sign_b64(service, "dev-0001", challenge["challenge_b64"])
    with pytest.raises(AuthenticationError) as exc:
        service.authenticate_device("dev-0001", challenge["challenge_b64"], signature)
    assert exc.value.reason == "challenge_invalid"


def test_cross_device_challenge_rejected(service, provisioned_device):
    service.provision_device("dev-0002")
    challenge = service.issue_auth_challenge("dev-0001")
    signature = _sign_b64(service, "dev-0002", challenge["challenge_b64"])
    with pytest.raises(AuthenticationError) as exc:
        service.authenticate_device("dev-0002", challenge["challenge_b64"], signature)
    assert exc.value.reason == "challenge_invalid"


def test_challenge_consumed_after_failed_attempt(service, provisioned_device):
    """A failed attempt burns the challenge: it can never be reused."""
    challenge = service.issue_auth_challenge("dev-0001")
    wrong = _tampered_signature(service, "dev-0001", challenge["challenge_b64"])
    with pytest.raises(AuthenticationError):
        service.authenticate_device("dev-0001", challenge["challenge_b64"], wrong)
    correct = _sign_b64(service, "dev-0001", challenge["challenge_b64"])
    with pytest.raises(AuthenticationError) as exc:
        service.authenticate_device("dev-0001", challenge["challenge_b64"], correct)
    assert exc.value.reason == "challenge_invalid"


# -- unit: PUF-to-key binding ------------------------------------------------

def test_cloned_hardware_rejected_by_binding(service, provisioned_device):
    """Stolen private key + copied cert on different hardware fails the binding."""
    challenge = service.issue_auth_challenge("dev-0001")
    signature = _sign_b64(service, "dev-0001", challenge["challenge_b64"])
    enrollment = service.db.get_enrollment("dev-0001")
    clone = SRAMPUF("dev-0001", bit_size=256, seed=b"impostor-seed", noise_rate=0.01)
    with pytest.raises(AuthenticationError) as exc:
        service.auth.authenticate(
            device_id="dev-0001",
            challenge_b64=challenge["challenge_b64"],
            signature_b64=signature,
            puf=clone,
            enrollment=enrollment,
        )
    assert exc.value.reason == "puf_mismatch"


# -- unit: prerequisites ------------------------------------------------------

def test_authenticate_requires_provisioned_device(service):
    with pytest.raises(DeviceNotFound):
        service.issue_auth_challenge("nope")
    with pytest.raises(DeviceNotFound):
        service.authenticate_device("nope", "challenge", "signature")


def test_challenge_signature_helpers_reject_mismatched_device():
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    challenge = b"\xab" * 32
    signature = sign_challenge(key, "dev-a", challenge)
    assert verify_challenge_signature(key.public_key(), "dev-a", challenge, signature)
    assert not verify_challenge_signature(key.public_key(), "dev-b", challenge, signature)
    assert not verify_challenge_signature(key.public_key(), "dev-a", b"\x00" * 32, signature)


# -- REST API -----------------------------------------------------------------

def _api_challenge(client, device_id: str) -> dict:
    res = client.post("/api/auth/challenge", json={"device_id": device_id})
    assert res.status_code == 200
    return res.json()


def _api_authenticate(client, service, device_id: str, challenge: dict) -> dict:
    signature = _sign_b64(service, device_id, challenge["challenge_b64"])
    return client.post(
        "/api/auth/authenticate",
        json={
            "device_id": device_id,
            "challenge_b64": challenge["challenge_b64"],
            "signature_b64": signature,
        },
    )


def test_auth_api_valid_flow(client, service):
    client.post("/api/devices", json={"device_id": "dev-auth-1"})
    challenge = _api_challenge(client, "dev-auth-1")
    res = _api_authenticate(client, service, "dev-auth-1", challenge)
    assert res.status_code == 200
    assert res.json()["authenticated"] is True
    assert res.json()["checks"]["puf_binding_match"] is True


def test_auth_api_wrong_device_rejected(client, service):
    client.post("/api/devices", json={"device_id": "dev-auth-a"})
    client.post("/api/devices", json={"device_id": "dev-auth-b"})
    challenge = _api_challenge(client, "dev-auth-a")
    signature = _sign_b64(service, "dev-auth-b", challenge["challenge_b64"])
    res = client.post(
        "/api/auth/authenticate",
        json={
            "device_id": "dev-auth-a",
            "challenge_b64": challenge["challenge_b64"],
            "signature_b64": signature,
        },
    )
    assert res.status_code == 401
    assert res.headers.get("x-auth-reason") == "signature_invalid"


def test_auth_api_replay_rejected(client, service):
    client.post("/api/devices", json={"device_id": "dev-auth-replay"})
    challenge = _api_challenge(client, "dev-auth-replay")
    signature = _sign_b64(service, "dev-auth-replay", challenge["challenge_b64"])
    payload = {
        "device_id": "dev-auth-replay",
        "challenge_b64": challenge["challenge_b64"],
        "signature_b64": signature,
    }
    assert client.post("/api/auth/authenticate", json=payload).status_code == 200
    replay = client.post("/api/auth/authenticate", json=payload)
    assert replay.status_code == 401
    assert replay.headers.get("x-auth-reason") == "challenge_invalid"


def test_auth_api_unknown_device(client):
    assert client.post("/api/auth/challenge", json={"device_id": "nope"}).status_code == 404
    res = client.post(
        "/api/auth/authenticate",
        json={"device_id": "nope", "challenge_b64": "a", "signature_b64": "b"},
    )
    assert res.status_code == 404
