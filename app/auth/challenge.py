"""Challenge-response primitives for device authentication."""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..crypto.utils import b64decode

if TYPE_CHECKING:
    from ..database import Database

CHALLENGE_LENGTH = 32  # bytes of randomness per nonce
_AUTH_MAGIC = b"pufshield-auth:v1:"


def new_challenge() -> bytes:
    """Fresh cryptographically secure random nonce (Python ``secrets``).

    ``secrets.token_bytes`` draws from the operating system's CSPRNG and
    is suitable for one-time challenge values.
    """
    return secrets.token_bytes(CHALLENGE_LENGTH)


def challenge_message(device_id: str, challenge: bytes) -> bytes:
    """Canonical bytes a device signs for a given challenge.

    Binding ``device_id`` into the message prevents a challenge issued to
    one device from being answered by another device's key.
    """
    return _AUTH_MAGIC + device_id.encode("utf-8") + b":" + challenge


def sign_challenge(private_key, device_id: str, challenge: bytes) -> bytes:
    """Sign a challenge message with the device's private key (ECDSA-SHA256)."""
    return private_key.sign(
        challenge_message(device_id, challenge),
        ec.ECDSA(hashes.SHA256()),
    )


def verify_challenge_signature(public_key, device_id: str, challenge: bytes, signature: bytes) -> bool:
    """Verify an ECDSA-SHA256 signature over the challenge message."""
    try:
        public_key.verify(
            signature,
            challenge_message(device_id, challenge),
            ec.ECDSA(hashes.SHA256()),
        )
    except Exception:  # noqa: BLE001 - any verification failure means invalid
        return False
    return True


def consume_and_verify_challenge(
    db: "Database",
    public_key,
    device_id: str,
    challenge_b64: str,
    signature_b64: str,
) -> tuple[bool, bool, str]:
    """Atomically consume a one-time challenge and verify the device's signature.

    Shared by the challenge-response authentication flow and the secure
    boot engine so both reject replayed/failed attempts the same way.
    Returns ``(challenge_verified, signature_valid, reason)``:

    * ``challenge_verified`` - the challenge existed, was unexpired and
      unused, and has now been consumed (it can never be reused),
    * ``signature_valid`` - the ECDSA-SHA256 signature verifies with
      ``public_key`` over the canonical challenge message,
    * ``reason`` - a human-readable explanation of the first failure
      (``''`` on full success).
    """
    challenge_row = db.consume_challenge(challenge_b64, device_id)
    if challenge_row is None:
        return False, False, "unknown, expired, or already-used challenge (replay rejected)"
    try:
        challenge = b64decode(challenge_b64)
        signature = b64decode(signature_b64)
    except Exception as exc:  # noqa: BLE001 - malformed input is a failed attempt
        return True, False, "malformed challenge or signature encoding"
    if not verify_challenge_signature(public_key, device_id, challenge, signature):
        return True, False, "signature does not match the registered device public key"
    return True, True, ""
