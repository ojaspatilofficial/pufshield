"""Low-level cryptographic helpers built on the ``cryptography`` library."""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes, hmac, serialization

SUPPORTED_HASH = hashes.SHA256


def random_bytes(n: int) -> bytes:
    """Cryptographically secure random bytes."""
    return os.urandom(n)


def serialize_public_key(public_key) -> bytes:
    """Canonical DER SubjectPublicKeyInfo encoding of an EC public key."""
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sha256(data: bytes) -> bytes:
    """SHA-256 digest of ``data``."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Keyed HMAC-SHA256 (used to bind PUF helper data to device context)."""
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(message)
    return mac.finalize()
