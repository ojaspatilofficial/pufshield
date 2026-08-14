"""HKDF-SHA256 key derivation with domain separation.

The fuzzy extractor produces a single secret; domain separation ensures
keys derived for different purposes are cryptographically independent.
HKDF does not perform error correction - it only stretches and
domain-separates the already-corrected secret.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PUF_KEY_LABELS = ("device-auth", "firmware-encryption", "boot-integrity")
PUF_BINDING_LABEL = "puf-binding"

_APPLICATION_PREFIX = b"pufshield:v1:"


def hkdf_sha256(
    ikm: bytes,
    length: int,
    salt: bytes | None = None,
    info: bytes = b"",
) -> bytes:
    """Standard HKDF-SHA256 extract-and-expand."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def derive_device_keys(secret: bytes, device_id: str, key_size: int = 32) -> dict[str, bytes]:
    """Derive domain-separated device keys from the fuzzy-recovered secret.

    The HKDF salt binds the derivation to the device; the info string
    binds it to the key's purpose. Returns one ``key_size``-byte key per
    label in :data:`PUF_KEY_LABELS`.
    """
    salt = _APPLICATION_PREFIX + device_id.encode("utf-8")
    return {
        label: hkdf_sha256(
            secret,
            key_size,
            salt=salt,
            info=_APPLICATION_PREFIX + label.encode("ascii"),
        )
        for label in PUF_KEY_LABELS
    }


def derive_puf_binding(
    secret: bytes,
    device_public_key: bytes,
    device_id: str,
    key_size: int = 32,
) -> bytes:
    """Bind the PUF-derived secret to the device's public key.

    The binding is a domain-separated HKDF output keyed by the PUF
    secret. Recomputing it requires both the physical PUF (to recover
    the secret) and the certified public key, so a certificate or key
    copied onto different hardware never reproduces the registered
    binding.
    """
    salt = _APPLICATION_PREFIX + device_id.encode("utf-8")
    info = _APPLICATION_PREFIX + PUF_BINDING_LABEL.encode("ascii") + b":" + device_public_key
    return hkdf_sha256(secret, key_size, salt=salt, info=info)
