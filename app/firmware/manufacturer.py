"""Manufacturer key management.

The manufacturer holds a dedicated signing key pair, separate from the
device and CA keys. Firmware manifests (version + device id + payload
SHA-256 hash) are signed with the manufacturer private key, and everyone
verifies them with the trusted manufacturer public key.

The private key is generated on first use, persisted in the key store with
restrictive permissions, and is NEVER exposed through the REST API or the
frontend - only the public key is exported.
"""

from __future__ import annotations

import logging

from cryptography.hazmat.primitives.asymmetric import ec

from ..pki.key_store import KeyStore

logger = logging.getLogger(__name__)

MANUFACTURER_SCOPE = "manufacturer"
MANUFACTURER_KEY_NAME = "signing_key"
_CURVE = ec.SECP256R1()


class ManufacturerKeyError(Exception):
    """Raised when the manufacturer signing key is unavailable."""


def ensure_manufacturer_key(store: KeyStore | None = None) -> ec.EllipticCurvePrivateKey:
    """Load the manufacturer signing key, creating it on first use.

    Returns the private key for signing; callers that only verify should
    use :func:`load_manufacturer_public_key` and never touch the private
    key material directly.
    """
    store = store or KeyStore()
    key = store.load_private_key(MANUFACTURER_SCOPE, MANUFACTURER_KEY_NAME)
    if key is None:
        key = ec.generate_private_key(_CURVE)
        store.save_private_key(key, MANUFACTURER_SCOPE, MANUFACTURER_KEY_NAME)
        logger.info("Generated manufacturer signing key pair")
    return key


def load_manufacturer_public_key(store: KeyStore | None = None) -> ec.EllipticCurvePublicKey:
    """Return the trusted manufacturer public key (creating it if needed)."""
    return ensure_manufacturer_key(store).public_key()
