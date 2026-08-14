"""Firmware image creation and signing."""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from ..crypto.utils import b64decode, b64encode

_MAGIC = b"PUFB\x01"
_MANIFEST_MAGIC = b"PUFM\x01"


class FirmwareImage:
    """A signed firmware image bundle.

    Two signature layers protect the image:

    * the *device signature* - the device's EC private key signs the
      payload digest (proves the image came from/for this device), and
    * the *manufacturer signature* - the trusted manufacturer key signs
      the manifest (version + device id + payload SHA-256), so any
      modified firmware is detected by the trusted public key.

    Layout (JSON envelope, base64 payload)::

        {
          "magic": "PUFB\\x01",
          "version": "1.0.0",
          "device_id": "dev-0001",
          "payload_b64": "<base64 of firmware bytes>",
          "payload_sha256": "<hex digest>",
          "signature_b64": "<base64 DER ECDSA device signature>",
          "manufacturer_signature_b64": "<base64 DER ECDSA manifest signature>"
        }
    """

    def __init__(
        self,
        version: str,
        device_id: str,
        payload: bytes,
        signature: bytes | None = None,
        manufacturer_signature: bytes | None = None,
    ) -> None:
        if not isinstance(payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        self.version = version
        self.device_id = device_id
        self.payload = bytes(payload)
        self.signature = signature
        self.manufacturer_signature = manufacturer_signature

    @property
    def payload_digest(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()

    def _unsigned_body(self) -> bytes:
        body = {
            "magic": _MAGIC.decode("latin-1"),
            "version": self.version,
            "device_id": self.device_id,
            "payload_b64": b64encode(self.payload),
            "payload_sha256": self.payload_digest,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def manifest_bytes(self) -> bytes:
        """Canonical firmware manifest: version + device id + payload hash.

        This is what the manufacturer signs. It binds the binary's SHA-256
        digest to a version for a device, so a modified binary can never
        reproduce a valid manifest signature.
        """
        body = {
            "magic": _MANIFEST_MAGIC.decode("latin-1"),
            "version": self.version,
            "device_id": self.device_id,
            "payload_sha256": self.payload_digest,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, private_key: ec.EllipticCurvePrivateKey) -> "FirmwareImage":
        """Return a new image with the payload digest signed by the key."""
        signature = private_key.sign(
            self._unsigned_body(),
            ec.ECDSA(hashes.SHA256()),
        )
        return FirmwareImage(self.version, self.device_id, self.payload, signature, self.manufacturer_signature)

    def sign_manifest(self, private_key: ec.EllipticCurvePrivateKey) -> "FirmwareImage":
        """Return a new image with the manifest signed by the manufacturer key.

        ``private_key`` is the trusted manufacturer private key (kept in the
        key store, never exposed through any API).
        """
        signature = private_key.sign(
            self.manifest_bytes(),
            ec.ECDSA(hashes.SHA256()),
        )
        return FirmwareImage(self.version, self.device_id, self.payload, self.signature, signature)

    def verify(self, public_key: ec.EllipticCurvePublicKey) -> bool:
        """Verify the embedded device signature against the unsigned body."""
        if self.signature is None:
            return False
        try:
            public_key.verify(
                self.signature,
                self._unsigned_body(),
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception:  # noqa: BLE001 - any failure means invalid signature
            return False
        return True

    def verify_manifest(self, public_key: ec.EllipticCurvePublicKey) -> bool:
        """Verify the manufacturer signature against the manifest.

        Returns ``False`` for an unsigned image or any verification failure,
        so a modified payload (different SHA-256) or forged signature is
        always detected against the trusted manufacturer public key.
        """
        if self.manufacturer_signature is None:
            return False
        try:
            public_key.verify(
                self.manufacturer_signature,
                self.manifest_bytes(),
                ec.ECDSA(hashes.SHA256()),
            )
        except Exception:  # noqa: BLE001 - any failure means invalid signature
            return False
        return True

    def to_bundle(self) -> dict:
        """Serializable representation for storage/transport."""
        bundle = {
            "magic": _MAGIC.decode("latin-1"),
            "version": self.version,
            "device_id": self.device_id,
            "payload_b64": b64encode(self.payload),
            "payload_sha256": self.payload_digest,
        }
        if self.signature is not None:
            bundle["signature_b64"] = b64encode(self.signature)
        if self.manufacturer_signature is not None:
            bundle["manufacturer_signature_b64"] = b64encode(self.manufacturer_signature)
        return bundle

    @classmethod
    def from_bundle(cls, bundle: dict) -> "FirmwareImage":
        signature = b64decode(bundle["signature_b64"]) if bundle.get("signature_b64") else None
        manufacturer_signature = (
            b64decode(bundle["manufacturer_signature_b64"]) if bundle.get("manufacturer_signature_b64") else None
        )
        image = cls(
            version=bundle["version"],
            device_id=bundle["device_id"],
            payload=b64decode(bundle["payload_b64"]),
            signature=signature,
            manufacturer_signature=manufacturer_signature,
        )
        digest = bundle.get("payload_sha256")
        if digest and image.payload_digest != digest:
            raise ValueError("payload SHA-256 mismatch in bundle")
        return image

    def __repr__(self) -> str:
        return f"FirmwareImage(version={self.version!r}, device_id={self.device_id!r})"
