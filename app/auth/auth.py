"""Challenge-response device authentication.

The device proves possession of the private key matching its registered
certificate by signing a fresh, one-time challenge nonce. The server
verifies:

1. the challenge is valid (exists, belongs to the device, unexpired, and
   not previously used) - reused challenges and replayed responses are
   rejected,
2. the device certificate is present and chains to the root CA,
3. the signature verifies against the registered certificate public key,
   and
4. the PUF-to-key binding still holds (the response reproduces the
   enrolled credential bound to the device's certified public key).
"""

from __future__ import annotations

import logging
import time

from ..crypto.utils import b64encode, serialize_public_key
from ..database import Database
from ..pki import PKIManager
from ..puf import PUFEnrollment, SRAMPUF
from .challenge import consume_and_verify_challenge, new_challenge

logger = logging.getLogger(__name__)

DEFAULT_CHALLENGE_TTL = 60.0  # seconds a challenge stays valid


class AuthenticationError(Exception):
    """Raised when a device fails challenge-response authentication."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


class AuthManager:
    """Issue one-time challenges and verify signed challenge responses."""

    def __init__(
        self,
        pki: PKIManager | None = None,
        db: Database | None = None,
        ttl_seconds: float = DEFAULT_CHALLENGE_TTL,
    ) -> None:
        self.pki = pki or PKIManager()
        self.db = db or Database()
        self.ttl_seconds = ttl_seconds

    # -- public API ----------------------------------------------------

    def issue_challenge(self, device_id: str) -> dict:
        """Issue a fresh one-time challenge for ``device_id``."""
        challenge = new_challenge()
        expires_at = time.time() + self.ttl_seconds
        self.db.save_challenge(b64encode(challenge), device_id, expires_at)
        self.db.purge_expired_challenges()
        return {
            "device_id": device_id,
            "challenge_b64": b64encode(challenge),
            "expires_at": expires_at,
        }

    def authenticate(
        self,
        *,
        device_id: str,
        challenge_b64: str,
        signature_b64: str,
        puf: SRAMPUF,
        enrollment: PUFEnrollment,
    ) -> dict:
        """Verify a signed challenge response and the PUF-to-key binding.

        Returns ``{"device_id": ..., "authenticated": True, "checks": ...}``
        on success. Raises :class:`AuthenticationError` with a machine-
        readable ``reason`` on any failure. A challenge is consumed
        before verification, so every challenge works exactly once.
        """
        checks = {
            "challenge_verified": False,
            "certificate_valid": False,
            "signature_valid": False,
            "puf_match": False,
            "puf_binding_match": False,
        }

        try:
            # 1. registered public key + certificate trust chain.
            cert = self._device_certificate(device_id)
            checks["certificate_valid"] = True

            # 2. one-time challenge + signature over the challenge message.
            # The challenge is consumed atomically before the signature is
            # verified, so a failed or replayed attempt can never reuse it.
            challenge_verified, signature_valid, reason = consume_and_verify_challenge(
                self.db, cert.public_key(), device_id, challenge_b64, signature_b64
            )
            checks["challenge_verified"] = bool(challenge_verified)
            checks["signature_valid"] = bool(signature_valid)
            if not challenge_verified:
                raise AuthenticationError(
                    "challenge_invalid",
                    "unknown, expired, or already-used challenge (replay rejected)",
                )
            if not signature_valid:
                raise AuthenticationError("signature_invalid", reason)

            # 4. PUF-to-key binding: re-read the PUF, recompute credential + binding.
            test = PUFEnrollment.test(
                puf,
                enrollment,
                num_captures=1,
                device_public_key=serialize_public_key(cert.public_key()),
            )
            checks["puf_match"] = bool(test["matched"])
            checks["puf_binding_match"] = test["puf_binding_match"]
            if not test["matched"]:
                raise AuthenticationError(
                    "puf_mismatch",
                    "PUF response does not reproduce the enrolled credential / PUF-to-key binding",
                )
        except AuthenticationError as exc:
            self._log(device_id, success=False, reason=exc.reason, checks=checks)
            logger.warning("Authentication failed for %s: %s", device_id, exc.reason)
            raise
        self._log(device_id, success=True, reason="ok", checks=checks)
        logger.info("Device %s authenticated (challenge-response)", device_id)
        return {"device_id": device_id, "authenticated": True, "checks": checks}

    # -- internals ------------------------------------------------------

    def _device_certificate(self, device_id: str):
        """Load the device certificate and verify it chains to the root CA."""
        try:
            cert = self.pki.get_device_certificate(device_id)
            if not self.pki.verify_certificate_chain(cert):
                raise AuthenticationError(
                    "certificate_invalid",
                    "device certificate does not chain to the root CA",
                )
        except AuthenticationError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise AuthenticationError(
                "certificate_invalid",
                f"device certificate unavailable or invalid: {exc}",
            ) from exc
        return cert

    def _log(self, device_id: str, *, success: bool, reason: str, checks: dict) -> None:
        """Append an auth audit record.

        Every authentication attempt (success or failure) writes three
        records: a legacy boot-log row (status ``auth_success`` /
        ``auth_failed``), a dedicated ``authentication_events`` row, and a
        timestamped security event so the unified feed sees every attempt.
        """
        status = "auth_success" if success else "auth_failed"
        self.db.log_boot(device_id, None, status, reason, checks)
        self.db.log_authentication_event(device_id, success=success, reason=reason, checks=checks)
        self.db.log_security_event(
            event_type="auth",
            device_id=device_id,
            severity="info" if success else "high",
            result="success" if success else "failed",
            summary=reason,
            details={"reason": reason, "success": success, "checks": checks},
        )
