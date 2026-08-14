"""Complete secure boot engine.

The boot sequence combines the hardware root of trust (SRAM PUF) with a
PKI trust chain, challenge-response authentication, firmware integrity,
and anti-rollback policy. The mandatory stages run in order and each is
reported in the result; a failure in any mandatory stage blocks boot::

    SRAM PUF recovery
    -> PUF-PKI binding
    -> certificate verification
    -> challenge-response authentication
    -> firmware SHA-256 verification
    -> firmware signature verification
    -> anti-rollback verification
    -> BOOT ALLOWED | BOOT BLOCKED

The device certificate is loaded up front because its public key is needed
by the PUF-PKI binding and the challenge/signature stages; whether it
actually chains to the root CA is decided by its own stage.
"""

from __future__ import annotations

import enum
import logging

from cryptography.hazmat.primitives.asymmetric import ec

from ..auth.challenge import consume_and_verify_challenge
from ..crypto.utils import serialize_public_key
from ..database import Database
from ..firmware import FirmwareImage, VersionError, load_manufacturer_public_key, version_allowed
from ..pki import PKIManager
from ..puf import PUFEnrollment, SRAMPUF

logger = logging.getLogger(__name__)

BOOT_STAGE_ORDER = (
    "puf_recovery",
    "puf_pki_binding",
    "certificate_verification",
    "challenge_response",
    "firmware_hash",
    "firmware_signature",
    "anti_rollback",
)


class BootDecision(str, enum.Enum):
    ALLOWED = "BOOT_ALLOWED"
    BLOCKED = "BOOT_BLOCKED"


class BootStatus(str, enum.Enum):
    SUCCESS = "success"
    PUF_MISMATCH = "puf_mismatch"
    CERTIFICATE_INVALID = "certificate_invalid"
    AUTH_FAILED = "auth_failed"
    HASH_INVALID = "hash_invalid"
    SIGNATURE_INVALID = "signature_invalid"
    IMAGE_MISMATCH = "image_mismatch"
    ROLLBACK_REJECTED = "rollback_rejected"


class BootResult:
    """Outcome of a secure boot attempt: per-stage results + overall decision."""

    def __init__(self, status: BootStatus, message: str, stages: dict | None = None) -> None:
        self.status = status
        self.message = message
        self.stages = stages or {}

    @property
    def success(self) -> bool:
        return self.status is BootStatus.SUCCESS

    @property
    def decision(self) -> BootDecision:
        return BootDecision.ALLOWED if self.success else BootDecision.BLOCKED

    @property
    def checks(self) -> dict:
        """Flat aggregate of every stage's result (stage name -> passed + details)."""
        out: dict = {}
        for key, stage in self.stages.items():
            out[key] = bool(stage["passed"])
            out.update(stage["details"])
        return out

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "booted": self.decision is BootDecision.ALLOWED,
            "status": self.status.value,
            "success": self.success,
            "message": self.message,
            "stages": self.stages,
            "checks": self.checks,
        }

    def __repr__(self) -> str:
        return f"BootResult(status={self.status.value!r}, decision={self.decision.value!r})"


class SecureBootManager:
    """Orchestrates the full secure boot sequence."""

    def __init__(self, pki: PKIManager | None = None, db: Database | None = None) -> None:
        self.pki = pki or PKIManager()
        self.db = db or Database()

    def verify_boot(
        self,
        *,
        device_id: str,
        puf: SRAMPUF,
        enrollment: PUFEnrollment,
        image: FirmwareImage,
        minimum_version: str | None = None,
        expected_sha256: str | None = None,
        challenge_b64: str | None = None,
        signature_b64: str | None = None,
    ) -> BootResult:
        """Run the full boot verification sequence.

        Parameters:
            minimum_version: the device's anti-rollback floor (''/None =
                unrestricted). The rollback stage runs last, so it only ever
                sees a version covered by a valid manufacturer signature.
            expected_sha256: the SHA-256 digest registered for this image;
                the loaded payload must reproduce it or boot is blocked.
            challenge_b64 / signature_b64: challenge-response proof that the
                device holds its private key. Missing or invalid values fail
                the challenge stage (challenges are consumed atomically, so a
                failed or replayed attempt is rejected).
        """
        stages: dict[str, dict] = {}

        def stage(name: str, passed: bool, details: dict) -> bool:
            stages[name] = {"passed": bool(passed), "blocking": True, "details": dict(details)}
            return bool(passed)

        # The certificate is loaded up front: its public key is required by
        # the PUF-PKI binding and the challenge/signature stages. Whether the
        # certificate is trusted is decided by its own stage below.
        device_cert = None
        try:
            device_cert = self.pki.get_device_certificate(device_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Secure boot for %s: device certificate unavailable: %s", device_id, exc)

        # Stage 1 -- SRAM PUF recovery: re-read the PUF, error-correct it
        # against the enrolled helper data, and recover the fuzzy secret.
        puf_test = PUFEnrollment.test(
            puf,
            enrollment,
            num_captures=1,
            device_public_key=serialize_public_key(device_cert.public_key()) if device_cert else None,
        )
        puf_recovered = bool(puf_test["fuzzy_recovered"])
        if not stage(
            "puf_recovery",
            puf_recovered,
            {
                "puf_match": bool(puf_test["matched"]),
                "fuzzy_recovered": puf_recovered,
                "puf_binding_match": puf_test["puf_binding_match"],
                "hamming_distance": puf_test["hamming_distance"],
                "stable_bits_checked": puf_test["stable_bits_checked"],
                "bit_error_rate": puf_test["bit_error_rate"],
                "reliability": puf_test["reliability"],
            },
        ):
            return self._blocked(
                device_id, BootStatus.PUF_MISMATCH,
                "SRAM PUF recovery failed: response does not reproduce the enrolled credential", stages,
            )

        # Stage 2 -- PUF-PKI binding: the recovered secret must reproduce the
        # binding committed to the device's certified public key. A certificate
        # or private key copied onto different hardware fails here.
        binding_match = puf_test["puf_binding_match"]
        if not stage(
            "puf_pki_binding",
            binding_match is True,
            {"puf_binding_match": binding_match, "puf_match": bool(puf_test["matched"])},
        ):
            return self._blocked(
                device_id, BootStatus.PUF_MISMATCH,
                "PUF-PKI binding mismatch: certificate or key copied onto different hardware", stages,
            )

        # Stage 3 -- certificate verification: signature, issuer chain, expiry,
        # CA basic constraints (RFC 5280).
        cert_ok = device_cert is not None
        if cert_ok:
            try:
                cert_ok = self.pki.verify_certificate_chain(device_cert)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Secure boot for %s: certificate chain error: %s", device_id, exc)
                cert_ok = False
        if not stage(
            "certificate_verification",
            bool(cert_ok),
            {
                "certificate_available": device_cert is not None,
                "certificate_valid": bool(cert_ok),
                "certificate_serial": device_cert.serial_number if device_cert else None,
            },
        ):
            return self._blocked(
                device_id, BootStatus.CERTIFICATE_INVALID,
                "Device certificate is unavailable or does not chain to the root CA", stages,
            )

        # Stage 4 -- challenge-response authentication: the device proves
        # possession of its private key by signing a fresh one-time nonce.
        # Challenges are consumed atomically, so reused/replayed challenges
        # (and any failed attempt) are rejected.
        auth_ok = False
        auth_details = {
            "challenge_provided": bool(challenge_b64 and signature_b64),
            "challenge_verified": False,
            "auth_signature_valid": False,
        }
        if challenge_b64 and signature_b64:
            challenge_verified, signature_valid, reason = consume_and_verify_challenge(
                self.db, device_cert.public_key(), device_id, challenge_b64, signature_b64
            )
            auth_details["challenge_verified"] = bool(challenge_verified)
            auth_details["auth_signature_valid"] = bool(signature_valid)
            if not signature_valid:
                auth_details["challenge_reason"] = reason
            auth_ok = bool(challenge_verified and signature_valid)
        else:
            auth_details["challenge_reason"] = "challenge-response required but not provided"
        if not stage("challenge_response", auth_ok, auth_details):
            return self._blocked(
                device_id, BootStatus.AUTH_FAILED,
                "Challenge-response authentication failed (device did not prove possession of its key)", stages,
            )

        # Stage 5 -- firmware SHA-256 verification: the loaded payload must
        # reproduce the digest registered for this image. Any bit flip in the
        # binary is caught here, before any signature is evaluated.
        hash_ok = expected_sha256 is not None and image.payload_digest == expected_sha256
        if not stage(
            "firmware_hash",
            hash_ok,
            {
                "hash_valid": hash_ok,
                "recomputed_sha256": image.payload_digest,
                "registered_sha256": expected_sha256,
            },
        ):
            return self._blocked(
                device_id, BootStatus.HASH_INVALID,
                "Firmware SHA-256 mismatch: binary does not match the registered hash", stages,
            )

        # Stage 6 -- firmware signature verification: device signature against
        # the certified public key and manufacturer manifest signature against
        # the trusted manufacturer public key.
        device_sig_ok = isinstance(device_cert.public_key(), ec.EllipticCurvePublicKey) and image.verify(
            device_cert.public_key()
        )
        manufacturer_sig_ok = image.verify_manifest(load_manufacturer_public_key(self.pki.key_store))
        if not stage(
            "firmware_signature",
            bool(device_sig_ok and manufacturer_sig_ok),
            {
                "signature_valid": bool(device_sig_ok),
                "manufacturer_signature_valid": bool(manufacturer_sig_ok),
            },
        ):
            return self._blocked(
                device_id, BootStatus.SIGNATURE_INVALID,
                "Firmware signature verification failed (device or manufacturer signature invalid)", stages,
            )

        # Stage 7 -- anti-rollback verification: the (authenticated) image
        # version must satisfy the device's minimum allowed version. Malformed
        # versions fail closed.
        version_malformed = False
        try:
            allowed = version_allowed(image.version, minimum_version)
        except VersionError:
            allowed, version_malformed = False, True
        if not stage(
            "anti_rollback",
            bool(allowed),
            {
                "image_version": image.version,
                "minimum_version": minimum_version or None,
                "version_allowed": bool(allowed),
                "version_malformed": version_malformed,
            },
        ):
            if version_malformed:
                message = f"Firmware version {image.version!r} is malformed and cannot satisfy the minimum version policy"
            else:
                message = (
                    f"Firmware version {image.version} is below the minimum allowed version {minimum_version} "
                    "(rollback rejected)"
                )
            return self._blocked(device_id, BootStatus.ROLLBACK_REJECTED, message, stages)

        logger.info("Secure boot ALLOWED for %s (image %s)", device_id, image.version)
        return BootResult(BootStatus.SUCCESS, "All security checks passed; BOOT ALLOWED", stages)

    @staticmethod
    def _blocked(device_id: str, status: BootStatus, message: str, stages: dict) -> BootResult:
        logger.warning("Secure boot BLOCKED for %s [%s]: %s", device_id, status.value, message)
        return BootResult(status, message, stages)
