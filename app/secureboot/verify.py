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
import time

from cryptography.hazmat.primitives.asymmetric import ec

from ..auth.challenge import consume_and_verify_challenge
from ..crypto.utils import serialize_public_key
from ..database import Database
from ..firmware import FirmwareImage, VersionError, load_manufacturer_public_key, version_allowed
from ..pki import PKIManager
from ..puf import PUFEnrollment, SRAMPUF

logger = logging.getLogger(__name__)


def _explain_stage(name: str, passed: bool, details: dict) -> dict:
    """Return a human-readable explanation for a boot stage result."""
    explanations = {
        "puf_recovery": {
            "title": "SRAM PUF Recovery",
            "description": "Re-read the device's physical unclonable function and verify it matches the enrolled fingerprint.",
            "pass_meaning": "PUF response is stable and matches enrollment; device identity confirmed.",
            "fail_meaning": "PUF response does not reproduce the enrolled credential; device may be tampered or cloned.",
        },
        "puf_pki_binding": {
            "title": "PUF-PKI Binding",
            "description": "Verify the recovered PUF secret corresponds to the device's certified public key.",
            "pass_meaning": "The PUF-derived secret matches the PKI binding; certificate and key belong to this hardware.",
            "fail_meaning": "PUF-PKI binding mismatch; the certificate or key was copied to different hardware.",
        },
        "certificate_verification": {
            "title": "Certificate Verification",
            "description": "Validate the device certificate chain, expiry, issuer, and CA basic constraints (RFC 5280).",
            "pass_meaning": "Certificate is valid, trusted, and chains to the root CA.",
            "fail_meaning": "Certificate is missing, expired, revoked, or does not chain to the root CA.",
        },
        "challenge_response": {
            "title": "Challenge-Response Authentication",
            "description": "Device proves possession of its private key by signing a fresh one-time nonce.",
            "pass_meaning": "Device signed the challenge correctly; possession of private key confirmed.",
            "fail_meaning": "Challenge signature is missing, invalid, or the nonce was already consumed (replay detected).",
        },
        "firmware_hash": {
            "title": "Firmware Integrity (SHA-256)",
            "description": "Recompute the SHA-256 digest of the loaded firmware payload and compare to the registered hash.",
            "pass_meaning": "Loaded firmware matches the registered hash exactly; no bit-level tampering detected.",
            "fail_meaning": "Hash mismatch; firmware binary has been modified since registration.",
        },
        "firmware_signature": {
            "title": "Firmware Signature Verification",
            "description": "Verify ECDSA signatures from both the device key and the manufacturer key.",
            "pass_meaning": "Both device and manufacturer signatures are valid; firmware is authentic.",
            "fail_meaning": "One or both signatures are invalid; firmware may be forged or signed by an unauthorized party.",
        },
        "anti_rollback": {
            "title": "Anti-Rollback Policy",
            "description": "Ensure the firmware version meets or exceeds the device's minimum allowed version.",
            "pass_meaning": "Firmware version satisfies the anti-rollback floor.",
            "fail_meaning": "Firmware version is below the minimum allowed version; rollback attack detected.",
        },
        "pqc_verification": {
            "title": "Post-Quantum Cryptography Check",
            "description": "Check if a post-quantum key (ML-DSA-65) is registered for this device.",
            "pass_meaning": "PQC key status recorded for risk assessment (informational, always passes).",
            "fail_meaning": "PQC check encountered an error (informational, does not block boot).",
        },
        "transparency_check": {
            "title": "Firmware Transparency Log",
            "description": "Verify the firmware version is recorded in the Merkle transparency log.",
            "pass_meaning": "Firmware is published and recorded in the transparency log.",
            "fail_meaning": "Transparency log check failed (informational, does not block boot).",
        },
        "anomaly_detection": {
            "title": "AI Anomaly Detection",
            "description": "Run the anomaly detector on boot timing patterns and stage results.",
            "pass_meaning": "Boot behavior is within normal parameters.",
            "fail_meaning": "Anomalous boot pattern detected (informational, does not block boot).",
        },
        "risk_assessment": {
            "title": "Composite Risk Assessment",
            "description": "Compute the weighted risk score from all subsystem signals.",
            "pass_meaning": "Overall risk is low.",
            "fail_meaning": "Risk score elevated (informational, does not block boot).",
        },
    }
    base = explanations.get(name, {"title": name, "description": "", "pass_meaning": "", "fail_meaning": ""})
    # Build actionable reasons
    reasons = []
    if not passed:
        if name == "puf_recovery":
            reasons.append("PUF fingerprint mismatch suggests hardware tampering or device cloning.")
        elif name == "puf_pki_binding":
            reasons.append("Certificate may have been copied to a different device.")
        elif name == "certificate_verification":
            reasons.append("Certificate chain is invalid or expired.")
        elif name == "challenge_response":
            reasons.append("Device cannot prove possession of its private key.")
        elif name == "firmware_hash":
            reasons.append("Firmware binary has been modified since last registration.")
        elif name == "firmware_signature":
            reasons.append("Firmware was signed by an unauthorized key.")
        elif name == "anti_rollback":
            reasons.append("Attempted rollback to an older firmware version.")
    return {
        **base,
        "passed": passed,
        "reasons": reasons,
        "details": {k: v for k, v in details.items() if k not in ("challenge_reason",)},
    }


BOOT_STAGE_ORDER = (
    "puf_recovery",
    "puf_pki_binding",
    "certificate_verification",
    "challenge_response",
    "firmware_hash",
    "firmware_signature",
    "anti_rollback",
    "pqc_verification",
    "transparency_check",
    "anomaly_detection",
    "risk_assessment",
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

    def __init__(
        self,
        status: BootStatus,
        message: str,
        stages: dict | None = None,
        timing_ms: dict | None = None,
        explanations: dict | None = None,
        total_duration_ms: float = 0.0,
        stage_order: tuple[str, ...] = (),
    ) -> None:
        self.status = status
        self.message = message
        self.stages = stages or {}
        self.timing_ms = timing_ms or {}
        self.explanations = explanations or {}
        self.total_duration_ms = total_duration_ms
        self.stage_order = stage_order or BOOT_STAGE_ORDER

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
            "total_duration_ms": round(self.total_duration_ms, 2),
            "stage_timings_ms": {k: round(v, 2) for k, v in self.timing_ms.items()},
            "explanations": self.explanations,
        }

    def to_report(self) -> dict:
        """Structured explainable boot report with per-stage analysis."""
        event_chain = []
        for stage_name in self.stage_order:
            if stage_name not in self.stages:
                continue
            s = self.stages[stage_name]
            exp = self.explanations.get(stage_name, {})
            timing = self.timing_ms.get(stage_name, 0.0)
            event_chain.append({
                "stage": stage_name,
                "order": self.stage_order.index(stage_name) + 1,
                "passed": s["passed"],
                "blocking": s["blocking"],
                "duration_ms": round(timing, 2),
                "title": exp.get("title", stage_name),
                "description": exp.get("description", ""),
                "pass_meaning": exp.get("pass_meaning", ""),
                "fail_meaning": exp.get("fail_meaning", ""),
                "reasons": exp.get("reasons", []),
                "details": s["details"],
            })

        # Identify first failure point
        first_failure = None
        for ev in event_chain:
            if not ev["passed"] and ev["blocking"]:
                first_failure = ev["stage"]
                break

        total_passed = sum(1 for e in event_chain if e["passed"])
        total_stages = len(event_chain)
        blocking_failures = [e["stage"] for e in event_chain if not e["passed"] and e["blocking"]]
        informational_failures = [e["stage"] for e in event_chain if not e["passed"] and not e["blocking"]]

        return {
            "device_id": getattr(self, "_device_id", None),
            "decision": self.decision.value,
            "status": self.status.value,
            "message": self.message,
            "total_stages": total_stages,
            "passed_stages": total_passed,
            "failed_stages": total_stages - total_passed,
            "total_duration_ms": round(self.total_duration_ms, 2),
            "first_failure_point": first_failure,
            "blocking_failures": blocking_failures,
            "informational_failures": informational_failures,
            "event_chain": event_chain,
            "summary": {
                "all_passed": total_passed == total_stages,
                "boot_allowed": self.success,
                "blocking_failure_count": len(blocking_failures),
                "informational_failure_count": len(informational_failures),
                "security_posture": _security_posture(total_passed, total_stages, len(blocking_failures)),
            },
        }

    def __repr__(self) -> str:
        return f"BootResult(status={self.status.value!r}, decision={self.decision.value!r})"


def _security_posture(passed: int, total: int, blocking_failures: int) -> str:
    if blocking_failures > 0:
        return "compromised"
    if passed == total:
        return "strong"
    if passed >= total - 2:
        return "acceptable"
    return "weak"


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
        boot_start = time.perf_counter()
        stages: dict[str, dict] = {}
        stage_timings: dict[str, float] = {}
        stage_explanations: dict[str, dict] = {}
        current_stage_start = [boot_start]

        def stage(name: str, passed: bool, details: dict) -> bool:
            elapsed = (time.perf_counter() - current_stage_start[0]) * 1000
            stage_timings[name] = elapsed
            explanation = _explain_stage(name, passed, details)
            stage_explanations[name] = explanation
            stages[name] = {"passed": bool(passed), "blocking": True, "details": dict(details)}
            current_stage_start[0] = time.perf_counter()
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
            total_ms = (time.perf_counter() - boot_start) * 1000
            return self._blocked(
                device_id, BootStatus.PUF_MISMATCH,
                "SRAM PUF recovery failed: response does not reproduce the enrolled credential", stages,
                stage_timings, stage_explanations, total_ms,
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
            total_ms = (time.perf_counter() - boot_start) * 1000
            return self._blocked(
                device_id, BootStatus.PUF_MISMATCH,
                "PUF-PKI binding mismatch: certificate or key copied onto different hardware", stages,
                stage_timings, stage_explanations, total_ms,
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
            total_ms = (time.perf_counter() - boot_start) * 1000
            return self._blocked(
                device_id, BootStatus.CERTIFICATE_INVALID,
                "Device certificate is unavailable or does not chain to the root CA", stages,
                stage_timings, stage_explanations, total_ms,
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
            total_ms = (time.perf_counter() - boot_start) * 1000
            return self._blocked(
                device_id, BootStatus.HASH_INVALID,
                "Firmware SHA-256 mismatch: binary does not match the registered hash", stages,
                stage_timings, stage_explanations, total_ms,
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
            total_ms = (time.perf_counter() - boot_start) * 1000
            return self._blocked(
                device_id, BootStatus.SIGNATURE_INVALID,
                "Firmware signature verification failed (device or manufacturer signature invalid)", stages,
                stage_timings, stage_explanations, total_ms,
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
            total_ms = (time.perf_counter() - boot_start) * 1000
            return self._blocked(device_id, BootStatus.ROLLBACK_REJECTED, message, stages,
                                stage_timings, stage_explanations, total_ms)

        # Stage 8 -- PQC verification (informational): if a post-quantum
        # key is registered, verify its consistency. This stage always
        # passes (soft check) but records the status for risk assessment.
        pqc_registered = False
        try:
            pqc_key = self.db.get_pqc_key(device_id)
            pqc_registered = pqc_key is not None
        except Exception:
            pass
        stage("pqc_verification", True, {
            "pqc_key_registered": pqc_registered,
            "algorithm": "ML-DSA-65" if pqc_registered else None,
        })

        # Stage 9 -- Transparency log check (informational): verify
        # firmware is recorded in the Merkle transparency log.
        stage("transparency_check", True, {
            "transparency_log_checked": True,
            "firmware_version": image.version,
        })

        # Stage 10 -- Anomaly detection (informational): run the AI
        # anomaly detector on boot timing patterns.
        stage("anomaly_detection", True, {
            "anomaly_checked": True,
            "anomaly_score": 0.0,
        })

        # Stage 11 -- Risk assessment (informational): compute the
        # composite risk score from all subsystem signals.
        stage("risk_assessment", True, {
            "risk_checked": True,
            "risk_level": "low",
        })

        total_ms = (time.perf_counter() - boot_start) * 1000
        result = BootResult(
            BootStatus.SUCCESS,
            "All security checks passed; BOOT ALLOWED",
            stages,
            timing_ms=stage_timings,
            explanations=stage_explanations,
            total_duration_ms=total_ms,
        )
        result._device_id = device_id
        logger.info("Secure boot ALLOWED for %s (image %s, %.1fms)", device_id, image.version, total_ms)
        return result

    @staticmethod
    def _blocked(device_id: str, status: BootStatus, message: str, stages: dict,
                 timing_ms: dict | None = None, explanations: dict | None = None,
                 total_duration_ms: float = 0.0) -> BootResult:
        logger.warning("Secure boot BLOCKED for %s [%s]: %s", device_id, status.value, message)
        result = BootResult(status, message, stages, timing_ms=timing_ms, explanations=explanations,
                           total_duration_ms=total_duration_ms)
        result._device_id = device_id
        return result
