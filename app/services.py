"""Orchestration layer tying PUF, PKI, firmware, secure boot, and DB together."""

from __future__ import annotations

import datetime as dt
import logging

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .attacks import AttackSimulator
from .auth import AuthManager
from .auth.challenge import sign_challenge
from .config import get_settings
from .crypto.utils import b64decode, b64encode, random_bytes, serialize_public_key, sha256
from .database import Database
from .firmware import (
    FirmwareImage,
    VersionError,
    ensure_manufacturer_key,
    load_manufacturer_public_key,
    parse_version,
    version_allowed,
)
from .pki import PKIManager, is_ca_certificate
from .puf import DEFAULT_CAPTURES, PUFEnrollment, SRAMPUF
from .secureboot import BOOT_STAGE_ORDER, BootStatus, SecureBootManager

logger = logging.getLogger(__name__)

DEFAULT_FIRMWARE_PAYLOAD = b"PUFShield bootloader v1 -- verifies PUF + PKI before running application code.\n"


class DeviceAlreadyExists(Exception):
    pass


class DeviceNotFound(Exception):
    pass


class NoFirmwareError(Exception):
    pass


class NoEnrollmentError(Exception):
    pass


class Service:
    """High-level operations exposed by the REST API."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self.db = Database()
        self.pki = PKIManager()
        self.boot = SecureBootManager(self.pki, self.db)
        self.attacks = AttackSimulator()
        self.auth = AuthManager(self.pki, self.db)
        self._pufs: dict[str, SRAMPUF] = {}

    # -- provisioning --------------------------------------------------

    def provision_device(self, device_id: str, bit_size: int = 256, num_captures: int = DEFAULT_CAPTURES) -> dict:
        """Register a device: create its PUF, issue a certificate, and enroll.

        The device certificate is issued first so its public key can be
        bound to the PUF-derived secret during enrollment.
        """
        if self.db.get_device(device_id):
            raise DeviceAlreadyExists(f"device {device_id!r} already provisioned")

        cert = self.pki.issue_device_certificate(device_id)
        seed = random_bytes(self.settings.device_key_size_bytes)
        puf = SRAMPUF(device_id, bit_size=bit_size, seed=seed)
        enrollment = PUFEnrollment.enroll(
            puf,
            num_captures=num_captures,
            device_public_key=serialize_public_key(cert.public_key()),
        )
        self.db.upsert_device(device_id, bit_size, seed)
        self.db.upsert_enrollment(enrollment)
        self.db.save_certificate(device_id, cert)
        self.db.recompute_uniqueness()
        self._pufs[device_id] = puf

        logger.info("Provisioned device %s (PUF %d bits, cert serial %d)", device_id, bit_size, cert.serial_number)
        result = enrollment.to_dict()
        result["certificate_serial"] = cert.serial_number
        return result

    def get_device(self, device_id: str) -> dict:
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        enrollment = self.db.get_enrollment(device_id)
        info = {
            "device_id": device["device_id"],
            "bit_size": device["bit_size"],
            "min_firmware_version": device["min_firmware_version"],
            "created_at": device["created_at"],
        }
        if enrollment:
            info["enrollment"] = enrollment.to_dict()
        return info

    def list_devices(self) -> list[dict]:
        devices = self.db.list_devices()
        enrollments = {e.device_id: e.to_dict() for e in self.db.list_enrollments()}
        result = []
        for device in devices:
            info = {
                "device_id": device["device_id"],
                "bit_size": device["bit_size"],
                "min_firmware_version": device["min_firmware_version"],
                "created_at": device["created_at"],
            }
            if device["device_id"] in enrollments:
                info["enrollment"] = enrollments[device["device_id"]]
            result.append(info)
        return result

    def delete_device(self, device_id: str) -> dict:
        """Remove a device so it can be re-provisioned.

        Deletes the PUF enrollment, certificate, firmware images, and
        one-time challenges (via ``db.delete_device``), drops the PUF from
        the in-memory cache, and removes the device's key/cert files from
        the key store. Audit logs are preserved.
        """
        if not self.db.get_device(device_id):
            raise DeviceNotFound(f"device {device_id!r} not found")
        self.db.delete_device(device_id)
        self.pki.key_store.delete_scope("device", device_id)
        self._pufs.pop(device_id, None)
        logger.info("Deleted device %s (re-provisioning allowed)", device_id)
        return {"device_id": device_id, "deleted": True}

    def puf_for(self, device_id: str) -> SRAMPUF:
        """Return the PUF object for a provisioned device.

        The PUF is reconstructed from the seed stored at provisioning
        time, so the hardware identity is stable across requests and
        process restarts.
        """
        if device_id not in self._pufs:
            device = self.db.get_device(device_id)
            if not device:
                raise DeviceNotFound(f"device {device_id!r} not found")
            try:
                seed = bytes.fromhex(device["puf_seed"])
            except (TypeError, ValueError) as exc:
                raise RuntimeError(f"device {device_id!r} has a corrupt PUF seed in the database") from exc
            self._pufs[device_id] = SRAMPUF(device_id, bit_size=int(device["bit_size"]), seed=seed)
        return self._pufs[device_id]

    # -- PUF testing / analysis ----------------------------------------

    def test_puf(self, device_id: str, num_captures: int = DEFAULT_CAPTURES) -> dict:
        """Re-read a device's PUF and verify it against its enrollment.

        The device's certified public key is supplied so the PUF-to-key
        binding is verified along with the credential.
        """
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        enrollment = self.db.get_enrollment(device_id)
        if enrollment is None:
            raise NoEnrollmentError(f"device {device_id!r} has no PUF enrollment")

        puf = self.puf_for(device_id)
        cert = self.pki.get_device_certificate(device_id)
        return PUFEnrollment.test(
            puf,
            enrollment,
            num_captures=num_captures,
            device_public_key=serialize_public_key(cert.public_key()),
        )

    # -- challenge-response authentication ------------------------------

    def issue_auth_challenge(self, device_id: str) -> dict:
        """Issue a fresh one-time challenge for a provisioned device."""
        if not self.db.get_device(device_id):
            raise DeviceNotFound(f"device {device_id!r} not found")
        return self.auth.issue_challenge(device_id)

    def authenticate_device(self, device_id: str, challenge_b64: str, signature_b64: str) -> dict:
        """Authenticate a device by signed challenge response.

        Verifies the one-time challenge, the signature against the
        registered certificate public key, the certificate chain, and the
        PUF-to-key binding. Raises ``AuthenticationError`` on failure.
        """
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        enrollment = self.db.get_enrollment(device_id)
        if enrollment is None:
            raise NoEnrollmentError(f"device {device_id!r} has no PUF enrollment")
        puf = self.puf_for(device_id)
        return self.auth.authenticate(
            device_id=device_id,
            challenge_b64=challenge_b64,
            signature_b64=signature_b64,
            puf=puf,
            enrollment=enrollment,
        )

    def puf_analysis(self) -> dict:
        """Fleet-wide PUF statistics: uniqueness, reliability, BER, and per-device summary.

        ``stability_mask`` (hex, 1 = stable cell) and ``reference`` (hex,
        stable-only reference with unstable cells zeroed) are the enrolled
        helper data used by the console to render the real per-cell
        response (stable-1 / stable-0 / unstable); no credential or secret
        is included. Note that in this software simulation the PUF response
        itself is derivable from the stored ``puf_seed``, so these fields
        must not be relied on as a secret (see README limitations).
        """
        enrollments = self.db.list_enrollments()
        if not enrollments:
            return {
                "device_count": 0,
                "total_captures": 0,
                "mean_reliability": None,
                "mean_bit_error_rate": None,
                "mean_intra_device_hd": None,
                "mean_inter_device_hd": None,
                "mean_uniqueness": None,
                "devices": [],
            }
        mean_reliability = sum(e.reliability for e in enrollments) / len(enrollments)
        mean_ber = sum(e.bit_error_rate for e in enrollments) / len(enrollments)
        mean_intra = sum(e.intra_device_hd for e in enrollments) / len(enrollments)
        uniqueness = PUFEnrollment.mean_inter_device_hd([e.reference for e in enrollments])
        return {
            "device_count": len(enrollments),
            "total_captures": sum(e.num_captures for e in enrollments),
            "mean_reliability": round(mean_reliability, 6),
            "mean_bit_error_rate": round(mean_ber, 6),
            "mean_intra_device_hd": round(mean_intra, 6),
            "mean_inter_device_hd": round(uniqueness, 6),
            "mean_uniqueness": round(uniqueness, 6),
            "devices": [
                {
                    "device_id": e.device_id,
                    "bit_size": e.bit_size,
                    "num_captures": e.num_captures,
                    "stable_bit_count": e.stable_bit_count,
                    "unstable_bit_count": e.unstable_bit_count,
                    "reliability": round(e.reliability, 6),
                    "bit_error_rate": round(e.bit_error_rate, 6),
                    "intra_device_hd": round(e.intra_device_hd, 6),
                    "uniqueness": round(e.uniqueness, 6) if e.uniqueness is not None else None,
                    "stability_mask": e.stability_mask.hex(),
                    "reference": e.reference.hex(),
                }
                for e in enrollments
            ],
        }

    # -- firmware ------------------------------------------------------

    def sign_firmware(self, version: str, device_id: str, payload: bytes | None = None) -> FirmwareImage:
        """Build and cryptographically sign a firmware image for a device.

        The image is signed with the device's key (identity) and the
        manufacturer's key (manifest: version + device id + payload
        SHA-256). The manufacturer private key stays in the key store and
        is never returned. ``version`` must be a well-formed dotted
        numeric version (validated up front so stored policies are always
        comparable).
        """
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        parse_version(version)

        payload = payload if payload is not None else DEFAULT_FIRMWARE_PAYLOAD
        private_key = self.pki.key_store.load_private_key("device", device_id)
        if private_key is None:
            raise NoFirmwareError(f"no private key stored for device {device_id!r}")

        manufacturer_key = ensure_manufacturer_key(self.pki.key_store)
        image = FirmwareImage(version=version, device_id=device_id, payload=payload)
        return image.sign(private_key).sign_manifest(manufacturer_key)

    def create_firmware(self, version: str, device_id: str, payload: bytes | None = None) -> dict:
        """Build, sign, and store a firmware image for a device."""
        image = self.sign_firmware(version, device_id, payload)
        self.db.save_firmware(image.version, image.device_id, image.to_bundle())
        logger.info("Created firmware %s for %s", image.version, image.device_id)
        return image.to_bundle()

    def store_firmware_image(self, image: FirmwareImage) -> dict:
        """Persist an already-signed firmware image without re-signing it."""
        self.db.save_firmware(image.version, image.device_id, image.to_bundle())
        logger.info("Stored firmware %s for %s", image.version, image.device_id)
        return image.to_bundle()

    def list_firmware(self, device_id: str | None = None) -> list[dict]:
        return self.db.list_firmware(device_id)

    def get_manufacturer_public_key(self) -> dict:
        """Export the trusted manufacturer public key (never the private key)."""
        public_key = load_manufacturer_public_key(self.pki.key_store)
        return {
            "algorithm": "ECDSA",
            "curve": public_key.curve.name,
            "public_key_b64": b64encode(serialize_public_key(public_key)),
        }

    def get_device_certificate_info(self, device_id: str) -> dict:
        """Export a device's certificate and its chain-of-trust status.

        The private key is never exposed; only the certificate (PEM + parsed
        fields) and the result of the real RFC 5280 chain verification are
        returned.
        """
        if not self.db.get_device(device_id):
            raise DeviceNotFound(f"device {device_id!r} not found")
        cert = self.pki.get_device_certificate(device_id)
        self.db.save_certificate(device_id, cert)
        errors = self.pki.verify_chain(cert)
        public_key = cert.public_key()

        key_usage_names: list[str] = []
        try:
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            for attr in (
                "digital_signature", "content_commitment", "key_encipherment",
                "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
            ):
                if getattr(usage, attr):
                    key_usage_names.append(attr)
        except x509.ExtensionNotFound:
            pass

        return {
            "device_id": device_id,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "is_ca": bool(is_ca_certificate(cert)),
            "key_usage": key_usage_names,
            "public_key": {
                "algorithm": "ECDSA",
                "curve": public_key.curve.name,
                "fingerprint_sha256": sha256(serialize_public_key(public_key)).hex(),
            },
            "pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "chain_valid": not errors,
            "chain_errors": errors,
        }

    # -- anti-rollback policy ------------------------------------------

    def get_minimum_firmware_version(self, device_id: str) -> str:
        """Return the device's minimum allowed firmware version ('' = unrestricted)."""
        if not self.db.get_device(device_id):
            raise DeviceNotFound(f"device {device_id!r} not found")
        return self.db.get_min_firmware_version(device_id)

    def set_minimum_firmware_version(self, device_id: str, version: str) -> dict:
        """Set the anti-rollback floor for a device.

        ``version`` is validated as a strict dotted-numeric version
        (raises :class:`VersionError` for malformed input) so the stored
        policy is always comparable. An empty string clears the policy.
        """
        if not self.db.get_device(device_id):
            raise DeviceNotFound(f"device {device_id!r} not found")
        if version != "":
            parse_version(version)
        self.db.set_min_firmware_version(device_id, version)
        logger.info("Set minimum firmware version for %s to %r", device_id, version)
        return {"device_id": device_id, "min_firmware_version": version}

    def verify_firmware(self, device_id: str, firmware_version: str) -> dict:
        """Verify a stored firmware image: hash integrity + both signatures.

        Checks the SHA-256 payload hash against the registered manifest,
        the device signature against the device certificate public key,
        the manufacturer signature against the trusted manufacturer
        public key, and the anti-rollback version policy. ``verified`` is
        only true when all of them hold.
        """
        if not self.db.get_device(device_id):
            raise DeviceNotFound(f"device {device_id!r} not found")
        images = self.db.list_firmware(device_id)
        matching = [i for i in images if i["version"] == firmware_version]
        if not matching:
            raise NoFirmwareError(f"no firmware version {firmware_version!r} for device {device_id!r}")
        bundle = matching[0]["bundle"]

        try:
            image = FirmwareImage.from_bundle(bundle)
            hash_valid = True
        except ValueError:
            # payload_b64 was modified: reconstruct to report the live digest.
            image = FirmwareImage(bundle["version"], bundle["device_id"], b64decode(bundle["payload_b64"]))
            hash_valid = False

        cert = self.pki.get_device_certificate(device_id)
        manufacturer_key = ensure_manufacturer_key(self.pki.key_store)
        device_valid = image.verify(cert.public_key())
        manufacturer_valid = image.verify_manifest(manufacturer_key.public_key())
        minimum_version = self.db.get_min_firmware_version(device_id)
        try:
            allowed = version_allowed(firmware_version, minimum_version)
        except VersionError:
            allowed = False
        return {
            "device_id": device_id,
            "version": firmware_version,
            "minimum_version": minimum_version or None,
            "version_allowed": allowed,
            "hash_valid": hash_valid,
            "payload_sha256": image.payload_digest,
            "device_signature_valid": device_valid,
            "manufacturer_signature_valid": manufacturer_valid,
            "verified": hash_valid and device_valid and manufacturer_valid and allowed,
        }

    # -- secure boot ---------------------------------------------------

    def _boot_assets(self, device_id: str, firmware_version: str | None):
        """Shared lookup used by boot and attack flows.

        Returns ``(enrollment, image, expected_sha256)`` where
        ``expected_sha256`` is the digest registered for the selected image.
        """
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        enrollment = self.db.get_enrollment(device_id)
        if enrollment is None:
            raise NoEnrollmentError(f"device {device_id!r} has no PUF enrollment")

        images = self.db.list_firmware(device_id)
        if not images:
            raise NoFirmwareError(f"no firmware available for device {device_id!r}")
        if firmware_version:
            images = [i for i in images if i["version"] == firmware_version]
            if not images:
                raise NoFirmwareError(f"no firmware version {firmware_version!r} for device {device_id!r}")

        bundle = images[0]["bundle"]
        image = FirmwareImage.from_bundle(bundle)
        return enrollment, image, bundle.get("payload_sha256")

    def _device_challenge_response(self, device_id: str) -> tuple[str, str]:
        """Simulate the genuine device answering a fresh one-time challenge.

        Returns ``(challenge_b64, signature_b64)`` produced with the
        device's own private key, so the boot engine's challenge-response
        stage has a real signature to verify. Callers that want to test a
        failed challenge can pass their own (invalid) values instead.
        """
        issued = self.auth.issue_challenge(device_id)
        challenge_b64 = issued["challenge_b64"]
        signature_b64 = self._sign_challenge_b64(device_id, challenge_b64)
        return challenge_b64, signature_b64

    def _sign_challenge_b64(self, device_id: str, challenge_b64: str) -> str:
        """Sign a challenge exactly as the genuine device would."""
        private_key = self.pki.key_store.load_private_key("device", device_id)
        if private_key is None:
            raise NoFirmwareError(f"no private key stored for device {device_id!r}")
        return b64encode(sign_challenge(private_key, device_id, b64decode(challenge_b64)))

    def run_boot(
        self,
        device_id: str,
        firmware_version: str | None = None,
        challenge_b64: str | None = None,
        signature_b64: str | None = None,
    ) -> dict:
        """Simulate a full secure boot and record the audit log.

        When no challenge response is supplied, the genuine device is
        simulated: a challenge is issued and signed with the device's
        private key so the challenge-response stage is exercised for real.
        """
        enrollment, image, expected_sha256 = self._boot_assets(device_id, firmware_version)
        puf = self.puf_for(device_id)
        minimum_version = self.db.get_min_firmware_version(device_id)
        if not (challenge_b64 and signature_b64):
            challenge_b64, signature_b64 = self._device_challenge_response(device_id)

        result = self.boot.verify_boot(
            device_id=device_id,
            puf=puf,
            enrollment=enrollment,
            image=image,
            minimum_version=minimum_version,
            expected_sha256=expected_sha256,
            challenge_b64=challenge_b64,
            signature_b64=signature_b64,
        )
        self._log_boot(device_id, image.version, result)
        logger.info("Boot attempt for %s -> %s (%s)", device_id, result.decision.value, result.status.value)
        return result.to_dict()

    # -- attacks -------------------------------------------------------

    def list_attack_scenarios(self) -> list[dict]:
        return self.attacks.list_scenarios()

    def run_attack(
        self,
        attack_name: str,
        device_id: str,
        firmware_version: str | None = None,
        challenge_b64: str | None = None,
        signature_b64: str | None = None,
    ) -> dict:
        """Run a simulated attack through the *real* secure boot pipeline.

        Every attack mutates the actual data the boot engine verifies (the
        PUF response, the firmware payload or signer, the stored device
        certificate, the one-time challenge state, or the image selected
        for boot) and is then evaluated by ``verify_boot``. The recorded
        result, detection point, and reason are read from the pipeline's
        BootResult - never hardcoded.

        ``firmware_rollback`` targets ``firmware_version`` (an older,
        legitimately-signed image) and is only blocked if the device's real
        anti-rollback policy rejects it; without a policy the pipeline will
        honestly report BOOT_ALLOWED.
        """
        enrollment, image, expected_sha256 = self._boot_assets(device_id, firmware_version)
        puf = self.puf_for(device_id)
        bit_size = int(self.db.get_device(device_id)["bit_size"])
        minimum_version = self.db.get_min_firmware_version(device_id)

        if attack_name == "clone_device":
            puf = self.attacks.clone_device(device_id, bit_size=bit_size)
        elif attack_name == "tamper_firmware":
            image = self.attacks.tamper_firmware(image)
        elif attack_name == "wrong_signer":
            unauthorized = ec.generate_private_key(ec.SECP256R1())
            image = self.attacks.wrong_signer(image, unauthorized)
        elif attack_name == "certificate_forgery":
            self.attacks.forge_certificate(self.pki, device_id)
        elif attack_name == "replay_challenge":
            # The attacker captured a genuine signed challenge from an
            # earlier legitimate boot. That challenge has since been
            # consumed; replaying the same (challenge, signature) must be
            # rejected by the real challenge-response stage.
            issued = self.auth.issue_challenge(device_id)
            challenge_b64 = issued["challenge_b64"]
            signature_b64 = self._sign_challenge_b64(device_id, challenge_b64)
            self.db.consume_challenge(challenge_b64, device_id)
        elif attack_name == "firmware_rollback":
            if firmware_version is None:
                raise NoFirmwareError(
                    "firmware_rollback requires firmware_version (the older image being rolled back to)"
                )
        else:
            raise NoFirmwareError(f"unknown attack: {attack_name!r}")

        if not (challenge_b64 and signature_b64):
            challenge_b64, signature_b64 = self._device_challenge_response(device_id)

        result = self.boot.verify_boot(
            device_id=device_id,
            puf=puf,
            enrollment=enrollment,
            image=image,
            minimum_version=minimum_version,
            expected_sha256=expected_sha256,
            challenge_b64=challenge_b64,
            signature_b64=signature_b64,
        )

        record = self._attack_record(attack_name, device_id, firmware_version, result)
        self.db.log_attack(**record)
        self.db.log_security_event(
            event_type="attack",
            device_id=device_id,
            severity="critical" if record["result"] == "BOOT_BLOCKED" else "warning",
            result=record["result"],
            summary=record["reason"],
            details={
                "attack": attack_name,
                "detection_point": record["detection_point"],
                "firmware_version": record["firmware_version"],
            },
            timestamp=record["timestamp"],
        )
        self._log_boot(device_id, image.version, result)
        logger.info(
            "Attack %s on %s -> %s, detected at %s",
            attack_name, device_id, record["result"], record["detection_point"],
        )
        result_dict = result.to_dict()
        result_dict.update(record)
        result_dict["expected_failure"] = result.status is not BootStatus.SUCCESS
        return result_dict

    @staticmethod
    def _attack_record(attack_name: str, device_id: str, firmware_version: str | None, result) -> dict:
        """Build the persisted attack record from the pipeline's real outcome.

        ``detection_point`` is the first boot stage that did not pass; it is
        ``None`` when the pipeline allowed the boot (the attack was not
        caught by the configured defences).
        """
        detection_point = None
        for key in BOOT_STAGE_ORDER:
            stage = result.stages.get(key)
            if stage is not None and not stage["passed"]:
                detection_point = key
                break
        return {
            "attack": attack_name,
            "target": device_id,
            "firmware_version": firmware_version,
            "detection_point": detection_point,
            "result": result.decision.value,
            "reason": result.message,
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        }

    # -- logs ----------------------------------------------------------

    def list_boot_logs(self, limit: int = 100) -> list[dict]:
        return self.db.list_boot_logs(limit)

    def list_attack_logs(self, limit: int = 100) -> list[dict]:
        return self.db.list_attack_logs(limit)

    def list_authentication_logs(self, limit: int = 100, device_id: str | None = None) -> list[dict]:
        return self.db.list_authentication_events(limit, device_id=device_id)

    # -- security events -------------------------------------------------

    def list_security_events(
        self,
        limit: int = 100,
        event_type: str | None = None,
        device_id: str | None = None,
    ) -> list[dict]:
        """Chronological security event feed.

        Rows are the timestamped events written on every authentication,
        secure boot, and attack attempt (see ``db.log_security_event``).
        """
        return self.db.list_security_events(limit, event_type=event_type, device_id=device_id)

    # -- dashboard statistics ---------------------------------------------

    def dashboard_stats(self) -> dict:
        """Aggregate fleet, boot, attack, auth, and event counts for a dashboard."""
        devices = self.db.list_devices()
        firmware = self.db.list_firmware()
        boot_counts = self.db.count_boot_logs_by_status()
        attack_counts = self.db.count_attack_logs_by_result()

        boots_total = sum(
            count for status, count in boot_counts.items()
            if status not in ("auth_success", "auth_failed")
        )
        boots_allowed = boot_counts.get("success", 0)
        boots_blocked = boots_total - boots_allowed

        attack_total = sum(attack_counts.values())
        attack_blocked = attack_counts.get("BOOT_BLOCKED", 0)

        events = self.list_security_events(limit=10000)
        critical = sum(1 for event in events if event["severity"] == "critical")
        high = sum(1 for event in events if event["severity"] == "high")
        warning = sum(1 for event in events if event["severity"] == "warning")
        info = sum(1 for event in events if event["severity"] == "info")

        puf = self.puf_analysis()
        return {
            "devices": {"total": len(devices)},
            "firmware": {
                "total_images": len(firmware),
                "devices_with_firmware": len({item["device_id"] for item in firmware}),
            },
            "boots": {
                "total": boots_total,
                "allowed": boots_allowed,
                "blocked": boots_blocked,
                "success_rate": round(boots_allowed / boots_total, 4) if boots_total else None,
            },
            "auth": {
                "successes": boot_counts.get("auth_success", 0),
                "failures": boot_counts.get("auth_failed", 0),
            },
            "attacks": {
                "total": attack_total,
                "blocked": attack_blocked,
                "allowed": attack_total - attack_blocked,
                "blocked_rate": round(attack_blocked / attack_total, 4) if attack_total else None,
            },
            "security": {
                "events_total": len(events),
                "critical": critical,
                "high": high,
                "warning": warning,
                "info": info,
            },
            "puf": {
                "device_count": puf["device_count"],
                "mean_reliability": puf["mean_reliability"],
                "mean_uniqueness": puf["mean_uniqueness"],
                "mean_bit_error_rate": puf["mean_bit_error_rate"],
            },
        }

    def _log_boot(self, device_id: str, image_version: str | None, result) -> None:
        """Persist a boot decision with its per-stage checks.

        Each secure boot attempt also writes a timestamped security event
        (severity: ``info`` for a clean boot, ``high`` for a failed
        authentication, ``critical`` for any blocked boot).
        """
        checks = dict(result.checks)
        checks["decision"] = result.decision.value
        status = result.status.value
        self.db.log_boot(device_id, image_version, status, result.message, checks)
        self.db.log_security_event(
            event_type="boot",
            device_id=device_id,
            severity=self._severity_for_boot_status(status),
            result=status,
            summary=result.message,
            details={"decision": result.decision.value, "image_version": image_version, "checks": checks},
        )

    @staticmethod
    def _severity_for_boot_status(status: str) -> str:
        if status in ("success", "auth_success"):
            return "info"
        if status == "auth_failed":
            return "high"
        return "critical"
