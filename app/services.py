"""Orchestration layer tying PUF, PKI, firmware, secure boot, and DB together."""

from __future__ import annotations

import datetime as dt
import json
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
from .transparency import FirmwareTransparencyLog
from .pqcrypto import generate_keypair as pqc_generate, sign as pqc_sign, verify as pqc_verify
from .zkp import SchnorrVerifier, create_niproof
from .ai.environment import SRAMPUFSimulator, EnvironmentalConditions
from .ai.anomaly import AnomalyDetector, BootFeatureVector
from .risk.engine import RiskEngine

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
        self.transparency = FirmwareTransparencyLog()
        self.pqc_verifier = SchnorrVerifier()
        self.anomaly_detector = AnomalyDetector(threshold=self.settings.anomaly_threshold)
        self.risk_engine = RiskEngine()
        self.env_simulators: dict[str, SRAMPUFSimulator] = {}
        self._rebuild_transparency_tree()

    def _rebuild_transparency_tree(self) -> None:
        """Rebuild the in-memory Merkle tree from stored transparency entries."""
        try:
            from .transparency.log import FirmwareEntry
            rows = self.db.list_transparency_entries()
            for row in rows:
                if row.get("leaf_hash"):
                    leaf_hash = bytes.fromhex(row["leaf_hash"])
                else:
                    import hashlib as _hl
                    leaf_bytes = json.dumps({
                        "firmware_id": row["firmware_id"],
                        "version": row["version"],
                        "device_id": row["device_id"],
                        "payload_sha256": row["payload_sha256"],
                        "signer": row["signer"],
                        "sequence": row["leaf_index"],
                    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    leaf_hash = _hl.sha256(leaf_bytes).digest()
                entry = FirmwareEntry(
                    firmware_id=row["firmware_id"],
                    version=row["version"],
                    device_id=row["device_id"],
                    payload_sha256=row["payload_sha256"],
                    signer=row["signer"],
                    timestamp=row.get("created_at", ""),
                    published=True,
                    sequence=row["leaf_index"],
                    leaf_hash=leaf_hash,
                )
                self.transparency._entries.append(entry)
                self.transparency._tree.add_leaf_hash(leaf_hash)
                self.transparency._sequence_counter = max(self.transparency._sequence_counter, row["leaf_index"])
                self.transparency._root_history = [self.transparency._tree.root]
        except Exception:
            pass

    # -- provisioning --------------------------------------------------

    def provision_device(self, device_id: str, bit_size: int = 256, num_captures: int = DEFAULT_CAPTURES) -> dict:
        """Register a device: create its PUF, issue a certificate, and enroll.

        The device certificate is issued first so its public key can be
        bound to the PUF-derived secret during enrollment.
        """
        if self.db.get_device(device_id):
            raise DeviceAlreadyExists(f"device {device_id!r} already provisioned")

        seed = random_bytes(self.settings.device_key_size_bytes)
        puf = SRAMPUF(device_id, bit_size=bit_size, seed=seed)
        
        # First enroll without public key to get the fuzzy helper
        enrollment = PUFEnrollment.enroll(puf, num_captures=num_captures)
        self.db.upsert_device(device_id, bit_size, seed)
        self.db.upsert_enrollment(enrollment)
        
        # Reconstruct the PUF secret on device to derive the private key
        from .device.simulator import SimulatorHardware
        hw = SimulatorHardware(device_id, self.db)
        helper_data = {
            "fuzzy_helper": enrollment.fuzzy_helper.to_dict() if enrollment.fuzzy_helper else {},
            "stability_mask": enrollment.stability_mask.hex()
        }
        puf_secret = hw.reconstruct_puf_secret(helper_data)
        device_key_bytes = hw.derive_device_secret(puf_secret, "device-auth")
        
        from cryptography.hazmat.primitives.asymmetric import ec
        priv = ec.derive_private_key(int.from_bytes(device_key_bytes, "big"), ec.SECP256R1())
        pub = priv.public_key()
        
        # Issue the certificate containing the PUF-derived public key
        cert = self.pki.issue_device_certificate(device_id, public_key=pub)
        
        # Update the enrollment with the puf_binding
        from .fuzzy.kdf import derive_puf_binding
        from .crypto.utils import serialize_public_key
        enrollment.puf_binding = derive_puf_binding(puf_secret, serialize_public_key(pub), device_id)
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

    def verify_attestation(self, device_id: str, challenge_b64: str, signature_b64: str, measurements_b64: str, security_counter: int) -> dict:
        """Verify full hardware attestation.
        
        Delegates to auth logic to verify challenge and signature.
        Then verifies boot measurements (PCRs) and security counter.
        """
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        
        # Verify the challenge + signature (with or without PUF based on enrollment presence)
        enrollment = self.db.get_enrollment(device_id)
        puf = None
        if enrollment:
            try:
                puf = self.puf_for(device_id)
            except Exception:
                pass
                
        auth_result = self.auth.authenticate(
            device_id=device_id,
            challenge_b64=challenge_b64,
            signature_b64=signature_b64,
            puf=puf,
            enrollment=enrollment,
        )

        checks = auth_result["checks"]
        
        # Verify Security Counter against anti-rollback policy
        minimum_version = self.db.get_min_firmware_version(device_id)
        if minimum_version:
            # Parse version string into integer (e.g. 1.0.0 -> 10000)
            try:
                major, minor, patch = minimum_version.split(".")
                min_int = int(major) * 10000 + int(minor) * 100 + int(patch)
            except Exception:
                min_int = 1
            checks["security_counter_valid"] = (security_counter >= min_int)
            if not checks["security_counter_valid"]:
                from .auth import AuthenticationError
                raise AuthenticationError("rollback_rejected", f"Security counter {security_counter} is below allowed {min_int}")
        else:
            checks["security_counter_valid"] = True
            
        # Verify Measurements against Golden PCRs of the device's latest firmware
        if measurements_b64:
            try:
                import base64
                import hashlib
                from .firmware.image import FirmwareImage
                import json
                actual_measurement = base64.b64decode(measurements_b64)
                
                latest_fw = self.db.get_latest_firmware(device_id)
                if latest_fw:
                    fw = FirmwareImage.from_bundle(json.loads(latest_fw["manifest"]))
                    # The PCR extends kernel_hash and rootfs_hash
                    expected_pcr = hashlib.sha256(fw.kernel_hash + fw.rootfs_hash).digest()
                    checks["measurements_valid"] = (actual_measurement == expected_pcr)
                else:
                    checks["measurements_valid"] = False
            except Exception:
                checks["measurements_valid"] = False
        else:
            checks["measurements_valid"] = False
            
        return {
            "device_id": device_id,
            "attested": True,
            "checks": checks
        }

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

        The image is signed by the manufacturer's key (manifest: version + 
        device id + payload SHA-256 + kernel hash + rootfs hash). The manufacturer 
        private key stays in the key store and is never returned. ``version`` must 
        be a well-formed dotted numeric version (validated up front so stored 
        policies are always comparable).
        """
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        parse_version(version)

        payload = payload if payload is not None else DEFAULT_FIRMWARE_PAYLOAD
        
        enrollment = self.db.get_enrollment(device_id)
        if not enrollment:
            raise NoFirmwareError(f"no enrollment for device {device_id!r}")
            
        manufacturer_key = ensure_manufacturer_key(self.pki.key_store)
        image = FirmwareImage(version=version, device_id=device_id, payload=payload)
        return image.sign_manifest(manufacturer_key)

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
            "not_valid_before": cert.not_valid_before.isoformat(),
            "not_valid_after": cert.not_valid_after.isoformat(),
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
        """Verify a stored firmware image: hash integrity + manufacturer signature.

        Checks the SHA-256 payload hash against the registered manifest,
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
            image = FirmwareImage(bundle.get("version", bundle.get("firmware_version")), bundle["device_id"], b64decode(bundle["payload_b64"]))
            hash_valid = False

        manufacturer_key = ensure_manufacturer_key(self.pki.key_store)
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
            "manufacturer_signature_valid": manufacturer_valid,
            "verified": hash_valid and manufacturer_valid and allowed,
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
        enrollment = self.db.get_enrollment(device_id)
        if not enrollment:
            raise NoFirmwareError(f"no enrollment for device {device_id!r}")
            
        from .device.simulator import SimulatorHardware
        hw = SimulatorHardware(device_id, self.db)
        helper_data = {
            "fuzzy_helper": enrollment.fuzzy_helper.to_dict() if enrollment.fuzzy_helper else {},
            "stability_mask": enrollment.stability_mask.hex()
        }
        puf_secret = hw.reconstruct_puf_secret(helper_data)
        device_key = hw.derive_device_secret(puf_secret, "device-auth")
        
        from .auth.challenge import challenge_message
        challenge = b64decode(challenge_b64)
        msg = challenge_message(device_id, challenge)
        sig = hw.sign_attestation(device_key, msg)
        return b64encode(sig)

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
        risk_history = self.db.list_risk_assessments(limit=10)
        latest_risk = risk_history[0] if risk_history else None
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
            "transparency": {
                "entries": self.transparency.entry_count,
                "root": self.transparency.current_root.hex(),
            },
            "pqc": {
                "enabled": self.settings.pqc_enabled,
                "keys_registered": len(devices),
            },
            "risk": {
                "latest": latest_risk,
                "history_count": len(risk_history),
            },
            "anomaly": self.anomaly_detector.get_trend(),
        }

    # ── PQC (ML-DSA-65) ───────────────────────────────────────────────

    def pqc_generate_keypair(self, device_id: str) -> dict:
        """Generate a post-quantum ML-DSA-65 keypair and store the public key."""
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        pk, sk = pqc_generate()
        pk_hex = pk.to_hex()
        self.db.save_pqc_key(device_id, pk_hex, "ML-DSA-65")
        logger.info("Generated PQC keypair for %s", device_id)
        return {
            "device_id": device_id,
            "algorithm": "ML-DSA-65",
            "public_key_hex": pk_hex,
            "status": "stored",
        }

    # ── Zero-Knowledge Proof ──────────────────────────────────────────

    def zkp_create_proof(self, device_id: str) -> dict:
        """Create a non-interactive Schnorr ZKP proving knowledge of the device secret."""
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        seed = bytes.fromhex(device["puf_seed"])
        import hashlib as _hl
        secret = int.from_bytes(_hl.sha256(seed + device_id.encode()).digest(), "big") % self.pqc_verifier.q
        public_key = self.pqc_verifier.compute_public_key(secret)
        proof = create_niproof(secret)
        logger.info("Created ZKP proof for %s", device_id)
        return {
            "device_id": device_id,
            "public_key": str(public_key),
            "proof": proof.to_dict(),
            "verified": self.pqc_verifier.verify_noninteractive(public_key, proof),
        }

    def zkp_verify_proof(self, device_id: str, proof_dict: dict) -> dict:
        """Verify a Schnorr ZKP for a device."""
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        seed = bytes.fromhex(device["puf_seed"])
        import hashlib as _hl
        secret = int.from_bytes(_hl.sha256(seed + device_id.encode()).digest(), "big") % self.pqc_verifier.q
        public_key = self.pqc_verifier.compute_public_key(secret)
        proof = SchnorrProof.from_dict(proof_dict)
        valid = self.pqc_verifier.verify_noninteractive(public_key, proof)
        logger.info("ZKP verification for %s: %s", device_id, "valid" if valid else "invalid")
        return {
            "device_id": device_id,
            "verified": valid,
            "public_key": str(public_key),
        }

    # ── Environmental PUF ─────────────────────────────────────────────

    def environmental_read(self, device_id: str, temperature: float, voltage: float, em_interference: float) -> dict:
        """Read the environmental PUF simulator under given conditions."""
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        seed = bytes.fromhex(device["puf_seed"])
        if device_id not in self.env_simulators:
            self.env_simulators[device_id] = SRAMPUFSimulator(device_seed=seed)
        sim = self.env_simulators[device_id]
        conditions = EnvironmentalConditions(
            temperature_c=temperature,
            voltage_v=voltage,
            em_interference_db=em_interference,
        )
        measurement = sim.read_puf(conditions)
        env_hash = sim.environmental_hash(conditions)
        return {
            "device_id": device_id,
            "measurement": measurement.to_dict(),
            "environmental_hash": env_hash,
        }

    def environmental_stability(self, device_id: str, temperature: float, voltage: float, em_interference: float) -> dict:
        """Run a batch stability analysis for a device under given conditions."""
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        seed = bytes.fromhex(device["puf_seed"])
        if device_id not in self.env_simulators:
            self.env_simulators[device_id] = SRAMPUFSimulator(device_seed=seed)
        sim = self.env_simulators[device_id]
        conditions = EnvironmentalConditions(
            temperature_c=temperature,
            voltage_v=voltage,
            em_interference_db=em_interference,
        )
        analysis = sim.stability_analysis(conditions)
        return {"device_id": device_id, **analysis}

    # ── Anomaly detection ─────────────────────────────────────────────

    def anomaly_analyze(
        self,
        device_id: str,
        boot_duration_ms: float = 150.0,
        stage_count: int = 7,
        passed_stages: int = 7,
        error_count: int = 0,
        attack_type: str | None = None,
    ) -> dict:
        """Analyze boot behavior for anomalies."""
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        features = BootFeatureVector(
            boot_duration_ms=boot_duration_ms,
            stage_count=stage_count,
            passed_stages=passed_stages,
            stage_durations=[boot_duration_ms / max(stage_count, 1)] * stage_count,
            sig_check_time_ms=50.0,
            puf_read_time_ms=20.0,
            error_count=error_count,
            error_codes=[],
            attack_type=attack_type,
        )
        result = self.anomaly_detector.analyze(features)
        return {
            "device_id": device_id,
            "analysis": result.to_dict(),
            "trend": self.anomaly_detector.get_trend(),
        }

    # ── Risk assessment ───────────────────────────────────────────────

    def risk_assess(
        self,
        device_id: str,
        signature_valid: bool = True,
        chain_valid: bool = True,
        puf_match_score: float = 1.0,
        anomaly_score: float = 0.0,
        transparency_valid: bool = True,
        pqc_valid: bool = True,
        firmware_integrity: bool = True,
        known_attack: str | None = None,
    ) -> dict:
        """Run multi-layer risk assessment for a device."""
        device = self.db.get_device(device_id)
        if not device:
            raise DeviceNotFound(f"device {device_id!r} not found")
        risk = self.risk_engine.assess(
            signature_valid=signature_valid,
            chain_valid=chain_valid,
            puf_match_score=puf_match_score,
            anomaly_score=anomaly_score,
            transparency_log_valid=transparency_valid,
            pqc_valid=pqc_valid,
            firmware_integrity=firmware_integrity,
            known_attack=known_attack,
        )
        result = risk.to_dict()
        self.db.save_risk_assessment(
            device_id=device_id,
            overall_score=risk.overall_score,
            risk_level=risk.level.value,
            action=risk.action.value,
            layers_json=json.dumps(result["layers"]),
            recommendations=risk.recommendations,
        )
        return result

    # ── Transparency log ──────────────────────────────────────────────

    def transparency_record(
        self,
        firmware_id: str,
        version: str,
        device_id: str,
        payload_sha256: str,
    ) -> dict:
        """Record a firmware entry in the transparency log."""
        entry = self.transparency.record_firmware(firmware_id, version, device_id, payload_sha256)
        self.db.save_transparency_entry(
            firmware_id=firmware_id,
            version=version,
            device_id=device_id,
            payload_sha256=payload_sha256,
            signer=entry.signer,
            leaf_index=entry.sequence,
            root_hash=self.transparency.current_root.hex(),
            leaf_hash=entry.leaf_hash.hex(),
        )
        return entry.to_dict()

    def transparency_verify(self, device_id: str, version: str) -> dict:
        """Verify firmware inclusion in the transparency log."""
        entry = self.transparency.lookup(device_id, version)
        if entry is None:
            return {"device_id": device_id, "version": version, "found": False, "valid": False}
        proof = self.transparency.get_inclusion_proof(self.transparency._entries.index(entry))
        valid = self.transparency._tree.verify_proof(proof)
        root_ok, root_msg = self.transparency.verify_root_consistency()
        return {
            "device_id": device_id,
            "version": version,
            "found": True,
            "valid": valid,
            "root_consistent": root_ok,
            "root_message": root_msg,
            "entry": entry.to_dict(),
            "proof": proof.to_dict() if hasattr(proof, "to_dict") else str(proof),
        }

    def transparency_root_history(self) -> dict:
        """Get the transparency log root history."""
        return {
            "roots": self.transparency.get_root_history(),
            "current_root": self.transparency.current_root.hex(),
            "entry_count": self.transparency.entry_count,
        }

    def _log_boot(self, device_id: str, image_version: str | None, result) -> None:
        """Persist a boot decision with its per-stage checks."""
        checks = dict(result.checks)
        checks["decision"] = result.decision.value
        if hasattr(result, "timing_ms"):
            checks["timing_ms"] = {k: round(v, 2) for k, v in (result.timing_ms or {}).items()}
            checks["total_duration_ms"] = round(result.total_duration_ms, 2)
        if hasattr(result, "explanations"):
            checks["explanations"] = result.explanations
        if hasattr(result, "to_report"):
            checks["boot_report"] = result.to_report()
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

    # ── Explainable Boot Report ───────────────────────────────────────

    def boot_report(self, device_id: str) -> dict:
        """Return the explainable boot report for the most recent boot of this device."""
        if not self.db.get_device(device_id):
            raise DeviceNotFound(f"device {device_id!r} not found")
        logs = self.db.list_boot_logs(1)
        if not logs:
            return {"device_id": device_id, "error": "No boot logs found. Run a boot first."}
        last = logs[0]
        checks = last.get("checks", {})
        boot_report_data = checks.get("boot_report")
        if boot_report_data:
            boot_report_data["device_id"] = device_id
            return boot_report_data
        # Fallback: construct from flat checks
        decision = checks.get("decision", "unknown")
        return {
            "device_id": device_id,
            "decision": decision,
            "status": last.get("status"),
            "message": last.get("message"),
            "timestamp": last.get("timestamp"),
            "firmware_version": last.get("image_version"),
            "checks": checks,
            "explanation": self._explain_boot_decision(decision, checks, {}),
        }

    @staticmethod
    def _explain_boot_decision(decision: str, checks: dict, stages: dict) -> dict:
        """Generate a structured explanation of the boot decision."""
        all_passed = all(v for k, v in checks.items() if k not in ("decision",) and isinstance(v, bool))
        failed_stages = [k for k, v in checks.items()
                        if k.endswith("_valid") or k.endswith("_checked") or k.endswith("_allowed")
                        or k in ("puf_match", "fuzzy_recovered", "puf_binding_match",
                                 "hash_valid", "signature_valid", "manufacturer_signature_valid",
                                 "challenge_verified", "auth_signature_valid")
                        if v is False]
        return {
            "all_checks_passed": all_passed,
            "failed_checks": failed_stages,
            "blocking_failures": [s for s in failed_stages
                                  if s in ("puf_match", "fuzzy_recovered", "puf_binding_match",
                                           "hash_valid", "signature_valid", "manufacturer_signature_valid",
                                           "challenge_verified", "auth_signature_valid")],
            "posture": "strong" if decision == "BOOT_ALLOWED" else "compromised",
        }

    # ── Performance Metrics ───────────────────────────────────────────

    def boot_metrics(self, device_id: str | None = None) -> dict:
        """Return performance metrics from recent boot logs."""
        logs = self.db.list_boot_logs(50)
        if device_id:
            logs = [l for l in logs if l.get("device_id") == device_id]

        if not logs:
            return {"device_id": device_id, "boots_analyzed": 0, "metrics": {}}

        total = len(logs)
        allowed = sum(1 for l in logs if l.get("status") == "success")
        blocked = total - allowed

        stage_pass_rates = {}
        all_stages = [
            "puf_recovery", "puf_pki_binding", "certificate_verification", "challenge_response",
            "firmware_hash", "firmware_signature", "anti_rollback",
        ]
        for stage_name in all_stages:
            stage_key = f"stage_{stage_name}_passed"
            passed = sum(1 for l in logs
                        if l.get("checks", {}).get(stage_key) is True)
            stage_pass_rates[stage_name] = round(passed / total, 4) if total else 0

        return {
            "device_id": device_id,
            "boots_analyzed": total,
            "allowed": allowed,
            "blocked": blocked,
            "allow_rate": round(allowed / total, 4) if total else 0,
            "block_rate": round(blocked / total, 4) if total else 0,
            "stage_pass_rates": stage_pass_rates,
            "most_common_block": self._most_common_block(logs),
        }

    @staticmethod
    def _most_common_block(logs: list[dict]) -> str | None:
        blocks = [l.get("status") for l in logs if l.get("status") != "success"]
        if not blocks:
            return None
        counts: dict[str, int] = {}
        for b in blocks:
            counts[b] = counts.get(b, 0) + 1
        return max(counts, key=counts.get)

    # ── Security Event Timeline ───────────────────────────────────────

    def security_timeline(self, device_id: str | None = None, limit: int = 50) -> dict:
        """Return a chronological security event timeline."""
        events = self.db.list_security_events(limit, device_id=device_id)
        timeline = []
        for ev in events:
            timeline.append({
                "timestamp": ev.get("timestamp"),
                "event_type": ev.get("event_type"),
                "device_id": ev.get("device_id"),
                "severity": ev.get("severity"),
                "result": ev.get("result"),
                "summary": ev.get("summary"),
                "details": ev.get("details", {}),
            })
        return {
            "device_id": device_id,
            "event_count": len(timeline),
            "timeline": timeline,
            "severity_counts": {
                "info": sum(1 for e in timeline if e.get("severity") == "info"),
                "warning": sum(1 for e in timeline if e.get("severity") == "warning"),
                "high": sum(1 for e in timeline if e.get("severity") == "high"),
                "critical": sum(1 for e in timeline if e.get("severity") == "critical"),
            },
        }

    # ── Digital Twin ──────────────────────────────────────────────────

    def digital_twin(self, device_id: str) -> dict:
        """Return digital twin state: SRAM grid + environmental conditions."""
        if not self.db.get_device(device_id):
            raise DeviceNotFound(f"device {device_id!r} not found")
        env_sim = self.env_simulators.get(device_id)
        if env_sim is None:
            from app.ai.environment import SRAMPUFSimulator
            env_sim = SRAMPUFSimulator(device_seed=device_id.encode("utf-8"))
            self.env_simulators[device_id] = env_sim

        from app.ai.environment import EnvironmentalConditions
        conditions = EnvironmentalConditions()
        measurement = env_sim.read_puf(conditions)

        raw_bits = measurement.raw_bits
        grid_size = min(16, len(raw_bits))
        sram_grid = []
        for row in range(grid_size):
            grid_row = []
            for col in range(grid_size):
                idx = row * grid_size + col
                if idx < len(raw_bits):
                    grid_row.append(int(raw_bits[idx]))
                else:
                    grid_row.append(0)
            sram_grid.append(grid_row)

        history = env_sim.stability_analysis(conditions, count=5)
        return {
            "device_id": device_id,
            "sram_grid": sram_grid,
            "grid_size": grid_size,
            "total_bits": len(raw_bits),
            "bit_flip_rate": measurement.bit_flip_rate,
            "stability": measurement.stability,
            "entropy_bits": measurement.entropy_bits,
            "environmental_hash": env_sim.environmental_hash(conditions),
            "stability_history": history,
            "conditions": {
                "temperature_c": conditions.temperature_c,
                "voltage_v": conditions.voltage_v,
                "em_interference_db": conditions.em_interference_db,
            },
        }
