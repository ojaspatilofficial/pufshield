"""Simulated attacks against the secure boot pipeline.

These are educational scenarios that demonstrate the protections PUFShield
provides. Each attack mutates the *real* data the pipeline verifies (PUF
response, firmware payload, certificate, challenge state, or boot policy)
and is then evaluated by the genuine secure boot engine; the outcome and
detection point are never hardcoded.

Advanced attack techniques (side-channels, machine-learning model
building, EM analysis) are intentionally out of scope for the initial
version.
"""

from __future__ import annotations

import datetime as dt
import enum
import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ..crypto.utils import random_bytes
from ..firmware import FirmwareImage
from ..puf import SRAMPUF

logger = logging.getLogger(__name__)


class AttackType(str, enum.Enum):
    CLONE_DEVICE = "clone_device"
    TAMPER_FIRMWARE = "tamper_firmware"
    WRONG_SIGNER = "wrong_signer"
    REPLAY_CHALLENGE = "replay_challenge"
    CERTIFICATE_FORGERY = "certificate_forgery"
    FIRMWARE_ROLLBACK = "firmware_rollback"
    ENVIRONMENTAL_ATTACK = "environmental_attack"
    PQC_KEY_COMPROMISE = "pqc_key_compromise"
    TRANSPARENCY_TAMPER = "transparency_tamper"
    ANOMALY_EVASION = "anomaly_evasion"
    SIDE_CHANNEL = "side_channel"
    FIRMWARE_INJECTION = "firmware_injection"


class AttackScenario:
    """Describe a single simulated attack."""

    def __init__(self, attack_type: AttackType, description: str) -> None:
        self.attack_type = attack_type
        self.description = description

    @property
    def name(self) -> str:
        return self.attack_type.value

    def to_dict(self) -> dict:
        return {"name": self.attack_type.value, "description": self.description}


class AttackSimulator:
    """Generates adversarial conditions for secure boot testing."""

    def __init__(self) -> None:
        self.scenarios = [
            AttackScenario(AttackType.CLONE_DEVICE, "A cloned device reads back a different SRAM PUF response."),
            AttackScenario(AttackType.TAMPER_FIRMWARE, "An attacker modifies the firmware payload after signing."),
            AttackScenario(AttackType.WRONG_SIGNER, "An attacker signs firmware with an unauthorized device key."),
            AttackScenario(
                AttackType.REPLAY_CHALLENGE,
                "An attacker replays a one-time challenge-response captured from an earlier boot.",
            ),
            AttackScenario(
                AttackType.CERTIFICATE_FORGERY,
                "An attacker re-issues the device key under a rogue CA and swaps in the forged certificate.",
            ),
            AttackScenario(
                AttackType.FIRMWARE_ROLLBACK,
                "An attacker boots an older but legitimately-signed image that violates the minimum-version policy.",
            ),
            AttackScenario(
                AttackType.ENVIRONMENTAL_ATTACK,
                "Attacker manipulates temperature/voltage to cause PUF bit flips and bypass enrollment.",
            ),
            AttackScenario(
                AttackType.PQC_KEY_COMPROMISE,
                "Attacker obtains the ML-DSA-65 private key and forges a post-quantum signature.",
            ),
            AttackScenario(
                AttackType.TRANSPARENCY_TAMPER,
                "Attacker attempts to boot firmware not recorded in the Merkle transparency log.",
            ),
            AttackScenario(
                AttackType.ANOMALY_EVASION,
                "Attacker crafts a boot pattern that mimics genuine behavior to evade AI detection.",
            ),
            AttackScenario(
                AttackType.SIDE_CHANNEL,
                "Attacker exploits timing variations in the boot process to extract secrets.",
            ),
            AttackScenario(
                AttackType.FIRMWARE_INJECTION,
                "Attacker injects unauthorized firmware code into a legitimate firmware image.",
            ),
        ]

    def list_scenarios(self) -> list[dict]:
        return [s.to_dict() for s in self.scenarios]

    def clone_device(self, device_id: str, bit_size: int = 256, seed: bytes | None = None) -> SRAMPUF:
        """Return a different SRAM PUF pretending to be the same device."""
        logger.info("Simulating clone of %s with fresh PUF seed", device_id)
        return SRAMPUF(device_id, bit_size=bit_size, seed=seed or random_bytes(32))

    def tamper_firmware(self, image: FirmwareImage, replacement: bytes | None = None) -> FirmwareImage:
        """Return the same image with a modified (unsigned) payload.

        The original signatures are copied over unchanged - the attacker
        has no keys - so both the device signature and the manufacturer
        manifest signature (which covers the payload SHA-256) reject the
        modified binary.
        """
        tampered = FirmwareImage(
            version=image.version,
            device_id=image.device_id,
            payload=replacement if replacement is not None else b"TAMPERED-PAYLOAD" + random_bytes(16),
            signature=image.signature,
            manufacturer_signature=image.manufacturer_signature,
        )
        logger.info("Simulating firmware tampering on image %s", image.version)
        return tampered

    def wrong_signer(self, image: FirmwareImage, unauthorized_key, ) -> FirmwareImage:
        """Re-sign the image with a key that is not in the trust chain."""
        signed = image.sign(unauthorized_key)
        logger.info("Simulating image signed by unauthorized key")
        return signed

    def forge_certificate(self, pki, device_id: str) -> x509.Certificate:
        """Swap the device certificate for a forged one and return it.

        The attacker re-issues the device's *genuine* public key under a
        rogue, attacker-controlled CA and persists the forged leaf in the
        boot path. The PUF-PKI binding still holds (the key is unchanged),
        so the forged credential is rejected by the real certificate
        verification stage, which must fail to chain it to the trusted root.
        """
        genuine = pki.get_device_certificate(device_id)
        now = dt.datetime.now(dt.timezone.utc)
        rogue_key = ec.generate_private_key(ec.SECP256R1())
        rogue_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Rogue CA {device_id}")])

        rogue_ca = (
            x509.CertificateBuilder()
            .subject_name(rogue_subject)
            .issuer_name(rogue_subject)
            .public_key(rogue_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True,
                    crl_sign=True, encipher_only=None, decipher_only=None,
                ),
                critical=True,
            )
            .sign(rogue_key, hashes.SHA256())
        )

        forged = (
            x509.CertificateBuilder()
            .subject_name(genuine.subject)
            .issuer_name(rogue_ca.subject)
            .public_key(genuine.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=True,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=None, decipher_only=None,
                ),
                critical=True,
            )
            .sign(rogue_key, hashes.SHA256())
        )

        pki.key_store.save_certificate(forged, "device", device_id)
        logger.info("Simulating certificate forgery: swapped device %s certificate to rogue CA", device_id)
        return forged
