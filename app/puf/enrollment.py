"""PUF enrollment: capture, analyze, and credential derivation.

Enrollment reads the SRAM PUF several times and characterises it:

* stable bits   - cells that produced the same value in every capture
* unstable bits - cells that toggled between captures (metastable)
* stability mask - bitmask with 1 = stable cell
* intra-device Hamming distance - mean pairwise difference between
  captures of the same device (fraction of bits)
* bit error rate (BER) - mean difference of each capture from the
  majority reference (fraction of bits)
* reliability    - 1 - BER
* uniqueness     - mean pairwise inter-device Hamming distance across the
  fleet (fraction of bits)

Security: raw startup responses are NEVER stored or used directly as
credentials. The stable-only reference (unstable cells zeroed) is fed to
a code-offset fuzzy extractor (BCH error correction) that binds a random
secret to the device; HKDF-SHA256 derives domain-separated device keys
from that secret. The stored credential tag is an HMAC-SHA256 tag over
the device-auth key, keyed by a server-side secret, and a PUF-to-key
binding hash ties the PUF identity to the device's certified public key.
A database leak therefore never exposes the credential tag itself (its
HMAC key lives outside the database), and a noisy or foreign PUF
response - or a certificate copied onto different hardware - fails
authentication. Caveat for this *software simulation*: the PUF response
is reproducible from the stored ``puf_seed``, so the PUF factor is not a
secret against a full database dump - the seed (a stand-in for physical
hardware) must be protected; on real hardware it is never stored.
"""

from __future__ import annotations

import hmac
import itertools
import logging
from dataclasses import dataclass

from ..config import get_puf_credential_secret
from ..crypto.utils import hmac_sha256
from ..fuzzy import FuzzyExtractor, FuzzyHelper
from ..fuzzy.kdf import derive_device_keys, derive_puf_binding
from .sram_puf import SRAMPUF

logger = logging.getLogger(__name__)

DEFAULT_CAPTURES = 10


@dataclass
class PUFEnrollment:
    """Enrollment metadata for a single device (helper data + credential tag)."""

    device_id: str
    bit_size: int
    num_captures: int
    stable_bit_count: int
    unstable_bit_count: int
    stability_mask: bytes      # 1 = stable cell
    reference: bytes           # stable-only reference (unstable cells zeroed)
    credential_tag: bytes      # HMAC-SHA256(server_secret, device-auth key)
    intra_device_hd: float     # mean pairwise intra-device HD (fraction)
    bit_error_rate: float      # mean BER vs reference (fraction)
    reliability: float         # 1 - bit_error_rate
    uniqueness: float | None = None  # mean inter-device HD (fraction), set once fleet is > 1
    fuzzy_helper: FuzzyHelper | None = None  # code-offset helper binding the secret to the response
    puf_binding: bytes | None = None  # binding hash of PUF-derived secret + device public key

    # -- enrollment ----------------------------------------------------

    @classmethod
    def enroll(cls, puf: SRAMPUF, num_captures: int = DEFAULT_CAPTURES,
               server_secret: bytes | None = None,
               device_public_key: bytes | None = None) -> "PUFEnrollment":
        """Capture ``num_captures`` responses and build the enrollment record.

        ``device_public_key`` (DER SubjectPublicKeyInfo) optionally binds
        the PUF identity to the device's certified public key; the
        resulting binding hash is stored on the record.
        """
        captures = [puf.regenerate() for _ in range(max(1, num_captures))]
        stability_mask, reference = cls._derive_mask_and_reference(captures)
        stable_bits = cls._count_bits(stability_mask)

        secret, helper = cls._derive_fuzzy(reference)
        credential_tag = cls._derive_credential(secret, puf.device_id, server_secret)
        binding = (
            cls._derive_binding(secret, device_public_key, puf.device_id)
            if device_public_key is not None
            else None
        )
        enrollment = cls(
            device_id=puf.device_id,
            bit_size=puf.bit_size,
            num_captures=len(captures),
            stable_bit_count=stable_bits,
            unstable_bit_count=puf.bit_size - stable_bits,
            stability_mask=stability_mask,
            reference=reference,
            credential_tag=credential_tag,
            intra_device_hd=cls.intra_hd(captures),
            bit_error_rate=cls.ber_vs_reference(captures, reference),
            reliability=1.0 - cls.ber_vs_reference(captures, reference),
            fuzzy_helper=helper,
            puf_binding=binding,
        )
        logger.info(
            "Enrolled %s (%d bits, %d captures): %d stable / %d unstable, BER %.4f",
            puf.device_id, puf.bit_size, len(captures),
            enrollment.stable_bit_count, enrollment.unstable_bit_count, enrollment.bit_error_rate,
        )
        return enrollment

    # -- verification --------------------------------------------------

    @classmethod
    def test(cls, puf: SRAMPUF, enrollment: "PUFEnrollment", num_captures: int = DEFAULT_CAPTURES,
             server_secret: bytes | None = None,
             device_public_key: bytes | None = None) -> dict:
        """Re-read the PUF and report whether the credential still matches.

        The fresh response is error-corrected against the enrolled fuzzy
        helper data; the recovered secret must re-derive the enrolled
        device-auth key. When ``device_public_key`` is supplied, the
        PUF-to-key binding is recomputed and compared against the
        registered binding as well. Returns live metrics (intra-device
        HD, BER, reliability), the masked Hamming distance against the
        enrolled reference, the binding result, and the overall match.
        """
        if enrollment.fuzzy_helper is None:
            raise ValueError(f"enrollment for {enrollment.device_id!r} has no fuzzy helper data; re-enroll")
        captures = [puf.regenerate() for _ in range(max(1, num_captures))]
        candidate = captures[0]
        masked_candidate = cls.apply_mask(candidate, enrollment.stability_mask)

        recovered, credential_match = cls._verify_credential(masked_candidate, enrollment, server_secret)
        binding_match = cls._verify_binding(recovered, enrollment, device_public_key)
        matched = bool(credential_match) and (binding_match if binding_match is not None else True)
        return {
            "device_id": enrollment.device_id,
            "matched": matched,
            "num_captures": len(captures),
            "fuzzy_recovered": recovered is not None,
            "puf_binding_match": binding_match,
            "hamming_distance": SRAMPUF.hamming_distance(masked_candidate, enrollment.reference),
            "stable_bits_checked": enrollment.stable_bit_count,
            "intra_device_hd": cls.intra_hd(captures),
            "bit_error_rate": cls.ber_vs_reference(captures, enrollment.reference),
            "reliability": 1.0 - cls.ber_vs_reference(captures, enrollment.reference),
        }

    # -- analysis helpers ----------------------------------------------

    @staticmethod
    def _derive_mask_and_reference(captures: list[bytes]) -> tuple[bytes, bytes]:
        """Compute the stability mask and the stable-only majority reference."""
        byte_size = len(captures[0])
        bit_size = byte_size * 8
        mask = bytearray(byte_size)
        reference = bytearray(byte_size)
        for cell in range(bit_size):
            byte_index, bit_index = cell // 8, cell % 8
            first = (captures[0][byte_index] >> bit_index) & 1
            if all(((c[byte_index] >> bit_index) & 1) == first for c in captures[1:]):
                mask[byte_index] |= 1 << bit_index
                if first:
                    reference[byte_index] |= 1 << bit_index
        return bytes(mask), bytes(reference)

    @staticmethod
    def _derive_fuzzy(reference: bytes) -> tuple[bytes, FuzzyHelper]:
        """Commit a fuzzy secret to the stable-only reference (helper data)."""
        return FuzzyExtractor().enroll(reference)

    @staticmethod
    def _derive_credential(secret: bytes, device_id: str, server_secret: bytes | None) -> bytes:
        """HMAC-SHA256 tag over the HKDF-derived device-auth key.

        The server-side secret lives outside the database, so a DB leak
        alone never yields the credential tag. (Simulation caveat: the
        stored ``puf_seed`` reproduces the PUF response, so the seed - not
        the helper data - is what must be protected.)
        """
        keys = derive_device_keys(secret, device_id)
        return hmac_sha256(server_secret if server_secret is not None else get_puf_credential_secret(), keys["device-auth"])

    @staticmethod
    def _derive_binding(secret: bytes, device_public_key: bytes, device_id: str) -> bytes:
        """Binding hash coupling the PUF-derived secret to the public key."""
        return derive_puf_binding(secret, device_public_key, device_id)

    @staticmethod
    def _verify_binding(
        secret: bytes | None,
        enrollment: "PUFEnrollment",
        device_public_key: bytes | None,
    ) -> bool | None:
        """Recompute the PUF-to-key binding and compare it with the registered value.

        Returns ``None`` when no public key was supplied (binding check
        skipped), otherwise ``True``/``False``. Recovering the secret and
        holding the matching public key are both required - a certificate
        copied onto different hardware fails here.
        """
        if device_public_key is None:
            return None
        if secret is None or enrollment.puf_binding is None:
            return False
        candidate = PUFEnrollment._derive_binding(secret, device_public_key, enrollment.device_id)
        return hmac.compare_digest(candidate, enrollment.puf_binding)

    @staticmethod
    def _verify_credential(
        masked_candidate: bytes,
        enrollment: "PUFEnrollment",
        server_secret: bytes | None,
    ) -> tuple[bytes | None, bool]:
        """Reconstruct the fuzzy secret and compare the derived credential.

        Returns ``(secret, matched)`` where ``secret`` is the recovered
        secret bytes (or ``None`` when error correction fails). Error
        correction either recovers the exact secret (within tolerance) or
        the whole check fails - hashing alone is never used to bridge
        noisy responses.
        """
        recovered = FuzzyExtractor().reconstruct(masked_candidate, enrollment.fuzzy_helper)
        if recovered is None:
            return None, False
        candidate_tag = PUFEnrollment._derive_credential(recovered, enrollment.device_id, server_secret)
        return recovered, hmac.compare_digest(candidate_tag, enrollment.credential_tag)

    @staticmethod
    def apply_mask(data: bytes, mask: bytes) -> bytes:
        if len(data) != len(mask):
            raise ValueError("data and mask must have equal length")
        return bytes(a & b for a, b in zip(data, mask))

    @staticmethod
    def intra_hd(captures: list[bytes]) -> float:
        """Mean pairwise intra-device Hamming distance (fraction of bits)."""
        bit_size = len(captures[0]) * 8
        total = 0.0
        pairs = 0
        for a, b in itertools.combinations(captures, 2):
            total += SRAMPUF.hamming_distance(a, b)
            pairs += 1
        return (total / pairs / bit_size) if pairs else 0.0

    @staticmethod
    def ber_vs_reference(captures: list[bytes], reference: bytes) -> float:
        """Mean fraction of bits differing from the reference across captures."""
        bit_size = len(reference) * 8
        total = sum(SRAMPUF.hamming_distance(c, reference) for c in captures)
        return (total / len(captures) / bit_size) if captures else 0.0

    @staticmethod
    def _count_bits(data: bytes) -> int:
        return sum(b.bit_count() for b in data)

    @staticmethod
    def mean_inter_device_hd(references: list[bytes]) -> float:
        """Mean pairwise inter-device Hamming distance (fraction of bits).

        Pairs with different ``bit_size`` (a mixed-size fleet) are skipped so
        the metric never crashes on a heterogeneous deployment.
        """
        if len(references) < 2:
            return 0.0
        total = 0
        pairs = 0
        bit_size = 0
        for a, b in itertools.combinations(references, 2):
            if len(a) != len(b):
                continue
            total += SRAMPUF.hamming_distance(a, b)
            pairs += 1
            if pairs == 1:
                bit_size = len(a) * 8
        return (total / pairs / bit_size) if pairs else 0.0

    @staticmethod
    def mean_device_vs_fleet(reference: bytes, others: list[bytes]) -> float | None:
        """Mean HD between one device's reference and every comparable other.

        Returns ``None`` when no other enrollment shares the device's
        ``bit_size`` (mixed-size fleet).
        """
        comparable = [other for other in others if len(other) == len(reference)]
        if not comparable:
            return None
        total = sum(SRAMPUF.hamming_distance(reference, other) for other in comparable)
        return total / len(comparable) / (len(reference) * 8)

    # -- serialisation -------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "bit_size": self.bit_size,
            "num_captures": self.num_captures,
            "stable_bit_count": self.stable_bit_count,
            "unstable_bit_count": self.unstable_bit_count,
            "stability_mask": self.stability_mask.hex(),
            "intra_device_hd": round(self.intra_device_hd, 6),
            "bit_error_rate": round(self.bit_error_rate, 6),
            "reliability": round(self.reliability, 6),
            "uniqueness": round(self.uniqueness, 6) if self.uniqueness is not None else None,
        }
