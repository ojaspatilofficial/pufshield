"""SRAM PUF simulation.

A real SRAM PUF exploits manufacturing variation: at power-up each SRAM
cell toggles toward a preferred value, and a small fraction of cells are
metastable (they start at either value). This simulation reproduces the
essential properties without hardware:

* persistence - every device has a unique, reproducible startup pattern
* stability   - most cells always power up to the same value ("stable"),
                a small fraction are "metastable" and toggle on each cycle
* reliability - repeated power cycles differ only in the metastable cells,
                so the observable bit error rate equals ``noise_rate``
* uniqueness  - different devices (different identities/seeds) produce
                substantially different patterns

The stable per-cell values and the metastable cell positions are both
derived deterministically from a per-device seed that is stored at
provisioning time, so a device always powers up to the same baseline.
Power-cycle noise only affects metastable cells; the stable baseline is
never regenerated from scratch on each cycle.
"""

from __future__ import annotations

import hashlib
import os

from ..crypto.utils import random_bytes

_DEFAULT_NOISE_RATE = 0.01    # observable bit error rate (1% of cells toggle per cycle)
_METASTABLE_FLIP_PROB = 0.5   # metastable cells start ~randomly on each power cycle
_BIAS_SCALE = 1 << 16         # per-cell bias resolution (2 bytes of entropy per cell)


class SRAMPUF:
    """Simulated SRAM PUF for a single device.

    Parameters
    ----------
    device_id : str
        Human-readable device identifier, mixed into the derived pattern.
    bit_size : int
        Number of SRAM cells (must be a multiple of 8).
    seed : bytes | None
        Optional seed making the startup pattern reproducible (the
        device's permanent manufacturing variation). Defaults to a fresh
        random seed.
    noise_rate : float
        Observable bit error rate (fraction of metastable cells, 0.0-0.5).
        Higher values model noisier / less reliable SRAM.
    """

    def __init__(
        self,
        device_id: str,
        bit_size: int = 256,
        seed: bytes | None = None,
        noise_rate: float = _DEFAULT_NOISE_RATE,
    ) -> None:
        if bit_size % 8:
            raise ValueError("bit_size must be a multiple of 8")
        if not 0.0 <= noise_rate <= 0.5:
            raise ValueError("noise_rate must be between 0.0 and 0.5")
        self.device_id = device_id
        self.bit_size = bit_size
        self.byte_size = bit_size // 8
        self.noise_rate = noise_rate
        self._seed = seed if seed is not None else random_bytes(32)

    # -- lifecycle -----------------------------------------------------

    def startup(self, noise_rate: float | None = None) -> bytes:
        """Simulate one power cycle.

        Returns the device's persistent startup pattern. Metastable cells
        toggle with probability ``_METASTABLE_FLIP_PROB``; stable cells
        are identical on every cycle.
        """
        rate = self.noise_rate if noise_rate is None else noise_rate
        if rate <= 0.0:
            return self._stable_value()
        return self._apply_noise(self._stable_value(), rate)

    def power_cycle(self, noise_rate: float | None = None) -> bytes:
        """Alias for :meth:`startup`."""
        return self.startup(noise_rate=noise_rate)

    def enroll(self) -> bytes:
        """Capture the noise-free reference pattern used as helper data."""
        return self.startup(noise_rate=0.0)

    def regenerate(self, noise_rate: float | None = None) -> bytes:
        """Re-read the PUF after a power cycle, returning a noisy response."""
        return self.startup(noise_rate=noise_rate)

    def verify(self, reference: bytes, candidate: bytes, max_bit_errors: int | None = None) -> bool:
        """Check a freshly read response against the enrolled reference.

        ``max_bit_errors`` defaults to a tolerance derived from the
        configured noise rate and PUF size.
        """
        if len(reference) != len(candidate):
            return False
        return self.hamming_distance(reference, candidate) <= self._error_tolerance(max_bit_errors)

    # -- internals -----------------------------------------------------

    def _stable_value(self) -> bytes:
        """Deterministic, per-device startup baseline (one bit per cell).

        A stretched hash of the device seed and identity gives every
        device a stable, unique baseline reproduced on every power cycle.
        """
        value = b""
        counter = 0
        while len(value) < self.byte_size:
            value += hashlib.sha256(
                b"sram-puf:" + self.device_id.encode("utf-8") + b":" + self._seed + b":" + counter.to_bytes(4, "big")
            ).digest()
            counter += 1
        return value[: self.byte_size]

    def _metastable_mask(self, rate: float) -> bytes:
        """Bitmask (1 = metastable) derived deterministically from the seed.

        The fraction of metastable cells is ``2 * rate``; each metastable
        cell toggles with probability ``_METASTABLE_FLIP_PROB`` per cycle,
        so the resulting bit error rate equals ``rate``.
        """
        fraction = min(1.0, 2.0 * rate)
        threshold = int(fraction * _BIAS_SCALE)
        bias = self._bias_stream(self.bit_size)
        mask = bytearray(self.byte_size)
        for cell in range(self.bit_size):
            value = (bias[2 * cell] << 8) | bias[2 * cell + 1]
            if value < threshold:
                mask[cell // 8] |= 1 << (cell % 8)
        return bytes(mask)

    def _bias_stream(self, n_cells: int) -> bytes:
        """Deterministic per-cell entropy stream (2 bytes per cell)."""
        value = b""
        counter = 0
        needed = 2 * n_cells
        while len(value) < needed:
            value += hashlib.sha256(
                b"sram-bias:" + self.device_id.encode("utf-8") + b":" + self._seed + b":" + counter.to_bytes(4, "big")
            ).digest()
            counter += 1
        return value[:needed]

    def _apply_noise(self, stable: bytes, rate: float) -> bytes:
        """Toggle the metastable cells; stable cells keep their baseline value."""
        if rate <= 0.0:
            return stable
        mask = self._metastable_mask(rate)
        entropy = os.urandom(self.bit_size)  # one byte per cell, LSB decides the toggle
        result = bytearray(stable)
        for cell in range(self.bit_size):
            if mask[cell // 8] & (1 << (cell % 8)):
                if entropy[cell] & 1:
                    result[cell // 8] ^= 1 << (cell % 8)
        return bytes(result)

    def _error_tolerance(self, max_bit_errors: int | None) -> int:
        if max_bit_errors is not None:
            return max_bit_errors
        # Tolerate roughly 5x the expected number of flipped cells.
        expected = self.bit_size * self.noise_rate
        return max(1, int(round(expected * 5)))

    @staticmethod
    def hamming_distance(a: bytes, b: bytes) -> int:
        """Number of differing bits between two byte strings."""
        if len(a) != len(b):
            raise ValueError("operands must have equal length")
        return sum((x ^ y).bit_count() for x, y in zip(a, b))

    @staticmethod
    def bit_flip_rate(a: bytes, b: bytes) -> float:
        """Fraction of bits that differ between two responses (0.0-1.0)."""
        if len(a) != len(b):
            raise ValueError("operands must have equal length")
        return SRAMPUF.hamming_distance(a, b) / (len(a) * 8)
