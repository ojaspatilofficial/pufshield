"""Environmental SRAM PUF simulation with physical condition modeling.

Models the effect of temperature, voltage, and electromagnetic interference
on SRAM PUF behavior.  At power-up, SRAM cells settle into a pattern
influenced by manufacturing variability and environmental conditions.

The simulator provides:
- Baseline random startup pattern (the "PUF fingerprint")
- Temperature-dependent bit flip probability
- Voltage-dependent noise injection
- EM interference modeling
- Combined environmental hash generation
"""
from __future__ import annotations

import hashlib
import math
import os
import struct
import time
from dataclasses import dataclass, field


@dataclass
class EnvironmentalConditions:
    """Physical operating conditions for the SRAM PUF."""
    temperature_c: float = 25.0     # Celsius (-40 to 125)
    voltage_v: float = 3.3          # Volts (1.62 to 3.63)
    em_interference_db: float = 0.0 # dB above noise floor
    humidity_pct: float = 50.0      # Relative humidity (0-100, ignored in model)

    def to_dict(self) -> dict:
        return {
            "temperature_c": self.temperature_c,
            "voltage_v": self.voltage_v,
            "em_interference_db": self.em_interference_db,
            "humidity_pct": self.humidity_pct,
        }


@dataclass
class PUFMeasurement:
    """Result of an SRAM PUF read under given conditions."""
    raw_bits: bytes            # 32 bytes (256 bits)
    bit_flip_rate: float       # fraction of bits flipped vs baseline
    entropy_bits: float        # estimated min-entropy
    conditions: EnvironmentalConditions
    stability: float           # 0-1, 1 = perfectly stable
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "raw_bits_hex": self.raw_bits.hex(),
            "bit_flip_rate": round(self.bit_flip_rate, 6),
            "entropy_bits": round(self.entropy_bits, 4),
            "conditions": self.conditions.to_dict(),
            "stability": round(self.stability, 4),
            "timestamp": self.timestamp,
        }


class SRAMPUFSimulator:
    """Models SRAM PUF behavior under varying environmental conditions.

    The model:
    1. A baseline pattern is deterministically generated from a device seed.
    2. Temperature affects bit flip probability via Arrhenius-like model.
    3. Voltage deviations increase noise (below/nominal = more flips).
    4. EM interference injects correlated noise bursts.
    5. Combined entropy and stability are estimated from the model.

    Bit flip model:
        P(flip) = P_thermal(T) + P_voltage(V) + P_em(EM)
        where:
            P_thermal = A * exp(-Ea / (k * T))
            P_voltage = B * |V - V_nom|^2
            P_em      = C * (1 - 10^(-EM/20))
    """

    # Model constants (tuned for realistic SRAM PUF behavior)
    T_NOMINAL = 25.0          # Reference temperature (°C)
    V_NOMINAL = 3.3           # Reference voltage (V)
    K_BOLTZMANN = 8.617e-5    # Boltzmann constant (eV/K)
    E_ACTIVATION = 0.3        # Activation energy (eV) for SRAM switching
    A_THERMAL = 0.002         # Thermal noise prefactor
    B_VOLTAGE = 0.02          # Voltage sensitivity
    C_EM = 0.003              # EM sensitivity
    BASELINE_FLIP_RATE = 0.005  # Base flip rate at nominal conditions

    def __init__(self, device_seed: bytes | None = None) -> None:
        self.device_seed = device_seed or os.urandom(32)
        self._baseline: bytes | None = None

    @property
    def baseline(self) -> bytes:
        """The device's baseline SRAM pattern at nominal conditions."""
        if self._baseline is None:
            self._baseline = self._generate_baseline()
        return self._baseline

    def _generate_baseline(self) -> bytes:
        """Generate the baseline PUF pattern from the device seed."""
        h = hashlib.sha256()
        h.update(b"SRAM_PUF_BASELINE" + self.device_seed)
        return h.digest()

    def _temperature_flip_prob(self, temp_c: float) -> float:
        """Arrhenius-based thermal bit flip probability."""
        temp_k = temp_c + 273.15
        temp_nom_k = self.T_NOMINAL + 273.15
        if temp_k <= 0:
            return 1.0
        ratio = self.E_ACTIVATION / (self.K_BOLTZMANN * temp_k)
        ratio_nom = self.E_ACTIVATION / (self.K_BOLTZMANN * temp_nom_k)
        return self.A_THERMAL * math.exp(ratio_nom - ratio)

    def _voltage_flip_prob(self, voltage: float) -> float:
        """Voltage-dependent noise from nominal."""
        delta = voltage - self.V_NOMINAL
        return self.B_VOLTAGE * (delta / self.V_NOMINAL) ** 2

    def _em_flip_prob(self, em_db: float) -> float:
        """EM interference induced flip probability."""
        if em_db <= 0:
            return 0.0
        return self.C_EM * (1 - 10 ** (-em_db / 20))

    def _combined_flip_prob(self, conditions: EnvironmentalConditions) -> float:
        """Total bit flip probability under given conditions."""
        p = (self.BASELINE_FLIP_RATE +
             self._temperature_flip_prob(conditions.temperature_c) +
             self._voltage_flip_prob(conditions.voltage_v) +
             self._em_flip_prob(conditions.em_interference_db))
        return min(max(p, 0.0), 1.0)

    def read_puf(self, conditions: EnvironmentalConditions | None = None) -> PUFMeasurement:
        """Perform an SRAM PUF read under specified conditions.

        Returns a PUFMeasurement with the raw bits, estimated flip rate,
        entropy, and stability.
        """
        if conditions is None:
            conditions = EnvironmentalConditions()

        p_flip = self._combined_flip_prob(conditions)

        # Generate deterministic noise from conditions + device seed
        noise_seed = hashlib.sha256(
            self.device_seed +
            struct.pack('!f', conditions.temperature_c) +
            struct.pack('!f', conditions.voltage_v) +
            struct.pack('!f', conditions.em_interference_db)
        ).digest()

        # Apply bit flips based on probability
        noisy_bits = bytearray(self.baseline)
        flip_count = 0
        for i in range(len(noisy_bits)):
            for bit in range(8):
                byte_idx = noise_seed[i % len(noise_seed)]
                threshold = p_flip * 256
                if (byte_idx + bit * 37) % 256 < threshold:
                    noisy_bits[i] ^= (1 << bit)
                    flip_count += 1

        raw_bits = bytes(noisy_bits)
        bit_flip_rate = flip_count / (len(raw_bits) * 8)

        # Entropy estimation (min-entropy under noise)
        # For a 256-bit source with flip rate p, conditional entropy ≈ 256 * H(p)
        if 0 < p_flip < 1:
            h_p = -p_flip * math.log2(p_flip) - (1 - p_flip) * math.log2(1 - p_flip)
        else:
            h_p = 0
        entropy_bits = 256 * h_p

        stability = 1.0 - p_flip

        return PUFMeasurement(
            raw_bits=raw_bits,
            bit_flip_rate=bit_flip_rate,
            entropy_bits=entropy_bits,
            conditions=conditions,
            stability=stability,
        )

    def environmental_hash(self, conditions: EnvironmentalConditions) -> str:
        """Generate a condition-dependent hash for attestation.

        This hash encodes the environmental state as part of the
        device's response.  Changing any condition changes the hash.
        """
        measurement = self.read_puf(conditions)
        h = hashlib.sha256()
        h.update(measurement.raw_bits)
        h.update(struct.pack('!f', conditions.temperature_c))
        h.update(struct.pack('!f', conditions.voltage_v))
        h.update(struct.pack('!f', conditions.em_interference_db))
        return h.hexdigest()

    def batch_read(self, conditions: EnvironmentalConditions, count: int = 10) -> list[PUFMeasurement]:
        """Multiple PUF reads under the same conditions for statistical analysis."""
        results = []
        for i in range(count):
            # Each read uses a slightly different noise seed (iteration counter)
            saved = self.device_seed
            self.device_seed = hashlib.sha256(saved + i.to_bytes(4, 'big')).digest()
            self._baseline = None  # force regeneration
            results.append(self.read_puf(conditions))
            self.device_seed = saved
            self._baseline = None
        return results

    def stability_analysis(self, conditions: EnvironmentalConditions, count: int = 10) -> dict:
        """Statistical analysis of PUF stability under given conditions."""
        measurements = self.batch_read(conditions, count)
        flip_rates = [m.bit_flip_rate for m in measurements]
        stabilities = [m.stability for m in measurements]
        return {
            "mean_flip_rate": sum(flip_rates) / len(flip_rates),
            "std_flip_rate": (sum((r - sum(flip_rates)/len(flip_rates))**2 for r in flip_rates) / len(flip_rates)) ** 0.5,
            "mean_stability": sum(stabilities) / len(stabilities),
            "min_stability": min(stabilities),
            "max_stability": max(stabilities),
            "read_count": count,
            "conditions": conditions.to_dict(),
        }
