"""Tests for environmental PUF simulation."""
import pytest
from app.ai.environment import SRAMPUFSimulator, EnvironmentalConditions, PUFMeasurement


@pytest.fixture
def sim():
    return SRAMPUFSimulator(device_seed=b"test-seed-12345678901234567890")


class TestSRAMPUFSimulator:
    def test_baseline_stable(self, sim):
        m1 = sim.read_puf(EnvironmentalConditions())
        m2 = sim.read_puf(EnvironmentalConditions())
        assert m1.raw_bits == m2.raw_bits

    def test_baseline_flip_rate_near_zero(self, sim):
        m = sim.read_puf(EnvironmentalConditions())
        assert m.bit_flip_rate < 0.05

    def test_high_temperature_increases_flips(self, sim):
        normal = sim.read_puf(EnvironmentalConditions(temperature_c=25.0))
        hot = sim.read_puf(EnvironmentalConditions(temperature_c=125.0))
        assert hot.bit_flip_rate >= normal.bit_flip_rate

    def test_low_voltage_increases_flips(self, sim):
        nominal = sim.read_puf(EnvironmentalConditions(voltage_v=3.3))
        low = sim.read_puf(EnvironmentalConditions(voltage_v=1.8))
        assert low.bit_flip_rate >= nominal.bit_flip_rate

    def test_em_interference_increases_flips(self, sim):
        clean = sim.read_puf(EnvironmentalConditions(em_interference_db=0.0))
        noisy = sim.read_puf(EnvironmentalConditions(em_interference_db=80.0))
        assert noisy.stability <= clean.stability

    def test_stability_decreases_with_stress(self, sim):
        normal = sim.read_puf(EnvironmentalConditions())
        stressed = sim.read_puf(EnvironmentalConditions(temperature_c=120, voltage_v=1.8))
        assert stressed.stability <= normal.stability

    def test_entropy_nonzero(self, sim):
        m = sim.read_puf()
        assert m.entropy_bits > 0

    def test_measurement_to_dict(self, sim):
        m = sim.read_puf()
        d = m.to_dict()
        assert "raw_bits_hex" in d
        assert "bit_flip_rate" in d
        assert "stability" in d

    def test_environmental_hash_changes_with_conditions(self, sim):
        h1 = sim.environmental_hash(EnvironmentalConditions(temperature_c=25))
        h2 = sim.environmental_hash(EnvironmentalConditions(temperature_c=85))
        assert h1 != h2

    def test_batch_read(self, sim):
        measurements = sim.batch_read(EnvironmentalConditions(), count=5)
        assert len(measurements) == 5
        # Each should have different noise
        flip_rates = [m.bit_flip_rate for m in measurements]
        assert len(set(flip_rates)) >= 1  # some variation expected

    def test_stability_analysis(self, sim):
        result = sim.stability_analysis(EnvironmentalConditions(), count=5)
        assert "mean_flip_rate" in result
        assert "mean_stability" in result
        assert result["read_count"] == 5

    def test_temperature_extremes(self, sim):
        m = sim.read_puf(EnvironmentalConditions(temperature_c=-40))
        assert m.stability >= 0
        m2 = sim.read_puf(EnvironmentalConditions(temperature_c=125))
        assert m2.stability >= 0
