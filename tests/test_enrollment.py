"""Unit tests for PUF enrollment: metrics, credential derivation, and security."""

import pytest

from app.puf import PUFEnrollment, SRAMPUF


@pytest.fixture
def puf() -> SRAMPUF:
    return SRAMPUF("dev-enroll", bit_size=256, seed=b"enrollment-seed", noise_rate=0.01)


def test_enrollment_counts_stable_and_unstable_bits(puf):
    enrollment = PUFEnrollment.enroll(puf, num_captures=20)
    assert enrollment.stable_bit_count + enrollment.unstable_bit_count == puf.bit_size
    assert enrollment.stable_bit_count > 0
    assert enrollment.unstable_bit_count >= 0
    # With a 1% BER, some cells are expected to be metastable.
    assert enrollment.unstable_bit_count >= 1


def test_stability_mask_matches_counts(puf):
    enrollment = PUFEnrollment.enroll(puf, num_captures=20)
    assert len(enrollment.stability_mask) == puf.bit_size // 8
    stable_from_mask = sum(b.bit_count() for b in enrollment.stability_mask)
    assert stable_from_mask == enrollment.stable_bit_count


def test_reference_is_masked(puf):
    """Unstable cells must be zeroed in the reference."""
    enrollment = PUFEnrollment.enroll(puf, num_captures=20)
    assert enrollment.reference == PUFEnrollment.apply_mask(enrollment.reference, enrollment.stability_mask)


def test_metrics_in_valid_ranges(puf):
    enrollment = PUFEnrollment.enroll(puf, num_captures=20)
    assert 0.0 <= enrollment.intra_device_hd <= 1.0
    assert 0.0 <= enrollment.bit_error_rate <= 1.0
    assert 0.0 <= enrollment.reliability <= 1.0
    assert enrollment.reliability == pytest.approx(1.0 - enrollment.bit_error_rate)
    assert enrollment.bit_error_rate == pytest.approx(puf.noise_rate, abs=0.05)


def test_credential_tag_is_not_raw_response(puf):
    enrollment = PUFEnrollment.enroll(puf, num_captures=10)
    raw = puf.regenerate()
    assert enrollment.credential_tag != raw
    assert enrollment.credential_tag != enrollment.reference
    assert len(enrollment.credential_tag) == 32  # HMAC-SHA256 output


def test_verification_matches_same_device(puf):
    enrollment = PUFEnrollment.enroll(puf, num_captures=20)
    result = PUFEnrollment.test(puf, enrollment, num_captures=10)
    assert result["matched"] is True
    assert result["hamming_distance"] == 0


def test_verification_rejects_different_device():
    real = SRAMPUF("dev-real", bit_size=256, seed=b"seed-a", noise_rate=0.01)
    clone = SRAMPUF("dev-real", bit_size=256, seed=b"seed-b", noise_rate=0.01)
    enrollment = PUFEnrollment.enroll(real, num_captures=20)
    result = PUFEnrollment.test(clone, enrollment, num_captures=10)
    assert result["matched"] is False
    assert result["hamming_distance"] > 0


def test_verification_uses_masked_candidate():
    """A wrong device may still be re-checked only over stable cells."""
    real = SRAMPUF("dev-a", bit_size=512, seed=b"s1", noise_rate=0.01)
    other = SRAMPUF("dev-b", bit_size=512, seed=b"s2", noise_rate=0.01)
    enrollment = PUFEnrollment.enroll(real, num_captures=20)
    masked_other = PUFEnrollment.apply_mask(other.regenerate(), enrollment.stability_mask)
    assert masked_other != enrollment.reference


def test_apply_mask_zeroes_unstable_positions():
    mask = bytes([0b11110000])
    data = bytes([0b11111111])
    assert PUFEnrollment.apply_mask(data, mask) == bytes([0b11110000])


def test_apply_mask_requires_equal_length():
    with pytest.raises(ValueError):
        PUFEnrollment.apply_mask(b"\x00", b"\x00\x00")


def test_inter_device_hd_is_high():
    seeds = [f"seed-{i}".encode() for i in range(5)]
    references = [SRAMPUF(f"dev-{i}", bit_size=256, seed=s).enroll() for i, s in enumerate(seeds)]
    uniqueness = PUFEnrollment.mean_inter_device_hd(references)
    assert 0.35 < uniqueness <= 0.5


def test_inter_device_hd_single_device_is_zero():
    references = [SRAMPUF("dev-only", bit_size=256).enroll()]
    assert PUFEnrollment.mean_inter_device_hd(references) == 0.0


def test_to_dict_does_not_expose_reference_or_credential(puf):
    enrollment = PUFEnrollment.enroll(puf, num_captures=10)
    data = enrollment.to_dict()
    assert "credential_tag" not in data
    assert "reference" not in data
    assert "stability_mask" in data
    assert data["stable_bit_count"] == enrollment.stable_bit_count
