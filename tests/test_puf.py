"""Unit tests for the SRAM PUF simulator: repeatability, uniqueness, noise."""

import pytest

from app.puf import SRAMPUF


# -- creation / configuration -------------------------------------------


def test_creation_requires_multiple_of_eight_bits():
    with pytest.raises(ValueError):
        SRAMPUF("dev-bad-size", bit_size=100)


def test_noise_rate_validated():
    with pytest.raises(ValueError):
        SRAMPUF("dev-bad-noise", noise_rate=-0.01)
    with pytest.raises(ValueError):
        SRAMPUF("dev-bad-noise", noise_rate=0.6)


@pytest.mark.parametrize("bit_size", [8, 64, 256, 1024])
def test_response_length_matches_configured_size(bit_size):
    puf = SRAMPUF("dev-size", bit_size=bit_size)
    assert len(puf.startup()) == bit_size // 8


def test_device_creation_reproducible_from_seed():
    """Recreating a device from the same seed reproduces the same pattern."""
    seed = b"manufacturing-variation-001"
    a = SRAMPUF("dev-a", bit_size=256, seed=seed)
    b = SRAMPUF("dev-a", bit_size=256, seed=seed)
    assert a.startup(noise_rate=0.0) == b.startup(noise_rate=0.0)


# -- repeatability -------------------------------------------------------


def test_repeatability_no_noise_is_identical():
    puf = SRAMPUF("dev-repeat", bit_size=512, noise_rate=0.0)
    reference = puf.enroll()
    for _ in range(10):
        assert puf.regenerate() == reference


def test_repeatability_with_noise_stays_within_tolerance():
    puf = SRAMPUF("dev-repeat-noisy", bit_size=1024, noise_rate=0.01)
    reference = puf.enroll()
    for _ in range(20):
        response = puf.regenerate()
        assert puf.verify(reference, response)
        assert puf.bit_flip_rate(reference, response) < 0.05


def test_noise_is_bounded_not_random():
    """A 0.5% noise rate must never scramble a whole response."""
    puf = SRAMPUF("dev-bounded", bit_size=1024, noise_rate=0.005)
    reference = puf.enroll()
    for _ in range(20):
        assert puf.bit_flip_rate(reference, puf.regenerate()) < 0.05


def test_zero_noise_configuration_means_no_flips():
    puf = SRAMPUF("dev-clean", bit_size=256, noise_rate=0.0)
    reference = puf.enroll()
    assert puf.regenerate(noise_rate=0.0) == reference


# -- noise configurability ------------------------------------------------


def test_higher_noise_rate_flips_more_bits():
    quiet = SRAMPUF("dev-quiet", bit_size=4096, noise_rate=0.001)
    loud = SRAMPUF("dev-loud", bit_size=4096, noise_rate=0.05)
    ref_q, ref_l = quiet.enroll(), loud.enroll()
    flips_quiet = quiet.hamming_distance(ref_q, quiet.regenerate())
    flips_loud = loud.hamming_distance(ref_l, loud.regenerate())
    assert flips_loud > flips_quiet * 5
    assert flips_quiet < 4096 * 0.005
    assert flips_loud > 4096 * 0.02


def test_per_call_noise_rate_override():
    puf = SRAMPUF("dev-override", bit_size=1024, noise_rate=0.01)
    reference = puf.enroll()
    assert puf.regenerate(noise_rate=0.0) == reference


# -- uniqueness -----------------------------------------------------------


def test_different_devices_have_different_responses():
    a = SRAMPUF("dev-a", bit_size=256).enroll()
    b = SRAMPUF("dev-b", bit_size=256).enroll()
    distance = SRAMPUF.hamming_distance(a, b)
    assert distance > 256 * 0.30, "distinct devices should differ substantially"


def test_different_devices_even_with_same_seed():
    """Identity is mixed into the derivation, so the same seed cannot yield
    identical patterns for different devices."""
    seed = b"shared-seed"
    a = SRAMPUF("dev-x", bit_size=256, seed=seed).enroll()
    b = SRAMPUF("dev-y", bit_size=256, seed=seed).enroll()
    assert SRAMPUF.hamming_distance(a, b) > 256 * 0.20


def test_verify_rejects_foreign_device():
    a = SRAMPUF("dev-a", bit_size=256)
    b = SRAMPUF("dev-b", bit_size=256)
    assert not a.verify(a.enroll(), b.enroll())


def test_verify_rejects_wrong_length():
    puf = SRAMPUF("dev-len", bit_size=256)
    assert not puf.verify(puf.enroll(), b"\x00" * 16)


# -- hamming distance helpers ---------------------------------------------


def test_hamming_distance_basics():
    assert SRAMPUF.hamming_distance(b"\x00\x00", b"\x00\x00") == 0
    assert SRAMPUF.hamming_distance(b"\x00", b"\xff") == 8
    assert SRAMPUF.hamming_distance(b"\x0f\xf0", b"\x00\x00") == 8


def test_hamming_distance_requires_equal_length():
    with pytest.raises(ValueError):
        SRAMPUF.hamming_distance(b"\x00", b"\x00\x00")


def test_bit_flip_rate_in_unit_range():
    puf = SRAMPUF("dev-rate", bit_size=64)
    rate = puf.bit_flip_rate(puf.enroll(), puf.regenerate(noise_rate=0.01))
    assert 0.0 <= rate <= 1.0
