"""Tests for the fuzzy-extraction / error-correction layer.

Covers: BCH codec round-trips, clean / noisy / excessive-noise /
wrong-device recovery, HKDF domain separation, and the property that
hashing alone never performs error correction.
"""

import random

import pytest

from app.crypto.utils import sha256
from app.fuzzy import FuzzyExtractor, FuzzyHelper
from app.fuzzy.codes import BCH15_7_5, BCH31_16_7, select_code_for
from app.fuzzy.fuzzy import bits_to_bytes, bytes_to_bits
from app.fuzzy.kdf import (
    PUF_KEY_LABELS,
    derive_device_keys,
    derive_puf_binding,
    hkdf_sha256,
)

RESPONSE = bytes(range(32))  # deterministic 256-bit response


def random_bits(k: int, seed: int) -> list[int]:
    rng = random.Random(seed)
    return [rng.getrandbits(1) for _ in range(k)]


def flip_bits(data: bytes, positions: list[int]) -> bytes:
    bits = bytes_to_bits(data)
    for position in positions:
        bits[position] ^= 1
    return bits_to_bytes(bits)


# -- bit helpers ---------------------------------------------------------

def test_bit_helpers_roundtrip():
    assert bits_to_bytes(bytes_to_bits(RESPONSE)) == RESPONSE
    assert bytes_to_bits(b"\x01") == [1, 0, 0, 0, 0, 0, 0, 0]


# -- BCH codec -----------------------------------------------------------

@pytest.mark.parametrize("code", [BCH15_7_5, BCH31_16_7])
def test_bch_clean_roundtrip(code):
    message = random_bits(code.k, 3)
    codeword = code.encode(message)
    assert len(codeword) == code.n
    decoded, errors = code.decode(codeword)
    assert errors == 0
    assert decoded == codeword
    assert decoded[code.n - code.k:] == message


@pytest.mark.parametrize("code", [BCH15_7_5, BCH31_16_7])
def test_bch_corrects_up_to_t_errors(code):
    message = random_bits(code.k, 7)
    codeword = code.encode(message)
    positions = [0, 5, 11][: code.t]
    received = list(codeword)
    for position in positions:
        received[position] ^= 1
    decoded, errors = code.decode(received)
    assert errors == code.t
    assert decoded == codeword


@pytest.mark.parametrize("code", [BCH15_7_5, BCH31_16_7])
def test_bch_never_recovers_original_beyond_t_errors(code):
    message = random_bits(code.k, 9)
    codeword = code.encode(message)
    received = list(codeword)
    for position in range(code.t + 2):
        received[position] ^= 1
    result = code.decode(received)
    if result is not None:
        decoded, _errors = result
        assert decoded[code.n - code.k:] != message


def test_bch_generator_degrees_match_parameters():
    assert len(BCH15_7_5.generator) - 1 == BCH15_7_5.n - BCH15_7_5.k
    assert len(BCH31_16_7.generator) - 1 == BCH31_16_7.n - BCH31_16_7.k


def test_select_code_prefers_largest_byte_aligned_capacity():
    assert select_code_for(256) is BCH31_16_7
    assert select_code_for(160) is BCH31_16_7
    assert select_code_for(8) is None


# -- fuzzy extractor -----------------------------------------------------

@pytest.fixture
def extractor() -> FuzzyExtractor:
    return FuzzyExtractor()


def test_enroll_clean_recovery(extractor):
    secret, helper = extractor.enroll(RESPONSE)
    assert helper.code_name == "BCH31_16_7"
    assert helper.block_count == 8
    assert len(secret) == 16  # 8 blocks * 16 message bits / 8
    assert extractor.reconstruct(RESPONSE, helper) == secret


def test_enroll_binds_secret_to_response(extractor):
    secret_a, _ = extractor.enroll(RESPONSE)
    secret_b, _ = extractor.enroll(bytes([x ^ 0xFF for x in RESPONSE]))
    assert secret_a != secret_b


def test_noisy_recovery_within_tolerance(extractor):
    """Up to ``t`` errors per block still recover the exact secret."""
    secret, helper = extractor.enroll(RESPONSE)
    noisy = flip_bits(RESPONSE, [1, 4, 9, 40, 60])  # 3 errors in block 0, 2 in block 1
    assert extractor.reconstruct(noisy, helper) == secret


def test_excessive_noise_fails(extractor):
    """More than ``t`` errors in one block must not recover the secret."""
    secret, helper = extractor.enroll(RESPONSE)
    noisy = flip_bits(RESPONSE, [0, 1, 2, 3])  # 4 errors in block 0 (t == 3)
    recovered = extractor.reconstruct(noisy, helper)
    assert recovered is None or recovered != secret


def test_wrong_device_fails(extractor):
    """A different device's response must not recover the secret."""
    secret, helper = extractor.enroll(RESPONSE)
    other = bytes([(x + 1) % 256 for x in RESPONSE])
    recovered = extractor.reconstruct(other, helper)
    assert recovered is None or recovered != secret


def test_noise_tolerance_is_configured(extractor):
    assert extractor.noise_tolerance == extractor.code.t == 3


def test_enroll_accepts_explicit_secret(extractor):
    secret = b"\x42" * 16
    recovered, helper = extractor.enroll(RESPONSE, secret=secret)
    assert recovered == secret
    assert extractor.reconstruct(RESPONSE, helper) == secret


def test_enroll_rejects_mismatched_secret_length(extractor):
    with pytest.raises(ValueError):
        extractor.enroll(RESPONSE, secret=b"too-short")


def test_helper_serialization_roundtrip(extractor):
    _, helper = extractor.enroll(RESPONSE)
    assert FuzzyHelper.from_dict(helper.to_dict()) == helper


# -- HKDF key derivation -------------------------------------------------

def test_hkdf_matches_rfc5869_test_vector():
    """RFC 5869 Test Case 1 (SHA-256) - proves the HKDF is standard, not custom."""
    ikm = bytes([0x0B]) * 22
    salt = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C])
    info = bytes([0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9])
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert hkdf_sha256(ikm, 42, salt=salt, info=info) == expected


def test_hkdf_domain_separation():
    secret = b"\xab" * 16
    keys = derive_device_keys(secret, "dev-1")
    assert set(keys) == set(PUF_KEY_LABELS)
    assert all(len(key) == 32 for key in keys.values())
    assert len(set(keys.values())) == len(PUF_KEY_LABELS)  # labels differ
    assert keys["device-auth"] != derive_device_keys(secret, "dev-2")["device-auth"]
    assert keys["device-auth"] != derive_device_keys(b"\xcd" * 16, "dev-1")["device-auth"]
    assert derive_device_keys(secret, "dev-1") == derive_device_keys(secret, "dev-1")


def test_hashing_alone_does_not_correct_errors(extractor):
    """Point: within noise tolerance, SHA-256 still differs for noisy input."""
    noisy = flip_bits(RESPONSE, [1, 4, 9])
    assert sha256(RESPONSE) != sha256(noisy)
    secret, helper = extractor.enroll(RESPONSE)
    assert extractor.reconstruct(noisy, helper) == secret


# -- PUF-to-key binding -----------------------------------------------------

def test_puf_binding_domain_separation():
    secret = b"\x11" * 16
    pub_a = b"\x30\x59\x02\x01\x01" + bytes(range(10))
    pub_b = b"\x30\x59\x02\x01\x01" + bytes(range(10, 20))
    assert derive_puf_binding(secret, pub_a, "dev-1") != derive_puf_binding(secret, pub_b, "dev-1")
    assert derive_puf_binding(secret, pub_a, "dev-1") != derive_puf_binding(secret, pub_a, "dev-2")
    assert derive_puf_binding(secret, pub_a, "dev-1") != derive_puf_binding(b"\x22" * 16, pub_a, "dev-1")
    assert derive_puf_binding(secret, pub_a, "dev-1") == derive_puf_binding(secret, pub_a, "dev-1")
    assert len(derive_puf_binding(secret, pub_a, "dev-1")) == 32


# -- enrollment integration ----------------------------------------------

def test_puf_test_reports_fuzzy_recovery(service, provisioned_device):
    enrollment = service.db.get_enrollment("dev-0001")
    assert enrollment.fuzzy_helper is not None
    result = service.test_puf("dev-0001", num_captures=1)
    assert result["matched"] is True
    assert result["fuzzy_recovered"] is True
