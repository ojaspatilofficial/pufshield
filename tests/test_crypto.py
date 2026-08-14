"""Tests for crypto helpers."""

from app.crypto.utils import b64decode, b64encode, hmac_sha256, random_bytes, sha256


def test_random_bytes_length():
    assert len(random_bytes(32)) == 32
    assert len(random_bytes(0)) == 0


def test_random_bytes_are_not_all_zero():
    assert random_bytes(16) != b"\x00" * 16


def test_sha256_known_vector():
    assert sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_base64_roundtrip():
    payload = b"hello \x00\xff\x01 world"
    assert b64decode(b64encode(payload)) == payload


def test_hmac_sha256_is_deterministic():
    assert hmac_sha256(b"key", b"message") == hmac_sha256(b"key", b"message")


def test_hmac_sha256_differs_on_message():
    assert hmac_sha256(b"key", b"message") != hmac_sha256(b"key", b"message2")
