"""Fuzzy extraction / error-correction layer.

Real BCH error-correcting codes turn noisy PUF responses into exact,
repeatable secrets; HKDF-SHA256 then derives domain-separated device
keys. Error correction lives in :mod:`codes`, never in hashing.
"""

from .codes import BCHCode, DEFAULT_CODE, get_code, select_code_for
from .fuzzy import FuzzyExtractor, FuzzyHelper, bits_to_bytes, bytes_to_bits
from .kdf import derive_device_keys, derive_puf_binding, hkdf_sha256

__all__ = [
    "BCHCode",
    "DEFAULT_CODE",
    "FuzzyExtractor",
    "FuzzyHelper",
    "bits_to_bytes",
    "bytes_to_bits",
    "derive_device_keys",
    "derive_puf_binding",
    "get_code",
    "hkdf_sha256",
    "select_code_for",
]
