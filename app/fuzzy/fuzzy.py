"""Fuzzy extraction (code-offset fuzzy commitment) for noisy PUF responses.

Real SRAM responses are noisy: a handful of cells flip between power
cycles. A fuzzy extractor turns a noisy-but-reproducible response into an
exact, repeatable secret:

1. ``enroll`` binds a random secret to the response as helper data:
   ``helper = codeword(secret) XOR response``, block by block.
2. ``reconstruct`` XORs the helper with a fresh (noisy) response and
   decodes the result with a BCH code, recovering the same secret as long
   as every block differs from the enrolled response in at most ``t`` bits.

All error correction is performed by the BCH codec (``codes.py``).
Hashing (HKDF in ``kdf.py``) is used only to derive keys from the
recovered secret, never to correct errors.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .codes import BCHCode, DEFAULT_CODE, get_code, select_code_for


def bytes_to_bits(data: bytes) -> list[int]:
    """Bit list in LSB-first order (matches the PUF's per-cell bit indexing)."""
    return [((byte >> bit) & 1) for byte in data for bit in range(8)]


def bits_to_bytes(bits: list[int]) -> bytes:
    """Pack an LSB-first bit list back into bytes (padding trailing bits with zero)."""
    result = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            result[i // 8] |= 1 << (i % 8)
    return bytes(result)


@dataclass
class FuzzyHelper:
    """Public helper data binding a secret to a specific PUF response.

    ``helper = codeword XOR response`` per codeword block. The helper
    alone reveals no key material; the secret is only recoverable from
    the helper together with the enrolled device's response.
    """

    code_name: str
    blocks: list[list[int]] = field(default_factory=list)

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    def to_dict(self) -> dict:
        return {"code_name": self.code_name, "blocks": self.blocks}

    @classmethod
    def from_dict(cls, data: dict) -> "FuzzyHelper":
        return cls(code_name=data["code_name"], blocks=[list(block) for block in data["blocks"]])


class FuzzyExtractor:
    """Code-offset fuzzy extractor for fixed-length noisy responses."""

    def __init__(self, code: BCHCode | None = None) -> None:
        self.code = code if code is not None else DEFAULT_CODE

    @property
    def noise_tolerance(self) -> int:
        """Maximum number of bit errors correctable per codeword block."""
        return self.code.t

    def select_code(self, response_bit_count: int) -> BCHCode:
        """Choose the best code for a response length (mutates ``self.code``)."""
        code = select_code_for(response_bit_count)
        if code is None:
            raise ValueError(
                f"response of {response_bit_count} bits cannot hold a byte-aligned BCH secret"
            )
        self.code = code
        return code

    def enroll(self, response: bytes, secret: bytes | None = None) -> tuple[bytes, FuzzyHelper]:
        """Commit ``secret`` to ``response``; returns ``(secret, helper)``.

        The secret defaults to fresh random bytes of the code's capacity
        (``k * blocks`` bits). Callers may supply their own secret, which
        must match the code's capacity exactly.
        """
        bits = bytes_to_bits(response)
        self.select_code(len(bits))
        blocks = len(bits) // self.code.n
        secret_size = self.code.k * blocks // 8
        if secret is None:
            secret = os.urandom(secret_size)
        if len(secret) != secret_size:
            raise ValueError(f"secret must be exactly {secret_size} bytes for this response")
        secret_bits = bytes_to_bits(secret)
        helper_blocks: list[list[int]] = []
        for block in range(blocks):
            message = secret_bits[block * self.code.k:(block + 1) * self.code.k]
            codeword = self.code.encode(message)
            response_block = bits[block * self.code.n:(block + 1) * self.code.n]
            helper_blocks.append([c ^ r for c, r in zip(codeword, response_block)])
        return secret, FuzzyHelper(code_name=self.code.name, blocks=helper_blocks)

    def reconstruct(self, response: bytes, helper: FuzzyHelper) -> bytes | None:
        """Recover the enrolled secret from a (possibly noisy) response.

        Returns the secret when every block decodes within the code's
        error tolerance; returns ``None`` on excessive noise or when the
        response does not belong to the enrolled device.
        """
        bits = bytes_to_bits(response)
        code = get_code(helper.code_name)
        recovered: list[int] = []
        for block, helper_block in enumerate(helper.blocks):
            start = block * code.n
            noisy = bits[start:start + code.n]
            if len(noisy) != code.n:
                return None
            decoded = code.decode([h ^ r for h, r in zip(helper_block, noisy)])
            if decoded is None:
                return None
            codeword, _errors = decoded
            recovered.extend(codeword[code.n - code.k:])
        return bits_to_bytes(recovered)
