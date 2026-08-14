"""Binary BCH error-correcting codes over GF(2^m).

This module provides a self-contained implementation of narrow-sense
binary BCH codes for the fuzzy extractor. It performs *actual* algebraic
error correction (syndrome computation, Berlekamp-Massey, Chien search);
hashing is never used to correct errors.

Presets
-------
BCH15_7_5  : GF(2^4), codeword 15 bits, message 7 bits,  corrects <= 2 errors
BCH31_16_7 : GF(2^5), codeword 31 bits, message 16 bits, corrects <= 3 errors
"""

from __future__ import annotations


class GF2M:
    """Arithmetic in GF(2^m) using exponent/log tables for a primitive polynomial."""

    def __init__(self, m: int, primitive_poly: int) -> None:
        if not 1 < m < 16:
            raise ValueError("m must satisfy 1 < m < 16")
        self.m = m
        self.order = (1 << m) - 1
        self.primitive_poly = primitive_poly
        self._exp = [0] * (1 << m)
        self._log = [0] * (1 << m)
        self._build_tables()

    def _build_tables(self) -> None:
        x = 1
        for i in range(self.order):
            self._exp[i] = x
            self._log[x] = i
            x <<= 1
            if x & (1 << self.m):
                x ^= self.primitive_poly
        self._exp[self.order] = self._exp[0]

    def alpha_pow(self, e: int) -> int:
        """Element ``alpha**e`` (exponents are taken modulo the field order)."""
        return self._exp[e % self.order]

    def add(self, a: int, b: int) -> int:
        return a ^ b

    def mul(self, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return self._exp[(self._log[a] + self._log[b]) % self.order]

    def inv(self, a: int) -> int:
        if a == 0:
            raise ZeroDivisionError("inverse of 0 is undefined")
        return self._exp[(self.order - self._log[a]) % self.order]


def _poly_mul(a: list[int], b: list[int], field: GF2M) -> list[int]:
    """Multiply two polynomials (LSB-first coefficients) over GF(2^m)."""
    result = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj:
                result[i + j] ^= field.mul(ai, bj)
    return result


def _poly_remainder(dividend: list[int], divisor: list[int]) -> list[int]:
    """Remainder of ``dividend`` modulo the monic ``divisor`` over GF(2)."""
    rem = list(dividend)
    degree = len(divisor) - 1
    while rem and len(rem) - 1 >= degree:
        if rem[-1] == 0:
            rem.pop()
            continue
        shift = len(rem) - 1 - degree
        for i in range(len(divisor)):
            rem[shift + i] ^= divisor[i]
        rem.pop()
    return rem


class BCHCode:
    """A narrow-sense binary BCH code with designed distance ``2t + 1``.

    Parameters
    ----------
    name : str
        Human-readable identifier (e.g. ``"BCH31_16_7"``).
    m : int
        Extension degree; the codeword length is ``n = 2**m - 1``.
    k : int
        Message length in bits.
    t : int
        Number of bit errors the code can correct per codeword.
    primitive_poly : int
        Coefficients of the primitive polynomial defining GF(2^m).
    """

    def __init__(self, name: str, m: int, k: int, t: int, primitive_poly: int) -> None:
        self.name = name
        self.m = m
        self.n = (1 << m) - 1
        self.k = k
        self.t = t
        self.d = 2 * t + 1
        self.field = GF2M(m, primitive_poly)
        self.generator = self._compute_generator()
        degree = len(self.generator) - 1
        if degree != self.n - self.k:
            raise ValueError(f"{name}: generator degree {degree} != n-k = {self.n - self.k}")

    def __repr__(self) -> str:
        return f"BCHCode({self.name!r}, n={self.n}, k={self.k}, t={self.t})"

    # -- construction --------------------------------------------------

    def _compute_generator(self) -> list[int]:
        """Generator polynomial = lcm of the minimal polynomials of alpha^1..alpha^(2t)."""
        poly = [1]
        for exponent in range(1, 2 * self.t, 2):
            minimal = self._minimal_polynomial(exponent)
            poly = _poly_mul(poly, minimal, self.field)
        return poly

    def _minimal_polynomial(self, exponent: int) -> list[int]:
        """Minimal polynomial of ``alpha**exponent`` (product over its conjugates)."""
        coset: list[int] = []
        value = exponent
        while value not in coset:
            coset.append(value)
            value = (value * 2) % self.field.order
        poly = [1]
        for element in coset:
            root = self.field.alpha_pow(element)
            poly = _poly_mul(poly, [root, 1], self.field)  # (x + root)
        return poly

    # -- encoding ------------------------------------------------------

    def encode(self, message: list[int]) -> list[int]:
        """Systematically encode ``k`` message bits into an ``n``-bit codeword."""
        if len(message) != self.k:
            raise ValueError(f"message must have {self.k} bits, got {len(message)}")
        payload = [0] * (self.n - self.k) + list(message)
        remainder = _poly_remainder(payload, self.generator)
        codeword = payload[:]
        for i, bit in enumerate(remainder):
            codeword[i] ^= bit
        return codeword

    # -- decoding ------------------------------------------------------

    def decode(self, received: list[int]) -> tuple[list[int], int] | None:
        """Correct up to ``t`` errors; return ``(codeword, errors_corrected)``.

        Returns ``None`` when the word cannot be decoded unambiguously
        (more than ``t`` errors, or a detected-but-uncorrectable pattern).
        """
        if len(received) != self.n:
            raise ValueError(f"received word must have {self.n} bits, got {len(received)}")
        syndromes = self._syndromes(received)
        if all(s == 0 for s in syndromes):
            return list(received), 0

        locator, degree = _berlekamp_massey(syndromes, self.field)
        if degree > self.t:
            return None
        positions = _chien_search(locator, degree, self.field)
        if positions is None:
            return None

        codeword = list(received)
        for position in positions:
            codeword[position] ^= 1
        # Reject "corrections" that do not land on a valid codeword.
        if any(s != 0 for s in self._syndromes(codeword)):
            return None
        return codeword, len(positions)

    def _syndromes(self, received: list[int]) -> list[int]:
        """Syndromes S_1 .. S_{2t} (S_j = received polynomial evaluated at alpha^j)."""
        return [self._evaluate(received, self.field.alpha_pow(j)) for j in range(1, 2 * self.t + 1)]

    def _evaluate(self, coefficients: list[int], x: int) -> int:
        result = 0
        for coefficient in reversed(coefficients):
            result = self.field.mul(result, x) ^ coefficient
        return result


def _berlekamp_massey(syndromes: list[int], field: GF2M) -> tuple[list[int], int]:
    """Find the error locator polynomial; returns ``(sigma, L)`` with ``sigma[0] == 1``."""
    c: list[int] = [1]
    b: list[int] = [1]
    l = 0
    m = 1
    last_discrepancy = 1
    for i in range(len(syndromes)):
        discrepancy = syndromes[i]
        for j in range(1, min(l, i) + 1):
            if j < len(c) and c[j]:
                discrepancy ^= field.mul(c[j], syndromes[i - j])
        if discrepancy == 0:
            m += 1
            continue
        backup = c[:]
        coef = field.mul(discrepancy, field.inv(last_discrepancy))
        for j, bj in enumerate(b):
            if bj:
                index = j + m
                while len(c) <= index:
                    c.append(0)
                c[index] ^= field.mul(coef, bj)
        if 2 * l <= i:
            l = i + 1 - l
            b = backup
            last_discrepancy = discrepancy
            m = 1
        else:
            m += 1
    return c, l


def _chien_search(locator: list[int], degree: int, field: GF2M) -> list[int] | None:
    """Find error positions where ``sigma(alpha^i) == 0``; position = ``(n - i) mod n``."""
    roots: list[int] = []
    for i in range(field.order):
        value = 0
        for j, coef in enumerate(locator):
            if coef:
                value ^= field.mul(coef, field.alpha_pow(i * j))
        if value == 0:
            roots.append(i)
    if len(roots) != degree:
        return None
    return [(field.order - i) % field.order for i in roots]


# -- presets -------------------------------------------------------------

BCH15_7_5 = BCHCode(name="BCH15_7_5", m=4, k=7, t=2, primitive_poly=0b10011)
BCH31_16_7 = BCHCode(name="BCH31_16_7", m=5, k=16, t=3, primitive_poly=0b100101)

CODE_REGISTRY: dict[str, BCHCode] = {
    code.name: code for code in (BCH15_7_5, BCH31_16_7)
}

DEFAULT_CODE = BCH31_16_7


def get_code(name: str) -> BCHCode:
    """Look up a BCH code by name."""
    try:
        return CODE_REGISTRY[name]
    except KeyError:
        raise ValueError(f"unknown code: {name!r}") from None


def select_code_for(response_bit_count: int, codes: list[BCHCode] | None = None) -> BCHCode | None:
    """Pick the code maximising byte-aligned secret capacity for a response.

    The recovered secret must be byte-aligned, so codes whose total message
    capacity does not divide evenly into bytes are skipped.
    """
    best: BCHCode | None = None
    best_bits = -1
    for code in codes if codes is not None else list(CODE_REGISTRY.values()):
        blocks = response_bit_count // code.n
        if blocks < 1:
            continue
        message_bits = code.k * blocks
        if message_bits % 8:
            continue
        if message_bits > best_bits:
            best = code
            best_bits = message_bits
    return best
