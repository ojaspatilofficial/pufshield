"""Secure firmware version parsing and comparison.

Anti-rollback policy compares the version embedded in a manufacturer-
signed firmware manifest against the minimum allowed version stored for
each device. The comparison must never be fooled by crafted version
strings, so parsing is strict and deterministic:

* a version is a dotted sequence of non-negative integers (e.g.
  ``"1.2.3"``),
* no leading/trailing whitespace, empty components, or duplicated dots,
* no leading zeros (``"01"`` is ambiguous and rejected),
* at most eight components.

Comparison is numeric and treats missing trailing components as zero
(``"2.0"`` equals ``"2.0.0"`` and is less than ``"2.0.1"``). Any
unparseable version raises :class:`VersionError`; anti-rollback callers
treat that as *fail closed* - an unknown/crafted version is never allowed
to boot.
"""

from __future__ import annotations

import re
from itertools import zip_longest

_VERSION_PATTERN = re.compile(r"^\d+(\.\d+)*$")
_MAX_COMPONENTS = 8


class VersionError(ValueError):
    """Raised when a version string is not a well-formed dotted version."""


def parse_version(value: str) -> tuple[int, ...]:
    """Parse a dotted numeric version into a comparable tuple of integers.

    Raises :class:`VersionError` for malformed input so callers can fail
    closed instead of making a wrong comparison.
    """
    if not isinstance(value, str) or not _VERSION_PATTERN.match(value):
        raise VersionError(f"malformed firmware version: {value!r}")
    parts = value.split(".")
    if len(parts) > _MAX_COMPONENTS:
        raise VersionError(f"firmware version has too many components: {value!r}")
    numbers: list[int] = []
    for part in parts:
        if len(part) > 1 and part.startswith("0"):
            raise VersionError(f"firmware version component has leading zero: {value!r}")
        numbers.append(int(part))
    return tuple(numbers)


def compare_versions(left: str, right: str) -> int:
    """Compare two versions numerically; missing components count as zero.

    Returns a negative number if ``left < right``, ``0`` if equal, and a
    positive number if ``left > right``.
    """
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    for a, b in zip_longest(left_parts, right_parts, fillvalue=0):
        if a != b:
            return -1 if a < b else 1
    return 0


def version_allowed(image_version: str, minimum_version: str | None) -> bool:
    """Return whether ``image_version`` satisfies the anti-rollback policy.

    An empty or ``None`` minimum means no policy (anything is allowed).
    Otherwise the image version must be numerically greater than or equal
    to the minimum. Raises :class:`VersionError` when either version is
    malformed so callers can fail closed.
    """
    if minimum_version is None or minimum_version == "":
        return True
    return compare_versions(image_version, minimum_version) >= 0
