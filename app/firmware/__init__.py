"""Firmware module: image format, signing, and manufacturer key management."""

from .image import FirmwareImage
from .manufacturer import (
    MANUFACTURER_KEY_NAME,
    MANUFACTURER_SCOPE,
    ManufacturerKeyError,
    ensure_manufacturer_key,
    load_manufacturer_public_key,
)
from .version import VersionError, compare_versions, parse_version, version_allowed

__all__ = [
    "FirmwareImage",
    "MANUFACTURER_KEY_NAME",
    "MANUFACTURER_SCOPE",
    "ManufacturerKeyError",
    "VersionError",
    "compare_versions",
    "ensure_manufacturer_key",
    "load_manufacturer_public_key",
    "parse_version",
    "version_allowed",
]
