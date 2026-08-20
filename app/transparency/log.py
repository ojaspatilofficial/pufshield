"""Firmware transparency log built on a Merkle tree.

Every published firmware version is recorded in an append-only log.
The log provides inclusion proofs, root consistency verification, and
historical root chain integrity.

At boot, firmware must appear in the transparency log with a valid
inclusion proof — even if the signature is valid. This protects against
a compromised signing key issuing unauthorized firmware.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
from dataclasses import dataclass, field

from .merkle import MerkleTree, MerkleProof

logger = logging.getLogger(__name__)


@dataclass
class FirmwareEntry:
    """A single firmware record in the transparency log."""
    firmware_id: str
    version: str
    device_id: str
    payload_sha256: str
    signer: str
    timestamp: str
    published: bool
    sequence: int
    leaf_hash: bytes = field(default_factory=bytes, repr=False)

    def to_dict(self) -> dict:
        return {
            "firmware_id": self.firmware_id,
            "version": self.version,
            "device_id": self.device_id,
            "payload_sha256": self.payload_sha256,
            "signer": self.signer,
            "timestamp": self.timestamp,
            "published": self.published,
            "sequence": self.sequence,
            "leaf_hash": self.leaf_hash.hex(),
        }

    def leaf_data(self) -> bytes:
        """Canonical bytes hashed into the Merkle tree."""
        return json.dumps({
            "firmware_id": self.firmware_id,
            "version": self.version,
            "device_id": self.device_id,
            "payload_sha256": self.payload_sha256,
            "signer": self.signer,
            "timestamp": self.timestamp,
            "sequence": self.sequence,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")


class FirmwareTransparencyLog:
    """Append-only firmware transparency log with Merkle tree backing."""

    def __init__(self) -> None:
        self._entries: list[FirmwareEntry] = []
        self._tree = MerkleTree()
        self._root_history: list[bytes] = [self._tree.root]
        self._sequence_counter = 0

    @property
    def current_root(self) -> bytes:
        return self._tree.root

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def record_firmware(
        self,
        firmware_id: str,
        version: str,
        device_id: str,
        payload_sha256: str,
        signer: str = "manufacturer",
    ) -> FirmwareEntry:
        """Append a new firmware record to the log."""
        self._sequence_counter += 1
        entry = FirmwareEntry(
            firmware_id=firmware_id,
            version=version,
            device_id=device_id,
            payload_sha256=payload_sha256,
            signer=signer,
            timestamp=dt.datetime.now(dt.timezone.utc).isoformat(),
            published=True,
            sequence=self._sequence_counter,
        )
        entry.leaf_hash = hashlib.sha256(entry.leaf_data()).digest()
        self._entries.append(entry)
        self._tree.add_leaf_hash(entry.leaf_hash)
        self._root_history.append(self._tree.root)
        logger.info(
            "Recorded firmware %s v%s for %s (seq=%d)", firmware_id, version, device_id, entry.sequence
        )
        return entry

    def lookup(self, device_id: str, version: str) -> FirmwareEntry | None:
        """Find a published firmware record by device and version."""
        for entry in self._entries:
            if entry.device_id == device_id and entry.version == version and entry.published:
                return entry
        return None

    def lookup_by_payload(self, payload_sha256: str) -> FirmwareEntry | None:
        """Find a published firmware record by its payload hash."""
        for entry in self._entries:
            if entry.payload_sha256 == payload_sha256 and entry.published:
                return entry
        return None

    def get_inclusion_proof(self, index: int) -> MerkleProof:
        """Generate a Merkle inclusion proof for the entry at ``index``."""
        return self._tree.get_proof(index)

    def verify_inclusion(self, entry: FirmwareEntry) -> bool:
        """Verify that an entry is included in the current tree."""
        proof = self.get_inclusion_proof(self._entries.index(entry))
        return self._tree.verify_proof(proof)

    def verify_root_consistency(self) -> tuple[bool, str]:
        """Verify that the root history forms a consistent chain.

        Each root must be derivable from the previous roots by appending
        leaves. Returns (is_consistent, message).
        """
        if len(self._root_history) < 2:
            return True, "genesis root — consistent"

        test_tree = MerkleTree()
        for i, root in enumerate(self._root_history):
            if i == 0:
                if test_tree.root != root:
                    return False, f"genesis root mismatch at index {i}"
                continue
            if i <= len(self._entries):
                entry = self._entries[i - 1]
                test_tree.add_leaf_hash(entry.leaf_hash)
                if test_tree.root != root:
                    return False, f"root mismatch at index {i} (sequence {i})"
            else:
                return False, f"root history has more entries ({len(self._root_history)}) than firmware records ({len(self._entries)})"

        return True, f"root chain verified ({len(self._root_history)} roots)"

    def list_entries(self, device_id: str | None = None) -> list[dict]:
        """List all published firmware records."""
        entries = self._entries
        if device_id:
            entries = [e for e in entries if e.device_id == device_id]
        return [e.to_dict() for e in entries]

    def get_root_history(self) -> list[dict]:
        """Return the root chain with sequence numbers."""
        return [
            {"sequence": i, "root": root.hex()}
            for i, root in enumerate(self._root_history)
        ]
