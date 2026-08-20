"""Merkle tree for firmware transparency logs.

An append-only Merkle tree where each leaf is a firmware record hash.
Supports inclusion proofs, root consistency verification, and
historical root chain integrity checking.

The tree uses SHA-256 and standard binary Merkle construction.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


@dataclass
class MerkleProof:
    """Inclusion proof for a leaf at a given index."""
    leaf_index: int
    leaf_hash: bytes
    path: list[tuple[bytes, str]]  # (sibling_hash, "left"|"right")
    root: bytes

    def to_dict(self) -> dict:
        return {
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash.hex(),
            "path": [{"hash": h.hex(), "position": p} for h, p in self.path],
            "root": self.root.hex(),
        }


class MerkleTree:
    """Append-only binary Merkle tree."""

    def __init__(self) -> None:
        self._leaves: list[bytes] = []
        self._layers: list[list[bytes]] = []
        self._rebuild()

    @property
    def root(self) -> bytes:
        return self._layers[-1][0] if self._layers and self._layers[0] else _sha256(b"")

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    def add_leaf(self, data: bytes) -> int:
        """Add a leaf (data is hashed). Returns the leaf index."""
        leaf_hash = _sha256(data)
        index = len(self._leaves)
        self._leaves.append(leaf_hash)
        self._rebuild()
        return index

    def add_leaf_hash(self, leaf_hash: bytes) -> int:
        """Add a pre-computed leaf hash. Returns the leaf index."""
        index = len(self._leaves)
        self._leaves.append(leaf_hash)
        self._rebuild()
        return index

    def get_proof(self, index: int) -> MerkleProof:
        """Generate an inclusion proof for the leaf at ``index``."""
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"leaf index {index} out of range (0..{len(self._leaves) - 1})")
        path: list[tuple[bytes, str]] = []
        current_index = index
        for layer in self._layers:
            if len(layer) < 2:
                break
            if current_index % 2 == 0:
                sibling = layer[current_index + 1] if current_index + 1 < len(layer) else layer[current_index]
                path.append((sibling, "right"))
            else:
                sibling = layer[current_index - 1]
                path.append((sibling, "left"))
            current_index //= 2
        return MerkleProof(
            leaf_index=index,
            leaf_hash=self._leaves[index],
            path=path,
            root=self.root,
        )

    def verify_proof(self, proof: MerkleProof) -> bool:
        """Verify an inclusion proof against this tree's current root."""
        current = proof.leaf_hash
        for sibling_hash, position in proof.path:
            if position == "left":
                current = _sha256(sibling_hash + current)
            else:
                current = _sha256(current + sibling_hash)
        return current == self.root and proof.leaf_index < len(self._leaves)

    def root_history(self) -> list[bytes]:
        """Return the full root chain from the genesis (empty) root."""
        roots = [self.root]
        saved = list(self._leaves)
        for i in range(len(saved) - 1, -1, -1):
            self._leaves = saved[:i]
            self._rebuild()
            roots.append(self.root)
        self._leaves = saved
        self._rebuild()
        roots.reverse()
        return roots

    def _rebuild(self) -> None:
        if not self._leaves:
            self._layers = [[]]
            return
        self._layers = [list(self._leaves)]
        current = list(self._leaves)
        while len(current) > 1:
            next_layer = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                next_layer.append(_sha256(left + right))
            self._layers.append(next_layer)
            current = next_layer
