"""Tests for Merkle tree and firmware transparency log."""
import hashlib
import pytest
from app.transparency.merkle import MerkleTree, MerkleProof, _sha256
from app.transparency.log import FirmwareTransparencyLog, FirmwareEntry


class TestMerkleTree:
    def test_empty_tree_root(self):
        tree = MerkleTree()
        assert tree.root == _sha256(b"")
        assert tree.leaf_count == 0

    def test_single_leaf(self):
        tree = MerkleTree()
        tree.add_leaf(b"firmware-v1")
        assert tree.leaf_count == 1
        assert tree.root == _sha256(b"firmware-v1")

    def test_two_leaves(self):
        tree = MerkleTree()
        tree.add_leaf(b"a")
        tree.add_leaf(b"b")
        assert tree.leaf_count == 2
        assert tree.root == _sha256(_sha256(b"a") + _sha256(b"b"))

    def test_add_leaf_hash(self):
        tree = MerkleTree()
        h = _sha256(b"test")
        tree.add_leaf_hash(h)
        assert tree.leaf_count == 1
        assert tree.root == h

    def test_inclusion_proof_valid(self):
        tree = MerkleTree()
        for i in range(4):
            tree.add_leaf(f"fw-{i}".encode())
        proof = tree.get_proof(0)
        assert tree.verify_proof(proof)

    def test_inclusion_proof_invalid_index(self):
        tree = MerkleTree()
        tree.add_leaf(b"fw-0")
        with pytest.raises(IndexError):
            tree.get_proof(5)

    def test_inclusion_proof_modified_leaf(self):
        tree = MerkleTree()
        tree.add_leaf(b"fw-0")
        tree.add_leaf(b"fw-1")
        proof = tree.get_proof(0)
        proof.leaf_hash = _sha256(b"tampered")
        assert not tree.verify_proof(proof)

    def test_root_changes_with_leaves(self):
        tree = MerkleTree()
        root0 = tree.root
        tree.add_leaf(b"fw-0")
        root1 = tree.root
        assert root0 != root1

    def test_root_history(self):
        tree = MerkleTree()
        tree.add_leaf(b"a")
        tree.add_leaf(b"b")
        tree.add_leaf(b"c")
        history = tree.root_history()
        assert len(history) == 4  # genesis + 3


class TestFirmwareTransparencyLog:
    def test_record_and_lookup(self):
        tl = FirmwareTransparencyLog()
        entry = tl.record_firmware("fw-001", "1.0.0", "dev-001", "aa" * 32)
        assert entry.sequence == 1
        assert entry.firmware_id == "fw-001"
        found = tl.lookup("dev-001", "1.0.0")
        assert found is not None
        assert found.firmware_id == "fw-001"

    def test_lookup_not_found(self):
        tl = FirmwareTransparencyLog()
        assert tl.lookup("dev-999", "1.0.0") is None

    def test_inclusion_proof(self):
        tl = FirmwareTransparencyLog()
        tl.record_firmware("fw-001", "1.0.0", "dev-001", "aa" * 32)
        entry = tl.lookup("dev-001", "1.0.0")
        assert tl.verify_inclusion(entry)

    def test_root_consistency(self):
        tl = FirmwareTransparencyLog()
        tl.record_firmware("fw-001", "1.0.0", "dev-001", "aa" * 32)
        tl.record_firmware("fw-002", "2.0.0", "dev-001", "bb" * 32)
        ok, msg = tl.verify_root_consistency()
        assert ok

    def test_append_only(self):
        tl = FirmwareTransparencyLog()
        tl.record_firmware("fw-001", "1.0.0", "dev-001", "aa" * 32)
        assert tl.entry_count == 1
        # entries list is internal - no delete method
        entries = tl.list_entries()
        assert len(entries) == 1

    def test_list_entries_filtered(self):
        tl = FirmwareTransparencyLog()
        tl.record_firmware("fw-001", "1.0.0", "dev-001", "aa" * 32)
        tl.record_firmware("fw-002", "1.0.0", "dev-002", "bb" * 32)
        assert len(tl.list_entries("dev-001")) == 1
        assert len(tl.list_entries("dev-002")) == 1

    def test_root_history(self):
        tl = FirmwareTransparencyLog()
        tl.record_firmware("fw-001", "1.0.0", "dev-001", "aa" * 32)
        history = tl.get_root_history()
        assert len(history) >= 2  # genesis + 1
        assert "root" in history[0]
