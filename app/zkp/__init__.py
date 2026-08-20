"""Zero-knowledge proof module."""
from .schnorr import (
    SchnorrProof,
    SchnorrVerifier,
    create_proof,
    create_niproof,
)

__all__ = ["SchnorrProof", "SchnorrVerifier", "create_proof", "create_niproof"]
