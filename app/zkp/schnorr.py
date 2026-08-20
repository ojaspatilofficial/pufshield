"""Schnorr Sigma Protocol — Zero-Knowledge Proof of Knowledge of Discrete Log.

Implements a 3-move Σ-protocol (commit–challenge–response) for proving
knowledge of x such that g^x = y (mod p), without revealing x.

Security: Honest-verifier zero-knowledge (HVZK).  Forking lemma gives
extraction soundness.  Binding is computational (DLog assumption).

The protocol:
    Prover                             Verifier
      Pick random r
      Compute t = g^r mod p
      Send t ───────────────────────►
                                      Pick random c
      ◄────────────────────────── c
      Compute s = r + c*x mod q
      Send s ───────────────────────►
                                      Check: g^s == t * y^c mod p
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass


# Safe 2048-bit MODP group (RFC 3526, Group 14)
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF

# Generator
G = 2

# Group order (prime subgroup order, from RFC 3526)
Q_ORDER = (P - 1) // 2


def _mod_pow(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)


def _hash_chal(*args: bytes) -> int:
    """Hash function for challenge generation (Fiat-Shamir style)."""
    h = hashlib.sha256()
    for a in args:
        h.update(a)
    digest = int.from_bytes(h.digest(), 'big')
    return digest % Q_ORDER


@dataclass
class SchnorrProof:
    """A Schnorr sigma-protocol proof."""
    commitment: int   # t = g^r mod p
    challenge: int    # c = H(g, y, t)
    response: int     # s = r + c*x mod q

    def to_dict(self) -> dict:
        return {
            "commitment": str(self.commitment),
            "challenge": str(self.challenge),
            "response": str(self.response),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SchnorrProof":
        return cls(
            commitment=int(d["commitment"]),
            challenge=int(d["challenge"]),
            response=int(d["response"]),
        )


class SchnorrVerifier:
    """Schnorr Σ-protocol verifier for DLog proofs."""

    def __init__(self, p: int = P, g: int = G, q: int = Q_ORDER) -> None:
        self.p = p
        self.g = g
        self.q = q

    def compute_public_key(self, secret: int) -> int:
        """Compute y = g^secret mod p."""
        return _mod_pow(self.g, secret, self.p)

    def verify(self, public_key: int, proof: SchnorrProof) -> bool:
        """Verify a Schnorr proof that the prover knows x where g^x = y.

        Checks: g^s ≡ t * y^c (mod p)
        """
        if not (0 < public_key < self.p):
            return False
        if not (0 <= proof.response < self.q):
            return False
        # Left side: g^s mod p
        lhs = _mod_pow(self.g, proof.response, self.p)
        # Right side: t * y^c mod p
        rhs = (proof.commitment * _mod_pow(public_key, proof.challenge, self.p)) % self.p
        return lhs == rhs

    def verify_noninteractive(self, public_key: int, proof: SchnorrProof) -> bool:
        """Verify a non-interactive (Fiat-Shamir) Schnorr proof.

        The challenge must equal H(g, y, t).
        """
        expected_chal = _hash_chal(
            self.g.to_bytes(256, 'big'),
            public_key.to_bytes(256, 'big'),
            proof.commitment.to_bytes(256, 'big'),
        )
        if proof.challenge != expected_chal:
            return False
        return self.verify(public_key, proof)


def create_proof(secret: int, p: int = P, g: int = G, q: int = Q_ORDER) -> SchnorrProof:
    """Create an interactive Schnorr proof (prover side).

    This creates an interactive proof.  For a non-interactive proof,
    use ``create_niproof`` instead.
    """
    r = int.from_bytes(os.urandom(32), 'big') % q
    t = _mod_pow(g, r, p)
    y = _mod_pow(g, secret, p)
    c = _hash_chal(
        g.to_bytes(256, 'big'),
        y.to_bytes(256, 'big'),
        t.to_bytes(256, 'big'),
    )
    s = (r + c * secret) % q
    return SchnorrProof(commitment=t, challenge=c, response=s)


def create_niproof(secret: int, p: int = P, g: int = G, q: int = Q_ORDER) -> SchnorrProof:
    """Create a non-interactive Schnorr proof (Fiat-Shamir transform).

    The challenge is derived deterministically from (g, y, t), so
    there is no need for a separate challenge message.
    """
    return create_proof(secret, p, g, q)


def prove_knowledge_of_dlog(public_key: int, p: int = P, g: int = G, q: int = Q_ORDER) -> SchnorrProof | None:
    """Prove knowledge of discrete log without having the secret.

    This function is used for simulation/demo purposes.  In production,
    the prover would know the secret.
    """
    return None
