"""Tests for Schnorr ZKP module."""
import hashlib
import pytest
from app.zkp.schnorr import (
    SchnorrVerifier, SchnorrProof,
    create_proof, create_niproof, P, G, Q_ORDER,
)


@pytest.fixture
def verifier():
    return SchnorrVerifier()


@pytest.fixture
def keypair():
    secret = 42
    verifier = SchnorrVerifier()
    public_key = verifier.compute_public_key(secret)
    return secret, public_key


class TestSchnorrVerifier:
    def test_compute_public_key(self, verifier):
        pk = verifier.compute_public_key(1)
        assert pk == G % P

    def test_valid_niproof(self, verifier, keypair):
        secret, public_key = keypair
        proof = create_niproof(secret)
        assert verifier.verify_noninteractive(public_key, proof)

    def test_invalid_proof_wrong_response(self, verifier, keypair):
        secret, public_key = keypair
        proof = create_niproof(secret)
        tampered = SchnorrProof(
            commitment=proof.commitment,
            challenge=proof.challenge,
            response=proof.response + 1,
        )
        assert not verifier.verify(public_key, tampered)

    def test_invalid_proof_wrong_commitment(self, verifier, keypair):
        secret, public_key = keypair
        proof = create_niproof(secret)
        tampered = SchnorrProof(
            commitment=proof.commitment + 1,
            challenge=proof.challenge,
            response=proof.response,
        )
        assert not verifier.verify(public_key, tampered)

    def test_proof_roundtrip_dict(self, verifier, keypair):
        secret, public_key = keypair
        proof = create_niproof(secret)
        d = proof.to_dict()
        reconstructed = SchnorrProof.from_dict(d)
        assert verifier.verify_noninteractive(public_key, reconstructed)

    def test_wrong_secret_fails(self, verifier):
        secret1 = 42
        secret2 = 43
        pk = verifier.compute_public_key(secret1)
        proof = create_niproof(secret2)
        assert not verifier.verify_noninteractive(pk, proof)

    def test_zero_secret(self, verifier):
        proof = create_niproof(0)
        pk = verifier.compute_public_key(0)
        assert verifier.verify_noninteractive(pk, proof)

    def test_large_secret(self, verifier):
        secret = Q_ORDER - 1
        pk = verifier.compute_public_key(secret)
        proof = create_niproof(secret)
        assert verifier.verify_noninteractive(pk, proof)

    def test_niproof_is_fiat_shamir(self):
        secret = 123
        verifier = SchnorrVerifier()
        pk = verifier.compute_public_key(secret)
        for _ in range(3):
            proof = create_niproof(secret)
            assert verifier.verify_noninteractive(pk, proof)
            expected_chal = hashlib.sha256(
                G.to_bytes(256, "big")
                + pk.to_bytes(256, "big")
                + proof.commitment.to_bytes(256, "big")
            ).digest()
            expected_int = int.from_bytes(expected_chal, "big") % Q_ORDER
            assert proof.challenge == expected_int
