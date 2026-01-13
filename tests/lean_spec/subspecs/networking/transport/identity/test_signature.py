"""Tests for identity proof signatures."""

import os

from lean_spec.subspecs.networking.transport.identity import (
    NOISE_IDENTITY_PREFIX,
    IdentityKeypair,
    create_identity_proof,
    verify_identity_proof,
)


class TestIdentityProof:
    """Tests for identity proof creation and verification."""

    def test_create_and_verify(self) -> None:
        """Identity proof can be verified."""
        identity_key = IdentityKeypair.generate()
        noise_public_key = os.urandom(32)

        proof = create_identity_proof(identity_key, noise_public_key)
        assert verify_identity_proof(
            identity_key.public_key_bytes(),
            noise_public_key,
            proof,
        )

    def test_verify_wrong_noise_key(self) -> None:
        """Verification fails with wrong Noise key."""
        identity_key = IdentityKeypair.generate()
        noise_public_key = os.urandom(32)
        wrong_noise_key = os.urandom(32)

        proof = create_identity_proof(identity_key, noise_public_key)
        assert not verify_identity_proof(
            identity_key.public_key_bytes(),
            wrong_noise_key,
            proof,
        )

    def test_verify_wrong_identity_key(self) -> None:
        """Verification fails with wrong identity key."""
        identity_key1 = IdentityKeypair.generate()
        identity_key2 = IdentityKeypair.generate()
        noise_public_key = os.urandom(32)

        proof = create_identity_proof(identity_key1, noise_public_key)
        assert not verify_identity_proof(
            identity_key2.public_key_bytes(),
            noise_public_key,
            proof,
        )

    def test_proof_is_deterministic(self) -> None:
        """Same inputs produce same proof format (but not same bytes due to ECDSA k)."""
        identity_key = IdentityKeypair.generate()
        noise_public_key = os.urandom(32)

        proof1 = create_identity_proof(identity_key, noise_public_key)
        proof2 = create_identity_proof(identity_key, noise_public_key)

        assert verify_identity_proof(identity_key.public_key_bytes(), noise_public_key, proof1)
        assert verify_identity_proof(identity_key.public_key_bytes(), noise_public_key, proof2)

    def test_noise_identity_prefix(self) -> None:
        """NOISE_IDENTITY_PREFIX matches libp2p-noise spec."""
        assert NOISE_IDENTITY_PREFIX == b"noise-libp2p-static-key:"

    def test_proof_binds_identity_to_noise_key(self) -> None:
        """Proof prevents identity key substitution."""
        identity_key_real = IdentityKeypair.generate()
        identity_key_attacker = IdentityKeypair.generate()
        noise_public_key = os.urandom(32)

        proof = create_identity_proof(identity_key_real, noise_public_key)

        assert verify_identity_proof(
            identity_key_real.public_key_bytes(),
            noise_public_key,
            proof,
        )
        assert not verify_identity_proof(
            identity_key_attacker.public_key_bytes(),
            noise_public_key,
            proof,
        )
