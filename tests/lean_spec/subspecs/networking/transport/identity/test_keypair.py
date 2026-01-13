"""Tests for secp256k1 identity keypair."""

import pytest

from lean_spec.subspecs.networking.transport.identity import (
    IdentityKeypair,
    verify_signature,
)
from lean_spec.subspecs.networking.transport.peer_id import KeyType


class TestIdentityKeypair:
    """Tests for IdentityKeypair class."""

    def test_generate(self) -> None:
        """Generated keypair has valid structure."""
        keypair = IdentityKeypair.generate()

        public_key = keypair.public_key_bytes()
        assert len(public_key) == 33
        assert public_key[0] in (0x02, 0x03)

        private_key = keypair.private_key_bytes()
        assert len(private_key) == 32

    def test_generate_unique(self) -> None:
        """Each generated keypair is unique."""
        keypair1 = IdentityKeypair.generate()
        keypair2 = IdentityKeypair.generate()

        assert keypair1.public_key_bytes() != keypair2.public_key_bytes()
        assert keypair1.private_key_bytes() != keypair2.private_key_bytes()

    def test_from_bytes_roundtrip(self) -> None:
        """Keypair can be loaded from raw bytes."""
        original = IdentityKeypair.generate()
        private_bytes = original.private_key_bytes()

        restored = IdentityKeypair.from_bytes(private_bytes)

        assert restored.public_key_bytes() == original.public_key_bytes()
        assert restored.private_key_bytes() == original.private_key_bytes()

    def test_from_bytes_invalid_length(self) -> None:
        """Loading from invalid bytes raises ValueError."""
        with pytest.raises(ValueError, match="Expected 32 bytes"):
            IdentityKeypair.from_bytes(b"\x00" * 16)

        with pytest.raises(ValueError, match="Expected 32 bytes"):
            IdentityKeypair.from_bytes(b"\x00" * 64)

    def test_sign_and_verify(self) -> None:
        """Signatures can be verified."""
        keypair = IdentityKeypair.generate()
        message = b"test message"

        signature = keypair.sign(message)

        assert verify_signature(keypair.public_key_bytes(), message, signature)

    def test_verify_wrong_message(self) -> None:
        """Verification fails with wrong message."""
        keypair = IdentityKeypair.generate()
        message = b"original message"
        wrong_message = b"different message"

        signature = keypair.sign(message)

        assert not verify_signature(keypair.public_key_bytes(), wrong_message, signature)

    def test_verify_wrong_key(self) -> None:
        """Verification fails with wrong public key."""
        keypair1 = IdentityKeypair.generate()
        keypair2 = IdentityKeypair.generate()
        message = b"test message"

        signature = keypair1.sign(message)

        assert not verify_signature(keypair2.public_key_bytes(), message, signature)

    def test_to_peer_id(self) -> None:
        """PeerId derivation produces valid result."""
        keypair = IdentityKeypair.generate()
        peer_id = keypair.to_peer_id()

        peer_id_str = str(peer_id)
        assert peer_id_str.startswith("16Uiu2")
        assert len(peer_id_str) > 40

    def test_peer_id_deterministic(self) -> None:
        """Same key always produces same PeerId."""
        keypair = IdentityKeypair.generate()

        peer_id1 = keypair.to_peer_id()
        peer_id2 = keypair.to_peer_id()

        assert str(peer_id1) == str(peer_id2)

    def test_peer_id_uses_secp256k1_key_type(self) -> None:
        """PeerId derivation uses SECP256K1 key type."""
        keypair = IdentityKeypair.generate()

        peer_id = keypair.to_peer_id()
        multihash = peer_id.to_bytes()

        assert multihash[2] == 0x08
        assert multihash[3] == KeyType.SECP256K1

    def test_compressed_public_key_format(self) -> None:
        """Public key is in compressed SEC1 format."""
        keypair = IdentityKeypair.generate()
        public_key = keypair.public_key_bytes()

        assert len(public_key) == 33
        assert public_key[0] in (0x02, 0x03)

    def test_signature_der_format(self) -> None:
        """Signature is in DER format."""
        keypair = IdentityKeypair.generate()
        message = b"test"

        signature = keypair.sign(message)

        assert signature[0] == 0x30
        assert 68 <= len(signature) <= 72
