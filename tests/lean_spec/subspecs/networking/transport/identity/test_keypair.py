"""Tests for secp256k1 identity keypair."""

import pytest

from lean_spec.subspecs.networking.transport.identity import (
    IdentityKeypair,
    Secp256k1PublicKey,
)
from lean_spec.subspecs.networking.transport.peer_id import KeyType
from lean_spec.types import Bytes33


class TestSecp256k1PublicKey:
    """Tests for Secp256k1PublicKey class."""

    def test_from_bytes_roundtrip(self) -> None:
        """Public key can be loaded from raw bytes and re-serialized."""
        keypair = IdentityKeypair.generate()
        raw = keypair.public_key.to_bytes()

        restored = Secp256k1PublicKey.from_bytes(raw)
        assert restored.to_bytes() == raw

    def test_verify_valid_signature(self) -> None:
        """Valid signature passes verification."""
        keypair = IdentityKeypair.generate()
        message = b"test message"
        signature = keypair.sign(message)

        assert keypair.public_key.verify(message, signature)

    def test_verify_wrong_message(self) -> None:
        """Verification fails with wrong message."""
        keypair = IdentityKeypair.generate()
        signature = keypair.sign(b"original message")

        assert not keypair.public_key.verify(b"different message", signature)

    def test_verify_wrong_key(self) -> None:
        """Verification fails with wrong public key."""
        keypair1 = IdentityKeypair.generate()
        keypair2 = IdentityKeypair.generate()
        signature = keypair1.sign(b"test message")

        assert not keypair2.public_key.verify(b"test message", signature)

    def test_from_bytes_invalid(self) -> None:
        """Invalid bytes raise an error."""
        with pytest.raises(ValueError):
            Secp256k1PublicKey.from_bytes(Bytes33(bytes(33)))


class TestIdentityKeypair:
    """Tests for IdentityKeypair class."""

    def test_generate(self) -> None:
        """Generated keypair has valid structure."""
        keypair = IdentityKeypair.generate()

        public_key = keypair.public_key.to_bytes()
        assert len(public_key) == 33
        assert public_key[0] in (0x02, 0x03)

        private_key = keypair.private_key_bytes()
        assert len(private_key) == 32

    def test_generate_unique(self) -> None:
        """Each generated keypair is unique."""
        keypair1 = IdentityKeypair.generate()
        keypair2 = IdentityKeypair.generate()

        assert keypair1.public_key.to_bytes() != keypair2.public_key.to_bytes()
        assert keypair1.private_key_bytes() != keypair2.private_key_bytes()

    def test_from_bytes_roundtrip(self) -> None:
        """Keypair can be loaded from raw bytes."""
        original = IdentityKeypair.generate()
        restored = IdentityKeypair.from_bytes(original.private_key_bytes())
        assert restored.public_key.to_bytes() == original.public_key.to_bytes()
        assert restored.private_key_bytes() == original.private_key_bytes()

    def test_sign_and_verify(self) -> None:
        """Signatures can be verified."""
        keypair = IdentityKeypair.generate()
        message = b"test message"

        signature = keypair.sign(message)

        assert keypair.public_key.verify(message, signature)

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
        multihash = peer_id.multihash

        assert multihash[2] == 0x08
        assert multihash[3] == KeyType.SECP256K1

    def test_compressed_public_key_format(self) -> None:
        """Public key is in compressed SEC1 format."""
        keypair = IdentityKeypair.generate()
        public_key = keypair.public_key.to_bytes()

        assert len(public_key) == 33
        assert public_key[0] in (0x02, 0x03)

    def test_signature_der_format(self) -> None:
        """Signature is in DER format."""
        keypair = IdentityKeypair.generate()
        message = b"test"

        signature = keypair.sign(message)

        assert signature[0] == 0x30
        assert 68 <= len(signature) <= 72
