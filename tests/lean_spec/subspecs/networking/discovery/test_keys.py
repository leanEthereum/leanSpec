"""Tests for Discovery v5 key derivation."""

import pytest

from lean_spec.subspecs.networking.discovery.crypto import (
    generate_secp256k1_keypair,
)
from lean_spec.subspecs.networking.discovery.keys import (
    compute_node_id,
    derive_keys,
    derive_keys_from_pubkey,
)


def make_challenge_data(id_nonce: bytes = bytes(16)) -> bytes:
    """
    Build mock challenge_data for testing.

    Challenge data format: masking-iv (16) + static-header (23) + authdata (24)
    Authdata for WHOAREYOU: id-nonce (16) + enr-seq (8)
    """
    masking_iv = bytes(16)  # Mock IV
    # Static header: protocol-id (6) + version (2) + flag (1) + nonce (12) + authdata-size (2)
    static_header = b"discv5" + b"\x00\x01" + b"\x01" + bytes(12) + b"\x00\x18"
    # Authdata: id-nonce (16) + enr-seq (8)
    authdata = id_nonce + bytes(8)
    return masking_iv + static_header + authdata


class TestDeriveKeys:
    """Tests for session key derivation."""

    def test_derives_two_16_byte_keys(self):
        """Test that key derivation produces two 16-byte keys."""
        secret = bytes(32)
        initiator_id = bytes(32)
        recipient_id = bytes(32)
        challenge_data = make_challenge_data()

        init_key, recv_key = derive_keys(secret, initiator_id, recipient_id, challenge_data)

        assert len(init_key) == 16
        assert len(recv_key) == 16

    def test_different_secrets_produce_different_keys(self):
        """Test that different secrets produce different keys."""
        secret1 = bytes.fromhex("00" * 32)
        secret2 = bytes.fromhex("01" + "00" * 31)
        initiator_id = bytes(32)
        recipient_id = bytes(32)
        challenge_data = make_challenge_data()

        keys1 = derive_keys(secret1, initiator_id, recipient_id, challenge_data)
        keys2 = derive_keys(secret2, initiator_id, recipient_id, challenge_data)

        assert keys1 != keys2

    def test_different_node_ids_produce_different_keys(self):
        """Test that different node IDs produce different keys."""
        secret = bytes(32)
        initiator_id1 = bytes.fromhex("00" * 32)
        initiator_id2 = bytes.fromhex("01" + "00" * 31)
        recipient_id = bytes(32)
        challenge_data = make_challenge_data()

        keys1 = derive_keys(secret, initiator_id1, recipient_id, challenge_data)
        keys2 = derive_keys(secret, initiator_id2, recipient_id, challenge_data)

        assert keys1 != keys2

    def test_different_challenge_data_produce_different_keys(self):
        """Test that different challenge data produces different keys."""
        secret = bytes(32)
        initiator_id = bytes(32)
        recipient_id = bytes(32)
        challenge_data1 = make_challenge_data(bytes.fromhex("00" * 16))
        challenge_data2 = make_challenge_data(bytes.fromhex("01" + "00" * 15))

        keys1 = derive_keys(secret, initiator_id, recipient_id, challenge_data1)
        keys2 = derive_keys(secret, initiator_id, recipient_id, challenge_data2)

        assert keys1 != keys2

    def test_order_matters(self):
        """Test that initiator and recipient order matters."""
        secret = bytes(32)
        node_a = bytes.fromhex("aa" * 32)
        node_b = bytes.fromhex("bb" * 32)
        challenge_data = make_challenge_data()

        keys_ab = derive_keys(secret, node_a, node_b, challenge_data)
        keys_ba = derive_keys(secret, node_b, node_a, challenge_data)

        assert keys_ab != keys_ba

    def test_invalid_secret_length_raises(self):
        """Test that invalid secret length raises ValueError."""
        with pytest.raises(ValueError, match="Secret must be 32 bytes"):
            derive_keys(bytes(31), bytes(32), bytes(32), make_challenge_data())

    def test_invalid_initiator_id_length_raises(self):
        """Test that invalid initiator ID length raises ValueError."""
        with pytest.raises(ValueError, match="Initiator ID must be 32 bytes"):
            derive_keys(bytes(32), bytes(31), bytes(32), make_challenge_data())

    def test_invalid_recipient_id_length_raises(self):
        """Test that invalid recipient ID length raises ValueError."""
        with pytest.raises(ValueError, match="Recipient ID must be 32 bytes"):
            derive_keys(bytes(32), bytes(32), bytes(31), make_challenge_data())


class TestDeriveKeysFromPubkey:
    """Tests for key derivation from ECDH."""

    def test_initiator_and_recipient_derive_compatible_keys(self):
        """Test that both parties derive compatible keys."""
        priv_a, pub_a = generate_secp256k1_keypair()
        priv_b, pub_b = generate_secp256k1_keypair()
        node_a = compute_node_id(pub_a)
        node_b = compute_node_id(pub_b)
        challenge_data = make_challenge_data()

        # A initiates to B
        send_a, recv_a = derive_keys_from_pubkey(
            priv_a, pub_b, bytes(node_a), bytes(node_b), challenge_data, is_initiator=True
        )

        # B responds to A
        send_b, recv_b = derive_keys_from_pubkey(
            priv_b, pub_a, bytes(node_b), bytes(node_a), challenge_data, is_initiator=False
        )

        # A's send key should be B's recv key and vice versa
        assert send_a == recv_b
        assert recv_a == send_b


class TestComputeNodeId:
    """Tests for node ID computation."""

    def test_computes_32_byte_node_id(self):
        """Test that node ID is 32 bytes."""
        _, pub = generate_secp256k1_keypair()
        node_id = compute_node_id(pub)

        assert len(node_id) == 32

    def test_same_pubkey_produces_same_node_id(self):
        """Test that same public key produces same node ID."""
        _, pub = generate_secp256k1_keypair()

        id1 = compute_node_id(pub)
        id2 = compute_node_id(pub)

        assert id1 == id2

    def test_different_pubkeys_produce_different_node_ids(self):
        """Test that different public keys produce different node IDs."""
        _, pub1 = generate_secp256k1_keypair()
        _, pub2 = generate_secp256k1_keypair()

        id1 = compute_node_id(pub1)
        id2 = compute_node_id(pub2)

        assert id1 != id2

    def test_accepts_compressed_pubkey(self):
        """Test that compressed public key format is accepted."""
        _, pub = generate_secp256k1_keypair()
        assert len(pub) == 33

        node_id = compute_node_id(pub)
        assert len(node_id) == 32

    def test_accepts_uncompressed_pubkey(self):
        """Test that uncompressed public key format is accepted."""
        from lean_spec.subspecs.networking.discovery.crypto import pubkey_to_uncompressed

        _, compressed = generate_secp256k1_keypair()
        uncompressed = pubkey_to_uncompressed(compressed)
        assert len(uncompressed) == 65

        node_id = compute_node_id(uncompressed)
        assert len(node_id) == 32

    def test_compressed_and_uncompressed_produce_same_id(self):
        """Test that both formats produce the same node ID."""
        from lean_spec.subspecs.networking.discovery.crypto import pubkey_to_uncompressed

        _, compressed = generate_secp256k1_keypair()
        uncompressed = pubkey_to_uncompressed(compressed)

        id_compressed = compute_node_id(compressed)
        id_uncompressed = compute_node_id(uncompressed)

        assert id_compressed == id_uncompressed
