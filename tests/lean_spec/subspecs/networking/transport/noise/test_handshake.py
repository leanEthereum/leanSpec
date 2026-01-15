"""
Tests for Noise XX handshake implementation.

Tests the full XX pattern state machine:
    -> e                 # Message 1: Initiator sends ephemeral
    <- e, ee, s, es      # Message 2: Responder full message
    -> s, se             # Message 3: Initiator completes

Test vectors from noisesocket spec where available.
https://github.com/noisesocket/spec/blob/master/test_vectors.json
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from lean_spec.subspecs.networking.transport.noise.constants import CipherKey
from lean_spec.subspecs.networking.transport.noise.crypto import generate_keypair
from lean_spec.subspecs.networking.transport.noise.handshake import (
    HandshakeRole,
    HandshakeState,
    NoiseError,
    NoiseHandshake,
)
from lean_spec.subspecs.networking.transport.noise.types import CipherState


class TestHandshakeCreation:
    """Tests for handshake initialization."""

    def test_initiator_creation(self) -> None:
        """Create initiator handshake."""
        static_key, _ = generate_keypair()

        handshake = NoiseHandshake.initiator(static_key)

        assert handshake.role == HandshakeRole.INITIATOR
        assert handshake._state == HandshakeState.INITIALIZED
        assert handshake.remote_static_public is None
        assert handshake.remote_ephemeral_public is None
        # local_ephemeral_public is now an X25519PublicKey object
        assert isinstance(handshake.local_ephemeral_public, x25519.X25519PublicKey)
        assert len(handshake.local_ephemeral_public.public_bytes_raw()) == 32

    def test_responder_creation(self) -> None:
        """Create responder handshake."""
        static_key, _ = generate_keypair()

        handshake = NoiseHandshake.responder(static_key)

        assert handshake.role == HandshakeRole.RESPONDER
        assert handshake._state == HandshakeState.AWAITING_MESSAGE_1
        assert handshake.remote_static_public is None
        assert handshake.remote_ephemeral_public is None
        # local_ephemeral_public is now an X25519PublicKey object
        assert isinstance(handshake.local_ephemeral_public, x25519.X25519PublicKey)
        assert len(handshake.local_ephemeral_public.public_bytes_raw()) == 32

    def test_ephemeral_keys_are_unique(self) -> None:
        """Each handshake gets unique ephemeral keys."""
        static_key, _ = generate_keypair()

        h1 = NoiseHandshake.initiator(static_key)
        h2 = NoiseHandshake.initiator(static_key)

        # Compare the raw bytes since key objects are not directly comparable
        h1_pub_bytes = h1.local_ephemeral_public.public_bytes_raw()
        h2_pub_bytes = h2.local_ephemeral_public.public_bytes_raw()
        assert h1_pub_bytes != h2_pub_bytes


class TestMessage1:
    """Tests for Message 1: -> e."""

    def test_write_message_1(self) -> None:
        """Initiator writes message 1 containing ephemeral pubkey."""
        static_key, _ = generate_keypair()
        handshake = NoiseHandshake.initiator(static_key)

        msg1 = handshake.write_message_1()

        # Message 1 is just the ephemeral public key (32 bytes)
        assert len(msg1) == 32
        # Compare bytes to key's raw bytes
        assert msg1 == handshake.local_ephemeral_public.public_bytes_raw()
        assert handshake._state == HandshakeState.AWAITING_MESSAGE_2

    def test_only_initiator_writes_message_1(self) -> None:
        """Responder cannot write message 1."""
        static_key, _ = generate_keypair()
        handshake = NoiseHandshake.responder(static_key)

        with pytest.raises(NoiseError, match="Only initiator"):
            handshake.write_message_1()

    def test_read_message_1(self) -> None:
        """Responder reads message 1."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)

        # Compare the raw bytes of key objects
        assert responder.remote_ephemeral_public is not None
        remote_eph_bytes = responder.remote_ephemeral_public.public_bytes_raw()
        local_eph_bytes = initiator.local_ephemeral_public.public_bytes_raw()
        assert remote_eph_bytes == local_eph_bytes
        assert responder._state == HandshakeState.INITIALIZED

    def test_only_responder_reads_message_1(self) -> None:
        """Initiator cannot read message 1."""
        static_key, _ = generate_keypair()
        handshake = NoiseHandshake.initiator(static_key)

        with pytest.raises(NoiseError, match="Only responder"):
            handshake.read_message_1(bytes(32))

    def test_message_1_wrong_size(self) -> None:
        """Message 1 must be exactly 32 bytes."""
        static_key, _ = generate_keypair()
        handshake = NoiseHandshake.responder(static_key)

        with pytest.raises(NoiseError, match="32 bytes"):
            handshake.read_message_1(bytes(31))

        with pytest.raises(NoiseError, match="32 bytes"):
            handshake.read_message_1(bytes(33))


class TestMessage2:
    """Tests for Message 2: <- e, ee, s, es."""

    def test_write_message_2(self) -> None:
        """Responder writes message 2."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)

        msg2 = responder.write_message_2()

        # Message 2: 32 (ephemeral) + 48 (encrypted static = 32 + 16 tag)
        assert len(msg2) >= 80
        assert responder._state == HandshakeState.AWAITING_MESSAGE_3

    def test_write_message_2_with_payload(self) -> None:
        """Responder includes payload in message 2."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)

        payload = b"Hello from responder"
        msg2 = responder.write_message_2(payload)

        # Message 2: 32 + 48 + (len(payload) + 16)
        expected_min_len = 80 + len(payload) + 16
        assert len(msg2) >= expected_min_len

    def test_only_responder_writes_message_2(self) -> None:
        """Initiator cannot write message 2."""
        static_key, _ = generate_keypair()
        handshake = NoiseHandshake.initiator(static_key)

        with pytest.raises(NoiseError, match="Only responder"):
            handshake.write_message_2()

    def test_read_message_2(self) -> None:
        """Initiator reads message 2."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        msg2 = responder.write_message_2()
        initiator.read_message_2(msg2)

        # Initiator now knows responder's static key
        assert initiator.remote_static_public is not None
        assert initiator.remote_ephemeral_public is not None
        init_remote_static = initiator.remote_static_public.public_bytes_raw()
        resp_local_static = responder.local_static_public.public_bytes_raw()
        assert init_remote_static == resp_local_static
        init_remote_eph = initiator.remote_ephemeral_public.public_bytes_raw()
        resp_local_eph = responder.local_ephemeral_public.public_bytes_raw()
        assert init_remote_eph == resp_local_eph

    def test_read_message_2_extracts_payload(self) -> None:
        """Initiator decrypts payload from message 2."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)

        payload = b"Responder identity data"
        msg2 = responder.write_message_2(payload)
        received_payload = initiator.read_message_2(msg2)

        assert received_payload == payload

    def test_message_2_too_short(self) -> None:
        """Message 2 must be at least 80 bytes."""
        init_static, _ = generate_keypair()
        initiator = NoiseHandshake.initiator(init_static)
        initiator.write_message_1()

        with pytest.raises(NoiseError, match="too short"):
            initiator.read_message_2(bytes(79))


class TestMessage3:
    """Tests for Message 3: -> s, se."""

    def test_write_message_3(self) -> None:
        """Initiator writes message 3."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        msg2 = responder.write_message_2()
        initiator.read_message_2(msg2)
        msg3 = initiator.write_message_3()

        # Message 3: 48 (encrypted static = 32 + 16 tag)
        assert len(msg3) >= 48
        assert initiator._state == HandshakeState.COMPLETE

    def test_write_message_3_with_payload(self) -> None:
        """Initiator includes payload in message 3."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        msg2 = responder.write_message_2()
        initiator.read_message_2(msg2)

        payload = b"Initiator identity"
        msg3 = initiator.write_message_3(payload)

        # Message 3: 48 + (len(payload) + 16)
        expected_min_len = 48 + len(payload) + 16
        assert len(msg3) >= expected_min_len

    def test_only_initiator_writes_message_3(self) -> None:
        """Responder cannot write message 3."""
        static_key, _ = generate_keypair()
        handshake = NoiseHandshake.responder(static_key)

        with pytest.raises(NoiseError, match="Only initiator"):
            handshake.write_message_3()

    def test_read_message_3(self) -> None:
        """Responder reads message 3."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        msg2 = responder.write_message_2()
        initiator.read_message_2(msg2)
        msg3 = initiator.write_message_3()
        responder.read_message_3(msg3)

        # Responder now knows initiator's static key
        assert responder.remote_static_public is not None
        resp_remote_static = responder.remote_static_public.public_bytes_raw()
        init_local_static = initiator.local_static_public.public_bytes_raw()
        assert resp_remote_static == init_local_static
        assert responder._state == HandshakeState.COMPLETE

    def test_read_message_3_extracts_payload(self) -> None:
        """Responder decrypts payload from message 3."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        msg2 = responder.write_message_2()
        initiator.read_message_2(msg2)

        payload = b"Initiator identity data"
        msg3 = initiator.write_message_3(payload)
        received_payload = responder.read_message_3(msg3)

        assert received_payload == payload

    def test_message_3_too_short(self) -> None:
        """Message 3 must be at least 48 bytes."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        _ = responder.write_message_2()  # Need to write msg2 to advance state
        responder._state = HandshakeState.AWAITING_MESSAGE_3

        with pytest.raises(NoiseError, match="too short"):
            responder.read_message_3(bytes(47))


class TestFinalization:
    """Tests for handshake finalization."""

    def test_finalize_derives_cipher_states(self) -> None:
        """Both parties derive compatible cipher states."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        # Complete handshake
        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        msg2 = responder.write_message_2()
        initiator.read_message_2(msg2)
        msg3 = initiator.write_message_3()
        responder.read_message_3(msg3)

        init_send, init_recv = initiator.finalize()
        resp_send, resp_recv = responder.finalize()

        # Initiator's send = Responder's recv, and vice versa
        assert init_send.key == resp_recv.key
        assert init_recv.key == resp_send.key

    def test_cipher_states_work_for_encryption(self) -> None:
        """Derived cipher states can encrypt/decrypt."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        # Complete handshake
        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        msg2 = responder.write_message_2()
        initiator.read_message_2(msg2)
        msg3 = initiator.write_message_3()
        responder.read_message_3(msg3)

        init_send, init_recv = initiator.finalize()
        resp_send, resp_recv = responder.finalize()

        # Initiator sends, responder receives
        plaintext = b"Hello from initiator"
        ciphertext = init_send.encrypt_with_ad(b"", plaintext)
        decrypted = resp_recv.decrypt_with_ad(b"", ciphertext)
        assert decrypted == plaintext

        # Responder sends, initiator receives
        plaintext2 = b"Hello from responder"
        ciphertext2 = resp_send.encrypt_with_ad(b"", plaintext2)
        decrypted2 = init_recv.decrypt_with_ad(b"", ciphertext2)
        assert decrypted2 == plaintext2

    def test_finalize_before_complete_fails(self) -> None:
        """Cannot finalize until handshake complete."""
        static_key, _ = generate_keypair()
        handshake = NoiseHandshake.initiator(static_key)

        with pytest.raises(NoiseError, match="not complete"):
            handshake.finalize()

        handshake.write_message_1()

        with pytest.raises(NoiseError, match="not complete"):
            handshake.finalize()


class TestFullHandshake:
    """Integration tests for complete handshake."""

    def test_complete_handshake_no_payload(self) -> None:
        """Complete handshake without payloads."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        # Full exchange
        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        msg2 = responder.write_message_2()
        initiator.read_message_2(msg2)
        msg3 = initiator.write_message_3()
        responder.read_message_3(msg3)

        # Both complete
        assert initiator._state == HandshakeState.COMPLETE
        assert responder._state == HandshakeState.COMPLETE

        # Both know each other's static keys
        assert initiator.remote_static_public is not None
        assert responder.remote_static_public is not None
        init_remote_bytes = initiator.remote_static_public.public_bytes_raw()
        resp_local_bytes = responder.local_static_public.public_bytes_raw()
        assert init_remote_bytes == resp_local_bytes
        resp_remote_bytes = responder.remote_static_public.public_bytes_raw()
        init_local_bytes = initiator.local_static_public.public_bytes_raw()
        assert resp_remote_bytes == init_local_bytes

        # Ciphers are compatible
        init_send, init_recv = initiator.finalize()
        resp_send, resp_recv = responder.finalize()
        assert init_send.key == resp_recv.key
        assert init_recv.key == resp_send.key

    def test_complete_handshake_with_payloads(self) -> None:
        """Complete handshake with identity payloads."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        resp_identity = b"Responder libp2p identity protobuf"
        init_identity = b"Initiator libp2p identity protobuf"

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        msg2 = responder.write_message_2(resp_identity)
        payload2 = initiator.read_message_2(msg2)
        msg3 = initiator.write_message_3(init_identity)
        payload3 = responder.read_message_3(msg3)

        assert payload2 == resp_identity
        assert payload3 == init_identity

    def test_handshake_with_deterministic_keys(self) -> None:
        """
        Handshake with known keys for reproducibility.

        Uses test vectors from noisesocket spec where available.
        """
        # Known test keys (from noisesocket spec)
        init_static_bytes = bytes.fromhex(
            "0001020300010203000102030001020300010203000102030001020300010203"
        )
        resp_static_bytes = bytes.fromhex(
            "0001020304000102030400010203040001020304000102030400010203040001"
        )

        init_static = x25519.X25519PrivateKey.from_private_bytes(init_static_bytes)
        resp_static = x25519.X25519PrivateKey.from_private_bytes(resp_static_bytes)

        initiator = NoiseHandshake.initiator(init_static)
        responder = NoiseHandshake.responder(resp_static)

        msg1 = initiator.write_message_1()
        responder.read_message_1(msg1)
        msg2 = responder.write_message_2()
        initiator.read_message_2(msg2)
        msg3 = initiator.write_message_3()
        responder.read_message_3(msg3)

        # Verify handshake completed
        assert initiator._state == HandshakeState.COMPLETE
        assert responder._state == HandshakeState.COMPLETE

        # Verify static keys exchanged
        init_static_pub = init_static.public_key().public_bytes_raw()
        resp_static_pub = resp_static.public_key().public_bytes_raw()

        assert initiator.remote_static_public is not None
        assert responder.remote_static_public is not None
        assert initiator.remote_static_public.public_bytes_raw() == resp_static_pub
        assert responder.remote_static_public.public_bytes_raw() == init_static_pub

    def test_multiple_handshakes_produce_different_keys(self) -> None:
        """Different handshakes produce different session keys."""
        init_static, _ = generate_keypair()
        resp_static, _ = generate_keypair()

        # First handshake
        init1 = NoiseHandshake.initiator(init_static)
        resp1 = NoiseHandshake.responder(resp_static)

        msg1_1 = init1.write_message_1()
        resp1.read_message_1(msg1_1)
        msg2_1 = resp1.write_message_2()
        init1.read_message_2(msg2_1)
        msg3_1 = init1.write_message_3()
        resp1.read_message_3(msg3_1)

        send1, recv1 = init1.finalize()

        # Second handshake (same static keys, new ephemeral)
        init2 = NoiseHandshake.initiator(init_static)
        resp2 = NoiseHandshake.responder(resp_static)

        msg1_2 = init2.write_message_1()
        resp2.read_message_1(msg1_2)
        msg2_2 = resp2.write_message_2()
        init2.read_message_2(msg2_2)
        msg3_2 = init2.write_message_3()
        resp2.read_message_3(msg3_2)

        send2, recv2 = init2.finalize()

        # Session keys should be different (due to ephemeral keys)
        assert send1.key != send2.key
        assert recv1.key != recv2.key


class TestCipherState:
    """Tests for CipherState."""

    def test_nonce_increments(self) -> None:
        """Nonce increments after each operation."""
        key = CipherKey(bytes(32))
        cipher = CipherState(key=key)

        assert cipher.nonce == 0

        cipher.encrypt_with_ad(b"", b"test")
        assert cipher.nonce == 1

        cipher.encrypt_with_ad(b"", b"test")
        assert cipher.nonce == 2

    def test_has_key(self) -> None:
        """has_key returns True when key is set."""
        cipher = CipherState(key=CipherKey(bytes(32)))
        assert cipher.has_key() is True

    def test_encrypt_decrypt_roundtrip(self) -> None:
        """CipherState can encrypt and decrypt."""
        key = CipherKey(bytes(32))
        send = CipherState(key=key, nonce=0)
        recv = CipherState(key=key, nonce=0)

        plaintext = b"Hello, World!"
        ciphertext = send.encrypt_with_ad(b"aad", plaintext)
        decrypted = recv.decrypt_with_ad(b"aad", ciphertext)

        assert decrypted == plaintext
