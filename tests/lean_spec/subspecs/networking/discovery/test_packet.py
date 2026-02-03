"""Tests for Discovery v5 packet encoding/decoding."""

import pytest

from lean_spec.subspecs.networking.discovery.messages import PacketFlag
from lean_spec.subspecs.networking.discovery.packet import (
    HANDSHAKE_HEADER_SIZE,
    MESSAGE_AUTHDATA_SIZE,
    STATIC_HEADER_SIZE,
    WHOAREYOU_AUTHDATA_SIZE,
    decode_handshake_authdata,
    decode_message_authdata,
    decode_packet_header,
    decode_whoareyou_authdata,
    encode_handshake_authdata,
    encode_message_authdata,
    encode_packet,
    encode_whoareyou_authdata,
    generate_id_nonce,
    generate_nonce,
)


class TestNonceGeneration:
    """Tests for nonce generation."""

    def test_generate_nonce_is_12_bytes(self):
        """Test that generated nonce is 12 bytes."""
        nonce = generate_nonce()
        assert len(nonce) == 12

    def test_generate_id_nonce_is_16_bytes(self):
        """Test that generated ID nonce is 16 bytes."""
        id_nonce = generate_id_nonce()
        assert len(id_nonce) == 16

    def test_generates_different_nonces(self):
        """Test that each generation produces different nonces."""
        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        assert nonce1 != nonce2


class TestMessageAuthdata:
    """Tests for MESSAGE packet authdata."""

    def test_encode_message_authdata(self):
        """Test MESSAGE authdata encoding."""
        src_id = bytes(32)
        authdata = encode_message_authdata(src_id)

        assert len(authdata) == MESSAGE_AUTHDATA_SIZE
        assert authdata == src_id

    def test_decode_message_authdata(self):
        """Test MESSAGE authdata decoding."""
        src_id = bytes.fromhex("aa" * 32)
        authdata = encode_message_authdata(src_id)
        decoded = decode_message_authdata(authdata)

        assert decoded.src_id == src_id

    def test_invalid_size_raises(self):
        """Test that invalid authdata size raises ValueError."""
        with pytest.raises(ValueError, match="Invalid MESSAGE authdata size"):
            decode_message_authdata(bytes(31))


class TestWhoAreYouAuthdata:
    """Tests for WHOAREYOU packet authdata."""

    def test_encode_whoareyou_authdata(self):
        """Test WHOAREYOU authdata encoding."""
        id_nonce = bytes(16)
        enr_seq = 42

        authdata = encode_whoareyou_authdata(id_nonce, enr_seq)

        assert len(authdata) == WHOAREYOU_AUTHDATA_SIZE

    def test_decode_whoareyou_authdata(self):
        """Test WHOAREYOU authdata decoding."""
        id_nonce = bytes.fromhex("aa" * 16)
        enr_seq = 12345

        authdata = encode_whoareyou_authdata(id_nonce, enr_seq)
        decoded = decode_whoareyou_authdata(authdata)

        assert bytes(decoded.id_nonce) == id_nonce
        assert int(decoded.enr_seq) == enr_seq

    def test_roundtrip(self):
        """Test encoding then decoding preserves values."""
        id_nonce = bytes.fromhex("01" * 16)
        enr_seq = 2**63 - 1  # Max uint64

        authdata = encode_whoareyou_authdata(id_nonce, enr_seq)
        decoded = decode_whoareyou_authdata(authdata)

        assert bytes(decoded.id_nonce) == id_nonce
        assert int(decoded.enr_seq) == enr_seq

    def test_invalid_size_raises(self):
        """Test that invalid authdata size raises ValueError."""
        with pytest.raises(ValueError, match="Invalid WHOAREYOU authdata size"):
            decode_whoareyou_authdata(bytes(23))


class TestHandshakeAuthdata:
    """Tests for HANDSHAKE packet authdata."""

    def test_encode_handshake_authdata(self):
        """Test HANDSHAKE authdata encoding."""
        src_id = bytes(32)
        id_signature = bytes(64)
        eph_pubkey = bytes([0x02]) + bytes(32)  # Compressed pubkey format

        authdata = encode_handshake_authdata(src_id, id_signature, eph_pubkey)

        # 32 (src_id) + 1 (sig_size) + 1 (eph_key_size) + 64 (sig) + 33 (eph)
        expected_size = HANDSHAKE_HEADER_SIZE + 64 + 33
        assert len(authdata) == expected_size

    def test_decode_handshake_authdata(self):
        """Test HANDSHAKE authdata decoding."""
        src_id = bytes.fromhex("aa" * 32)
        id_signature = bytes.fromhex("bb" * 64)
        eph_pubkey = bytes([0x02]) + bytes.fromhex("cc" * 32)

        authdata = encode_handshake_authdata(src_id, id_signature, eph_pubkey)
        decoded = decode_handshake_authdata(authdata)

        assert decoded.src_id == src_id
        assert decoded.sig_size == 64
        assert decoded.eph_key_size == 33
        assert decoded.id_signature == id_signature
        assert decoded.eph_pubkey == eph_pubkey
        assert decoded.record is None

    def test_with_enr_record(self):
        """Test HANDSHAKE authdata with ENR record."""
        src_id = bytes(32)
        id_signature = bytes(64)
        eph_pubkey = bytes([0x02]) + bytes(32)
        record = b"enr:-IS4QHCYrY..."  # Mock ENR

        authdata = encode_handshake_authdata(src_id, id_signature, eph_pubkey, record)
        decoded = decode_handshake_authdata(authdata)

        assert decoded.record == record

    def test_invalid_src_id_length_raises(self):
        """Test that invalid src_id length raises ValueError."""
        with pytest.raises(ValueError, match="Source ID must be 32 bytes"):
            encode_handshake_authdata(bytes(31), bytes(64), bytes(33))

    def test_invalid_signature_length_raises(self):
        """Test that invalid signature length raises ValueError."""
        with pytest.raises(ValueError, match="Signature must be 64 bytes"):
            encode_handshake_authdata(bytes(32), bytes(63), bytes(33))

    def test_invalid_eph_pubkey_length_raises(self):
        """Test that invalid ephemeral pubkey length raises ValueError."""
        with pytest.raises(ValueError, match="Ephemeral pubkey must be 33 bytes"):
            encode_handshake_authdata(bytes(32), bytes(64), bytes(32))


class TestPacketEncoding:
    """Tests for full packet encoding/decoding."""

    def test_encode_message_packet(self):
        """Test MESSAGE packet encoding."""
        dest_node_id = bytes(32)
        src_node_id = bytes(32)
        nonce = bytes(12)
        authdata = encode_message_authdata(src_node_id)
        message = b"encrypted message"
        encryption_key = bytes(16)

        packet = encode_packet(
            dest_node_id=dest_node_id,
            src_node_id=src_node_id,
            flag=PacketFlag.MESSAGE,
            nonce=nonce,
            authdata=authdata,
            message=message,
            encryption_key=encryption_key,
        )

        # Packet should contain: masking_iv (16) + masked_header + encrypted_message
        assert len(packet) > 16 + STATIC_HEADER_SIZE + len(authdata)

    def test_encode_whoareyou_packet(self):
        """Test WHOAREYOU packet encoding."""
        dest_node_id = bytes(32)
        src_node_id = bytes(32)
        nonce = bytes(12)
        id_nonce = bytes(16)
        authdata = encode_whoareyou_authdata(id_nonce, 0)

        packet = encode_packet(
            dest_node_id=dest_node_id,
            src_node_id=src_node_id,
            flag=PacketFlag.WHOAREYOU,
            nonce=nonce,
            authdata=authdata,
            message=b"",
            encryption_key=None,  # WHOAREYOU doesn't encrypt
        )

        # WHOAREYOU has no message content
        expected_size = 16 + STATIC_HEADER_SIZE + WHOAREYOU_AUTHDATA_SIZE
        assert len(packet) == expected_size

    def test_decode_packet_header(self):
        """Test packet header decoding."""
        local_node_id = bytes(32)
        remote_node_id = bytes(32)
        nonce = bytes(12)
        authdata = encode_whoareyou_authdata(bytes(16), 42)

        packet = encode_packet(
            dest_node_id=local_node_id,
            src_node_id=remote_node_id,
            flag=PacketFlag.WHOAREYOU,
            nonce=nonce,
            authdata=authdata,
            message=b"",
            encryption_key=None,
        )

        header, message_bytes = decode_packet_header(local_node_id, packet)

        assert header.flag == PacketFlag.WHOAREYOU
        assert bytes(header.nonce) == nonce
        assert header.authdata == authdata
        assert message_bytes == b""

    def test_invalid_dest_node_id_length_raises(self):
        """Test that invalid dest_node_id length raises ValueError."""
        with pytest.raises(ValueError, match="Destination node ID must be 32 bytes"):
            encode_packet(
                dest_node_id=bytes(31),
                src_node_id=bytes(32),
                flag=PacketFlag.MESSAGE,
                nonce=bytes(12),
                authdata=bytes(32),
                message=b"",
                encryption_key=bytes(16),
            )

    def test_invalid_nonce_length_raises(self):
        """Test that invalid nonce length raises ValueError."""
        with pytest.raises(ValueError, match="Nonce must be 12 bytes"):
            encode_packet(
                dest_node_id=bytes(32),
                src_node_id=bytes(32),
                flag=PacketFlag.MESSAGE,
                nonce=bytes(11),
                authdata=bytes(32),
                message=b"",
                encryption_key=bytes(16),
            )


class TestConstants:
    """Tests for packet format constants."""

    def test_static_header_size(self):
        """Test static header size constant."""
        # protocol_id (6) + version (2) + flag (1) + nonce (12) + authdata_size (2)
        assert STATIC_HEADER_SIZE == 23

    def test_message_authdata_size(self):
        """Test MESSAGE authdata size constant."""
        # src_id (32)
        assert MESSAGE_AUTHDATA_SIZE == 32

    def test_whoareyou_authdata_size(self):
        """Test WHOAREYOU authdata size constant."""
        # id_nonce (16) + enr_seq (8)
        assert WHOAREYOU_AUTHDATA_SIZE == 24

    def test_handshake_header_size(self):
        """Test HANDSHAKE header size constant."""
        # src_id (32) + sig_size (1) + eph_key_size (1)
        assert HANDSHAKE_HEADER_SIZE == 34


# ==============================================================================
# Phase 6: Packet Size Validation Tests
# ==============================================================================


class TestPacketSizeLimits:
    """Packet size boundary validation.

    Per spec:
    - MIN_PACKET_SIZE = 63 bytes (masking-iv + min header)
    - MAX_PACKET_SIZE = 1280 bytes (IPv6 MTU)
    """

    def test_min_packet_size_constant(self):
        """MIN_PACKET_SIZE matches spec minimum."""
        from lean_spec.subspecs.networking.discovery.config import MIN_PACKET_SIZE

        # masking-iv (16) + static-header (23) + min authdata (24 for WHOAREYOU)
        assert MIN_PACKET_SIZE == 63

    def test_max_packet_size_constant(self):
        """MAX_PACKET_SIZE matches IPv6 MTU."""
        from lean_spec.subspecs.networking.discovery.config import MAX_PACKET_SIZE

        # IPv6 minimum MTU = 1280 bytes
        assert MAX_PACKET_SIZE == 1280

    def test_reject_undersized_packet(self):
        """Packets smaller than MIN_PACKET_SIZE are rejected."""
        from lean_spec.subspecs.networking.discovery.config import MIN_PACKET_SIZE

        local_node_id = bytes(32)

        # Packet that's too small.
        undersized_packet = bytes(MIN_PACKET_SIZE - 1)

        with pytest.raises(ValueError, match="too small"):
            decode_packet_header(local_node_id, undersized_packet)

    def test_minimum_valid_packet_structure(self):
        """Minimum valid packet has correct structure."""
        from lean_spec.subspecs.networking.discovery.config import MIN_PACKET_SIZE

        # WHOAREYOU is the smallest packet type:
        # masking-iv (16) + static-header (23) + authdata (24) = 63 bytes
        expected_min = 16 + STATIC_HEADER_SIZE + WHOAREYOU_AUTHDATA_SIZE
        assert expected_min == MIN_PACKET_SIZE

    def test_encode_packet_enforces_max_size(self):
        """encode_packet raises error if packet exceeds max size."""
        src_id = bytes(32)
        dest_id = bytes(32)
        nonce = bytes(12)
        encryption_key = bytes(16)

        # Create authdata.
        authdata = encode_message_authdata(src_id)

        # Try to create a packet with message that would exceed max size.
        # Need message large enough that total > 1280
        # Overhead: masking-iv(16) + static(23) + authdata(32) + tag(16) = 87
        # So message > 1193 should trigger error.
        large_message = bytes(1300)

        with pytest.raises(ValueError, match="exceeds max size"):
            encode_packet(
                dest_node_id=dest_id,
                src_node_id=src_id,
                flag=PacketFlag.MESSAGE,
                nonce=nonce,
                authdata=authdata,
                message=large_message,
                encryption_key=encryption_key,
            )

    def test_truncated_static_header_rejected(self):
        """Incomplete static header is rejected."""
        local_node_id = bytes(32)

        # Packet with only masking-iv and partial static header.
        # masking-iv (16) + partial static header (10 bytes) = 26 bytes
        truncated_packet = bytes(26)

        with pytest.raises(ValueError, match="too small"):
            decode_packet_header(local_node_id, truncated_packet)

    def test_truncated_authdata_rejected(self):
        """Packet with incomplete authdata is rejected."""
        from lean_spec.subspecs.networking.discovery.crypto import aes_ctr_encrypt

        local_node_id = bytes(32)
        masking_iv = bytes(16)

        # Build a valid static header but with claimed authdata larger than packet.
        # static-header: protocol-id (6) + version (2) + flag (1) + nonce (12) + authdata-size (2)
        # Claim authdata size of 100 bytes.
        static_header = b"discv5" + b"\x00\x01\x00" + bytes(12) + b"\x00\x64"  # 0x64 = 100

        # Encrypt/mask the header.
        masking_key = local_node_id[:16]
        masked_header = aes_ctr_encrypt(masking_key, masking_iv, static_header)

        # Create packet: masking-iv + masked-header + only 10 bytes (not 100).
        # This will be rejected because total size < MIN_PACKET_SIZE (63 bytes)
        incomplete_packet = masking_iv + masked_header + bytes(10)

        with pytest.raises(ValueError, match="too small"):
            decode_packet_header(local_node_id, incomplete_packet)


class TestPacketProtocolValidation:
    """Protocol ID and version validation in packet decoding."""

    def test_invalid_protocol_id_rejected(self):
        """Packet with wrong protocol ID is rejected."""
        from lean_spec.subspecs.networking.discovery.crypto import aes_ctr_encrypt

        local_node_id = bytes(32)
        masking_iv = bytes(16)

        # Build header with wrong protocol ID but correct structure.
        # static-header: protocol-id (6) + version (2) + flag (1) + nonce (12) + authdata-size (2)
        wrong_protocol_header = b"WRONG!" + b"\x00\x01\x01" + bytes(12) + b"\x00\x18"

        # Mask the entire content (header + authdata).
        # Authdata for WHOAREYOU = 24 bytes.
        full_content = wrong_protocol_header + bytes(24)
        masking_key = local_node_id[:16]
        masked_content = aes_ctr_encrypt(masking_key, masking_iv, full_content)

        # Packet = masking-iv + masked-content
        packet = masking_iv + masked_content

        with pytest.raises(ValueError, match="Invalid protocol ID"):
            decode_packet_header(local_node_id, packet)

    def test_invalid_protocol_version_rejected(self):
        """Packet with unsupported protocol version is rejected."""
        from lean_spec.subspecs.networking.discovery.crypto import aes_ctr_encrypt

        local_node_id = bytes(32)
        masking_iv = bytes(16)

        # Build header with wrong version (0x0099 instead of 0x0001).
        wrong_version_header = b"discv5" + b"\x00\x99\x01" + bytes(12) + b"\x00\x18"

        # Full masked content.
        full_content = wrong_version_header + bytes(24)
        masking_key = local_node_id[:16]
        masked_content = aes_ctr_encrypt(masking_key, masking_iv, full_content)

        packet = masking_iv + masked_content

        with pytest.raises(ValueError, match="Unsupported protocol version"):
            decode_packet_header(local_node_id, packet)
