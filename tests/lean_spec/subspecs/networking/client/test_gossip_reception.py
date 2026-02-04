"""Tests for gossip message reception functionality.

This module tests the GossipHandler class, GossipMessageError exception,
and read_gossip_message async function that handle incoming gossip messages
from peers in the P2P network.

Gossip message format:
- Topic length (varint)
- Topic string (UTF-8)
- Data length (varint)
- Data (Snappy-compressed SSZ)
"""

from __future__ import annotations

import asyncio

import pytest

from lean_spec.snappy import compress, frame_compress, frame_decompress
from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.containers.attestation import SignedAttestation
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.networking.client.event_source import (
    GossipHandler,
    GossipMessageError,
    read_gossip_message,
)
from lean_spec.subspecs.networking.gossipsub.topic import (
    ENCODING_POSTFIX,
    TOPIC_PREFIX,
    GossipTopic,
    TopicKind,
)
from lean_spec.subspecs.networking.varint import encode_varint
from lean_spec.types import Bytes32
from tests.lean_spec.helpers.builders import make_signed_attestation, make_signed_block

# =============================================================================
# Test Fixtures and Helpers
# =============================================================================


class MockStream:
    """
    A mock stream for testing read_gossip_message.

    Simulates a QUIC stream by returning data in chunks.
    """

    def __init__(self, data: bytes, chunk_size: int = 1024) -> None:
        """
        Initialize the mock stream.

        Args:
            data: Complete data to return from reads.
            chunk_size: Maximum bytes per read call.
        """
        self.data = data
        self.chunk_size = chunk_size
        self.offset = 0
        self._stream_id = 0

    @property
    def stream_id(self) -> int:
        """Return a mock stream ID."""
        return self._stream_id

    @property
    def protocol_id(self) -> str:
        """Return a mock protocol ID."""
        return "/meshsub/1.1.0"

    async def read(self, n: int = -1) -> bytes:
        """
        Read data from the mock stream.

        Args:
            n: Ignored, uses chunk_size instead.

        Returns:
            Next chunk of data, or empty bytes if exhausted.
        """
        if self.offset >= len(self.data):
            return b""
        end = min(self.offset + self.chunk_size, len(self.data))
        chunk = self.data[self.offset : end]
        self.offset = end
        return chunk

    async def write(self, data: bytes) -> None:
        """Mock write (not used in reception tests)."""
        pass

    async def close(self) -> None:
        """Mock close."""
        pass

    async def reset(self) -> None:
        """Mock reset."""
        pass


def make_block_topic(fork_digest: str = "0x00000000") -> str:
    """Create a valid block topic string."""
    return f"/{TOPIC_PREFIX}/{fork_digest}/block/{ENCODING_POSTFIX}"


def make_attestation_topic(fork_digest: str = "0x00000000", subnet_id: int = 0) -> str:
    """Create a valid attestation subnet topic string."""
    return f"/{TOPIC_PREFIX}/{fork_digest}/attestation_{subnet_id}/{ENCODING_POSTFIX}"


def make_test_signed_block() -> SignedBlockWithAttestation:
    """Create a minimal signed block for testing."""
    return make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
    )


def make_test_signed_attestation() -> SignedAttestation:
    """Create a minimal signed attestation for testing."""
    return make_signed_attestation(
        validator=ValidatorIndex(0),
        target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
    )


def build_gossip_message(topic: str, ssz_data: bytes) -> bytes:
    """
    Build a complete gossip message from topic and SSZ data.

    Format: [topic_len varint][topic][data_len varint][compressed_data]

    Uses Snappy framed compression as required by Ethereum gossip protocol.
    """
    topic_bytes = topic.encode("utf-8")
    compressed_data = frame_compress(ssz_data)

    message = bytearray()
    message.extend(encode_varint(len(topic_bytes)))
    message.extend(topic_bytes)
    message.extend(encode_varint(len(compressed_data)))
    message.extend(compressed_data)

    return bytes(message)


# =============================================================================
# Tests for GossipMessageError
# =============================================================================


class TestGossipMessageError:
    """Tests for the GossipMessageError exception."""

    def test_is_exception_subclass(self) -> None:
        """GossipMessageError inherits from Exception."""
        assert issubclass(GossipMessageError, Exception)

    def test_message_preserved(self) -> None:
        """Error message is preserved."""
        msg = "Test error message"
        error = GossipMessageError(msg)
        assert str(error) == msg

    def test_can_be_raised_and_caught(self) -> None:
        """Can be raised and caught properly."""
        with pytest.raises(GossipMessageError, match="specific error"):
            raise GossipMessageError("specific error")


# =============================================================================
# Tests for GossipHandler.get_topic()
# =============================================================================


class TestGossipHandlerGetTopic:
    """Tests for GossipHandler.get_topic() method."""

    def test_valid_block_topic(self) -> None:
        """Parses valid block topic string."""
        handler = GossipHandler(fork_digest="0x12345678")
        topic_str = "/leanconsensus/0x12345678/block/ssz_snappy"

        topic = handler.get_topic(topic_str)

        assert isinstance(topic, GossipTopic)
        assert topic.kind == TopicKind.BLOCK
        assert topic.fork_digest == "0x12345678"

    def test_valid_attestation_subnet_topic(self) -> None:
        """Parses valid attestation subnet topic string."""
        handler = GossipHandler(fork_digest="0x00000000")
        topic_str = "/leanconsensus/0x00000000/attestation_0/ssz_snappy"

        topic = handler.get_topic(topic_str)

        assert isinstance(topic, GossipTopic)
        assert topic.kind == TopicKind.ATTESTATION_SUBNET
        assert topic.fork_digest == "0x00000000"

    def test_invalid_topic_format_missing_parts(self) -> None:
        """Raises GossipMessageError for topic with missing parts."""
        handler = GossipHandler(fork_digest="0x00000000")

        with pytest.raises(GossipMessageError, match="Invalid topic"):
            handler.get_topic("/invalid/topic")

    def test_invalid_topic_format_wrong_prefix(self) -> None:
        """Raises GossipMessageError for wrong network prefix."""
        handler = GossipHandler(fork_digest="0x00000000")

        with pytest.raises(GossipMessageError, match="Invalid topic"):
            handler.get_topic("/wrongprefix/0x00000000/block/ssz_snappy")

    def test_invalid_topic_format_wrong_encoding(self) -> None:
        """Raises GossipMessageError for wrong encoding suffix."""
        handler = GossipHandler(fork_digest="0x00000000")

        with pytest.raises(GossipMessageError, match="Invalid topic"):
            handler.get_topic("/leanconsensus/0x00000000/block/ssz")

    def test_invalid_topic_format_unknown_topic_name(self) -> None:
        """Raises GossipMessageError for unknown topic name."""
        handler = GossipHandler(fork_digest="0x00000000")

        with pytest.raises(GossipMessageError, match="Invalid topic"):
            handler.get_topic("/leanconsensus/0x00000000/unknown/ssz_snappy")

    def test_empty_topic_string(self) -> None:
        """Raises GossipMessageError for empty topic string."""
        handler = GossipHandler(fork_digest="0x00000000")

        with pytest.raises(GossipMessageError, match="Invalid topic"):
            handler.get_topic("")


# =============================================================================
# Tests for GossipHandler.decode_message()
# =============================================================================


class TestGossipHandlerDecodeMessage:
    """Tests for GossipHandler.decode_message() method."""

    def test_decode_valid_block_message(self) -> None:
        """Decodes valid block message correctly."""
        handler = GossipHandler(fork_digest="0x00000000")
        block = make_test_signed_block()
        ssz_bytes = block.encode_bytes()
        compressed = frame_compress(ssz_bytes)
        topic_str = make_block_topic()

        result = handler.decode_message(topic_str, compressed)

        assert isinstance(result, SignedBlockWithAttestation)

    def test_decode_valid_attestation_message(self) -> None:
        """Decodes valid attestation message correctly."""
        handler = GossipHandler(fork_digest="0x00000000")
        attestation = make_test_signed_attestation()
        ssz_bytes = attestation.encode_bytes()
        compressed = frame_compress(ssz_bytes)
        topic_str = make_attestation_topic()

        result = handler.decode_message(topic_str, compressed)

        assert isinstance(result, SignedAttestation)

    def test_decode_invalid_topic_format(self) -> None:
        """Raises GossipMessageError for invalid topic format."""
        handler = GossipHandler(fork_digest="0x00000000")
        compressed = compress(b"\x00" * 32)

        with pytest.raises(GossipMessageError, match="Invalid topic"):
            handler.decode_message("/bad/topic", compressed)

    def test_decode_invalid_snappy_compression(self) -> None:
        """Raises GossipMessageError for invalid Snappy data."""
        handler = GossipHandler(fork_digest="0x00000000")
        topic_str = make_block_topic()
        # Invalid snappy: claims uncompressed length of 1000 bytes but has truncated data
        # Snappy format: [uncompressed_length varint][compressed_data]
        invalid_snappy = b"\xe8\x07"  # varint for 1000, but no data following

        with pytest.raises(GossipMessageError, match="Snappy decompression failed"):
            handler.decode_message(topic_str, invalid_snappy)

    def test_decode_invalid_ssz_encoding(self) -> None:
        """Raises GossipMessageError for invalid SSZ data."""
        handler = GossipHandler(fork_digest="0x00000000")
        topic_str = make_block_topic()
        # Valid Snappy framing wrapping garbage SSZ
        compressed = frame_compress(b"\xff\xff\xff\xff")

        with pytest.raises(GossipMessageError, match="SSZ decode failed"):
            handler.decode_message(topic_str, compressed)

    def test_decode_empty_snappy_data(self) -> None:
        """Raises GossipMessageError for empty compressed data."""
        handler = GossipHandler(fork_digest="0x00000000")
        topic_str = make_block_topic()

        with pytest.raises(GossipMessageError, match="Snappy decompression failed"):
            handler.decode_message(topic_str, b"")

    def test_decode_truncated_ssz_data(self) -> None:
        """Raises GossipMessageError for truncated SSZ data."""
        handler = GossipHandler(fork_digest="0x00000000")
        block = make_test_signed_block()
        ssz_bytes = block.encode_bytes()
        truncated = ssz_bytes[:10]  # Truncate SSZ data
        compressed = frame_compress(truncated)
        topic_str = make_block_topic()

        with pytest.raises(GossipMessageError, match="SSZ decode failed"):
            handler.decode_message(topic_str, compressed)


# =============================================================================
# Tests for read_gossip_message()
# =============================================================================


class TestReadGossipMessage:
    """Tests for the read_gossip_message async function."""

    def test_read_valid_block_message(self) -> None:
        """Reads valid block message from stream."""

        async def run() -> tuple[str, bytes]:
            block = make_test_signed_block()
            ssz_bytes = block.encode_bytes()
            topic_str = make_block_topic()
            message_data = build_gossip_message(topic_str, ssz_bytes)

            stream = MockStream(message_data)
            return await read_gossip_message(stream)

        topic, compressed = asyncio.run(run())
        topic_str = make_block_topic()

        assert topic == topic_str
        assert len(compressed) > 0

    def test_read_valid_attestation_message(self) -> None:
        """Reads valid attestation message from stream."""

        async def run() -> tuple[str, bytes]:
            attestation = make_test_signed_attestation()
            ssz_bytes = attestation.encode_bytes()
            topic_str = make_attestation_topic()
            message_data = build_gossip_message(topic_str, ssz_bytes)

            stream = MockStream(message_data)
            return await read_gossip_message(stream)

        topic, compressed = asyncio.run(run())
        topic_str = make_attestation_topic()

        assert topic == topic_str
        assert len(compressed) > 0

    def test_read_empty_stream(self) -> None:
        """Raises GossipMessageError for empty stream."""

        async def run() -> tuple[str, bytes]:
            stream = MockStream(b"")
            return await read_gossip_message(stream)

        with pytest.raises(GossipMessageError, match="Empty gossip message"):
            asyncio.run(run())

    def test_read_truncated_topic_length(self) -> None:
        """Raises GossipMessageError for incomplete topic length varint."""

        async def run() -> tuple[str, bytes]:
            # A varint byte with continuation bit set but no following bytes
            incomplete_varint = b"\x80"  # Continuation bit set, needs more bytes
            stream = MockStream(incomplete_varint)
            return await read_gossip_message(stream)

        with pytest.raises(GossipMessageError, match="Truncated gossip message"):
            asyncio.run(run())

    def test_read_truncated_topic_string(self) -> None:
        """Raises GossipMessageError for truncated topic string."""

        async def run() -> tuple[str, bytes]:
            topic = make_block_topic()
            topic_bytes = topic.encode("utf-8")
            # Claim topic is 100 bytes but only provide partial data
            truncated = encode_varint(100) + topic_bytes[:10]
            stream = MockStream(truncated)
            return await read_gossip_message(stream)

        with pytest.raises(GossipMessageError, match="Truncated gossip message"):
            asyncio.run(run())

    def test_read_truncated_data_length(self) -> None:
        """Raises GossipMessageError for truncated data length varint."""

        async def run() -> tuple[str, bytes]:
            topic = make_block_topic()
            topic_bytes = topic.encode("utf-8")
            # Complete topic but incomplete data length varint
            data = encode_varint(len(topic_bytes)) + topic_bytes + b"\x80"
            stream = MockStream(data)
            return await read_gossip_message(stream)

        with pytest.raises(GossipMessageError, match="Truncated gossip message"):
            asyncio.run(run())

    def test_read_truncated_data(self) -> None:
        """Raises GossipMessageError for truncated message data."""

        async def run() -> tuple[str, bytes]:
            topic = make_block_topic()
            topic_bytes = topic.encode("utf-8")
            compressed = compress(b"test data")
            # Claim data is 1000 bytes but only provide partial
            data = (
                encode_varint(len(topic_bytes)) + topic_bytes + encode_varint(1000) + compressed[:5]
            )
            stream = MockStream(data)
            return await read_gossip_message(stream)

        with pytest.raises(GossipMessageError, match="Truncated gossip message"):
            asyncio.run(run())

    def test_read_invalid_utf8_topic(self) -> None:
        """Raises GossipMessageError for invalid UTF-8 in topic."""

        async def run() -> tuple[str, bytes]:
            # Invalid UTF-8 sequence
            invalid_utf8 = b"\xff\xfe"
            data = encode_varint(len(invalid_utf8)) + invalid_utf8
            # Add data portion
            data += encode_varint(4) + b"test"
            stream = MockStream(data)
            return await read_gossip_message(stream)

        with pytest.raises(GossipMessageError, match="Invalid topic encoding"):
            asyncio.run(run())

    def test_read_small_chunks(self) -> None:
        """Successfully reads message delivered in small chunks."""

        async def run() -> tuple[str, bytes]:
            block = make_test_signed_block()
            ssz_bytes = block.encode_bytes()
            topic_str = make_block_topic()
            message_data = build_gossip_message(topic_str, ssz_bytes)

            # Use tiny chunks to test incremental parsing
            stream = MockStream(message_data, chunk_size=5)
            return await read_gossip_message(stream)

        topic, compressed = asyncio.run(run())
        topic_str = make_block_topic()

        assert topic == topic_str
        assert len(compressed) > 0

    def test_read_large_message(self) -> None:
        """Successfully reads larger gossip message."""

        async def run() -> tuple[str, bytes, bytes]:
            block = make_test_signed_block()
            ssz_bytes = block.encode_bytes()
            topic_str = make_block_topic()
            message_data = build_gossip_message(topic_str, ssz_bytes)

            stream = MockStream(message_data)
            topic, compressed = await read_gossip_message(stream)
            return topic, compressed, ssz_bytes

        topic, compressed, ssz_bytes = asyncio.run(run())
        topic_str = make_block_topic()

        assert topic == topic_str
        # Verify the compressed data can be decompressed (framed format)
        decompressed = frame_decompress(compressed)
        assert decompressed == ssz_bytes

    def test_read_single_byte_chunks(self) -> None:
        """Successfully reads message with single-byte chunks."""

        async def run() -> tuple[str, bytes]:
            attestation = make_test_signed_attestation()
            ssz_bytes = attestation.encode_bytes()
            topic_str = make_attestation_topic()
            message_data = build_gossip_message(topic_str, ssz_bytes)

            # Single byte at a time - stress test incremental parsing
            stream = MockStream(message_data, chunk_size=1)
            return await read_gossip_message(stream)

        topic, _ = asyncio.run(run())
        topic_str = make_attestation_topic()

        assert topic == topic_str


# =============================================================================
# Integration Tests
# =============================================================================


class TestGossipReceptionIntegration:
    """Integration tests for the complete gossip reception flow."""

    def test_full_block_reception_flow(self) -> None:
        """Tests complete flow: stream -> parse -> decompress -> decode."""

        async def run() -> tuple[SignedBlockWithAttestation | SignedAttestation | None, bytes]:
            handler = GossipHandler(fork_digest="0x00000000")
            original_block = make_test_signed_block()
            ssz_bytes = original_block.encode_bytes()
            topic_str = make_block_topic()
            message_data = build_gossip_message(topic_str, ssz_bytes)

            # Step 1: Read from stream
            stream = MockStream(message_data)
            parsed_topic, compressed = await read_gossip_message(stream)

            # Step 2: Decode message
            decoded = handler.decode_message(parsed_topic, compressed)

            return decoded, original_block.encode_bytes()

        decoded, original_bytes = asyncio.run(run())

        # Step 3: Verify result
        assert isinstance(decoded, SignedBlockWithAttestation)
        assert decoded.encode_bytes() == original_bytes

    def test_full_attestation_reception_flow(self) -> None:
        """Tests complete flow for attestation messages."""

        async def run() -> tuple[
            SignedBlockWithAttestation | SignedAttestation | None, bytes, TopicKind
        ]:
            handler = GossipHandler(fork_digest="0x00000000")
            original_attestation = make_test_signed_attestation()
            ssz_bytes = original_attestation.encode_bytes()
            topic_str = make_attestation_topic()
            message_data = build_gossip_message(topic_str, ssz_bytes)

            # Step 1: Read from stream
            stream = MockStream(message_data)
            parsed_topic, compressed = await read_gossip_message(stream)

            # Step 2: Get topic info
            topic = handler.get_topic(parsed_topic)

            # Step 3: Decode message
            decoded = handler.decode_message(parsed_topic, compressed)

            return decoded, original_attestation.encode_bytes(), topic.kind

        decoded, original_bytes, topic_kind = asyncio.run(run())

        # Step 4: Verify result
        assert topic_kind == TopicKind.ATTESTATION_SUBNET
        assert isinstance(decoded, SignedAttestation)
        assert decoded.encode_bytes() == original_bytes

    def test_handler_fork_digest_stored(self) -> None:
        """Handler stores fork digest for topic validation."""
        digest = "0xaabbccdd"
        handler = GossipHandler(fork_digest=digest)
        assert handler.fork_digest == digest

    def test_roundtrip_preserves_data_integrity(self) -> None:
        """Data integrity preserved through encode-compress-stream-decompress-decode."""

        async def run() -> tuple[bytes, bytes]:
            handler = GossipHandler(fork_digest="0x00000000")
            original = make_test_signed_block()
            original_bytes = original.encode_bytes()

            # Encode and compress
            topic_str = make_block_topic()
            message_data = build_gossip_message(topic_str, original_bytes)

            # Simulate network transfer via stream
            stream = MockStream(message_data)
            _, compressed = await read_gossip_message(stream)

            # Decode
            decoded = handler.decode_message(topic_str, compressed)
            assert decoded is not None, "decode_message should not return None for valid input"
            decoded_bytes = decoded.encode_bytes()

            return decoded_bytes, original_bytes

        decoded_bytes, original_bytes = asyncio.run(run())

        # Verify exact match
        assert decoded_bytes == original_bytes


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestGossipReceptionEdgeCases:
    """Edge case tests for gossip reception."""

    def test_handler_with_different_fork_digests(self) -> None:
        """Handler works with various fork digest formats."""
        for digest in ["0x00000000", "0xffffffff", "0x12345678", "0xabcdef01"]:
            handler = GossipHandler(fork_digest=digest)
            topic_str = f"/{TOPIC_PREFIX}/{digest}/block/{ENCODING_POSTFIX}"
            topic = handler.get_topic(topic_str)
            assert topic.fork_digest == digest

    def test_zero_length_compressed_data(self) -> None:
        """Handles message with zero-length data field."""

        async def run() -> tuple[str, bytes]:
            topic = make_block_topic()
            topic_bytes = topic.encode("utf-8")
            # Zero-length data
            data = encode_varint(len(topic_bytes)) + topic_bytes + encode_varint(0)
            stream = MockStream(data)
            return await read_gossip_message(stream)

        topic_result, compressed = asyncio.run(run())
        topic = make_block_topic()
        assert topic_result == topic
        assert compressed == b""

    def test_decode_corrupted_snappy_data(self) -> None:
        """Detects corruption in Snappy compressed data."""
        handler = GossipHandler(fork_digest="0x00000000")
        topic_str = make_block_topic()

        # Create truncated snappy data that claims large uncompressed length
        # This will fail during decompression with "Truncated" or similar error
        corrupted = b"\xff\xff\xff\x7f"  # varint claiming huge uncompressed length

        with pytest.raises(GossipMessageError, match="Snappy decompression failed"):
            handler.decode_message(topic_str, corrupted)

    def test_very_long_topic_string(self) -> None:
        """Handles messages with unusually long topic strings."""

        async def run() -> str:
            # Create a long but valid-format topic
            long_digest = "0x" + "a" * 100
            topic = f"/{TOPIC_PREFIX}/{long_digest}/block/{ENCODING_POSTFIX}"
            topic_bytes = topic.encode("utf-8")
            compressed = compress(b"test")

            data = encode_varint(len(topic_bytes)) + topic_bytes
            data += encode_varint(len(compressed)) + compressed

            stream = MockStream(data)
            parsed_topic, _ = await read_gossip_message(stream)
            return parsed_topic

        parsed_topic = asyncio.run(run())
        long_digest = "0x" + "a" * 100
        expected_topic = f"/{TOPIC_PREFIX}/{long_digest}/block/{ENCODING_POSTFIX}"

        assert parsed_topic == expected_topic

    @pytest.mark.parametrize(
        "invalid_data",
        [
            b"\x00",  # Just a zero byte (topic length 0)
            b"\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80",  # Overlong varint
        ],
        ids=["zero_byte_topic_length", "overlong_varint"],
    )
    def test_malformed_varint_data(self, invalid_data: bytes) -> None:
        """Handles various malformed varint patterns."""

        async def run() -> tuple[str, bytes]:
            stream = MockStream(invalid_data)
            return await read_gossip_message(stream)

        with pytest.raises(GossipMessageError):
            asyncio.run(run())

    def test_topic_only_message_missing_data(self) -> None:
        """Raises error when message has topic but no data section."""

        async def run() -> tuple[str, bytes]:
            topic = make_block_topic()
            topic_bytes = topic.encode("utf-8")
            # Only topic, no data length or data
            data = encode_varint(len(topic_bytes)) + topic_bytes
            stream = MockStream(data)
            return await read_gossip_message(stream)

        with pytest.raises(GossipMessageError, match="Truncated gossip message"):
            asyncio.run(run())
