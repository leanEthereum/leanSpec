"""
Tests for the gossip message handler.

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

import pytest

from consensus_testing import make_signed_attestation, make_signed_block
from lean_spec.node.networking.client.event_source import (
    GossipHandler,
    GossipMessageError,
    read_gossip_message,
)
from lean_spec.node.networking.gossipsub.topic import (
    ENCODING_POSTFIX,
    TOPIC_PREFIX,
    ForkMismatchError,
    GossipTopic,
    TopicKind,
)
from lean_spec.node.networking.varint import encode_varint
from lean_spec.node.snappy import compress, decompress
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import SignedAttestation, SignedBlock
from lean_spec.spec.ssz import Bytes32

FORK_DIGEST = "0xaabbccdd"
WRONG_FORK_DIGEST = "0x11223344"


def _block_topic(digest: str = FORK_DIGEST) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/block/{ENCODING_POSTFIX}"


def _attestation_topic(digest: str = FORK_DIGEST, subnet_id: int = 0) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/attestation_{subnet_id}/{ENCODING_POSTFIX}"


def _aggregation_topic(digest: str = FORK_DIGEST) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/aggregation/{ENCODING_POSTFIX}"


def _make_block() -> SignedBlock:
    return make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
    )


def _make_attestation() -> SignedAttestation:
    return make_signed_attestation(
        validator=ValidatorIndex(0),
        target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
    )


def _build_gossip_wire(topic: str, ssz_data: bytes) -> bytes:
    """
    Build a complete gossip wire-format message.

    Produces the four-field frame that peers send over QUIC gossip streams:
    varint-encoded topic length, UTF-8 topic, varint-encoded data length,
    and Snappy-compressed SSZ payload.
    """
    topic_bytes = topic.encode("utf-8")
    compressed = compress(ssz_data)
    buffer = bytearray()
    buffer.extend(encode_varint(len(topic_bytes)))
    buffer.extend(topic_bytes)
    buffer.extend(encode_varint(len(compressed)))
    buffer.extend(compressed)
    return bytes(buffer)


class ChunkedMockStream:
    """
    Simulates a QUIC stream that delivers data in configurable chunks.

    Each call to read returns the next chunk from the list.
    Returns empty bytes once all chunks are exhausted, signaling EOF.
    Used to test wire-format reassembly across arbitrary read boundaries.
    """

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = iter(chunks)

    async def read(self) -> bytes:
        """Return next chunk or empty bytes when exhausted."""
        return next(self._chunks, b"")

    def write(self, data: bytes) -> None:
        """No-op write."""

    async def drain(self) -> None:
        """No-op drain."""

    async def close(self) -> None:
        """No-op close."""


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

    async def read(self) -> bytes:
        """Return next chunk of data, or empty bytes if exhausted."""
        if self.offset >= len(self.data):
            return b""
        chunk_end = min(self.offset + self.chunk_size, len(self.data))
        chunk = self.data[self.offset : chunk_end]
        self.offset = chunk_end
        return chunk

    def write(self, data: bytes) -> None:
        """Mock write (not used in reception tests)."""

    async def drain(self) -> None:
        """Mock drain (not used in reception tests)."""

    async def close(self) -> None:
        """Mock close."""
        pass

    async def reset(self) -> None:
        """Mock reset."""
        pass


def make_block_topic(network_name: str = "0x00000000") -> str:
    """Create a valid block topic string."""
    return f"/{TOPIC_PREFIX}/{network_name}/block/{ENCODING_POSTFIX}"


def make_attestation_topic(network_name: str = "0x00000000", subnet_id: int = 0) -> str:
    """Create a valid attestation subnet topic string."""
    return f"/{TOPIC_PREFIX}/{network_name}/attestation_{subnet_id}/{ENCODING_POSTFIX}"


def make_test_signed_block() -> SignedBlock:
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

    Format: [topic_length varint][topic][data_length varint][compressed_data]

    Uses raw Snappy compression as required by Ethereum gossip protocol.
    """
    topic_bytes = topic.encode("utf-8")
    compressed_data = compress(ssz_data)

    message = bytearray()
    message.extend(encode_varint(len(topic_bytes)))
    message.extend(topic_bytes)
    message.extend(encode_varint(len(compressed_data)))
    message.extend(compressed_data)

    return bytes(message)


class TestGossipMessageError:
    """Tests for the GossipMessageError exception."""

    def test_is_exception_subclass(self) -> None:
        """GossipMessageError inherits from Exception."""
        assert issubclass(GossipMessageError, Exception)

    def test_message_preserved(self) -> None:
        """Error message is preserved."""
        message = "Test error message"
        error = GossipMessageError(message)
        assert str(error) == message

    def test_can_be_raised_and_caught(self) -> None:
        """Can be raised and caught properly."""
        with pytest.raises(GossipMessageError) as exception_info:
            raise GossipMessageError("specific error")
        assert str(exception_info.value) == "specific error"


class TestGossipHandlerGetTopic:
    """Tests for GossipHandler.get_topic() method."""

    def test_valid_block_topic(self) -> None:
        """Parses valid block topic string."""
        handler = GossipHandler(network_name="0x12345678")
        topic_str = "/leanconsensus/0x12345678/block/ssz_snappy"

        topic = handler.get_topic(topic_str)

        assert isinstance(topic, GossipTopic)
        assert topic.kind == TopicKind.BLOCK
        assert topic.network_name == "0x12345678"

    def test_valid_attestation_subnet_topic(self) -> None:
        """Parses valid attestation subnet topic string."""
        handler = GossipHandler(network_name="0x00000000")
        topic_str = "/leanconsensus/0x00000000/attestation_0/ssz_snappy"

        topic = handler.get_topic(topic_str)

        assert isinstance(topic, GossipTopic)
        assert topic.kind == TopicKind.ATTESTATION_SUBNET
        assert topic.network_name == "0x00000000"

    def test_invalid_topic_format_missing_parts(self) -> None:
        """Raises GossipMessageError for topic with missing parts."""
        handler = GossipHandler(network_name="0x00000000")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.get_topic("/invalid/topic")
        assert str(exception_info.value) == (
            "Invalid topic: Invalid topic format: expected 4 parts, got 2"
        )

    def test_invalid_topic_format_wrong_prefix(self) -> None:
        """Raises GossipMessageError for wrong network prefix."""
        handler = GossipHandler(network_name="0x00000000")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.get_topic("/wrongprefix/0x00000000/block/ssz_snappy")
        assert str(exception_info.value) == (
            "Invalid topic: Invalid prefix: expected 'leanconsensus', got 'wrongprefix'"
        )

    def test_invalid_topic_format_wrong_encoding(self) -> None:
        """Raises GossipMessageError for wrong encoding suffix."""
        handler = GossipHandler(network_name="0x00000000")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.get_topic("/leanconsensus/0x00000000/block/ssz")
        assert str(exception_info.value) == (
            "Invalid topic: Invalid encoding: expected 'ssz_snappy', got 'ssz'"
        )

    def test_invalid_topic_format_unknown_topic_name(self) -> None:
        """Raises GossipMessageError for unknown topic name."""
        handler = GossipHandler(network_name="0x00000000")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.get_topic("/leanconsensus/0x00000000/unknown/ssz_snappy")
        assert str(exception_info.value) == "Invalid topic: Unknown topic: 'unknown'"

    def test_empty_topic_string(self) -> None:
        """Raises GossipMessageError for empty topic string."""
        handler = GossipHandler(network_name="0x00000000")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.get_topic("")
        assert str(exception_info.value) == (
            "Invalid topic: Invalid topic format: expected 4 parts, got 1"
        )


class TestGossipHandlerDecodeMessage:
    """Tests for GossipHandler.decode_message() method."""

    def test_decode_valid_block_message(self) -> None:
        """Decodes valid block message correctly."""
        handler = GossipHandler(network_name="0x00000000")
        block = make_test_signed_block()
        ssz_bytes = block.encode_bytes()
        compressed = compress(ssz_bytes)
        topic_str = make_block_topic()

        decoded_message = handler.decode_message(topic_str, compressed)

        assert isinstance(decoded_message, SignedBlock)

    def test_decode_valid_attestation_message(self) -> None:
        """Decodes valid attestation message correctly."""
        handler = GossipHandler(network_name="0x00000000")
        attestation = make_test_signed_attestation()
        ssz_bytes = attestation.encode_bytes()
        compressed = compress(ssz_bytes)
        topic_str = make_attestation_topic()

        decoded_message = handler.decode_message(topic_str, compressed)

        assert isinstance(decoded_message, SignedAttestation)

    def test_decode_invalid_topic_format(self) -> None:
        """Raises GossipMessageError for invalid topic format."""
        handler = GossipHandler(network_name="0x00000000")
        compressed = compress(b"\x00" * 32)

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message("/bad/topic", compressed)
        assert str(exception_info.value) == (
            "Invalid topic: Invalid topic format: expected 4 parts, got 2"
        )

    def test_decode_invalid_snappy_compression(self) -> None:
        """Raises GossipMessageError for invalid Snappy data."""
        handler = GossipHandler(network_name="0x00000000")
        topic_str = make_block_topic()
        # Invalid snappy: claims uncompressed length of 1000 bytes but has truncated data
        # Snappy format: [uncompressed_length varint][compressed_data]
        invalid_snappy = b"\xe8\x07"  # varint for 1000, but no data following

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(topic_str, invalid_snappy)
        assert str(exception_info.value) == (
            "Snappy decompression failed: "
            "Unexpected end of input at position 2, output has 0 bytes but expected 1000"
        )

    def test_decode_invalid_ssz_encoding(self) -> None:
        """Raises GossipMessageError for invalid SSZ data."""
        handler = GossipHandler(network_name="0x00000000")
        topic_str = make_block_topic()
        # Valid Snappy compression wrapping garbage SSZ
        compressed = compress(b"\xff\xff\xff\xff")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(topic_str, compressed)
        assert str(exception_info.value) == "SSZ decode failed: Uint32: expected 4 bytes, got 0"

    def test_decode_empty_snappy_data(self) -> None:
        """Raises GossipMessageError for empty compressed data."""
        handler = GossipHandler(network_name="0x00000000")
        topic_str = make_block_topic()

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(topic_str, b"")
        assert str(exception_info.value) == "Snappy decompression failed: Empty input"

    def test_decode_truncated_ssz_data(self) -> None:
        """Raises GossipMessageError for truncated SSZ data."""
        handler = GossipHandler(network_name="0x00000000")
        block = make_test_signed_block()
        ssz_bytes = block.encode_bytes()
        truncated = ssz_bytes[:10]  # Truncate SSZ data
        compressed = compress(truncated)
        topic_str = make_block_topic()

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(topic_str, compressed)
        assert str(exception_info.value) == "SSZ decode failed: Slot: expected 8 bytes, got 2"


class TestReadGossipMessage:
    """Tests for the read_gossip_message async function."""

    async def test_read_valid_block_message(self) -> None:
        """Reads valid block message from stream."""
        block = make_test_signed_block()
        ssz_bytes = block.encode_bytes()
        topic_str = make_block_topic()
        message_data = build_gossip_message(topic_str, ssz_bytes)

        stream = MockStream(message_data)
        topic, compressed = await read_gossip_message(stream)

        assert topic == topic_str
        assert len(compressed) > 0

    async def test_read_valid_attestation_message(self) -> None:
        """Reads valid attestation message from stream."""
        attestation = make_test_signed_attestation()
        ssz_bytes = attestation.encode_bytes()
        topic_str = make_attestation_topic()
        message_data = build_gossip_message(topic_str, ssz_bytes)

        stream = MockStream(message_data)
        topic, compressed = await read_gossip_message(stream)

        assert topic == topic_str
        assert len(compressed) > 0

    async def test_read_empty_stream(self) -> None:
        """Raises GossipMessageError for empty stream."""
        stream = MockStream(b"")

        with pytest.raises(GossipMessageError) as exception_info:
            await read_gossip_message(stream)
        assert str(exception_info.value) == "Empty gossip message"

    async def test_read_truncated_topic_length(self) -> None:
        """Raises GossipMessageError for incomplete topic length varint."""
        # A varint byte with continuation bit set but no following bytes
        incomplete_varint = b"\x80"  # Continuation bit set, needs more bytes
        stream = MockStream(incomplete_varint)

        with pytest.raises(GossipMessageError) as exception_info:
            await read_gossip_message(stream)
        assert str(exception_info.value) == "Truncated gossip message"

    async def test_read_truncated_topic_string(self) -> None:
        """Raises GossipMessageError for truncated topic string."""
        topic = make_block_topic()
        topic_bytes = topic.encode("utf-8")
        # Claim topic is 100 bytes but only provide partial data
        truncated = encode_varint(100) + topic_bytes[:10]
        stream = MockStream(truncated)

        with pytest.raises(GossipMessageError) as exception_info:
            await read_gossip_message(stream)
        assert str(exception_info.value) == "Truncated gossip message"

    async def test_read_truncated_data_length(self) -> None:
        """Raises GossipMessageError for truncated data length varint."""
        topic = make_block_topic()
        topic_bytes = topic.encode("utf-8")
        # Complete topic but incomplete data length varint
        gossip_wire = encode_varint(len(topic_bytes)) + topic_bytes + b"\x80"
        stream = MockStream(gossip_wire)

        with pytest.raises(GossipMessageError) as exception_info:
            await read_gossip_message(stream)
        assert str(exception_info.value) == "Truncated gossip message"

    async def test_read_truncated_data(self) -> None:
        """Raises GossipMessageError for truncated message data."""
        topic = make_block_topic()
        topic_bytes = topic.encode("utf-8")
        compressed = compress(b"test data")
        # Claim data is 1000 bytes but only provide partial
        gossip_wire = (
            encode_varint(len(topic_bytes)) + topic_bytes + encode_varint(1000) + compressed[:5]
        )
        stream = MockStream(gossip_wire)

        with pytest.raises(GossipMessageError) as exception_info:
            await read_gossip_message(stream)
        assert str(exception_info.value) == "Truncated gossip message"

    async def test_read_invalid_utf8_topic(self) -> None:
        """Raises GossipMessageError for invalid UTF-8 in topic."""
        # Invalid UTF-8 sequence
        invalid_utf8 = b"\xff\xfe"
        gossip_wire = encode_varint(len(invalid_utf8)) + invalid_utf8
        # Add data portion
        gossip_wire += encode_varint(4) + b"test"
        stream = MockStream(gossip_wire)

        with pytest.raises(GossipMessageError) as exception_info:
            await read_gossip_message(stream)
        assert str(exception_info.value) == (
            "Invalid topic encoding: "
            "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
        )

    async def test_read_small_chunks(self) -> None:
        """Successfully reads message delivered in small chunks."""
        block = make_test_signed_block()
        ssz_bytes = block.encode_bytes()
        topic_str = make_block_topic()
        message_data = build_gossip_message(topic_str, ssz_bytes)

        # Use tiny chunks to test incremental parsing
        stream = MockStream(message_data, chunk_size=5)
        topic, compressed = await read_gossip_message(stream)

        assert topic == topic_str
        assert len(compressed) > 0

    async def test_read_large_message(self) -> None:
        """Successfully reads larger gossip message."""
        block = make_test_signed_block()
        ssz_bytes = block.encode_bytes()
        topic_str = make_block_topic()
        message_data = build_gossip_message(topic_str, ssz_bytes)

        stream = MockStream(message_data)
        topic, compressed = await read_gossip_message(stream)

        assert topic == topic_str
        # Verify the compressed data can be decompressed (raw Snappy format)
        decompressed = decompress(compressed)
        assert decompressed == ssz_bytes

    async def test_read_single_byte_chunks(self) -> None:
        """Successfully reads message with single-byte chunks."""
        attestation = make_test_signed_attestation()
        ssz_bytes = attestation.encode_bytes()
        topic_str = make_attestation_topic()
        message_data = build_gossip_message(topic_str, ssz_bytes)

        # Single byte at a time - stress test incremental parsing
        stream = MockStream(message_data, chunk_size=1)
        topic, _ = await read_gossip_message(stream)

        assert topic == topic_str


class TestGossipReceptionIntegration:
    """Integration tests for the complete gossip reception flow."""

    async def test_full_block_reception_flow(self) -> None:
        """Tests complete flow: stream -> parse -> decompress -> decode."""
        handler = GossipHandler(network_name="0x00000000")
        original_block = make_test_signed_block()
        ssz_bytes = original_block.encode_bytes()
        topic_str = make_block_topic()
        message_data = build_gossip_message(topic_str, ssz_bytes)

        # Step 1: Read from stream
        stream = MockStream(message_data)
        parsed_topic, compressed = await read_gossip_message(stream)

        # Step 2: Decode message
        decoded = handler.decode_message(parsed_topic, compressed)

        # Step 3: Verify result
        assert isinstance(decoded, SignedBlock)
        assert decoded.encode_bytes() == original_block.encode_bytes()

    async def test_full_attestation_reception_flow(self) -> None:
        """Tests complete flow for attestation messages."""
        handler = GossipHandler(network_name="0x00000000")
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

        # Step 4: Verify result
        assert topic.kind == TopicKind.ATTESTATION_SUBNET
        assert isinstance(decoded, SignedAttestation)
        assert decoded.encode_bytes() == original_attestation.encode_bytes()

    def test_handler_fork_digest_stored(self) -> None:
        """Handler stores network name for topic validation."""
        digest = "0xaabbccdd"
        handler = GossipHandler(network_name=digest)
        assert handler.network_name == digest

    async def test_roundtrip_preserves_data_integrity(self) -> None:
        """Data integrity preserved through encode-compress-stream-decompress-decode."""
        handler = GossipHandler(network_name="0x00000000")
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

        # Verify exact match
        assert decoded_bytes == original_bytes


class TestGossipReceptionEdgeCases:
    """Edge case tests for gossip reception."""

    def test_handler_with_different_fork_digests(self) -> None:
        """Handler works with various network name formats."""
        for digest in ["0x00000000", "0xffffffff", "0x12345678", "0xabcdef01"]:
            handler = GossipHandler(network_name=digest)
            topic_str = f"/{TOPIC_PREFIX}/{digest}/block/{ENCODING_POSTFIX}"
            topic = handler.get_topic(topic_str)
            assert topic.network_name == digest

    async def test_zero_length_compressed_data(self) -> None:
        """Handles message with zero-length data field."""
        topic = make_block_topic()
        topic_bytes = topic.encode("utf-8")
        # Zero-length data
        gossip_wire = encode_varint(len(topic_bytes)) + topic_bytes + encode_varint(0)
        stream = MockStream(gossip_wire)

        parsed_topic, compressed = await read_gossip_message(stream)

        assert parsed_topic == topic
        assert compressed == b""

    def test_decode_corrupted_snappy_data(self) -> None:
        """Detects corruption in Snappy compressed data."""
        handler = GossipHandler(network_name="0x00000000")
        topic_str = make_block_topic()

        # Create truncated snappy data that claims large uncompressed length
        # This will fail during decompression with "Truncated" or similar error
        corrupted = b"\xff\xff\xff\x7f"  # varint claiming huge uncompressed length

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(topic_str, corrupted)
        assert str(exception_info.value) == (
            "Snappy decompression failed: "
            "Unexpected end of input at position 4, output has 0 bytes but expected 268435455"
        )

    async def test_very_long_topic_string(self) -> None:
        """Handles messages with unusually long topic strings."""
        # Create a long but valid-format topic
        long_digest = "0x" + "a" * 100
        topic = f"/{TOPIC_PREFIX}/{long_digest}/block/{ENCODING_POSTFIX}"
        topic_bytes = topic.encode("utf-8")
        compressed = compress(b"test")

        gossip_wire = encode_varint(len(topic_bytes)) + topic_bytes
        gossip_wire += encode_varint(len(compressed)) + compressed

        stream = MockStream(gossip_wire)
        parsed_topic, _ = await read_gossip_message(stream)

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
    async def test_malformed_varint_data(self, invalid_data: bytes) -> None:
        """Handles various malformed varint patterns."""
        stream = MockStream(invalid_data)

        with pytest.raises(GossipMessageError):
            await read_gossip_message(stream)

    async def test_topic_only_message_missing_data(self) -> None:
        """Raises error when message has topic but no data section."""
        topic = make_block_topic()
        topic_bytes = topic.encode("utf-8")
        # Only topic, no data length or data
        gossip_wire = encode_varint(len(topic_bytes)) + topic_bytes
        stream = MockStream(gossip_wire)

        with pytest.raises(GossipMessageError) as exception_info:
            await read_gossip_message(stream)
        assert str(exception_info.value) == "Truncated gossip message"


class TestGossipHandlerForkMismatch:
    """
    Network name validation on incoming gossip messages.

    Every gossip topic embeds a network name identifying the consensus fork.
    Messages from peers on a different fork must be rejected immediately
    to avoid processing incompatible data.
    """

    def test_decode_message_raises_fork_mismatch(self) -> None:
        """Rejects messages whose topic carries a different network name."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        block = _make_block()
        compressed = compress(block.encode_bytes())

        with pytest.raises(ForkMismatchError) as exception_info:
            handler.decode_message(_block_topic(WRONG_FORK_DIGEST), compressed)
        assert str(exception_info.value) == (
            f"Fork mismatch: expected {FORK_DIGEST}, got {WRONG_FORK_DIGEST}"
        )

    def test_get_topic_raises_fork_mismatch(self) -> None:
        """Rejects topic strings with mismatched network name."""
        handler = GossipHandler(network_name=FORK_DIGEST)

        with pytest.raises(ForkMismatchError) as exception_info:
            handler.get_topic(_block_topic(WRONG_FORK_DIGEST))
        assert str(exception_info.value) == (
            f"Fork mismatch: expected {FORK_DIGEST}, got {WRONG_FORK_DIGEST}"
        )

    def test_fork_mismatch_error_attributes(self) -> None:
        """ForkMismatchError exposes expected and actual digests."""
        error = ForkMismatchError(expected=FORK_DIGEST, actual=WRONG_FORK_DIGEST)

        assert error.expected == FORK_DIGEST
        assert error.actual == WRONG_FORK_DIGEST

    def test_fork_mismatch_is_value_error(self) -> None:
        """ForkMismatchError inherits from ValueError."""
        assert issubclass(ForkMismatchError, ValueError)

    def test_decode_message_fork_mismatch_not_wrapped_as_gossip_error(self) -> None:
        """ForkMismatchError propagates directly, not wrapped in GossipMessageError."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        compressed = compress(b"\x00" * 32)

        with pytest.raises(ForkMismatchError):
            handler.decode_message(_block_topic(WRONG_FORK_DIGEST), compressed)

        # Verify it does NOT raise GossipMessageError
        try:
            handler.decode_message(_block_topic(WRONG_FORK_DIGEST), compressed)
        except ForkMismatchError:
            pass
        except GossipMessageError:
            pytest.fail("ForkMismatchError should not be wrapped in GossipMessageError")


class TestGossipHandlerAggregationTopic:
    """
    Aggregated attestation topic parsing and decoding.

    The aggregation topic carries attestations that have been aggregated
    by a committee member. The gossip handler must recognize this topic
    kind and decode its SSZ payload accordingly.
    """

    def test_get_topic_recognizes_aggregation(self) -> None:
        """Parses aggregation topic and returns AGGREGATED_ATTESTATION kind."""
        handler = GossipHandler(network_name=FORK_DIGEST)

        topic = handler.get_topic(_aggregation_topic())

        assert topic == GossipTopic(
            kind=TopicKind.AGGREGATED_ATTESTATION,
            network_name=FORK_DIGEST,
        )

    def test_decode_message_invalid_ssz_for_aggregation(self) -> None:
        """Raises GossipMessageError when SSZ bytes are invalid for aggregation."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        compressed = compress(b"\xff\xff\xff\xff")

        with pytest.raises(GossipMessageError) as exception_info:
            handler.decode_message(_aggregation_topic(), compressed)
        assert str(exception_info.value) == "SSZ decode failed: Slot: expected 8 bytes, got 4"


class TestReadGossipMessageChunked:
    """
    Gossip wire-format reassembly across arbitrary read boundaries.

    QUIC streams may deliver data in chunks of any size. The reader must
    correctly reassemble the four-field gossip frame regardless of where
    chunk boundaries fall: inside a varint, inside the topic string,
    between topic and data, or across three or more pieces.
    """

    async def test_message_split_at_varint_boundary(self) -> None:
        """Correctly reassembles when a read boundary falls inside a varint."""
        block = _make_block()
        wire = _build_gossip_wire(_block_topic(), block.encode_bytes())

        # Split so first chunk contains only 1 byte (partial varint for topic len)
        chunks = [wire[:1], wire[1:]]
        stream = ChunkedMockStream(chunks)
        topic, compressed = await read_gossip_message(stream)

        assert topic == _block_topic()
        assert len(compressed) > 0

    async def test_message_split_inside_topic(self) -> None:
        """Correctly reassembles when a read boundary falls inside the topic string."""
        block = _make_block()
        wire = _build_gossip_wire(_block_topic(), block.encode_bytes())

        # Split inside the topic string (offset 5 is well within topic bytes)
        chunks = [wire[:5], wire[5:]]
        stream = ChunkedMockStream(chunks)
        topic, compressed = await read_gossip_message(stream)

        assert topic == _block_topic()
        assert len(compressed) > 0

    async def test_message_split_between_topic_and_data(self) -> None:
        """Correctly reassembles when the split falls between topic and data sections."""
        block = _make_block()
        topic_str = _block_topic()
        wire = _build_gossip_wire(topic_str, block.encode_bytes())

        # Find the boundary: after topic_length varint + topic bytes
        topic_bytes = topic_str.encode("utf-8")
        varint_length = len(encode_varint(len(topic_bytes)))
        boundary = varint_length + len(topic_bytes)

        chunks = [wire[:boundary], wire[boundary:]]
        stream = ChunkedMockStream(chunks)
        topic, compressed = await read_gossip_message(stream)

        assert topic == topic_str
        assert len(compressed) > 0

    async def test_three_chunk_delivery(self) -> None:
        """Handles message delivered in three arbitrary pieces."""
        attestation = _make_attestation()
        wire = _build_gossip_wire(_attestation_topic(), attestation.encode_bytes())

        third_length = len(wire) // 3
        chunks = [
            wire[:third_length],
            wire[third_length : 2 * third_length],
            wire[2 * third_length :],
        ]
        stream = ChunkedMockStream(chunks)
        topic, _ = await read_gossip_message(stream)

        assert topic == _attestation_topic()


class TestGossipHandlerDecodeRoundtrip:
    """
    SSZ encode-compress-decode roundtrip fidelity.

    Gossip messages are SSZ-encoded, Snappy-compressed, and sent over
    the wire. Decoding must recover the original SSZ bytes exactly,
    ensuring no data loss through the compression layer.
    """

    def test_block_roundtrip_preserves_ssz(self) -> None:
        """Block SSZ bytes are identical after decode."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        block = _make_block()
        original_bytes = block.encode_bytes()

        decoded_message = handler.decode_message(
            _block_topic(),
            compress(original_bytes),
        )

        assert isinstance(decoded_message, SignedBlock)
        assert decoded_message.encode_bytes() == original_bytes

    def test_attestation_roundtrip_preserves_ssz(self) -> None:
        """Attestation SSZ bytes are identical after decode."""
        handler = GossipHandler(network_name=FORK_DIGEST)
        attestation = _make_attestation()
        original_bytes = attestation.encode_bytes()

        decoded_message = handler.decode_message(
            _attestation_topic(),
            compress(original_bytes),
        )

        assert isinstance(decoded_message, SignedAttestation)
        assert decoded_message.encode_bytes() == original_bytes


class TestGossipHandlerForkValidation:
    """Test suite for GossipHandler fork compatibility validation."""

    def test_decode_message_rejects_wrong_fork(self) -> None:
        """GossipHandler.decode_message() raises ForkMismatchError for wrong fork."""
        handler = GossipHandler(network_name="0x12345678")

        # Topic with different network_name
        wrong_fork_topic = "/leanconsensus/0xdeadbeef/block/ssz_snappy"

        with pytest.raises(ForkMismatchError) as exc_info:
            handler.decode_message(wrong_fork_topic, b"dummy_data")

        assert exc_info.value.expected == "0x12345678"
        assert exc_info.value.actual == "0xdeadbeef"

    def test_get_topic_rejects_wrong_fork(self) -> None:
        """GossipHandler.get_topic() raises ForkMismatchError for wrong fork."""
        handler = GossipHandler(network_name="0x12345678")

        # Topic with different network_name
        wrong_fork_topic = "/leanconsensus/0xdeadbeef/attestation/ssz_snappy"

        with pytest.raises(ForkMismatchError) as exc_info:
            handler.get_topic(wrong_fork_topic)

        assert exc_info.value.expected == "0x12345678"
        assert exc_info.value.actual == "0xdeadbeef"

    def test_get_topic_accepts_matching_fork(self) -> None:
        """GossipHandler.get_topic() returns topic for matching fork."""
        handler = GossipHandler(network_name="0x12345678")
        assert handler.get_topic("/leanconsensus/0x12345678/block/ssz_snappy") == GossipTopic(
            kind=TopicKind.BLOCK, network_name="0x12345678"
        )
