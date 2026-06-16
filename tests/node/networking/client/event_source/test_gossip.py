"""
Tests for the gossip message handler.

This module tests the GossipHandler class and GossipMessageError exception
that handle incoming gossip messages from peers in the P2P network.
"""

from __future__ import annotations

import pytest

from lean_spec.node.networking.client.event_source import (
    GossipHandler,
    GossipMessageError,
)
from lean_spec.node.networking.gossipsub.topic import (
    ENCODING_POSTFIX,
    TOPIC_PREFIX,
    ForkMismatchError,
    GossipTopic,
    TopicKind,
)

FORK_DIGEST = "0xaabbccdd"
WRONG_FORK_DIGEST = "0x11223344"


def _block_topic(digest: str = FORK_DIGEST) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/block/{ENCODING_POSTFIX}"


def _aggregation_topic(digest: str = FORK_DIGEST) -> str:
    return f"/{TOPIC_PREFIX}/{digest}/aggregation/{ENCODING_POSTFIX}"


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


class TestGossipReceptionEdgeCases:
    """Edge case tests for gossip reception."""

    def test_handler_fork_digest_stored(self) -> None:
        """Handler stores network name for topic validation."""
        digest = "0xaabbccdd"
        handler = GossipHandler(network_name=digest)
        assert handler.network_name == digest

    def test_handler_with_different_fork_digests(self) -> None:
        """Handler works with various network name formats."""
        for digest in ["0x00000000", "0xffffffff", "0x12345678", "0xabcdef01"]:
            handler = GossipHandler(network_name=digest)
            topic_str = f"/{TOPIC_PREFIX}/{digest}/block/{ENCODING_POSTFIX}"
            topic = handler.get_topic(topic_str)
            assert topic.network_name == digest


class TestGossipHandlerForkMismatch:
    """
    Network name validation on incoming gossip messages.

    Every gossip topic embeds a network name identifying the consensus fork.
    Messages from peers on a different fork must be rejected immediately
    to avoid processing incompatible data.
    """

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


class TestGossipHandlerForkValidation:
    """Test suite for GossipHandler fork compatibility validation."""

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
