"""Tests for the gossipsub message type."""

from __future__ import annotations

from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.types import MessageId


class TestGossipsubMessageId:
    """Tests for GossipsubMessage ID computation."""

    def test_id_is_deterministic(self) -> None:
        """Same topic + data produce the same ID."""
        msg1 = GossipsubMessage(topic=b"topic", raw_data=b"data")
        msg2 = GossipsubMessage(topic=b"topic", raw_data=b"data")
        assert msg1.id == msg2.id

    def test_id_differs_with_different_data(self) -> None:
        """Different data produces a different ID."""
        msg1 = GossipsubMessage(topic=b"topic", raw_data=b"data1")
        msg2 = GossipsubMessage(topic=b"topic", raw_data=b"data2")
        assert msg1.id != msg2.id

    def test_id_differs_with_different_topic(self) -> None:
        """Different topic produces a different ID."""
        msg1 = GossipsubMessage(topic=b"topicA", raw_data=b"data")
        msg2 = GossipsubMessage(topic=b"topicB", raw_data=b"data")
        assert msg1.id != msg2.id

    def test_id_is_20_bytes(self) -> None:
        """Message ID is exactly 20 bytes."""
        message = GossipsubMessage(topic=b"t", raw_data=b"d")
        assert len(message.id) == 20
        assert isinstance(message.id, MessageId)

    def test_id_is_cached(self) -> None:
        """The ID is computed once and the same object is returned on subsequent accesses."""
        message = GossipsubMessage(topic=b"t", raw_data=b"d")
        first_id = message.id
        second_id = message.id

        assert first_id is second_id

    def test_compute_id_default_domain_invalid_snappy(self) -> None:
        """compute_id uses the invalid-snappy domain when domain is omitted."""
        from lean_spec.node.networking.config import (
            MESSAGE_DOMAIN_INVALID_SNAPPY,
            MESSAGE_DOMAIN_VALID_SNAPPY,
        )

        id_default = GossipsubMessage.compute_id(b"t", b"data")
        id_explicit_invalid = GossipsubMessage.compute_id(
            b"t", b"data", domain=MESSAGE_DOMAIN_INVALID_SNAPPY
        )
        id_explicit_valid = GossipsubMessage.compute_id(
            b"t", b"data", domain=MESSAGE_DOMAIN_VALID_SNAPPY
        )

        assert id_default == id_explicit_invalid
        assert id_default != id_explicit_valid


class TestGossipsubMessageHash:
    """Tests for GossipsubMessage.__hash__."""

    def test_same_message_same_hash(self) -> None:
        """Messages with same content have the same hash."""
        msg1 = GossipsubMessage(topic=b"t", raw_data=b"d")
        msg2 = GossipsubMessage(topic=b"t", raw_data=b"d")
        assert hash(msg1) == hash(msg2)

    def test_usable_in_set(self) -> None:
        """Messages can be stored in a set, deduplicated by content."""
        msg1 = GossipsubMessage(topic=b"t", raw_data=b"d")
        msg2 = GossipsubMessage(topic=b"t", raw_data=b"d")
        msg3 = GossipsubMessage(topic=b"t", raw_data=b"other")

        s = {msg1, msg2, msg3}
        assert len(s) == 2
