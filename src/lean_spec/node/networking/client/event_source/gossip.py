"""Decoder for inbound gossipsub messages."""

from __future__ import annotations

from dataclasses import dataclass

from lean_spec.node.networking.client.event_source.protocol import GossipMessageError
from lean_spec.node.networking.gossipsub.topic import (
    ForkMismatchError,
    GossipTopic,
)


@dataclass(slots=True)
class GossipHandler:
    """
    Parses and validates topics for incoming gossip messages from peers.

    Topics contain:

    - Network name: 4-byte identifier derived from genesis + fork version.
    - Message type: "blocks" or "attestation".
    - Encoding: Always "ssz_snappy" for Ethereum.

    Validating the topic prevents:

    - Routing attacks: Reject messages for different forks.
    - Type confusion: Ensure we decode with the correct schema.
    - Protocol violations: Reject malformed topic strings.
    """

    network_name: str
    """Expected network name for topic validation.

    Messages with mismatched fork digests are rejected. This prevents
    cross-fork message injection attacks.
    """

    def get_topic(self, topic_str: str) -> GossipTopic:
        """
        Parse and validate a topic string without decoding the payload.

        Useful when only topic validation is needed (e.g., checking fork
        digest before investing in decompression/deserialization).

        Args:
            topic_str: Full topic string.

        Returns:
            Parsed GossipTopic.

        Raises:
            ForkMismatchError: If network_name does not match.
            GossipMessageError: If the topic is invalid.
        """
        try:
            return GossipTopic.from_string_validated(topic_str, self.network_name)
        except ForkMismatchError:
            raise
        except ValueError as exception:
            raise GossipMessageError(f"Invalid topic: {exception}") from exception
