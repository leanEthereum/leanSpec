"""
Gossipsub Topics
================

Topic definitions for the Lean Ethereum gossipsub network.

Overview
--------

Gossipsub organizes messages by topic. Each topic identifies a specific
message type (blocks, attestations, etc.) within a specific fork.

Topic Format
------------

Topics follow a structured format::

    /{prefix}/{fork_digest}/{topic_name}/{encoding}

    Example: /leanconsensus/0x12345678/block/ssz_snappy

**Components:**

+----------------+----------------------------------------------------------+
| Component      | Description                                              |
+================+==========================================================+
| prefix         | Network identifier (`leanconsensus`)                   |
+----------------+----------------------------------------------------------+
| fork_digest    | 4-byte fork identifier as hex (`0x12345678`)           |
+----------------+----------------------------------------------------------+
| topic_name     | Message type (`block`, `attestation`)                |
+----------------+----------------------------------------------------------+
| encoding       | Serialization format (always `ssz_snappy`)             |
+----------------+----------------------------------------------------------+

Fork Digest
-----------

The fork digest ensures peers on different forks don't exchange
incompatible messages. It's derived from the fork version and
genesis validators root.

Topic Types
-----------

+----------------+----------------------------------------------------------+
| Topic          | Content                                                  |
+================+==========================================================+
| block          | Signed beacon blocks                                     |
+----------------+----------------------------------------------------------+
| attestation    | Signed attestations                                      |
+----------------+----------------------------------------------------------+

References:
----------
- Ethereum P2P: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

TOPIC_PREFIX: str = "leanconsensus"
"""Network prefix for Lean consensus gossip topics.

Identifies this network in topic strings. Different networks
(mainnet, testnets) may use different prefixes.
"""

ENCODING_POSTFIX: str = "ssz_snappy"
"""Encoding suffix for SSZ with Snappy compression.

All Ethereum consensus gossip messages use SSZ serialization
with Snappy compression.
"""

BLOCK_TOPIC_NAME: str = "block"
"""Topic name for block messages.

Used in the topic string to identify signed beacon block messages.
"""

ATTESTATION_TOPIC_NAME: str = "attestation"
"""Topic name for attestation messages.

Used in the topic string to identify signed attestation messages.
"""

ATTESTATION_SUBNET_TOPIC_NAME: str = "attestation_{subnet_id}"
"""Template topic name for attestation subnet messages.

Used in the topic string to identify attestation messages for a specific subnet.
`{subnet_id}` should be replaced with the subnet identifier (0-63).
"""

AGGREGATED_ATTESTATION_TOPIC_NAME: str = "aggregation"
"""Topic name for committee aggregation messages.

Used in the topic string to identify committee's aggregation messages.
"""


class TopicKind(Enum):
    """Gossip topic types.

    Enumerates the different message types that can be gossiped.

    Each variant corresponds to a specific `topic_name` in the
    topic string format.
    """

    BLOCK = BLOCK_TOPIC_NAME
    """Signed beacon block messages."""

    ATTESTATION = ATTESTATION_TOPIC_NAME
    """Signed attestation messages."""

    ATTESTATION_SUBNET = ATTESTATION_SUBNET_TOPIC_NAME
    """Attestation subnet messages."""

    AGGREGATED_ATTESTATION = AGGREGATED_ATTESTATION_TOPIC_NAME
    """Committee aggregated signatures messages."""

    def __str__(self) -> str:
        """Return the topic name string."""
        return self.value


@dataclass(frozen=True, slots=True)
class GossipTopic:
    """A fully-qualified gossipsub topic.

    Immutable representation of a topic that combines the message type
    and fork digest. Can be converted to/from the string format.
    """

    kind: TopicKind
    """The topic type (block, attestation, etc.).

    Determines what kind of messages are exchanged on this topic.
    """

    fork_digest: str
    """Fork digest as 0x-prefixed hex string.

    Identifies the fork this topic belongs to.

    Peers must match on fork digest to exchange messages on a topic.
    """

    def __str__(self) -> str:
        """Return the full topic string.

        Returns:
            Topic in format `/{prefix}/{fork}/{name}/{encoding}`
        """
        return f"/{TOPIC_PREFIX}/{self.fork_digest}/{self.kind}/{ENCODING_POSTFIX}"

    def __bytes__(self) -> bytes:
        """Return the topic string as UTF-8 bytes.

        Returns:
            Topic string encoded as bytes.
        """
        return str(self).encode("utf-8")

    @classmethod
    def from_string(cls, topic_str: str) -> GossipTopic:
        """Parse a topic string into a GossipTopic.

        Args:
            topic_str: Full topic string to parse.

        Returns:
            Parsed GossipTopic instance.

        Raises:
            ValueError: If the topic string is malformed.

        Example::

            topic = GossipTopic.from_string("/leanconsensus/0x12345678/block/ssz_snappy")
        """
        parts = topic_str.lstrip("/").split("/")

        if len(parts) != 4:
            raise ValueError(f"Invalid topic format: expected 4 parts, got {len(parts)}")

        prefix, fork_digest, topic_name, encoding = parts

        if prefix != TOPIC_PREFIX:
            raise ValueError(f"Invalid prefix: expected '{TOPIC_PREFIX}', got '{prefix}'")

        if encoding != ENCODING_POSTFIX:
            raise ValueError(f"Invalid encoding: expected '{ENCODING_POSTFIX}', got '{encoding}'")

        try:
            kind = TopicKind(topic_name)
        except ValueError:
            raise ValueError(f"Unknown topic: '{topic_name}'") from None

        return cls(kind=kind, fork_digest=fork_digest)

    @classmethod
    def block(cls, fork_digest: str) -> GossipTopic:
        """Create a block topic for the given fork.

        Args:
            fork_digest: Fork digest as 0x-prefixed hex string.

        Returns:
            GossipTopic for block messages.
        """
        return cls(kind=TopicKind.BLOCK, fork_digest=fork_digest)

    @classmethod
    def attestation(cls, fork_digest: str) -> GossipTopic:
        """Create an attestation topic for the given fork.

        Args:
            fork_digest: Fork digest as 0x-prefixed hex string.

        Returns:
            GossipTopic for attestation messages.
        """
        return cls(kind=TopicKind.ATTESTATION, fork_digest=fork_digest)

    @classmethod
    def committee_aggregation(cls, fork_digest: str) -> GossipTopic:
        """Create a committee aggregation topic for the given fork.

        Args:
            fork_digest: Fork digest as 0x-prefixed hex string.

        Returns:
            GossipTopic for committee aggregation messages.
        """
        return cls(kind=TopicKind.AGGREGATED_ATTESTATION, fork_digest=fork_digest)


def format_topic_string(
    topic_name: str,
    fork_digest: str,
    prefix: str = TOPIC_PREFIX,
    encoding: str = ENCODING_POSTFIX,
) -> str:
    """Format a complete gossip topic string.

    Low-level function for constructing topic strings. For most cases,
    use `GossipTopic` instead.

    Args:
        topic_name: Message type (e.g., "block", "attestation").
        fork_digest: Fork digest as 0x-prefixed hex string.
        prefix: Network prefix (defaults to TOPIC_PREFIX).
        encoding: Encoding suffix (defaults to ENCODING_POSTFIX).

    Returns:
        Formatted topic string.

    Example::

        topic_str = format_topic_string("block", "0x12345678")
        assert topic_str == "/leanconsensus/0x12345678/block/ssz_snappy"
    """
    return f"/{prefix}/{fork_digest}/{topic_name}/{encoding}"


def parse_topic_string(topic_str: str) -> tuple[str, str, str, str]:
    """Parse a topic string into its components.

    Low-level function for deconstructing topic strings. For most cases,
    use ``GossipTopic.from_string()`` instead.

    Args:
        topic_str: Topic string to parse.

    Returns:
        Tuple of (prefix, fork_digest, topic_name, encoding).

    Raises:
        ValueError: If the topic string is malformed.

    Example::

        prefix, fork, name, enc = parse_topic_string("/leanconsensus/0x12345678/block/ssz_snappy")
        assert prefix == "leanconsensus"
        assert fork == "0x12345678"
        assert name == "block"
        assert enc == "ssz_snappy"
    """
    parts = topic_str.lstrip("/").split("/")

    if len(parts) != 4:
        raise ValueError(f"Invalid topic format: expected 4 parts, got {len(parts)}")

    return (parts[0], parts[1], parts[2], parts[3])
