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

    /{prefix}/{network_name}/{topic_name}/{encoding}

    Example: /leanconsensus/12345678/block/ssz_snappy

**Components:**

+----------------+----------------------------------------------------------+
| Component      | Description                                              |
+================+==========================================================+
| prefix         | Network identifier (`leanconsensus`)                   |
+----------------+----------------------------------------------------------+
| network_name    | 4-byte fork identifier as hex (`12345678`)             |
+----------------+----------------------------------------------------------+
| topic_name     | Message type (`blocks`, `attestation`)               |
+----------------+----------------------------------------------------------+
| encoding       | Serialization format (always `ssz_snappy`)             |
+----------------+----------------------------------------------------------+

Fork Digest
-----------

The network name ensures peers on different forks don't exchange
incompatible messages. It's derived from the fork version and
genesis validators root.

Topic Types
-----------

+----------------+----------------------------------------------------------+
| Topic          | Content                                                  |
+================+==========================================================+
| blocks         | Signed beacon blocks                                     |
+----------------+----------------------------------------------------------+
| attestation    | Signed attestations                                      |
+----------------+----------------------------------------------------------+

References:
----------
- Ethereum P2P: https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final

from lean_spec.forks.lstar.containers.validator import SubnetId
from lean_spec.subspecs.networking.gossipsub.types import TopicId


class ForkMismatchError(ValueError):
    """Raised when a topic's network_name does not match the expected value."""

    def __init__(self, expected: str, actual: str) -> None:
        """Initialize with expected and actual fork digests."""
        self.expected = expected
        self.actual = actual
        super().__init__(f"Fork mismatch: expected {expected}, got {actual}")


TOPIC_PREFIX: Final = "leanconsensus"
"""Network prefix for Lean consensus gossip topics.

Identifies this network in topic strings. Different networks
(mainnet, testnets) may use different prefixes.
"""

ENCODING_POSTFIX: Final = "ssz_snappy"
"""Encoding suffix for SSZ with Snappy compression.

All Ethereum consensus gossip messages use SSZ serialization
with Snappy compression.
"""

BLOCK_TOPIC_NAME: Final = "block"
"""Topic name for block messages.

Used in the topic string to identify signed beacon block messages.
"""


ATTESTATION_SUBNET_TOPIC_PREFIX: Final = "attestation"
"""Base prefix for attestation subnet topic names.

Full topic names are formatted as "attestation_{subnet_id}".
"""

AGGREGATED_ATTESTATION_TOPIC_NAME: Final = "aggregation"
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

    ATTESTATION_SUBNET = ATTESTATION_SUBNET_TOPIC_PREFIX
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
    and network name. Can be converted to/from the string format.
    """

    kind: TopicKind
    """The topic type (block, attestation, etc.).

    Determines what kind of messages are exchanged on this topic.
    """

    network_name: str
    """Network name as hex string (no 0x prefix), like the beacon chain.

    Identifies the fork this topic belongs to.

    Peers must match on network name to exchange messages on a topic.
    """

    subnet_id: SubnetId | None = None
    """Subnet id for attestation subnet topics (required for ATTESTATION_SUBNET)."""

    def to_topic_id(self) -> TopicId:
        """Return the full topic string as a TopicId.

        Returns:
            Topic in format `/{prefix}/{fork}/{name}/{encoding}`
        """
        if self.kind is TopicKind.ATTESTATION_SUBNET:
            if self.subnet_id is None:
                raise ValueError("subnet_id is required for attestation subnet topics")
            topic_name = f"attestation_{self.subnet_id}"
        else:
            topic_name = str(self.kind)
        return TopicId(f"/{TOPIC_PREFIX}/{self.network_name}/{topic_name}/{ENCODING_POSTFIX}")

    def __str__(self) -> str:
        """Return the full topic string."""
        return self.to_topic_id()

    def validate_fork(self, expected_network_name: str) -> None:
        """
        Validate that the topic's network_name matches expected.

        Args:
            expected_network_name: Expected network name (hex string (no 0x prefix)).

        Raises:
            ForkMismatchError: If network_name does not match.
        """
        if self.network_name != expected_network_name:
            raise ForkMismatchError(expected_network_name, self.network_name)

    @classmethod
    def from_string(cls, topic_str: str) -> GossipTopic:
        """Parse a topic string into a GossipTopic.

        Args:
            topic_str: Full topic string to parse.

        Returns:
            Parsed GossipTopic instance.

        Raises:
            ValueError: If the topic string is malformed.
        """
        prefix, network_name, topic_name, encoding = parse_topic_string(topic_str)

        if prefix != TOPIC_PREFIX:
            raise ValueError(f"Invalid prefix: expected '{TOPIC_PREFIX}', got '{prefix}'")

        if encoding != ENCODING_POSTFIX:
            raise ValueError(f"Invalid encoding: expected '{ENCODING_POSTFIX}', got '{encoding}'")

        # Handle attestation subnet topics which have format attestation_N
        if topic_name.startswith("attestation_"):
            try:
                # Validate the subnet ID is a valid integer
                subnet_part = topic_name[len("attestation_") :]
                subnet_id = SubnetId(int(subnet_part))
                return cls(
                    kind=TopicKind.ATTESTATION_SUBNET,
                    network_name=network_name,
                    subnet_id=subnet_id,
                )
            except ValueError:
                pass  # Fall through to the normal TopicKind parsing

        try:
            kind = TopicKind(topic_name)
        except ValueError:
            raise ValueError(f"Unknown topic: '{topic_name}'") from None

        return cls(kind=kind, network_name=network_name)

    @classmethod
    def from_string_validated(cls, topic_str: str, expected_network_name: str) -> GossipTopic:
        """Parse a topic string and validate fork compatibility.

        Combines parsing and fork validation into a single operation.
        Use this when receiving gossip messages to reject wrong-fork topics early.

        Args:
            topic_str: Full topic string to parse.
            expected_network_name: Expected network name (hex string (no 0x prefix)).

        Returns:
            Parsed GossipTopic instance.

        Raises:
            ValueError: If the topic string is malformed.
            ForkMismatchError: If network_name does not match expected.
        """
        topic = cls.from_string(topic_str)
        topic.validate_fork(expected_network_name)
        return topic

    @classmethod
    def block(cls, network_name: str) -> GossipTopic:
        """Create a block topic for the given fork.

        Args:
            network_name: Network name as hex string (no 0x prefix) string.

        Returns:
            GossipTopic for block messages.
        """
        return cls(kind=TopicKind.BLOCK, network_name=network_name)

    @classmethod
    def committee_aggregation(cls, network_name: str) -> GossipTopic:
        """Create a committee aggregation topic for the given fork.

        Args:
            network_name: Network name as hex string (no 0x prefix) string.

        Returns:
            GossipTopic for committee aggregation messages.
        """
        return cls(kind=TopicKind.AGGREGATED_ATTESTATION, network_name=network_name)

    @classmethod
    def attestation_subnet(cls, network_name: str, subnet_id: SubnetId) -> GossipTopic:
        """Create an attestation subnet topic for the given fork and subnet.

        Args:
            network_name: Network name as hex string (no 0x prefix) string.
            subnet_id: Subnet ID for the attestation topic.

        Returns:
            GossipTopic for attestation subnet messages.
        """
        return cls(
            kind=TopicKind.ATTESTATION_SUBNET, network_name=network_name, subnet_id=subnet_id
        )


def parse_topic_string(topic_str: str) -> tuple[str, str, str, str]:
    """Parse a topic string into its components.

    Low-level function for deconstructing topic strings.
    Prefer the dataclass parser for most use cases.

    Args:
        topic_str: Topic string to parse.

    Returns:
        Tuple of (prefix, network_name, topic_name, encoding).

    Raises:
        ValueError: If the topic string is malformed.
    """
    parts = topic_str.lstrip("/").split("/")

    if len(parts) != 4:
        raise ValueError(f"Invalid topic format: expected 4 parts, got {len(parts)}")

    return (parts[0], parts[1], parts[2], parts[3])
