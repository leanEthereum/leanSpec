"""
Gossipsub protocol

- Parameters for gossipsub operation.
- Message ID computation based on topic and message data, with snappy decompression handling.
"""

import hashlib
from typing import Annotated, Callable, Optional

from pydantic import Field

from lean_spec.subspecs.chain.config import DEVNET_CONFIG
from lean_spec.subspecs.networking.config import (
    MESSAGE_DOMAIN_INVALID_SNAPPY,
    MESSAGE_DOMAIN_VALID_SNAPPY,
)
from lean_spec.types import StrictBaseModel


class GossipsubParameters(StrictBaseModel):
    """A model holding the canonical gossipsub parameters."""

    protocol_id: str = "/meshsub/1.0.0"
    """The protocol ID for gossip messages."""

    d: int = 8
    """The target number of peers for a stable gossip mesh topic."""

    d_low: int = 6
    """
    The low watermark for the number of peers in a stable gossip mesh topic.
    """

    d_high: int = 12
    """
    The high watermark for the number of peers in a stable gossip mesh topic.
    """

    d_lazy: int = 6
    """The target number of peers for gossip-only connections."""

    heartbeat_interval_secs: float = 0.7
    """The frequency of the gossipsub heartbeat in seconds."""

    fanout_ttl_secs: int = 60
    """The time-to-live for fanout maps in seconds."""

    mcache_len: int = 6
    """The number of history windows to retain full messages in the cache."""

    mcache_gossip: int = 3
    """The number of history windows to gossip about."""

    seen_ttl_secs: int = (
        DEVNET_CONFIG.second_per_slot.as_int()
        * DEVNET_CONFIG.justification_lookback_slots.as_int()
        * 2
    )
    """
    The expiry time in seconds for the cache of seen message IDs.

    This is calculated as SECONDS_PER_SLOT * JUSTIFICATION_LOOKBACK_SLOTS * 2.
    """


MessageId = Annotated[bytes, Field(min_length=20, max_length=20)]
"""A 20-byte ID for gossipsub messages."""


class GossipsubMessage:
    """
    Represents a gossipsub message and manages its ID computation.

    This class encapsulates the topic, data, and the logic to generate a
    message ID, correctly handling snappy decompression. The generated ID is
    cached for efficiency.
    """

    def __init__(
        self,
        topic: bytes,
        data: bytes,
        snappy_decompress: Optional[Callable[[bytes], bytes]] = None,
    ):
        """
        Initializes the message.

        Args:
            topic: The topic byte string.
            data: The raw message data.
            snappy_decompress: Optional snappy decompression function.
        """
        self.topic: bytes = topic
        self.raw_data: bytes = data
        self._snappy_decompress = snappy_decompress
        self._id: Optional[MessageId] = None  # Cache for the computed ID

    @property
    def id(self) -> MessageId:
        """
        Computes and returns the 20-byte message ID.

        The ID is computed on first access and then cached. The computation
        logic depends on whether the message data can be successfully
        decompressed with snappy.
        """
        # Return the cached ID if it's already been computed
        if self._id is not None:
            return self._id

        # Determine domain and data based on snappy decompression
        if self._snappy_decompress:
            try:
                # Try to decompress the data with snappy
                decompressed_data = self._snappy_decompress(self.raw_data)
                # Valid snappy decompression - use valid domain
                domain, data_for_hash = (
                    MESSAGE_DOMAIN_VALID_SNAPPY,
                    decompressed_data,
                )
            except Exception:
                # Invalid snappy decompression - use invalid domain
                domain, data_for_hash = (
                    MESSAGE_DOMAIN_INVALID_SNAPPY,
                    self.raw_data,
                )
        else:
            # No decompressor provided - use invalid domain
            domain, data_for_hash = (
                MESSAGE_DOMAIN_INVALID_SNAPPY,
                self.raw_data,
            )

        # Compute the raw ID bytes and cast to our strict type before caching
        self._id = MessageId(self._compute_raw_id(domain, data_for_hash))
        return self._id

    def _compute_raw_id(self, domain: bytes, message_data: bytes) -> bytes:
        """
        Computes SHA256(domain + uint64_le(len(topic)) + topic + message_data)[:20].

        Args:
            domain: The 4-byte domain for message-id isolation.
            message_data: The message data (either decompressed or raw).

        Returns:
            A 20-byte raw bytes digest.
        """
        # Concatenate all components: domain + topic_len + topic + data
        data_to_hash = domain + len(self.topic).to_bytes(8, "little") + self.topic + message_data
        # Compute SHA256 and take the first 20 bytes
        return hashlib.sha256(data_to_hash).digest()[:20]
