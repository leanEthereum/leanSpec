"""
Gossipsub protocol

- Message ID computation based on topic and message data, with snappy decompression handling.
"""

import hashlib
from typing import Annotated, Callable, Optional

from pydantic import Field

from lean_spec.subspecs.networking.config import (
    MESSAGE_DOMAIN_INVALID_SNAPPY,
    MESSAGE_DOMAIN_VALID_SNAPPY,
)

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
        # Cache for the computed ID
        self._id: Optional[MessageId] = None

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
