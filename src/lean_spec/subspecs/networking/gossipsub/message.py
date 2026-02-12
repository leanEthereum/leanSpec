"""
Gossipsub Message
=================

Message representation and ID computation for the gossipsub protocol.

Overview
--------

Each gossipsub message carries a topic and payload. Messages are
identified by a 20-byte ID computed from their contents.

Message ID Function
-------------------

Ethereum consensus uses a custom message ID function based on SHA256::

    message_id = SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]

**Components:**

+-----------------+--------------------------------------------------------+
| Component       | Description                                            |
+=================+========================================================+
| domain          | 1-byte prefix indicating snappy validity (0x00/0x01)   |
+-----------------+--------------------------------------------------------+
| uint64_le       | Topic length as 8-byte little-endian integer           |
+-----------------+--------------------------------------------------------+
| topic           | Topic string as UTF-8 bytes                            |
+-----------------+--------------------------------------------------------+
| data            | Message payload (decompressed if snappy is valid)      |
+-----------------+--------------------------------------------------------+

**Domain Bytes:**

- ``0x01`` (VALID_SNAPPY): Snappy decompression succeeded, use decompressed data
- ``0x00`` (INVALID_SNAPPY): Decompression failed or no decompressor, use raw data

This ensures messages with compression issues get different IDs,
preventing cache pollution from invalid variants.

Snappy Compression
------------------

Ethereum consensus requires SSZ data to be snappy-compressed.
The message ID computation attempts decompression to determine
which domain byte to use.

References:
----------
- `Ethereum P2P spec <https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/p2p-interface.md>`_
- `Gossipsub v1.0 <https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md>`_
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from lean_spec.subspecs.networking.config import (
    MESSAGE_DOMAIN_INVALID_SNAPPY,
    MESSAGE_DOMAIN_VALID_SNAPPY,
)
from lean_spec.types import Bytes20

from .types import MessageId

SnappyDecompressor = Callable[[bytes], bytes]
"""Callable that decompresses snappy-compressed data.

Should raise an exception if decompression fails.
"""


@dataclass(slots=True)
class GossipsubMessage:
    r"""A gossipsub message with lazy ID computation.

    Encapsulates topic, payload, and message ID logic. The ID is
    computed lazily on first access and cached thereafter.

    Message ID Computation
    ----------------------

    The 20-byte ID is computed as::

        SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]

    Where `domain` depends on snappy decompression success.
    """

    topic: bytes
    """Topic string as UTF-8 encoded bytes."""

    raw_data: bytes
    """Raw message payload.

    Typically snappy-compressed SSZ data. The actual content
    depends on the topic (block, attestation, etc.).
    """

    snappy_decompress: SnappyDecompressor | None = field(default=None, repr=False)
    """Optional snappy decompression function.

    If provided, decompression is attempted during ID computation
    to determine the domain byte. Pass `snappy.decompress` from
    the python-snappy library, or any compatible callable.
    """

    _cached_id: MessageId | None = field(
        default=None, init=False, repr=False, compare=False, hash=False
    )
    """Cached message ID.

    Computed lazily on first access to `id` property. Once computed,
    the same ID is returned for all subsequent accesses.
    """

    @property
    def id(self) -> MessageId:
        """Get the 20-byte message ID.

        Computed lazily on first access using the Ethereum consensus
        message ID function. The result is cached.

        Returns:
            20-byte message ID (Bytes20).
        """
        if self._cached_id is None:
            self._cached_id = self.compute_id(self.topic, self.raw_data, self.snappy_decompress)
        return self._cached_id

    @staticmethod
    def compute_id(
        topic: bytes,
        data: bytes,
        snappy_decompress: SnappyDecompressor | None = None,
    ) -> MessageId:
        """Compute a 20-byte message ID from raw data.

        Implements the Ethereum consensus message ID function::

            SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]

        Domain Selection
        ----------------

        - If `snappy_decompress` is provided and succeeds:
            domain = 0x01, use decompressed data
        - Otherwise:
            domain = 0x00, use raw data

        Args:
            topic: Topic string as bytes.
            data: Message payload (potentially compressed).
            snappy_decompress: Optional decompression function.

        Returns:
            20-byte message ID.
        """
        if snappy_decompress is not None:
            try:
                data_for_hash = snappy_decompress(data)
                domain = MESSAGE_DOMAIN_VALID_SNAPPY
            except Exception:
                data_for_hash = data
                domain = MESSAGE_DOMAIN_INVALID_SNAPPY
        else:
            data_for_hash = data
            domain = MESSAGE_DOMAIN_INVALID_SNAPPY

        preimage = bytes(domain) + len(topic).to_bytes(8, "little") + topic + data_for_hash

        return Bytes20(hashlib.sha256(preimage).digest()[:20])

    @property
    def topic_str(self) -> str:
        """Get the topic as a UTF-8 string.

        Returns:
            Topic decoded from bytes to string.
        """
        return self.topic.decode("utf-8")

    def __hash__(self) -> int:
        """Hash based on message ID.

        Allows messages to be used in sets and as dict keys.
        """
        return hash(self.id)
