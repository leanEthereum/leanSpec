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

- `0x01000000` (VALID_SNAPPY): Snappy decompression succeeded, use decompressed data
- `0x00000000` (INVALID_SNAPPY): Decompression failed or no decompressor, use raw data

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
from dataclasses import dataclass, field

from lean_spec.subspecs.networking.config import MESSAGE_DOMAIN_INVALID_SNAPPY

from .types import MessageId


@dataclass(slots=True)
class GossipsubMessage:
    r"""A gossipsub message with lazy ID computation.

    Encapsulates topic, payload, and message ID logic. The ID is
    computed lazily on first access and cached thereafter.

    Message ID Computation
    ----------------------

    The 20-byte ID is computed as::

        SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]

    Where `domain` is 0x01 for valid-snappy and 0x00 otherwise.
    """

    topic: bytes
    """Topic string as UTF-8 encoded bytes."""

    raw_data: bytes
    """Raw message payload.

    Typically snappy-compressed SSZ data. The actual content
    depends on the topic (block, attestation, etc.).
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
            self._cached_id = self.compute_id(self.topic, self.raw_data)
        return self._cached_id

    @staticmethod
    def compute_id(
        topic: bytes,
        data: bytes,
        *,
        domain: bytes | None = None,
    ) -> MessageId:
        """Compute a 20-byte message ID from raw data.

        Implements the Ethereum consensus message ID function::

            SHA256(domain + uint64_le(len(topic)) + topic + data)[:20]

        Args:
            topic: Topic string as bytes.
            data: Message payload. Callers that have already decompressed
                the payload must pass the explicit `domain` so the hash
                uses the correct domain separator.
            domain: Explicit domain bytes. Defaults to the invalid-snappy
                domain when omitted; callers handling decompression must
                pass the valid-snappy domain explicitly.

        Returns:
            20-byte message ID.
        """
        if domain is None:
            domain = MESSAGE_DOMAIN_INVALID_SNAPPY

        preimage = bytes(domain) + len(topic).to_bytes(8, "little") + topic + data

        return MessageId(hashlib.sha256(preimage).digest()[:20])

    def __hash__(self) -> int:
        """Hash based on message ID.

        Allows messages to be used in sets and as dict keys.
        """
        return hash(self.id)
