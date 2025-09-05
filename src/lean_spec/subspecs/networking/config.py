"""Networking Configuration Constants."""

from typing_extensions import Final

from .types import DomainType

MAX_REQUEST_BLOCKS: Final = 2**10
"""Maximum number of blocks in a single request."""

MESSAGE_DOMAIN_INVALID_SNAPPY: Final = DomainType(b"\x00\x00\x00\x00")
"""4-byte domain for gossip message-id isolation of invalid snappy messages."""

MESSAGE_DOMAIN_VALID_SNAPPY: Final = DomainType(b"\x01\x00\x00\x00")
"""4-byte domain for gossip message-id isolation of valid snappy messages."""
