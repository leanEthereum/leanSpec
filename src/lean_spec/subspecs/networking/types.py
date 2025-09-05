"""Networking-related type definitions for the specification."""

from typing import Annotated

from pydantic import Field

DomainType = Annotated[bytes, Field(min_length=4, max_length=4)]
"""A 4-byte value used for domain separation in message-ids."""

ProtocolId = str
"""A string representing a libp2p protocol ID."""
