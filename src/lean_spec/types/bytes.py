"""This defines all Byte types used."""

from pydantic import Field
from typing_extensions import Annotated

Bytes1 = Annotated[
    bytes,
    Field(
        min_length=1,
        max_length=1,
        description="A Byte1 type.",
    ),
]
"""
A type alias for a 1 byte value.
"""
