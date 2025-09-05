"""Hash Type Specification."""

from pydantic import Field
from typing_extensions import Annotated

Bytes32 = Annotated[
    bytes,
    Field(
        min_length=32,
        max_length=32,
        description="A 32-byte hash.",
    ),
]
"""
A type alias for a 32-byte value, commonly used for hashes and roots.
"""
