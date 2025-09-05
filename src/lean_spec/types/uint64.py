"""Unsigned 64-bit Integer Type Specification."""

from pydantic import Field
from typing_extensions import Annotated

UINT64_MAX = 2**64
"""The maximum value for an unsigned 64-bit integer (2**64)."""

Uint64 = Annotated[int, Field(ge=0, lt=UINT64_MAX)]
"""A type alias to represent a uint64."""
