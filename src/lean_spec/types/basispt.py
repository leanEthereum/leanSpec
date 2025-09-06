"""Basis Point Type Specification."""

from pydantic import Field
from typing_extensions import Annotated

from .uint import Uint64

BasisPoint = Annotated[
    Uint64,
    Field(le=Uint64(10000), description="A value in basis points (1/10000)."),
]
"""
A type alias for basis points.

A basis point (bps) is 1/100th of a percent. 100% = 10,000 bps.
"""
