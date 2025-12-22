"""Reusable type definitions for the Lean Ethereum specification."""

from .base import CamelModel, StrictBaseModel
from .basispt import BasisPoint
from .boolean import Boolean
from .byte_arrays import ZERO_HASH, Bytes32, Bytes52, Bytes3116
from .collections import SSZList, SSZVector
from .container import Container
from .exceptions import (
    SSZError,
    SSZSerializationError,
    SSZTypeError,
    SSZValueError,
)
from .ssz_base import SSZType
from .uint import Uint64
from .validator import is_proposer

__all__ = [
    # Core types
    "Uint64",
    "BasisPoint",
    "Bytes32",
    "Bytes52",
    "Bytes3116",
    "ZERO_HASH",
    "CamelModel",
    "StrictBaseModel",
    "is_proposer",
    "SSZList",
    "SSZVector",
    "SSZType",
    "Boolean",
    "Container",
    # Exceptions
    "SSZError",
    "SSZTypeError",
    "SSZValueError",
    "SSZSerializationError",
]
