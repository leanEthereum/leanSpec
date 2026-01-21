"""Reusable type definitions for the Lean Ethereum specification."""

from .base import CamelModel, StrictBaseModel
from .basispt import BasisPoint
from .bitfields import BaseBitlist
from .boolean import Boolean
from .byte_arrays import ZERO_HASH, Bytes12, Bytes16, Bytes20, Bytes32, Bytes52
from .collections import SSZList, SSZVector
from .container import Container
from .exceptions import (
    SSZError,
    SSZSerializationError,
    SSZTypeError,
    SSZValueError,
)
from .rlp import RLPDecodingError, RLPItem
from .rlp import decode as rlp_decode
from .rlp import encode as rlp_encode
from .ssz_base import SSZType
from .uint import Uint64
from .validator import is_proposer

__all__ = [
    # Core types
    "BaseBitlist",
    "Uint64",
    "BasisPoint",
    "Bytes12",
    "Bytes16",
    "Bytes20",
    "Bytes32",
    "Bytes52",
    "ZERO_HASH",
    "CamelModel",
    "StrictBaseModel",
    "is_proposer",
    "SSZList",
    "SSZVector",
    "SSZType",
    "Boolean",
    "Container",
    # RLP encoding/decoding
    "rlp_encode",
    "rlp_decode",
    "RLPItem",
    "RLPDecodingError",
    # Exceptions
    "SSZError",
    "SSZTypeError",
    "SSZValueError",
    "SSZSerializationError",
]
