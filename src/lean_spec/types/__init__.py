"""Reusable type definitions for the Lean Ethereum specification."""

from .base import CamelModel, StrictBaseModel
from .bitfields import BaseBitlist, BaseBitvector
from .boolean import Boolean
from .byte_arrays import (
    ZERO_HASH,
    BaseByteList,
    BaseBytes,
    ByteListMiB,
    Bytes1,
    Bytes4,
    Bytes12,
    Bytes16,
    Bytes20,
    Bytes32,
    Bytes33,
    Bytes52,
    Bytes64,
    Bytes65,
)
from .collections import SSZList, SSZVector
from .container import Container
from .exceptions import (
    SSZError,
    SSZSerializationError,
    SSZTypeError,
    SSZValueError,
)
from .rlp import RLPDecodingError, RLPItem, decode_rlp, decode_rlp_list, encode_rlp
from .ssz_base import SSZType
from .uint import Uint8, Uint16, Uint32, Uint64
from .union import SSZUnion

__all__ = [
    # Core types
    "BaseBitlist",
    "BaseBitvector",
    "Uint8",
    "Uint16",
    "Uint32",
    "Uint64",
    "BaseBytes",
    "BaseByteList",
    "Bytes1",
    "Bytes4",
    "Bytes12",
    "Bytes16",
    "Bytes20",
    "Bytes32",
    "Bytes33",
    "Bytes52",
    "Bytes64",
    "Bytes65",
    "ByteListMiB",
    "ZERO_HASH",
    "CamelModel",
    "StrictBaseModel",
    "SSZList",
    "SSZVector",
    "SSZType",
    "SSZUnion",
    "Boolean",
    "Container",
    # RLP encoding/decoding
    "encode_rlp",
    "decode_rlp",
    "decode_rlp_list",
    "RLPItem",
    "RLPDecodingError",
    # Exceptions
    "SSZError",
    "SSZTypeError",
    "SSZValueError",
    "SSZSerializationError",
]
