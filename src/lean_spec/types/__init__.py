"""Reusable type definitions for the Lean Ethereum specification."""

from .base import CamelModel, StrictBaseModel
from .basispt import BasisPoint
from .boolean import Boolean
from .byte_arrays import Bytes32, Bytes52, Bytes3116
from .collections import SSZList, SSZVector
from .container import Container
from .uint import Uint64
from .validator import ValidatorIndex, is_proposer

__all__ = [
    "Uint64",
    "BasisPoint",
    "Bytes32",
    "Bytes52",
    "Bytes3116",
    "CamelModel",
    "StrictBaseModel",
    "ValidatorIndex",
    "is_proposer",
    "SSZList",
    "SSZVector",
    "Boolean",
    "Container",
]
