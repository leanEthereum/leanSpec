"""
The container types for the Lean consensus specification.

All containers use SSZ encoding. SSZ provides deterministic serialization and
efficient merkleization.

Hash functions used for merkleization differ by devnet. Early devnets use
SHA256. Later devnets will switch to Poseidon2 for better SNARK compatibility.
"""

from .attestation import (
    AggregatedAttestation,
    AggregationBits,
    Attestation,
    AttestationData,
    SignedAggregatedAttestation,
    SignedAttestation,
)
from .block import (
    Block,
    BlockBody,
    BlockHeader,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from .checkpoint import Checkpoint
from .config import Config
from .slot import Slot
from .state import State
from .validator import Validator, ValidatorIndex, ValidatorIndices

__all__ = [
    "AggregatedAttestation",
    "AggregationBits",
    "Attestation",
    "AttestationData",
    "Block",
    "BlockBody",
    "BlockHeader",
    "BlockWithAttestation",
    "Checkpoint",
    "Config",
    "SignedAggregatedAttestation",
    "SignedAttestation",
    "SignedBlockWithAttestation",
    "Slot",
    "State",
    "Validator",
    "ValidatorIndex",
    "ValidatorIndices",
]
