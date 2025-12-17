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
    NaiveAggregatedSignature,
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
from .state import State
from .validator import Validator

__all__ = [
    "AggregatedAttestation",
    "NaiveAggregatedSignature",
    "AggregationBits",
    "AttestationData",
    "Attestation",
    "SignedAttestation",
    "SignedAggregatedAttestation",
    "Block",
    "BlockWithAttestation",
    "BlockBody",
    "BlockHeader",
    "Checkpoint",
    "Config",
    "SignedBlockWithAttestation",
    "Validator",
    "State",
]
