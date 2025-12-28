"""State-specific SSZ types for the Lean Ethereum consensus specification."""

from __future__ import annotations

from typing import TYPE_CHECKING

from lean_spec.subspecs.chain.config import DEVNET_CONFIG
from lean_spec.subspecs.xmss.aggregation import MultisigAggregatedSignature
from lean_spec.types import Bytes32, SSZList, Uint64
from lean_spec.types.bitfields import BaseBitlist

from ..attestation import AggregationBits, AttestationData
from ..block import Block
from ..validator import Validator

if TYPE_CHECKING:
    from .state import State

# Type aliases for signature aggregation
AttestationSignatureKey = tuple[Uint64, bytes]
"""Key type for looking up signatures: (validator_id, attestation_data_root)."""

AggregatedSignaturePayload = tuple[AggregationBits, MultisigAggregatedSignature]
"""Aggregated signature payload with its participant bitlist."""

AggregatedSignaturePayloads = list[AggregatedSignaturePayload]
"""List of aggregated signature payloads with their participant bitlists."""

BlockLookup = dict[Bytes32, Block]
"""Mapping from block root to Block objects."""

StateLookup = dict[Bytes32, "State"]
"""Mapping from state root to State objects."""

AttestationsByValidator = dict[Uint64, AttestationData]
"""Mapping from validator index to attestation data."""


class HistoricalBlockHashes(SSZList[Bytes32]):
    """List of historical block root hashes up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = int(DEVNET_CONFIG.historical_roots_limit)


class JustificationRoots(SSZList[Bytes32]):
    """List of justified block roots up to historical_roots_limit."""

    ELEMENT_TYPE = Bytes32
    LIMIT = int(DEVNET_CONFIG.historical_roots_limit)


class JustifiedSlots(BaseBitlist):
    """Bitlist tracking justified slots up to historical roots limit."""

    LIMIT = int(DEVNET_CONFIG.historical_roots_limit)


class JustificationValidators(BaseBitlist):
    """Bitlist for tracking validator justifications per historical root."""

    LIMIT = int(DEVNET_CONFIG.historical_roots_limit) * int(DEVNET_CONFIG.validator_registry_limit)


class Validators(SSZList[Validator]):
    """Validator registry tracked in the state."""

    ELEMENT_TYPE = Validator
    LIMIT = int(DEVNET_CONFIG.validator_registry_limit)
