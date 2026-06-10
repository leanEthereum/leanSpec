"""
Container types for the Lean consensus specification.

This package is the public container surface for the lstar fork.
The types are split across submodules by domain role:

- interval, identifiers, participation: scalar units and registry index sets
- aggregation: post-quantum signature aggregation proofs
- genesis: chain configuration committed into the state
- validator: the validator registry
- checkpoint: Casper-FFG checkpoints and the attestation vote they anchor
- attestation, block: vote envelopes and the blocks that carry them
- state, store: per-block consensus state and the node's fork-choice view
"""

from lean_spec.spec.forks.lstar.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.spec.forks.lstar.containers.aggregation import (
    AggregationError,
    MultiMessageAggregate,
    SingleMessageAggregate,
)
from lean_spec.spec.forks.lstar.containers.attestation import (
    AggregatedAttestation,
    AggregatedAttestations,
    Attestation,
    SignedAggregatedAttestation,
    SignedAttestation,
)
from lean_spec.spec.forks.lstar.containers.block import (
    Block,
    BlockBody,
    BlockHeader,
    SignedBlock,
)
from lean_spec.spec.forks.lstar.containers.checkpoint import AttestationData, Checkpoint
from lean_spec.spec.forks.lstar.containers.genesis import GenesisConfig
from lean_spec.spec.forks.lstar.containers.identifiers import (
    SubnetId,
    ValidatorIndex,
    ValidatorIndices,
)
from lean_spec.spec.forks.lstar.containers.interval import Interval
from lean_spec.spec.forks.lstar.containers.participation import AggregationBits
from lean_spec.spec.forks.lstar.containers.state import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    State,
)
from lean_spec.spec.forks.lstar.containers.store import AttestationSignatureEntry, Store
from lean_spec.spec.forks.lstar.containers.validator import (
    Validator,
    Validators,
)
from lean_spec.spec.forks.lstar.slot import IMMEDIATE_JUSTIFICATION_WINDOW, Slot

__all__ = [
    "IMMEDIATE_JUSTIFICATION_WINDOW",
    "VALIDATOR_REGISTRY_LIMIT",
    "AggregatedAttestation",
    "AggregatedAttestations",
    "AggregationBits",
    "AggregationError",
    "Attestation",
    "AttestationData",
    "AttestationSignatureEntry",
    "Block",
    "BlockBody",
    "BlockHeader",
    "Checkpoint",
    "GenesisConfig",
    "HistoricalBlockHashes",
    "Interval",
    "JustificationRoots",
    "JustificationValidators",
    "JustifiedSlots",
    "MultiMessageAggregate",
    "SignedAggregatedAttestation",
    "SignedAttestation",
    "SignedBlock",
    "SingleMessageAggregate",
    "Slot",
    "State",
    "Store",
    "SubnetId",
    "Validator",
    "ValidatorIndex",
    "ValidatorIndices",
    "Validators",
]
