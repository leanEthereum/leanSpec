"""Multi-fork dispatch layer for leanSpec consensus specification."""

from .lstar.containers import (
    IMMEDIATE_JUSTIFICATION_WINDOW,
    VALIDATOR_REGISTRY_LIMIT,
    AggregatedAttestation,
    AggregatedAttestations,
    AggregationBits,
    Attestation,
    AttestationData,
    AttestationSignatureEntry,
    Block,
    BlockBody,
    BlockHeader,
    Checkpoint,
    Config,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    Slot,
    State,
    SubnetId,
    Validator,
    ValidatorIndex,
    ValidatorIndices,
    Validators,
)
from .lstar.spec import LstarSpec, LstarStore
from .protocol import ForkProtocol, SpecStateType, SpecStoreType
from .registry import ForkRegistry

Store = LstarStore
"""Public alias resolving to the concrete LstarStore until other forks land."""

FORK_SEQUENCE: list[ForkProtocol] = [LstarSpec()]
"""Ordered oldest to newest. ForkRegistry enforces strictly increasing VERSION."""

DEFAULT_REGISTRY: ForkRegistry = ForkRegistry(FORK_SEQUENCE)
"""Shared registry over the registered forks. Convenient for top-level callers."""

__all__ = [
    "AggregatedAttestation",
    "AggregatedAttestations",
    "AggregationBits",
    "Attestation",
    "AttestationData",
    "AttestationSignatureEntry",
    "Block",
    "BlockBody",
    "BlockHeader",
    "Checkpoint",
    "Config",
    "DEFAULT_REGISTRY",
    "FORK_SEQUENCE",
    "ForkProtocol",
    "ForkRegistry",
    "IMMEDIATE_JUSTIFICATION_WINDOW",
    "LstarSpec",
    "LstarStore",
    "SignedAggregatedAttestation",
    "SignedAttestation",
    "SignedBlock",
    "Slot",
    "SpecStateType",
    "SpecStoreType",
    "State",
    "Store",
    "SubnetId",
    "VALIDATOR_REGISTRY_LIMIT",
    "Validator",
    "ValidatorIndex",
    "ValidatorIndices",
    "Validators",
]
