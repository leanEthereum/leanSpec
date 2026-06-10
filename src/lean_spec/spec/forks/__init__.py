"""Multi-fork dispatch layer for leanSpec consensus specification."""

from lean_spec.spec.forks.lstar.containers import (
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
    GenesisConfig,
    Interval,
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
from lean_spec.spec.forks.lstar.errors import RejectionReason, SpecRejectionError
from lean_spec.spec.forks.lstar.spec import LstarSpec, LstarStore
from lean_spec.spec.forks.protocol import ForkProtocol
from lean_spec.spec.forks.registry import ForkRegistry

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
    "DEFAULT_REGISTRY",
    "FORK_SEQUENCE",
    "ForkProtocol",
    "ForkRegistry",
    "GenesisConfig",
    "IMMEDIATE_JUSTIFICATION_WINDOW",
    "Interval",
    "LstarSpec",
    "LstarStore",
    "RejectionReason",
    "SpecRejectionError",
    "SignedAggregatedAttestation",
    "SignedAttestation",
    "SignedBlock",
    "Slot",
    "State",
    "Store",
    "SubnetId",
    "VALIDATOR_REGISTRY_LIMIT",
    "Validator",
    "ValidatorIndex",
    "ValidatorIndices",
    "Validators",
]
