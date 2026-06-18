"""Fork-choice store: the node's local view of the chain."""

from typing import NamedTuple

from pydantic import Field

from lean_spec.base import StrictBaseModel
from lean_spec.spec.crypto.xmss.containers import Signature
from lean_spec.spec.forks.lstar.containers.aggregation import SingleMessageAggregate
from lean_spec.spec.forks.lstar.containers.checkpoint import AttestationData, Checkpoint
from lean_spec.spec.forks.lstar.containers.genesis import GenesisConfig
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex
from lean_spec.spec.forks.lstar.containers.interval import Interval
from lean_spec.spec.ssz import Bytes32, Container


class AttestationSignatureEntry(NamedTuple):
    """One validator paired with its signature for an attestation."""

    validator_index: ValidatorIndex
    """Index of the validator that produced the signature."""

    signature: Signature
    """Signature over the attestation."""


class Store[StateT: Container, BlockT: Container](StrictBaseModel):
    """A node's local view of the chain for running fork choice."""

    time: Interval
    """Current time in intervals since genesis."""

    config: GenesisConfig
    """Chain configuration parameters."""

    head: Bytes32
    """Root of the head block that fork choice currently selects."""

    safe_target: Bytes32
    """Root of the block a validator is safe to attest to."""

    latest_justified: Checkpoint
    """Highest-slot justified checkpoint observed so far."""

    latest_finalized: Checkpoint
    """
    Finalization as seen from the canonical head, not irreversible economic finality.

    This tracks the head chain's view and is reorg-mutable.
    A reorg onto a fork that finalized a lower slot lowers this value.
    """

    blocks: dict[Bytes32, BlockT] = Field(default_factory=dict)
    """
    Known blocks indexed by their root.

    Every block eligible to participate in fork choice appears here.
    """

    states: dict[Bytes32, StateT] = Field(default_factory=dict)
    """Post-state of each known block, indexed by block root."""

    validator_index: ValidatorIndex | None
    """Index of the validator that owns this view, or none for an observer."""

    attestation_signatures: dict[AttestationData, set[AttestationSignatureEntry]] = Field(
        default_factory=dict
    )
    """Per-validator signatures observed, grouped by the vote they sign."""

    latest_new_aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] = Field(
        default_factory=dict
    )
    """Pending single-message proofs awaiting promotion, grouped by the vote they support."""

    latest_known_aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] = Field(
        default_factory=dict
    )
    """Single-message proofs counted toward fork choice, grouped by the vote they support."""
