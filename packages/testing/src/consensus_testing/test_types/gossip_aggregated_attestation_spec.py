"""Lightweight aggregated-gossip attestation specification."""

from __future__ import annotations

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Bytes32, CamelModel


class GossipAggregatedAttestationSpec(CamelModel):
    """
    Specification for an aggregated attestation received via gossip.

    The spec allows overriding head/source checkpoints to exercise validation logic.
    """

    validator_ids: list[ValidatorIndex]
    """Claimed validators participating in the aggregation."""

    slot: Slot
    """Slot of the attestation."""

    target_slot: Slot
    """Slot of the attestation target checkpoint."""

    target_root_label: str | None = None
    """Label referencing the target block root."""

    target_root: Bytes32 | None = None
    """Optional explicit target root (bypasses label lookup)."""

    head_root_label: str | None = None
    """Optional label for the head checkpoint."""

    head_root: Bytes32 | None = None
    """Optional explicit head root."""

    head_slot: Slot | None = None
    """Optional override for the head checkpoint slot."""

    source_root_label: str | None = None
    """Optional label for the source checkpoint."""

    source_root: Bytes32 | None = None
    """Optional explicit source root."""

    source_slot: Slot | None = None
    """Optional override for the source checkpoint slot."""

    valid_signature: bool = True
    """Whether the aggregated proof should be generated with valid signatures."""

    signer_ids: list[ValidatorIndex] | None = None
    """Optional override for which validators actually produce the signatures."""
