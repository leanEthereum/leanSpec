"""Gossip aggregated attestation validation vectors."""

import pytest
from consensus_testing import (
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    StoreChecks,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Bytes32

pytestmark = pytest.mark.valid_until("Devnet")


def _base_blocks() -> list[BlockStep]:
    return [
        BlockStep(
            block=BlockSpec(slot=Slot(1), label="block_1"),
            checks=StoreChecks(head_slot=Slot(1)),
        ),
        BlockStep(
            block=BlockSpec(slot=Slot(2), label="block_2"),
            checks=StoreChecks(head_slot=Slot(2)),
        ),
    ]


def test_valid_gossip_aggregated_attestation(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """A valid aggregated gossip attestation is accepted."""
    steps = [
        *_base_blocks(),
        GossipAggregatedAttestationStep(
            attestation=GossipAggregatedAttestationSpec(
                validator_ids=[ValidatorIndex(1)],
                slot=Slot(2),
                target_slot=Slot(2),
                target_root_label="block_2",
            ),
            checks=StoreChecks(head_slot=Slot(2)),
        ),
    ]

    fork_choice_test(steps=steps)


def test_aggregated_attestation_unknown_source_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Aggregated attestation referencing unknown source is rejected."""
    steps = [
        *_base_blocks(),
        GossipAggregatedAttestationStep(
            attestation=GossipAggregatedAttestationSpec(
                validator_ids=[ValidatorIndex(1)],
                slot=Slot(2),
                target_slot=Slot(2),
                target_root_label="block_2",
                source_root=Bytes32(b"\xff" * 32),
                source_slot=Slot(999),
            ),
            valid=False,
        ),
    ]

    fork_choice_test(steps=steps)


def test_aggregated_attestation_target_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Aggregated attestation with wrong target slot is rejected."""
    steps = [
        *_base_blocks(),
        GossipAggregatedAttestationStep(
            attestation=GossipAggregatedAttestationSpec(
                validator_ids=[ValidatorIndex(1)],
                slot=Slot(2),
                target_slot=Slot(3),
                target_root_label="block_2",
            ),
            valid=False,
        ),
    ]

    fork_choice_test(steps=steps)


def test_aggregated_attestation_head_slot_mismatch_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Head checkpoint slot mismatches are rejected."""
    steps = [
        *_base_blocks(),
        GossipAggregatedAttestationStep(
            attestation=GossipAggregatedAttestationSpec(
                validator_ids=[ValidatorIndex(1)],
                slot=Slot(2),
                target_slot=Slot(2),
                target_root_label="block_2",
                head_root_label="block_1",
                head_slot=Slot(1),
            ),
            valid=False,
        ),
    ]

    fork_choice_test(steps=steps)


def test_aggregated_attestation_source_after_target_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Topology violations (source > target) are rejected."""
    steps = [
        *_base_blocks(),
        BlockStep(
            block=BlockSpec(slot=Slot(3), label="block_3"),
            checks=StoreChecks(head_slot=Slot(3)),
        ),
        GossipAggregatedAttestationStep(
            attestation=GossipAggregatedAttestationSpec(
                validator_ids=[ValidatorIndex(1)],
                slot=Slot(3),
                target_slot=Slot(2),
                target_root_label="block_2",
                source_root_label="block_3",
                source_slot=Slot(3),
            ),
            valid=False,
        ),
    ]

    fork_choice_test(steps=steps)


def test_aggregated_attestation_too_far_in_future_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Attestations that are too far in the future are rejected."""
    steps = [
        *_base_blocks(),
        GossipAggregatedAttestationStep(
            attestation=GossipAggregatedAttestationSpec(
                validator_ids=[ValidatorIndex(1)],
                slot=Slot(4),
                target_slot=Slot(2),
                target_root_label="block_2",
            ),
            valid=False,
        ),
    ]

    fork_choice_test(steps=steps)
