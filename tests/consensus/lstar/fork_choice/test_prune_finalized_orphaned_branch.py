"""Fork Choice: pruning drops votes on a finalized-orphaned branch."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ExpectedRejection,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationStep,
    StoreChecks,
    build_genesis_state,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_finalization_prunes_vote_on_orphaned_branch(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Finalization prunes a counted vote whose head sits above the finalized slot but
    on a branch the finalized block orphaned, while head, justified, and finalized
    stay exactly where the canonical chain puts them.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis(0) -> block_1(1)
        - block_2(2) -> block_3(3) -> block_4(4)
        - orph_2(2) -> orph_3(3) -> orph_4(4)
    - block_2 carries V0..V5 targeting block_1, justifying slot 1.
    - block_3 carries V0..V5 targeting block_2, justifying slot 2 and finalizing slot 1.
    - the orphaned branch forks off block_1, below the eventual finalized slot 2.
    - a counted aggregate from V6 targets orph_4 at slot 4, above the finalized slot.
    - that vote's head orph_4 is not a descendant of block_2.

    When
    ----
    - block_4 carries V0..V5 targeting block_3, justifying slot 3 and finalizing slot 2.

    Then
    ----
    - head stays on block_4, on the canonical chain.
    - justified advances to slot 3 on block_3.
    - finalized advances to slot 2 on block_2.
    - the only counted target slot is 3, the one canonical vote whose head outlives slot 2.
    - the pending pool holds no target slots.
    - the orphaned vote targeting slot 4 is pruned despite its head outliving the finalized slot.
    """
    fork_choice_test(
        anchor_state=build_genesis_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), parent_label="genesis", label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="block_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    latest_justified_slot=Slot(1),
                    latest_finalized_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_2",
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(3),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                            source_slot=Slot(1),
                            source_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    latest_justified_slot=Slot(2),
                    latest_finalized_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="block_1", label="orph_2"),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="block_3"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="orph_2", label="orph_3"),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="block_3"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="orph_3", label="orph_4"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    latest_justified_slot=Slot(2),
                    latest_finalized_slot=Slot(1),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(6)],
                    slot=Slot(4),
                    target_slot=Slot(4),
                    target_root_label="orph_4",
                    head_root_label="orph_4",
                    head_slot=Slot(4),
                    source_slot=Slot(0),
                    source_root_label="genesis",
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    latest_new_aggregated_target_slots=[Slot(4)],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="block_3",
                    label="block_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(4),
                            target_slot=Slot(3),
                            target_root_label="block_3",
                            source_slot=Slot(2),
                            source_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="block_4",
                    latest_justified_slot=Slot(3),
                    latest_justified_root_label="block_3",
                    latest_finalized_slot=Slot(2),
                    latest_finalized_root_label="block_2",
                    latest_known_aggregated_target_slots=[Slot(3)],
                    latest_new_aggregated_target_slots=[],
                ),
            ),
        ],
    )


def test_re_gossip_of_pruned_orphaned_vote_is_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Re-gossiping a vote pruned onto a finalized-orphaned branch is rejected, not re-admitted.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis(0) -> block_1(1)
        - block_2(2) -> block_3(3) -> block_4(4)
        - orph_2(2) -> orph_3(3) -> orph_4(4)
    - an aggregate from V6 targets orph_4 at slot 4, admitted while finalized is slot 1.
    - block_4 finalizes slot 2 on block_2.
    - orph_4 is not a descendant of block_2, so finalization pruning drops that vote.
    - the pending pool now holds no target slots.
    - the counted pool holds only the canonical target slot 3.

    When
    ----
    - V6 re-gossips the same aggregate targeting orph_4 at slot 4.

    Then
    ----
    - validation fails because the head no longer descends from the finalized block.
    - the rejection reason is head not descendant of finalized.
    - the pending pool still holds no target slots.
    - the counted pool still holds only the canonical target slot 3.
    """
    fork_choice_test(
        anchor_state=build_genesis_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), parent_label="genesis", label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="block_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    latest_justified_slot=Slot(1),
                    latest_finalized_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_2",
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(3),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                            source_slot=Slot(1),
                            source_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    latest_justified_slot=Slot(2),
                    latest_finalized_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="block_1", label="orph_2"),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="block_3"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="orph_2", label="orph_3"),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="block_3"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="orph_3", label="orph_4"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    latest_justified_slot=Slot(2),
                    latest_finalized_slot=Slot(1),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(6)],
                    slot=Slot(4),
                    target_slot=Slot(4),
                    target_root_label="orph_4",
                    head_root_label="orph_4",
                    head_slot=Slot(4),
                    source_slot=Slot(0),
                    source_root_label="genesis",
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    latest_new_aggregated_target_slots=[Slot(4)],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="block_3",
                    label="block_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(4),
                            target_slot=Slot(3),
                            target_root_label="block_3",
                            source_slot=Slot(2),
                            source_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="block_4",
                    latest_justified_slot=Slot(3),
                    latest_finalized_slot=Slot(2),
                    latest_finalized_root_label="block_2",
                    latest_known_aggregated_target_slots=[Slot(3)],
                    latest_new_aggregated_target_slots=[],
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(6)],
                    slot=Slot(4),
                    target_slot=Slot(4),
                    target_root_label="orph_4",
                    head_root_label="orph_4",
                    head_slot=Slot(4),
                    source_slot=Slot(0),
                    source_root_label="genesis",
                ),
                valid=False,
                expected_rejection=ExpectedRejection(
                    reason=RejectionReason.HEAD_NOT_DESCENDANT_OF_FINALIZED,
                    exact_message="Head checkpoint must descend from the finalized block",
                ),
                checks=StoreChecks(
                    latest_new_aggregated_target_slots=[],
                    latest_known_aggregated_target_slots=[Slot(3)],
                ),
            ),
        ],
    )
