"""Equivocating Proposer Tests."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    AttestationCheck,
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationStep,
    GossipAttestationSpec,
    StoreChecks,
    TickStep,
    generate_pre_state,
)
from lean_spec.spec.forks import Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_equivocating_proposer_two_blocks_at_same_slot(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Two blocks at the same slot from one proposer are both accepted.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1)
        - equivocation_a(2)
        - equivocation_b(2)
    - equivocation_a includes V0's vote for block_1.
    - equivocation_b includes V1's vote for block_1.
    - the differing votes give the two blocks different roots.
    - neither block gains a weight advantage from its vote.

    When
    ----
    - the proposer publishes both blocks at slot 2.

    Then
    ----
    - the store accepts both blocks.
    - head is equivocation_a after the first block.
    - the two blocks have equal weight after the second block.
    - the tiebreaker picks the head by lexicographic root.
    - head stays at slot 2 throughout.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="equivocation_a",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                valid=True,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="equivocation_a",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="equivocation_b",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                valid=True,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    lexicographic_head_among=["equivocation_a", "equivocation_b"],
                ),
            ),
        ],
    )


def test_equivocating_proposer_with_split_attestations(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Votes split across equivocating forks move the head to the heavier fork.

    Given
    -----
    - 6 validators; a slot needs 4 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1)
        - fork_a(2)
        - fork_b(2)
    - fork_a includes V0's vote for block_1.
    - fork_b includes V1's vote for block_1.
    - the differing votes give the two forks different roots.
    - neither fork gains a weight advantage from its vote.

    When
    ----
    - V0 and V1 gossip-vote for fork_a, V2 and V3 gossip-vote for fork_b.
    - then V4 gossip-votes for fork_b.

    Then
    ----
    - the forks have equal weight at 2 each.
    - the tiebreaker picks the head by lexicographic root.
    - V4's vote gives fork_b weight 3 against fork_a's 2.
    - head moves to fork_b.
    - both forks remain in the store throughout.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="fork_a",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                valid=True,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    label="fork_b",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                valid=True,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    lexicographic_head_among=["fork_a", "fork_b"],
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(0),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="fork_a",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="fork_a",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(2),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="fork_b",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(3),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="fork_b",
                ),
            ),
            TickStep(
                time=12,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    lexicographic_head_among=["fork_a", "fork_b"],
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(4),
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="fork_b",
                ),
            ),
            TickStep(
                time=16,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_b",
                ),
            ),
        ],
    )


def test_same_slot_equivocating_attesters_count_once(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An equivocating validator is counted once, on the fork it first voted.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis -> common(1)
        - fork_a(2)
        - fork_b(3)
    - one vote at slot 3 targets fork_a from V0, V1, V2.
    - one vote at slot 3 targets fork_b from V0, V1, V3, V4.
    - V0 and V1 equivocate by voting on both forks at the same slot.
    - fork_a is gossiped first, so V0 and V1's first votes stick to it.

    When
    ----
    - both votes arrive by gossip and are accepted.

    Then
    ----
    - V0 and V1 count once, toward fork_a.
    - fork_a has effective weight 3 from V0, V1, V2.
    - fork_b has effective weight 2 from V3, V4.
    - head stays on fork_a.
    - no slot is justified by the below-threshold votes.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="common"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="common", label="fork_a"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="fork_a"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="common", label="fork_b"),
                checks=StoreChecks(lexicographic_head_among=["fork_a", "fork_b"]),
            ),
            TickStep(interval=18),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="fork_a",
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(3),
                        ValidatorIndex(4),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(3),
                    target_root_label="fork_b",
                ),
            ),
            TickStep(
                time=16,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a",
                    latest_justified_slot=Slot(0),
                    latest_finalized_slot=Slot(0),
                    latest_known_aggregated_target_slots=[Slot(2), Slot(3)],
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="known",
                            attestation_slot=Slot(3),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            location="known",
                            attestation_slot=Slot(3),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            location="known",
                            attestation_slot=Slot(3),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            location="known",
                            attestation_slot=Slot(3),
                            target_slot=Slot(3),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(4),
                            location="known",
                            attestation_slot=Slot(3),
                            target_slot=Slot(3),
                        ),
                    ],
                ),
            ),
        ],
    )
