"""Fork Choice: interval-0 acceptance and interval-2 aggregation branches of the tick."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
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


def test_interval_0_acceptance_with_proposal_recomputes_head(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Interval 0 with a proposal promotes pending votes and flips the head.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1)
        - block_a(2) -> block_a2(3)
        - block_b(4)
    - block_a2 carries V0, V1 voting for block_a, landing in the known pool.
    - block_a holds 2 known votes, below the justification threshold of 3.
    - block_a outweighs block_b, so the head follows block_a2.
    - V0, V1, V2, V3 gossip a slot-5 aggregate for block_b, landing in the new pool.
    - the gossiped votes outrank the block votes, since slot 5 is newer than slot 3.

    When
    ----
    - time crosses slot 5 interval 0 with a proposal.

    Then
    ----
    - interval 0 promotes the new-pool votes into the known pool.
    - the new aggregate pool is empty.
    - the known aggregate pool keys both the slot-2 and slot-4 targets.
    - V0 and V1 revote for block_b.
    - block_b holds 4 votes.
    - block_a holds 0 votes.
    - head flips from block_a2 to block_b.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="block_1", label="block_a"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_a"),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_a",
                    label="block_a2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                            ],
                            slot=Slot(3),
                            target_slot=Slot(2),
                            target_root_label="block_a",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="block_a2"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="block_1", label="block_b"),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="block_a2"),
            ),
            TickStep(interval=24),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(5),
                    target_slot=Slot(4),
                    target_root_label="block_b",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_a2",
                    latest_new_aggregated_target_slots=[Slot(4)],
                    latest_known_aggregated_target_slots=[Slot(2)],
                ),
            ),
            TickStep(
                interval=25,
                has_proposal=True,
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="block_b",
                    latest_known_aggregated_target_slots=[Slot(2), Slot(4)],
                    latest_new_aggregated_target_slots=[],
                ),
            ),
        ],
    )


def test_interval_2_aggregator_aggregates_raw_signatures(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Interval 2 turns raw gossip signatures into a pending aggregate.

    Given
    -----
    - 4 validators.
    - the chain:
        block_1(1) -> block_2(2)
    - V0, V1, V2 gossip raw signatures for block_2, kept in the raw signature pool.
    - the new aggregate pool starts empty.

    When
    ----
    - time crosses slot 3 interval 2, the aggregator action.

    Then
    ----
    - the aggregator folds the raw signatures into one pending aggregate.
    - the new aggregate pool now carries the block_2 target.
    - the raw signature pool drops the absorbed copies.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=4),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            TickStep(interval=14),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(0),
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
                is_aggregator=True,
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(1),
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
                is_aggregator=True,
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(2),
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
                is_aggregator=True,
                checks=StoreChecks(
                    attestation_signature_target_slots=[Slot(2)],
                    latest_new_aggregated_target_slots=[],
                ),
            ),
            TickStep(
                interval=17,
                checks=StoreChecks(
                    attestation_signature_target_slots=[],
                    latest_new_aggregated_target_slots=[Slot(2)],
                ),
            ),
        ],
    )
