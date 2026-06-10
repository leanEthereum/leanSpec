"""Fork Choice: Store pruning on finalization."""

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


def test_finalization_prunes_stale_aggregated_payloads(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Finalization prunes aggregate payloads whose target is at or below the finalized slot.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis(0) -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)
    - block_3 carries V0, V1, V2 justifying slot 1.
    - block_5 carries V0, V1, V2 justifying slot 2, which finalizes slot 1.
    - one stale aggregate from V0, V1, V2 targets block_1 at the finalized slot.
    - one fresh aggregate from V1, V2, V3 targets block_5 above the finalized slot.
    - both aggregates sit in the new pool.

    When
    ----
    - block_6 carries V0, V1, V2 justifying slot 3, which finalizes slot 2.

    Then
    ----
    - finalized advances to slot 2.
    - the stale aggregate targeting slot 1 is pruned.
    - the fresh aggregate targeting slot 5 survives in the known pool.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(3),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    latest_justified_slot=Slot(1),
                    latest_finalized_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), label="block_4"),
                checks=StoreChecks(head_slot=Slot(4)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    label="block_5",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(5),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    latest_justified_slot=Slot(2),
                    latest_finalized_slot=Slot(1),
                ),
            ),
            TickStep(time=22),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(5),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                    source_slot=Slot(0),
                    source_root_label="genesis",
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(5),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                    source_slot=Slot(2),
                    source_root_label="block_2",
                ),
                checks=StoreChecks(
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="new",
                            target_slot=Slot(1),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            location="new",
                            target_slot=Slot(5),
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    label="block_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(6),
                            target_slot=Slot(3),
                            target_root_label="block_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    latest_finalized_slot=Slot(2),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            location="known",
                            target_slot=Slot(5),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_finalization_prunes_stale_attestation_signatures(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Finalization prunes stale attestation data from every store pool at once.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        genesis(0) -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)
    - block_2, block_3, block_4 each carry 6 votes, finalizing up to slot 2.
    - block_5 carries no votes and does not advance finalization.
    - the raw signature pool holds votes for targets 1 through 5.
    - the new aggregate pool holds votes for targets 1 through 5.
    - the known aggregate pool holds votes for targets 1 through 5.

    When
    ----
    - block_6 carries V0 through V5 justifying slot 4, which finalizes slot 3.

    Then
    ----
    - finalized advances to slot 3.
    - votes targeting slots 1, 2, 3 are pruned from all three pools.
    - votes targeting slots 4, 5 survive in all three pools.
    """
    all_targets = [Slot(i) for i in range(1, 6)]

    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    label="block_2",
                    parent_label="block_1",
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
                    latest_justified_slot=Slot(1),
                    latest_finalized_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    label="block_3",
                    parent_label="block_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(3),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    latest_justified_slot=Slot(2),
                    latest_finalized_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    label="block_4",
                    parent_label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(4),
                            target_slot=Slot(3),
                            target_root_label="block_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    latest_justified_slot=Slot(3),
                    latest_finalized_slot=Slot(2),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    label="block_5",
                    parent_label="block_4",
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    latest_justified_slot=Slot(3),
                    latest_finalized_slot=Slot(2),
                ),
            ),
            TickStep(time=23),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(5),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(5),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="block_1",
                    source_slot=Slot(1),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(5),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                    source_root_label="block_2",
                    source_slot=Slot(2),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(5),
                    target_slot=Slot(4),
                    target_root_label="block_4",
                    source_root_label="block_3",
                    source_slot=Slot(3),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(5),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                    source_root_label="block_3",
                    source_slot=Slot(3),
                ),
            ),
            TickStep(
                time=24,
                checks=StoreChecks(
                    latest_finalized_slot=Slot(2),
                    attestation_signature_target_slots=[],
                    latest_new_aggregated_target_slots=[],
                    latest_known_aggregated_target_slots=all_targets,
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)],
                    slot=Slot(5),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)],
                    slot=Slot(5),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="block_1",
                    source_slot=Slot(1),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)],
                    slot=Slot(5),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                    source_root_label="block_2",
                    source_slot=Slot(2),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)],
                    slot=Slot(5),
                    target_slot=Slot(4),
                    target_root_label="block_4",
                    source_root_label="block_3",
                    source_slot=Slot(3),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)],
                    slot=Slot(5),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                    source_root_label="block_3",
                    source_slot=Slot(3),
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(6),
                    slot=Slot(5),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
                is_aggregator=True,
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(6),
                    slot=Slot(5),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="block_1",
                    source_slot=Slot(1),
                ),
                is_aggregator=True,
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(6),
                    slot=Slot(5),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                    source_root_label="block_2",
                    source_slot=Slot(2),
                ),
                is_aggregator=True,
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(6),
                    slot=Slot(5),
                    target_slot=Slot(4),
                    target_root_label="block_4",
                    source_root_label="block_3",
                    source_slot=Slot(3),
                ),
                is_aggregator=True,
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(6),
                    slot=Slot(5),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                    source_root_label="block_3",
                    source_slot=Slot(3),
                ),
                is_aggregator=True,
                checks=StoreChecks(
                    latest_finalized_slot=Slot(2),
                    attestation_signature_target_slots=all_targets,
                    latest_new_aggregated_target_slots=all_targets,
                    latest_known_aggregated_target_slots=all_targets,
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    label="block_6",
                    parent_label="block_5",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(6),
                            target_slot=Slot(4),
                            target_root_label="block_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    latest_justified_slot=Slot(5),
                    latest_finalized_slot=Slot(3),
                    attestation_signature_target_slots=[Slot(4), Slot(5)],
                    latest_new_aggregated_target_slots=[Slot(4), Slot(5)],
                    latest_known_aggregated_target_slots=[Slot(4), Slot(5)],
                ),
            ),
        ],
    )
