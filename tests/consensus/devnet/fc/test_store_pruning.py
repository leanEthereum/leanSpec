"""Fork Choice: Store pruning on finalization."""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    AttestationCheck,
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    GossipAttestationSpec,
    StoreChecks,
    TickStep,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_finalization_prunes_stale_aggregated_payloads(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Aggregated attestation payloads targeting finalized slots are pruned.

    Scenario
    --------
    Four validators. Linear chain through slot 6.

    Phase 1 -- Build chain and achieve first finalization (finalized=1)::

        genesis(0) -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)

    - block_3 carries supermajority (V0,V1,V2) justifying slot 1
    - block_5 carries supermajority (V0,V1,V2) justifying slot 2
    - Justifying slot 2 with source=1 finalizes slot 1

    Phase 2 -- Fire the aggregate interval, then submit gossip:

    - TickStep to time=22 advances to slot 5 interval 2 (aggregate interval).
      The pool is still empty so aggregate does nothing.
    - Stale: validators {0,1,2}, target=1 (at finalized slot)
    - Fresh: validators {1,2,3}, target=5 (above finalized slot)

    Both land in latest_new_aggregated_payloads at interval 27.

    Phase 3 -- Advance finalization to trigger pruning:

    - block_6 carries supermajority (V0,V1,V2) justifying slot 3
    - Justifying slot 3 with source=2 finalizes slot 2
    - BlockStep auto-ticks from interval 27 to interval 30 (slot 6 start),
      passing through slot 5 interval 4 which calls accept_new_attestations()
      -- gossip migrates from "new" to "known"
    - prune_stale_attestation_data removes entries where target <= finalized=2
    - Stale (target=1): pruned
    - Fresh (target=5): kept
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
                            validator_ids=[
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
                            validator_ids=[
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
                            validator_ids=[
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
    Finalization prunes stale attestation data across all store pools.

    Scenario
    --------
    1. Build a canonical chain through slot 5 and reach finalized slot 2
    2. Populate raw gossip signatures, pending aggregated payloads, and known
       aggregated payloads with attestation targets at slots 1 through 5
    3. Process block 6, which justifies slot 4 and advances finalization to slot 3

    Expected Behavior
    -----------------
    1. Before finalization advances, all three attestation pools contain targets
       at slots 1, 2, 3, 4, and 5
    2. After finalization reaches slot 3, targets 1, 2, and 3 are pruned
    3. Targets 4 and 5 remain in all three pools
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
                            validator_ids=[ValidatorIndex(i) for i in range(6)],
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
                            validator_ids=[ValidatorIndex(i) for i in range(6)],
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
                            validator_ids=[ValidatorIndex(i) for i in range(6)],
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(6),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(6),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(6),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(6),
                    target_slot=Slot(4),
                    target_root_label="block_4",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(6),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                    source_root_label="genesis",
                    source_slot=Slot(0),
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)],
                    slot=Slot(6),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)],
                    slot=Slot(6),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)],
                    slot=Slot(6),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)],
                    slot=Slot(6),
                    target_slot=Slot(4),
                    target_root_label="block_4",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(3), ValidatorIndex(4), ValidatorIndex(5)],
                    slot=Slot(6),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(6),
                    slot=Slot(6),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(6),
                    slot=Slot(6),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(6),
                    slot=Slot(6),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(6),
                    slot=Slot(6),
                    target_slot=Slot(4),
                    target_root_label="block_4",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_id=ValidatorIndex(6),
                    slot=Slot(6),
                    target_slot=Slot(5),
                    target_root_label="block_5",
                    source_root_label="genesis",
                    source_slot=Slot(0),
                ),
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
                            validator_ids=[ValidatorIndex(i) for i in range(6)],
                            slot=Slot(6),
                            target_slot=Slot(4),
                            target_root_label="block_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    latest_justified_slot=Slot(4),
                    latest_finalized_slot=Slot(3),
                    attestation_signature_target_slots=[Slot(4), Slot(5)],
                    latest_new_aggregated_target_slots=[Slot(4), Slot(5)],
                    latest_known_aggregated_target_slots=[Slot(4), Slot(5)],
                ),
            ),
        ],
    )
