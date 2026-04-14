"""Fork Choice: Finalization prunes stale aggregated payloads."""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    AttestationCheck,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
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
            # Phase 1: Build chain and achieve finalized=1, justified=2
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            # Justify slot 1: supermajority (3/4) with source=genesis/0, target=block_1/1
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
            # Justify slot 2: supermajority (3/4) with source=block_1/1, target=block_2/2
            # Finalization: range(1+1, 2) = [] -> finalizes slot 1
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
            # Phase 2: Fire aggregate interval on empty pool, then submit gossip
            #
            # aggregate() at interval 2 discards lone child proofs from "new".
            # Gossip must be submitted AFTER the aggregate interval so that
            # the subsequent acceptance interval (slot 5, interval 4) can
            # migrate them from "new" to "known" during the block_6 tick.
            #
            # time=22 => floor(22000/800) = interval 27 = slot 5, interval 2.
            # Pool is empty at this point so aggregate is a no-op.
            TickStep(time=22),
            # Store time is now interval 27 (slot 5, interval 2).
            # Both attestations go into latest_new_aggregated_payloads.
            #
            # Stale gossip: target=1 (at finalized slot), should be pruned later
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
            # Fresh gossip: target=5 (above finalized), should survive pruning
            # V3 is unique to this attestation (not in stale)
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
            # Phase 3: Advance finalization to trigger pruning
            #
            # block_6 carries supermajority (V0,V1,V2) justifying slot 3
            # Source auto-resolves to parent state's justified = (block_2, slot 2)
            #
            # BlockStep auto-ticks from interval 27 to interval 30 (slot 6 start),
            # passing through interval 29 (slot 5, interval 4) which calls
            # accept_new_attestations() -- gossip migrates from "new" to "known"
            #
            # on_block processes block_6:
            # - In-block attestation justifies slot 3, source=2 -> finalizes slot 2
            # - prune_stale_attestation_data is called
            # - Stale (target=1 <= finalized=2): REMOVED
            # - Fresh (target=5 > finalized=2): KEPT in "known"
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
