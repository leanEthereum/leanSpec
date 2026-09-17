"""A pending proof survives an aggregation round that has nothing to merge it with."""

import pytest

from consensus_testing import (
    AggregatedAttestationCheck,
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
)
from lean_spec.spec.forks import Interval, Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_lone_pending_proof_survives_aggregation(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Aggregation keeps a pending proof it had nothing to merge into.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis -> block_1(1)
    - one gossiped proof covers V0, V1 targeting block_1.
    - it arrives after the acceptance tick, so it is the only proof pending.
    - no raw signatures remain for that vote.

    When
    ----
    - the aggregation interval runs with that lone proof pending.

    Then
    ----
    - no new proof is built, since a lone child proof is already valid.
    - the pending pool still holds the proof covering V0, V1.
    - an acceptance tick migrates it into the accepted pool.
    - block_3 carries it, so V0 and V1's votes reach the chain.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            # Past the acceptance tick, so the proof below stays pending
            # instead of migrating straight into the accepted pool.
            TickStep(interval=int(Interval.from_slot(Slot(2))) + 1),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0), ValidatorIndex(1)],
                    slot=Slot(1),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                ),
                checks=StoreChecks(
                    new_pool_proof_participants={Slot(1): {0, 1}},
                ),
            ),
            # The aggregation interval. One child, no raw signatures, so the
            # round skips this vote: it must leave the proof where it is.
            TickStep(
                interval=int(Interval.from_slot(Slot(2))) + 2,
                checks=StoreChecks(
                    new_pool_proof_participants={Slot(1): {0, 1}},
                ),
            ),
            TickStep(interval=int(Interval.from_slot(Slot(2))) + 4),
            BlockStep(
                block=BlockSpec(slot=Slot(3), label="block_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    block_attestation_count=1,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={0, 1},
                            attestation_slot=Slot(1),
                            target_slot=Slot(1),
                        ),
                    ],
                ),
            ),
        ],
    )
