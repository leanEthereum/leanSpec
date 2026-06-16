"""Greedy set-cover draws from the fallback pool after the priority pool."""

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


def test_aggregate_covers_union_of_priority_and_fallback_pools(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Aggregation merges a fallback-pool proof with a priority-pool proof for one target.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis -> block_1(1)
    - one proof covers V0, V1 targeting block_1.
    - an acceptance tick migrates that proof into the accepted pool.
    - one proof covers V1, V2 targeting block_1.
    - that proof stays in the pending pool.
    - the two proofs share V1 and carry identical attestation data.

    When
    ----
    - the aggregation interval runs with both pools populated.
    - an acceptance tick migrates the merged proof into the accepted pool.
    - block_3 is built on block_1, carrying no votes of its own.

    Then
    ----
    - the pending (priority) proof is taken before the accepted (fallback) proof.
    - the fallback proof adds V0, the one validator still uncovered.
    - the pending pool holds one proof covering V0, V1, V2 for target slot 1.
    - block_3 holds 1 aggregated attestation.
    - that aggregation covers V0, V1, V2.
    - head is block_3.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            TickStep(interval=int(Interval.from_slot(Slot(1))) + 3),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(0), ValidatorIndex(1)],
                    slot=Slot(1),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                ),
            ),
            TickStep(interval=int(Interval.from_slot(Slot(1))) + 4),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(1),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                ),
            ),
            TickStep(
                interval=int(Interval.from_slot(Slot(2))) + 2,
                checks=StoreChecks(
                    new_pool_proof_participants={Slot(1): {0, 1, 2}},
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
                            participants={0, 1, 2},
                            attestation_slot=Slot(1),
                            target_slot=Slot(1),
                        ),
                    ],
                ),
            ),
        ],
    )
