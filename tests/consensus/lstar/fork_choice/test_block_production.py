"""Fork Choice: Block Production"""

import math

import pytest

from consensus_testing import (
    AggregatedAttestationCheck,
    AggregatedAttestationSpec,
    AttestationCheck,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
)
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.config import (
    INTERVALS_PER_SLOT,
    MAX_ATTESTATIONS_DATA,
    MILLISECONDS_PER_INTERVAL,
    SECONDS_PER_SLOT,
)

pytestmark = pytest.mark.valid_until("Lstar")


def test_block_builder_fixed_point_advances_justification(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Justifying one vote inside a block unlocks a second vote in the same build.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)
    - block_3 includes 3 votes for block_1.
    - block_3 justifies slot 1.
    - vote A carries source slot 1 and targets block_2 from V0, V1, V2.
    - vote B carries source slot 2 and targets block_4 from V1, V2, V3.
    - both votes arrive by gossip and wait in the known pool.
    - B's source slot 2 is not justified when the builder starts.

    When
    ----
    - block_6 is built on block_5, carrying no votes of its own.

    Then
    ----
    - the builder justifies slot 2 from A, which unlocks B.
    - the builder then justifies slot 4 from B.
    - justified reaches slot 4.
    - finalized reaches slot 1.
    - the block body holds 2 aggregated votes.
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
                    latest_justified_root_label="block_1",
                    latest_finalized_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), label="block_4"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    latest_justified_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), label="block_5"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    latest_justified_slot=Slot(1),
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
                    target_slot=Slot(2),
                    target_root_label="block_2",
                    source_root_label="block_1",
                    source_slot=Slot(1),
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
                    target_slot=Slot(4),
                    target_root_label="block_4",
                    source_root_label="block_2",
                    source_slot=Slot(2),
                ),
            ),
            TickStep(
                time=24,
                checks=StoreChecks(
                    latest_justified_slot=Slot(1),
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="known",
                            source_slot=Slot(1),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            location="known",
                            source_slot=Slot(2),
                            target_slot=Slot(4),
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6), label="block_6"),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    latest_justified_slot=Slot(4),
                    latest_justified_root_label="block_4",
                    latest_finalized_slot=Slot(1),
                    latest_finalized_root_label="block_1",
                    block_attestation_count=2,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={0, 1, 2},
                            attestation_slot=Slot(5),
                            target_slot=Slot(2),
                        ),
                        AggregatedAttestationCheck(
                            participants={1, 2, 3},
                            attestation_slot=Slot(5),
                            target_slot=Slot(4),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_produce_block_enforces_max_attestations_data_limit(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Block production caps the block body at the maximum number of distinct votes.

    Given
    -----
    - the chain:
        genesis -> block_1(1) -> ... -> the highest justifiable target slot
    - one vote from V0 per justifiable target slot arrives by gossip.
    - each vote names a different target.
    - this yields one more distinct attestation data entry than the limit allows.
    - only justifiable targets are used, so every entry is a real candidate.
    - a single voter never reaches the supermajority (2/3).
    - no entry justifies its target, so the cap alone bounds the count.

    When
    ----
    - the next block is produced with no votes of its own.

    Then
    ----
    - entries are ordered by target slot.
    - the entry with the highest target slot is dropped.
    - the produced block holds exactly the maximum number of votes.

    Timing
    ------
    - votes gossip after the aggregate interval of the last chain slot.
    - the pool is empty then, so the aggregate step changes nothing.
    - a tick to the next slot start moves the votes into the known pool.
    """
    limit = int(MAX_ATTESTATIONS_DATA)

    # The first limit + 1 slots that are justifiable after genesis.
    # One more than the cap, so exactly one candidate must be dropped.
    target_slots: list[int] = []
    candidate_slot = 1
    while len(target_slots) < limit + 1:
        if Slot(candidate_slot).is_justifiable_after(Slot(0)):
            target_slots.append(candidate_slot)
        candidate_slot += 1

    # Build a contiguous chain up to the highest target slot, then produce one
    # slot later. Every target block must exist on-chain to be a valid target.
    chain_length = target_slots[-1]
    block_production_slot = chain_length + 1

    aggregate_interval = chain_length * int(INTERVALS_PER_SLOT) + 2
    aggregate_time = math.ceil(aggregate_interval * int(MILLISECONDS_PER_INTERVAL) / 1000)
    next_slot_time = block_production_slot * int(SECONDS_PER_SLOT)

    chain_steps: list[BlockStep] = [
        BlockStep(
            block=BlockSpec(slot=Slot(n), label=f"block_{n}"),
            checks=(StoreChecks(head_slot=Slot(n)) if n == 1 or n == chain_length else None),
        )
        for n in range(1, chain_length + 1)
    ]

    attestation_steps: list[GossipAggregatedAttestationStep] = [
        GossipAggregatedAttestationStep(
            attestation=AggregatedAttestationSpec(
                validator_indices=[ValidatorIndex(0)],
                slot=Slot(chain_length),
                target_slot=Slot(n),
                target_root_label=f"block_{n}",
            ),
        )
        for n in target_slots
    ]

    fork_choice_test(
        steps=[
            *chain_steps,
            TickStep(time=aggregate_time),
            *attestation_steps,
            TickStep(time=next_slot_time),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(block_production_slot),
                    label=f"block_{block_production_slot}",
                ),
                checks=StoreChecks(
                    head_slot=Slot(block_production_slot),
                    block_attestation_count=limit,
                ),
            ),
        ]
    )


def test_produce_block_includes_pending_attestations(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Block production pulls in votes that arrived only by gossip.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2)
    - one vote from V1 and V2 targets block_2.
    - the vote arrives by gossip and waits in the pending pool.

    When
    ----
    - block_3 is produced with no votes of its own.

    Then
    ----
    - the builder merges the pending vote before the state transition.
    - the block body holds 1 aggregated vote.
    - the vote covers V1 and V2 at target slot 2.

    Timing
    ------
    - the vote gossips after the aggregate interval of slot 2.
    - the pool is empty then, so the aggregate step changes nothing.
    - the tick to slot 3 only advances time, it does not migrate the pending vote.
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
            TickStep(time=10),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            TickStep(time=12),
            BlockStep(
                block=BlockSpec(slot=Slot(3), label="block_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    block_attestation_count=1,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={1, 2},
                            attestation_slot=Slot(2),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_block_builder_recovers_finality_after_non_zero_boundary_stall(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Block production drives a second round of finality past a moved finalized slot.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_11(11)
    - block_3 includes 3 votes for block_1.
    - block_3 justifies slot 1.
    - block_8 includes 3 votes for block_2 and 3 votes for block_7.
    - block_8 justifies slots 2 and 7.
    - block_8 finalizes slot 1.
    - one vote carries source block_7 and targets block_10.
    - one vote carries source block_10 and targets block_11.
    - both votes arrive by gossip and wait in the known pool.

    When
    ----
    - block_12 is built on block_11, carrying no votes of its own.

    Then
    ----
    - the builder includes the block_7 to block_10 vote first.
    - that vote justifies slot 10 and finalizes slot 7.
    - the re-iteration then includes the block_10 to block_11 vote.
    - head is block_12 at slot 12.
    - justified reaches slot 11.
    - finalized reaches slot 10.
    - the block body holds both aggregated votes.

    Timing
    ------
    - votes gossip after the aggregate interval of slot 11.
    - the pool is empty then, so the aggregate step changes nothing.
    - a tick to the slot 12 boundary moves the votes into the known pool.
    """
    aggregate_interval = 11 * int(INTERVALS_PER_SLOT) + 2
    aggregate_time = math.ceil(aggregate_interval * int(MILLISECONDS_PER_INTERVAL) / 1000)
    block_time = 12 * int(SECONDS_PER_SLOT)

    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_2",
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
                block=BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
                checks=StoreChecks(head_slot=Slot(4)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="block_4", label="block_5"),
                checks=StoreChecks(head_slot=Slot(5)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6), parent_label="block_5", label="block_6"),
                checks=StoreChecks(head_slot=Slot(6)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7), parent_label="block_6", label="block_7"),
                checks=StoreChecks(head_slot=Slot(7)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    parent_label="block_7",
                    label="block_8",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(8),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(8),
                            target_slot=Slot(7),
                            target_root_label="block_7",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(8),
                    latest_justified_slot=Slot(7),
                    latest_justified_root_label="block_7",
                    latest_finalized_slot=Slot(1),
                    latest_finalized_root_label="block_1",
                ),
            ),
            *[
                BlockStep(
                    block=BlockSpec(
                        slot=Slot(n),
                        parent_label=f"block_{n - 1}",
                        label=f"block_{n}",
                    ),
                    checks=StoreChecks(head_slot=Slot(n)),
                )
                for n in range(9, 12)
            ],
            TickStep(time=aggregate_time),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(11),
                    target_slot=Slot(10),
                    target_root_label="block_10",
                    source_root_label="block_7",
                    source_slot=Slot(7),
                ),
            ),
            GossipAggregatedAttestationStep(
                attestation=AggregatedAttestationSpec(
                    validator_indices=[
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(11),
                    target_slot=Slot(11),
                    target_root_label="block_11",
                    source_root_label="block_10",
                    source_slot=Slot(10),
                ),
            ),
            TickStep(
                time=block_time,
                checks=StoreChecks(
                    latest_justified_slot=Slot(7),
                    latest_finalized_slot=Slot(1),
                    latest_known_aggregated_target_slots=[
                        Slot(2),
                        Slot(7),
                        Slot(10),
                        Slot(11),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(12), parent_label="block_11", label="block_12"),
                checks=StoreChecks(
                    head_slot=Slot(12),
                    head_root_label="block_12",
                    latest_justified_slot=Slot(11),
                    latest_justified_root_label="block_11",
                    latest_finalized_slot=Slot(10),
                    latest_finalized_root_label="block_10",
                    block_attestation_count=2,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={0, 1, 2},
                            attestation_slot=Slot(11),
                            target_slot=Slot(10),
                        ),
                        AggregatedAttestationCheck(
                            participants={1, 2, 3},
                            attestation_slot=Slot(11),
                            target_slot=Slot(11),
                        ),
                    ],
                ),
            ),
        ],
    )
