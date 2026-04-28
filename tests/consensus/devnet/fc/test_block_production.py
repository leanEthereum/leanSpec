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
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    StoreChecks,
    TickStep,
)

from lean_spec.subspecs.chain.config import (
    INTERVALS_PER_SLOT,
    MAX_ATTESTATIONS_DATA,
    MILLISECONDS_PER_INTERVAL,
    SECONDS_PER_SLOT,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_block_builder_fixed_point_advances_justification(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fixed-point loop: justification from attestation A unlocks attestation B.

    Scenario
    --------
    Four validators. Linear chain through slot 5::

        genesis(0) -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)

    Two gossip attestations with different sources:

    - A: source=1, target=2, validators {0, 1, 2}
    - B: source=2, target=4, validators {1, 2, 3}

    B's source (slot 2) is not yet justified when the builder starts.

    Fixed-point loop
    ----------------
    The builder iterates until no new attestations match::

        Pass 1: justified=1 -> A matches -> justifies 2, finalizes 1
        Pass 2: justified=2 -> B matches -> justifies 4
        Pass 3: nothing new  -> done

    Expected post-state
    -------------------
    - Justified slot: 4
    - Finalized slot: 1
    - Block body: 2 aggregated attestations (A and B)
    """
    fork_choice_test(
        steps=[
            # Chain setup
            # ===========
            #
            #   genesis(0) -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)
            #
            # Slot 3 carries a supermajority attestation that justifies slot 1.
            # This establishes the baseline: justified=1, finalized=0.
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            # Justify slot 1: 3 of 4 validators attest.
            # Threshold: 3 * count >= 2 * total -> 3*3=9 >= 2*4=8 -> passes.
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
                    latest_justified_root_label="block_1",
                    latest_finalized_slot=Slot(0),
                ),
            ),
            # Extend to slot 4 then slot 5. No attestations, no checkpoint change.
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
            # Attestation delivery
            # ====================
            #
            # Why gossip instead of in-block attestations?
            # In-block specs derive the source from the parent state's
            # justified checkpoint. Both A and B would get source=1,
            # and the fixed-point loop would never fire.
            #
            # Gossip aggregated steps let us set explicit source overrides,
            # so B can have source=2 (not yet justified).
            #
            # Timing:
            #
            #   22s = interval 27 = slot 5, interval 2 (aggregate interval)
            #   The attestation pool is empty here, so nothing is lost.
            #
            #   24s = interval 30 = slot 6, interval 0
            #   Passes through interval 29 (slot 5, interval 4) which
            #   migrates attestations from the "new" pool to "known".
            # Advance to the aggregate interval while the pool is empty.
            TickStep(time=22),
            # Attestation A: source=1, target=2
            # 3/4 validators. Matches justified=1 on the first pass.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
            # Attestation B: source=2, target=4
            # 3/4 validators. Source slot 2 is NOT justified yet.
            # Only unlocked after A justifies slot 2 on the first pass.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
            # Migrate attestations: tick to 24s (interval 29 fires acceptance).
            #
            # Invariant: justified is still slot 1.
            # Attestations are stored but not processed until a block is built.
            #
            # We check two validators unique to each attestation:
            # - V0 appears only in A (source=1, target=2)
            # - V3 appears only in B (source=2, target=4)
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
            # Fixed-point block production
            # ============================
            #
            # No explicit attestations -- the builder reads from the
            # "known" pool and iterates:
            #
            #   Pass 1: justified=1 -> A selected -> justifies 2
            #           Finalization: range(1+1, 2) is empty -> finalizes 1
            #           justified advances to 2
            #
            #   Pass 2: justified=2 -> B selected -> justifies 4
            #           Finalization: range(2+1, 4) = [3]
            #           Slot 3 is justifiable (delta=2 from finalized=1, within
            #           the immediate window of 5) -> gap exists -> no advance
            #           justified advances to 4
            #
            #   Pass 3: nothing new -> break
            #
            # Result:
            #   justified = 4
            #   finalized = 1
            #   block body = 2 aggregated attestations
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
    Block production caps attestation data entries at MAX_ATTESTATIONS_DATA.

    Scenario
    --------
    Linear chain through MAX_ATTESTATIONS_DATA + 1 blocks. After building
    the chain, the same number of aggregated attestations are gossiped —
    each targeting a different block — producing one more distinct
    AttestationData entry than the limit allows.

    Timing
    ------
    Attestations are gossiped after the aggregate interval of the last
    chain slot (so the aggregate step is a no-op on an empty pool), then
    a tick to the next slot start migrates them from "new" to "known".

    Block builder behavior
    ----------------------
    The builder sorts entries by target.slot and processes them in order.
    After selecting MAX_ATTESTATIONS_DATA entries it breaks, excluding the
    entry with the highest target slot.

    Expected post-state
    -------------------
    The produced block contains exactly MAX_ATTESTATIONS_DATA attestations.
    """
    limit = int(MAX_ATTESTATIONS_DATA)
    num_target_blocks = limit + 1
    block_production_slot = num_target_blocks + 1
    validators = [ValidatorIndex(0), ValidatorIndex(1), ValidatorIndex(2)]

    # Aggregate fires at interval 2 of the last chain slot.
    # With an empty pool this is a no-op, so no payloads are lost.
    # Compute the minimum integer second that reaches this interval.
    aggregate_interval = num_target_blocks * int(INTERVALS_PER_SLOT) + 2
    aggregate_time = math.ceil(aggregate_interval * int(MILLISECONDS_PER_INTERVAL) / 1000)
    # Next slot start migrates gossip payloads from "new" to "known".
    next_slot_time = block_production_slot * int(SECONDS_PER_SLOT)

    # Build a linear chain. Each block is labeled so attestations can
    # reference it as a target.
    chain_steps: list[BlockStep] = [
        BlockStep(
            block=BlockSpec(slot=Slot(n), label=f"block_{n}"),
            checks=(StoreChecks(head_slot=Slot(n)) if n == 1 or n == num_target_blocks else None),
        )
        for n in range(1, num_target_blocks + 1)
    ]

    # One gossip attestation per target block.
    # Each has a different target checkpoint → num_target_blocks distinct
    # AttestationData entries.
    # Source auto-resolves to the genesis justified checkpoint.
    attestation_steps: list[GossipAggregatedAttestationStep] = [
        GossipAggregatedAttestationStep(
            attestation=GossipAggregatedAttestationSpec(
                validator_ids=validators,
                slot=Slot(num_target_blocks),
                target_slot=Slot(n),
                target_root_label=f"block_{n}",
            ),
        )
        for n in range(1, num_target_blocks + 1)
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
    Block production includes attestations accumulated via gossip.

    Scenario
    --------
    Four validators. Linear chain through slot 2::

        genesis(0) -> block_1(1) -> block_2(2)

    One gossip aggregated attestation from validators {1, 2} targeting
    block_2.  The next block (slot 3) is produced without explicit
    attestations — the builder reads from the store's known payload pool.

    Timing
    ------
    ::

        10s = interval 12 = slot 2, interval 2 (aggregate)
              Pool is empty, so aggregation is a no-op.

        12s = interval 15 = slot 3, interval 0
              Advances time so the block at slot 3 is valid.

    The tick alone does not migrate pending payloads to known.
    The block builder merges and processes pending payloads internally
    before selecting attestations for the block body.

    Expected
    --------
    - 1 aggregated attestation in the block body
    - Covers validators {1, 2}
    - Target slot 2
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
            # Advance past the aggregate interval while the pool is empty.
            TickStep(time=10),
            # Validators 1 & 2 gossip an aggregated attestation targeting block_2.
            # data.slot=2 matches the current slot.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(1), ValidatorIndex(2)],
                    slot=Slot(2),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            # Advance time to slot 3 so the block proposal is valid.
            TickStep(time=12),
            # Produce block without explicit attestations.
            # The block builder merges pending gossip payloads before calling
            # the state transition, so the gossip attestation above is included.
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
    Block production recovers finality after the finalized slot has already moved.

    Scenario
    --------
    1. Justify block_1 in block_3
    2. Process block_8 so slots 2 and 7 become justified and slot 1 becomes finalized
    3. Extend the chain through block_11
    4. Gossip two aggregated attestations for slot 11:
       one from block_7 to block_10, then one from block_10 to block_11
    5. Produce block_12 without explicit attestation specs

    Expected Behavior
    -----------------
    1. The builder first includes the block_7 to block_10 attestation
    2. That attestation justifies slot 10 and finalizes slot 7
    3. The re-iteration then includes the block_10 to block_11 attestation
    4. The post-store head is block_12 at slot 12
    5. latest_justified_slot is 11
    6. latest_finalized_slot is 10
    7. The block body contains exactly both aggregated attestations
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
                            validator_ids=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(8),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                        AggregatedAttestationSpec(
                            validator_ids=[
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
                    checks=(StoreChecks(head_slot=Slot(n)) if n == 9 or n == 11 else None),
                )
                for n in range(9, 12)
            ],
            TickStep(time=aggregate_time),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
