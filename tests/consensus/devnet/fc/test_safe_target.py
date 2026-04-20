"""Safe target update tests."""

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
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_safe_target_advances_with_supermajority_weight(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Safe target advances when weight meets the 2/3 threshold.

    6 validators, threshold = ceil(12/3) = 4.
    4 attest to block_2, so weight = 4 ≥ 4 at block_1 and block_2.

    Walk (min_score=4):

        justified -> block_1 (4 ≥ 4) -> block_2 (4 ≥ 4) -> stop

    Result: safe_target = block_2 (advances from genesis).
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
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            # Advance past the aggregation window (interval 2) while the
            # attestation pool is empty, so aggregate() is a no-op.
            # floor(14 * 5/4) = 17 = slot 3, interval 2.
            TickStep(time=14),
            # 4/6 validators attest to block_2 → meets 2/3 threshold (4).
            # Aggregated attestation is added to the "new" pool via gossip.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                checks=StoreChecks(
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            # Tick to slot 3, interval 3 (time=15 → interval=18).
            # update_safe_target runs:
            # - merges "new" + "known"
            # - runs LMD-GHOST (min_score=4)
            # Weight ≥4 carries through block_1 → block_2, so walk reaches block_2.
            # "new" pool is not migrated here (only at interval 4).
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                    # Attestation still in "new" — interval 4 has not run.
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_safe_target_does_not_advance_below_supermajority(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Safe target stays at genesis when weight is below the 2/3 threshold.

    6 validators, threshold = ceil(12/3) = 4.
    Only 3 attest to block_2, so weight = 3 < 4 at every block.

    Walk (min_score=4):

        justified -> block_1 (weight 3 < 4, pruned) -> stop

    Result: safe_target remains at genesis.
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
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            # Advance past aggregation window (interval 2).
            TickStep(time=14),
            # Only 3 / 6 validators attest (one below the threshold of 4).
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            # Interval 3: weight 3 < 4, walk cannot leave the justified root.
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    # safe_target stays at genesis / justified anchor.
                    safe_target_slot=Slot(0),
                ),
            ),
        ],
    )


def test_safe_target_advances_incrementally_along_the_chain(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Safe target advances as ≥2/3 votes move forward.

     4 validators, threshold = ceil(8/3) = 3.
    Chain: genesis -> block_1 -> block_2 -> block_3.

    Each round, 3 validators update to a deeper block (latest vote replaces prior).

    Round 1:
        block_1=3 >= 3, block_2=0 -> safe_target = block_1

    Round 2:
        block_1=3, block_2=3 >= 3 -> safe_target = block_2

    Round 3:
        block_1=3, block_2=3, block_3=3 >= 3 -> safe_target = block_3
    """
    fork_choice_test(
        steps=[
            # 3-block chain.
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), label="block_3"),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="block_3"),
            ),
            # Round 1: 3 validators vote for block_1.
            # Weight accumulates at block_1 only (ancestors of the voted head).
            TickStep(time=14),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(1),
                    target_root_label="block_1",
                ),
            ),
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    safe_target_slot=Slot(1),
                    safe_target_root_label="block_1",
                ),
            ),
            # Round 2: slot-4 votes replace slot-3 votes.
            # Weight now reaches block_2 through the new head.
            TickStep(time=18),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(4),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            TickStep(
                time=19,
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                ),
            ),
            # Round 3: slot-5 votes replace slot-4 votes.
            # Full chain now carries weight=3 at every block.
            TickStep(time=22),
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                    ],
                    slot=Slot(5),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                ),
            ),
            TickStep(
                time=23,
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    safe_target_slot=Slot(3),
                    safe_target_root_label="block_3",
                ),
            ),
        ],
    )


def test_safe_target_follows_heavier_fork_on_split(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Safe target follows the fork with supermajority support.

    6 validators, threshold = 4.

    Two forks branch from block_1:

    - 4 validators -> block_b (weight 4 >= 4)
    - 2 validators -> block_a (weight 2 < 4)

    Walk (min_score=4):

        justified -> block_1 (weight 6) -> block_b (4 >= 4)
                                        -> block_a (2 < 4, pruned)

    Result: safe_target = block_b.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            # Both forks branch from block_1.
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="block_1", label="block_a"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="block_1", label="block_b"),
            ),
            TickStep(time=14),
            # Supermajority (4/6) attests to block_b.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(4),
                    target_slot=Slot(3),
                    target_root_label="block_b",
                ),
            ),
            # Minority (2/6) attests to block_a.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(4),
                        ValidatorIndex(5),
                    ],
                    slot=Slot(4),
                    target_slot=Slot(2),
                    target_root_label="block_a",
                ),
            ),
            # block_1 gets weight 6 (all validators walk through it).
            # At the fork, only block_b survives the min_score filter.
            TickStep(
                time=15,
                checks=StoreChecks(
                    safe_target_slot=Slot(3),
                    safe_target_root_label="block_b",
                ),
            ),
        ],
    )


def test_safe_target_is_conservative_relative_to_lmd_ghost_head(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Safe target can be shallower than the LMD-GHOST head.

    6 validators, threshold = 4.
    Chain: genesis -> block_1 -> block_2 -> block_3.

    - 4 vote block_2, 2 vote block_3

    Weights:
        block_1 = 6, block_2 = 6, block_3 = 2

    Safe walk (min_score=4):

        justified -> block_1 (6 >= 4) -> block_2 (6 >= 4)
                  -> block_3 (2 < 4, pruned)
        safe_target = block_2

    LMD-GHOST:

        continues to block_3 -> head = block_3

    Result: safe_target < head (conservative property).
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), label="block_3"),
                checks=StoreChecks(head_slot=Slot(3), head_root_label="block_3"),
            ),
            TickStep(time=14),
            # 4/6 validators vote for block_2. Weight propagates upward: block_1 += 4, block_2 += 4.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(4),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            # 2/6 validators vote for block_3.
            # Weight propagates: block_3 += 2, block_2 += 2, block_1 += 2.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(4),
                        ValidatorIndex(5),
                    ],
                    slot=Slot(4),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                ),
            ),
            # Combined weights: block_1=6, block_2=6, block_3=2.
            #
            # LMD-GHOST (no threshold):
            #   only path leads to block_3 → head = block_3
            #
            # update_safe_target (min_score=4):
            #   block_3 (2 < 4) pruned → stop at block_2
            #   safe_target = block_2
            #
            # Result: safe_target < head (conservative property)
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                ),
            ),
        ],
    )


def test_safe_target_unchanged_after_interval_4_migration(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Safe target computed at interval 3 is not affected by interval 4 migration.

    - interval 3: update_safe_target sets safe_target
    - interval 4: accept_new_attestations migrates "new" → "known"

    Expected behavior:
      safe_target remains unchanged after migration

    This is a regression guard against accidental resets to head or justified anchor.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            TickStep(time=14),
            # Supermajority (4/6) attestation for block_2.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            # Interval 3: update_safe_target fires → safe_target = block_2.
            TickStep(
                time=15,
                checks=StoreChecks(
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            # Interval 4 (time=16 → interval 20, passing interval 19):
            # accept_new_attestations fires.
            # "new" pool migrates to "known".
            # safe_target must remain unchanged (set at interval 3).
            TickStep(
                time=16,
                checks=StoreChecks(
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                    # Attestation now in "known".
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="known",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_safe_target_uses_merged_pools_at_interval_3(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Safe target requires merging both attestation pools.

    6 validators, threshold = 4.

    "known":  validators 0, 1 → block_2 (2 votes)
    "new":    validators 2, 3 → block_2 (2 votes)

    Neither pool alone meets threshold (2 < 4), but merged = 4 ≥ 4.

    Walk (min_score=4):

        justified -> block_1 (4) -> block_2 (4) -> block_3 (0, stop)
        safe_target = block_2

    Without merge: walk would stop at genesis.

    Note: attestations for block_2 appear in block_3’s body since
    validators can only vote for already-seen blocks.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2), head_root_label="block_2"),
            ),
            # block_3 carries in-block attestations from validators 0, 1.
            # These go directly into "known" (bypass gossip pipeline).
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                            ],
                            slot=Slot(3),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="known",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            location="known",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            # Move past interval 2 (aggregation window) with no gossip attestations.
            TickStep(time=14),
            # Gossip 2 more attestations into the "new" pool.
            # Combined with "known": total weight = 4 = threshold.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                    ],
                    slot=Slot(4),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                checks=StoreChecks(
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(2),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(3),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            # Interval 3: merge yields weight 4 at block_1 and block_2.
            # Walk reaches block_2, stops before block_3.
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                ),
            ),
        ],
    )


def test_safe_target_stays_at_justified_with_insufficient_weight(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Safe target does not advance when <2/3 validators attest.

    6 validators, threshold = 4.
    Only 2 validators attest → below threshold.

    Weights at block_2:
      block_1 = 2, block_2 = 2

    Both < min_score=4, so LMD-GHOST stops at justified root:

        justified -> no qualifying child -> stop
        safe_target = genesis / justified anchor

    Even though LMD-GHOST head may still advance without threshold.

    Key checks:
    - safe_target_slot = 0 (unchanged)
    - head_slot may advance (no threshold)
    - attestations remain in "new" pool until migration
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
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                ),
            ),
            # Advance past the aggregation window while the pool is empty.
            # floor(14 * 5/4) = 17 = slot 3, interval 2.
            TickStep(time=14),
            # Only 2/6 validators attest via gossip.
            # 2 < threshold (4), so safe_target does not advance.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                    ],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                checks=StoreChecks(
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            # Tick to slot 3 interval 3 (time=15 → interval=18).
            # update_safe_target runs.
            # Weights: block_1=2, block_2=2.
            # min_score=4 → no child qualifies.
            # Walk stops at justified root → safe_target = slot 0.
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    # safe_target unchanged — stays at genesis anchor.
                    safe_target_slot=Slot(0),
                    # Attestations still in "new" pool — interval 4 not yet run.
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
        ],
    )
