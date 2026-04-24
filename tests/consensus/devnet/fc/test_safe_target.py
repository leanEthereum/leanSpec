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


@pytest.mark.parametrize(
    "num_attesters",
    [
        # Far-below case. Weight 2 / threshold 4 = half the required mass.
        # Pins behavior in the strict interior of the below-threshold range.
        pytest.param(2, id="two_of_six"),
        # Tight boundary case. Weight 3 sits exactly one vote short of the
        # threshold, covering the off-by-one edge of the prune condition.
        pytest.param(3, id="three_of_six"),
    ],
)
def test_safe_target_does_not_advance_below_supermajority(
    fork_choice_test: ForkChoiceTestFiller,
    num_attesters: int,
) -> None:
    """Safe target stays at genesis when weight falls short of the 2/3 threshold.

    Fixture state:

    - 6 validators, threshold = ceil(12 / 3) = 4
    - Two-block chain rooted at the genesis/justified anchor
    - A single gossip aggregate signed by the first few validators,
      all voting for block_2

    Parametrized over two below-threshold attester counts:

    - 2/6 attesters (far below) -- weight 2, exercises the middle of the region
    - 3/6 attesters (tight edge) -- weight 3, exercises the off-by-one boundary

    Invariant:

        Every ancestor of block_2 carries the same weight (the attester count).
        With any attester count in {2, 3}, no child of the justified root clears
        the ceil(2N / 3) bar, so the safe-target walk halts immediately.

        The LMD-GHOST head has no threshold and still advances to block_2.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            # Phase 1: build a two-block chain above the justified anchor.
            #
            #     genesis (justified) --- block_1 --- block_2  (head)
            #
            # Each block is added while the chain is unanimous about its
            # parent, so the head follows the newest block trivially.
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
            # Phase 2: skip past the aggregation window (interval 2).
            #
            # Interval 2 is when gossip attestations get batched into an
            # aggregate. We tick through it while the gossip pool is empty
            # so the aggregation step is a no-op and the "known"/"new"
            # pools stay isolated for the rest of the test.
            TickStep(time=14),
            # Phase 3: gossip one aggregate from the first few validators.
            #
            #     attesters   :  {0, 1, ...,  num_attesters - 1}
            #     target      :  block_2
            #     destination :  the "new" pool (gossip arrivals land here)
            #
            # The "new" pool holds attestations collected in the current
            # slot until the interval-4 migration moves them into "known".
            # Here we only care that they arrive in "new" so the safe-target
            # computation at interval 3 can read them.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[ValidatorIndex(i) for i in range(num_attesters)],
                    slot=Slot(3),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
                checks=StoreChecks(
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(i),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        )
                        for i in range(num_attesters)
                    ],
                ),
            ),
            # Phase 4: tick into interval 3 of slot 3 and assert the pin.
            #
            # Weight propagates upward from the voted target through every
            # ancestor on the path to the justified root:
            #
            #     block_1 weight = num_attesters
            #     block_2 weight = num_attesters
            #
            # With num_attesters in {2, 3}, both < 4 = ceil(2 * 6 / 3), so
            # the weight-thresholded walk prunes every child of genesis and
            # the safe target stays pinned at slot 0.
            #
            # Head is still block_2: LMD-GHOST has no threshold and follows
            # the heaviest path regardless of the 2/3 condition.
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    safe_target_slot=Slot(0),
                ),
            ),
        ],
    )


def test_safe_target_advances_incrementally_along_the_chain(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Safe target advances one block at a time as votes shift forward.

    4 validators, threshold = ceil(8/3) = 3.
    Chain: genesis -> block_1 -> block_2 -> block_3.

    Each round, 3 validators move their vote to a deeper block.
    Latest vote per validator replaces the prior one.

    Round 1 (votes target block_1):

        block_1 weight=3 >= 3, block_2 weight=0 -> safe_target = block_1

    Round 2 (votes target block_2):

        block_1=3, block_2=3, block_3=0 -> safe_target = block_2

    Round 3 (votes target block_3):

        block_1=3, block_2=3, block_3=3 -> safe_target = block_3
    """
    fork_choice_test(
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
    """Safe target can be strictly shallower than the LMD-GHOST head.

    8 validators, threshold = ceil(16/3) = 6.
    Chain: genesis -> block_1 -> block_2 -> block_3.

    - 6 validators vote for block_2
    - 2 validators vote for block_3

    Weight propagation (votes walk upward from head through ancestors):

    - block_1 = 6 + 2 = 8
    - block_2 = 6 + 2 = 8  (block_3 voters walk through block_2)
    - block_3 = 2

    Safe walk (min_score=6):

        justified -> block_1 (8 >= 6) -> block_2 (8 >= 6)
                  -> block_3 (2 < 6, pruned)
        safe_target = block_2

    LMD-GHOST (no threshold):

        continues to block_3 -> head = block_3

    Confirms safe_target (slot 2) < head (slot 3).
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
            # 6/8 vote for block_2. Weight: block_1 += 6, block_2 += 6.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(0),
                        ValidatorIndex(1),
                        ValidatorIndex(2),
                        ValidatorIndex(3),
                        ValidatorIndex(4),
                        ValidatorIndex(5),
                    ],
                    slot=Slot(4),
                    target_slot=Slot(2),
                    target_root_label="block_2",
                ),
            ),
            # 2/8 vote for block_3. Weight: block_1 += 2, block_2 += 2, block_3 += 2.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(6),
                        ValidatorIndex(7),
                    ],
                    slot=Slot(4),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                ),
            ),
            # Totals: block_1=8, block_2=8, block_3=2.
            # Safe walk stops at block_2 (block_3 below threshold).
            # LMD-GHOST continues to block_3 (no threshold).
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


def test_safe_target_ignores_known_pool_at_interval_3(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Safe target only uses the "new" pool at interval 3.

    6 validators, threshold = 4.

    Attestation sources:

    - "known" pool (from block body): validators 0, 1 -> block_2
    - "new" pool (from gossip):       validators 2, 3 -> block_2

    Safe target is an availability signal tied to the current slot.
    Migration into "known" runs at interval 4, strictly after safe-target
    computation, so votes already living in "known" at interval 3 are
    historical and are intentionally excluded.

    Walk (min_score=4):

        justified -> block_1 (weight 2 < 4, pruned) -> stop

    Result: safe_target stays at genesis even though the merged view
    would have reached block_2.
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
            # Interval 3: only the "new" pool is considered.
            # Weight at block_1 = 2 < 4, so the walk cannot leave genesis.
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    safe_target_slot=Slot(0),
                ),
            ),
        ],
    )
