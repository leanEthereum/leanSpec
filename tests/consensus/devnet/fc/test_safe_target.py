"""Safe target update tests.

The safe target is the deepest block reachable from the latest justified
checkpoint that carries at least 2/3 supermajority attestation weight.
It is recomputed at interval 3 of every slot via Store.update_safe_target,
which runs LMD-GHOST with min_score = ceil(num_validators * 2 / 3).

These tests exercise every meaningful branch of that path:

  - Supermajority met    → safe target advances to the attested block.
  - Supermajority missed → safe target stays at the justified anchor.
  - Forks compete        → safe target follows the heavier branch.
  - Safe target is strictly conservative relative to the LMD-GHOST head.

Threshold arithmetic
--------------------
ceil(n * 2 / 3) via the negation trick: -(-n * 2 // 3)

  n=4  →  ceil(2.666…) = 3
  n=6  →  ceil(4.000)  = 4
  n=9  →  ceil(6.000)  = 6

Timing reference (SECONDS_PER_SLOT=4, INTERVALS_PER_SLOT=5)
------------------------------------------------------------
  MILLISECONDS_PER_INTERVAL = 800 ms
  interval  = floor(time_ms / 800) = floor(time_s * 5 / 4)

  time=12 → floor(15.0)  = 15  (slot 3, interval 0)
  time=14 → floor(17.5)  = 17  (slot 3, interval 2)
  time=15 → floor(18.75) = 18  (slot 3, interval 3)  ← update_safe_target
  time=16 → floor(20.0)  = 20  (slot 4, interval 0; passes through int 4=19)
"""

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
    """Safe target advances to the attested block when 2/3 threshold is met.

    Scenario
    --------
    6 validators, 2 blocks, 4/6 attestations for block_2.

    Threshold: ceil(6 * 2 / 3) = ceil(4.0) = 4.
    We supply exactly 4 validators (0, 1, 2, 3), which meets the threshold.

    Timeline
    --------
    1. Build chain: genesis → block_1 (slot 1) → block_2 (slot 2).
    2. Tick to slot 3 interval 2 (time=14) to pass the aggregation window
       without triggering any store action (no aggregator).
    3. Gossip aggregated attestation from validators 0-3 targeting block_2.
       => Proof enters latest_new_aggregated_payloads ("new" pool).
    4. Tick to slot 3 interval 3 (time=15).
       => update_safe_target fires.
       => Merges "new" + "known" pools; runs LMD-GHOST with min_score=4.
       => Validators 0/1/2/3 each contribute weight 1 to block_1 and block_2
          (their head is block_2, which walks up through block_1).
       => Walk: justified_root → block_1 (weight≥4) → block_2 (weight≥4) → leaf.
       => safe_target = block_2.

    Key assertions
    --------------
    * Before interval 3: safe_target = initial anchor (genesis/slot-0 block).
    * After interval 3:  safe_target = block_2.
    * Attestation remains in "new" pool (migration only at interval 4).
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
            # 4 / 6 validators gossip an aggregated attestation for block_2.
            # This is the exact supermajority threshold: ceil(6 * 2/3) = 4.
            # The proof goes directly into the "new" pool via
            # on_gossip_aggregated_attestation.
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
            # Tick to slot 3 interval 3 (floor(15 * 5/4) = 18).
            # update_safe_target fires unconditionally at this interval.
            # It merges "new" + "known" pools, then calls _compute_lmd_ghost_head
            # with min_score=4.  Four validators supply weight ≥ 4 to both
            # block_1 and block_2, so the walk reaches block_2.
            # The "new" pool is NOT migrated here (that is interval 4's job).
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
    """Safe target stays at the justified anchor when attestation weight is
    below the 2/3 threshold.

    Scenario
    --------
    6 validators, 2 blocks, only 3/6 attestations for block_2.

    Threshold: ceil(6 * 2 / 3) = 4.  We supply only 3 validators, which is
    one short of the threshold.

    The LMD-GHOST walk in update_safe_target starts from the latest justified
    root.  At each child it checks: weight ≥ min_score?  block_1 and block_2
    each accumulate weight 3 (validators 0, 1, 2 walk up through both).
    3 < 4, so the walk stops at the justified anchor and safe_target is
    unchanged.

    This test verifies that the threshold is a strict lower bound, not a
    "best effort" heuristic.
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
            # Tick to interval 3. update_safe_target fires but weight=3 < 4,
            # so the walk never steps past the justified anchor.
            # safe_target must remain at the genesis anchor (slot 0).
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
    """Safe target advances block-by-block as supermajority weight accumulates.

    Scenario
    --------
    4 validators, 3-block chain.  Threshold: ceil(4 * 2/3) = 3.

    Round 1 (slot 3): 3/4 validators attest to block_1 only.
      => safe_target = block_1 (weight=3 ≥ 3 at block_1, then 0 at block_2)

    Round 2 (slot 4): 3/4 validators attest to block_2 (replaces prior vote).
      => safe_target = block_2 (weight now ≥ 3 all the way to block_2)

    Round 3 (slot 5): 3/4 validators attest to block_3.
      => safe_target = block_3

    This verifies the walk stops correctly when attestations only cover part
    of the chain, and then advances as new votes arrive.

    Implementation note on "latest vote replaces earlier vote"
    -----------------------------------------------------------
    extract_attestations_from_aggregated_payloads keeps only the
    attestation with the highest slot per validator.  So injecting a
    block_2 attestation in slot 4 supersedes the block_1 attestation in
    slot 3: the validator's weight migrates entirely to block_2's subtree.
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
            # ── Round 1: attest to block_1 only ───────────────────────────────
            #
            # Validators 0, 1, 2 vote with head=block_1 and target=block_1.
            # Their weight (3) accumulates at block_1 but NOT at block_2 or
            # block_3 — the walk climbs from the head to the justified root, so
            # only ancestors of the voted head receive weight.
            # block_1 weight=3 ≥ threshold=3 → walk proceeds to block_1.
            # block_2 weight=0 < threshold   → walk stops.
            # safe_target = block_1.
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
            # ── Round 2: validators switch to attesting block_2 ───────────────
            #
            # Each new vote has a higher slot (4) than the prior vote (3),
            # so it replaces the earlier entry in the per-validator map.
            # All three validators now vote with head=block_2.
            # block_1 weight=3 ≥ 3 → walk advances to block_1.
            # block_2 weight=3 ≥ 3 → walk advances to block_2.
            # block_3 weight=0      → walk stops.
            # safe_target = block_2.
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
            # ── Round 3: validators switch to attesting block_3 ───────────────
            #
            # Slot-5 votes replace slot-4 votes.
            # All three validators now vote with head=block_3.
            # The full chain block_1→block_2→block_3 accumulates weight=3.
            # safe_target advances all the way to block_3.
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
    """Safe target tracks the fork branch that carries supermajority weight.

    Scenario
    --------
    6 validators, two forks from a common base.

    Fork A (block_a) and Fork B (block_b) both branch from block_1.
    Validators 0, 1, 2, 3 (4/6) attest to fork B.
    Validators 4, 5        (2/6) attest to fork A.

    Threshold: ceil(6 * 2/3) = 4.
    Fork B weight = 4 ≥ 4 → safe_target advances to block_b.
    Fork A weight = 2 < 4 → walk would stop before block_a.

    After update_safe_target:
      safe_target = block_b  (the fork with supermajority support)

    This also exercises the LMD-GHOST tiebreaker path: both forks descend
    from block_1.  With min_score=4, the walk from the justified root reaches
    block_1, then only enters block_b's subtree (weight=4), ignoring block_a
    (weight=2 < threshold).
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            # Fork A and Fork B both branch from block_1.
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
            # Minority (2/6) attests to block_a (below the threshold of 4).
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
            # Tick to interval 3.  update_safe_target walks from the justified
            # root with min_score=4.  At block_1 (weight=6, all validators walk
            # through it) the walk proceeds.  At the fork:
            #   block_b weight = 4 ≥ 4 → eligible
            #   block_a weight = 2 < 4 → pruned
            # Walk continues to block_b → leaf.
            # safe_target = block_b.
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
    """Safe target is at most as deep as the LMD-GHOST head, but can be shallower.

    Scenario
    --------
    9 validators, 3-block chain.  Threshold: ceil(9 * 2/3) = 6.

    LMD-GHOST head = block_3 (any block is reachable by the unconstrained walk).
    Safe target    = block_2 (the deepest block with ≥ 6 supporting validators).

    Attestation split:
      6/9 validators attest to block_2 (head=block_2) → weight=6 at block_1, block_2.
      3/9 validators attest to block_3 (head=block_3) → weight=3 at block_1, block_2, block_3.
      Combined weight at each block (latest-vote replaces earlier):
        block_1: 9 (all validators walk up through it)
        block_2: 9 (same — all votes are for block_2 or block_3, both ancestors include block_2)
        block_3: 3 (only validators 6/7/8 voted for block_3)

    Wait, that isn't right. Let me reconsider:
      extract_attestations_from_aggregated_payloads keeps the latest-slot vote per validator.
      All attestations are at slot=4 (same slot), so no replacement happens.

      Validators 0-5 vote head=block_2:   weight flows to block_1 and block_2.
      Validators 6-8 vote head=block_3:   weight flows to block_1, block_2, and block_3.

      Block weights:
        block_1: 9 (all 9 validators walk up through block_1)
        block_2: 9 (validators 0-5 stop here, validators 6-8 also pass through block_2 on
                    the way up from block_3 to block_1)
        block_3: 3 (only validators 6, 7, 8 voted for block_3 or deeper)

    min_score = 6.  Walk:
      justified → block_1 (9 ≥ 6) → block_2 (9 ≥ 6) → block_3 (3 < 6) → stop.
      safe_target = block_2.

    Hmm, that means safe_target = block_2 not block_3.

    But the LMD-GHOST head would be block_3 (9 weight at block_2, but block_3 is
    the only child of block_2, so walk proceeds there regardless; it only has
    weight=3 but there's no competing child so the walk goes there).

    So safe_target (block_2) < head (block_3). That's the "conservative" property.

    Actually wait: block_2 has weight=9 but block_3 has weight=3. In _compute_lmd_ghost_head
    with min_score=6: children of block_2 include block_3 with weight=3. Since 3 < 6,
    block_3 is pruned from children_map. So the walk stops at block_2, which has no
    qualifying children. safe_target = block_2. ✓

    LMD-GHOST (no min_score): children of block_2 = [block_3], weight=3.
    Walk goes to block_3 (only option). head = block_3. ✓

    Great, so safe_target=block_2 < head=block_3. That's the test.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=9),
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
            # 6 / 9 validators attest to block_2 as their head.
            # They walk up through block_1 only (their head IS block_2).
            # Weight contribution: block_1 += 6, block_2 += 6.
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
            # 3 / 9 validators attest to block_3 as their head.
            # They walk up block_3 → block_2 → block_1.
            # Weight contribution: block_1 += 3, block_2 += 3, block_3 += 3.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
                        ValidatorIndex(6),
                        ValidatorIndex(7),
                        ValidatorIndex(8),
                    ],
                    slot=Slot(4),
                    target_slot=Slot(3),
                    target_root_label="block_3",
                ),
            ),
            # Combined weights:
            #   block_1 = 9,  block_2 = 9,  block_3 = 3
            #
            # LMD-GHOST (no threshold):
            #   block_3 is the only child of block_2, weight=3.
            #   Walk proceeds unconditionally → head = block_3.
            #
            # update_safe_target (min_score = ceil(9*2/3) = 6):
            #   justified → block_1 (9 ≥ 6) → block_2 (9 ≥ 6)
            #   → block_3 (3 < 6) — pruned, walk stops.
            #   safe_target = block_2.
            #
            # This confirms: safe_target (block_2) is strictly shallower than
            # the LMD-GHOST head (block_3).
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
    """Safe target set at interval 3 is preserved after interval 4 migration.

    update_safe_target fires at interval 3 and updates safe_target.
    accept_new_attestations fires at interval 4 and migrates the "new" pool
    to "known".  Neither operation should move safe_target backward.

    This is a regression guard: if accept_new_attestations accidentally
    reset safe_target to the head or the justified anchor, this test would catch it.
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
            # Interval 4 (reached via time=16 → interval 20, passing through
            # interval 19):  accept_new_attestations fires.
            # The "new" pool migrates to "known".
            # safe_target must NOT change — it was already set at interval 3.
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
    """Safe target uses both "new" and "known" pools at interval 3.

    Background (from Store.update_safe_target docstring)
    -----------------------------------------------------
    At interval 3 the migration step (interval 4) has not yet run.
    Attestations can enter the "known" pool through two paths that bypass
    gossipsub:

    1. Proposer-bundled: attestations in a block body land directly in
       "known" via on_block.
    2. Self-attestation: a node's own vote is recorded locally in "known"
       without going through the gossip pipeline.

    Without the merge, update_safe_target would undercount support.

    This test exercises the merge by splitting attestation weight across
    both pools and verifying that the combined view meets the threshold
    when neither pool alone would.

    Scenario
    --------
    6 validators, threshold = 4.

    "known" pool (via block attestations — included in block_2's body):
      validators 0, 1 → weight=2 at block_1 and block_2.

    "new" pool (via gossip after the block):
      validators 2, 3 → weight=2 at block_1 and block_2.

    Neither pool alone reaches the threshold of 4.
    Combined they supply weight=4, which is exactly the threshold.
    update_safe_target must merge both pools → safe_target = block_2.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1), head_root_label="block_1"),
            ),
            # Block body includes 2 attestations (validators 0 and 1).
            # These land in "known" immediately via on_block.
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    label="block_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                            ],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="known",
                            source_slot=Slot(0),
                            target_slot=Slot(1),
                        ),
                        AttestationCheck(
                            validator=ValidatorIndex(1),
                            location="known",
                            source_slot=Slot(0),
                            target_slot=Slot(1),
                        ),
                    ],
                ),
            ),
            TickStep(time=14),
            # Gossip 2 more attestations (validators 2 and 3).
            # These land in "new" via on_gossip_aggregated_attestation.
            # Combined with the 2 in "known": total weight = 4 = threshold.
            GossipAggregatedAttestationStep(
                attestation=GossipAggregatedAttestationSpec(
                    validator_ids=[
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
                            validator=ValidatorIndex(2),
                            location="new",
                            source_slot=Slot(0),
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
            # Interval 3: update_safe_target merges "known" (validators 0, 1)
            # and "new" (validators 2, 3) → combined weight = 4 ≥ threshold.
            # Walk reaches block_2 → safe_target = block_2.
            #
            # If merge were absent (only "new" used): weight = 2 < 4 → no advance.
            # If merge were absent (only "known" used): weight = 2 < 4 → no advance.
            TickStep(
                time=15,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="block_2",
                    safe_target_slot=Slot(2),
                    safe_target_root_label="block_2",
                ),
            ),
        ],
    )
