"""Safe target update tests.

The safe target is the deepest block from the justified checkpoint with ≥2/3
attestation weight. It is recomputed at interval 3 using LMD-GHOST with
min_score = ceil(2/3 * validators).

Covers:
Supermajority met    → advances to attested block
Supermajority missed → stays at justified anchor
Fork choice          → follows heavier branch
Conservativeness     → safe_target ≤ LMD-GHOST head

Threshold:
  ceil(2n/3) = -(-2n // 3)
  n=4 → 3, n=6 → 4, n=9 → 6

Timing (4s slots, 5 intervals/slot):
  interval = floor(time_s * 5 / 4)

  t=12 → slot 3, int 0
  t=14 → slot 3, int 2
  t=15 → slot 3, int 3  ← update_safe_target
  t=16 → slot 4, int 0
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

    Example (6 validators, threshold=4):
     4 validators attest to block_2 → meets threshold

    Flow:
    1. Chain: genesis → block_1 → block_2
    2. Attestations (validators 0–3) enter "new" pool targeting block_2
    3. At interval 3, update_safe_target runs:
       - Merges "new" + "known"
       - LMD-GHOST with min_score=4

    Weights:
      block_1 = 4, block_2 = 4

    Walk:
      justified → block_1 → block_2 → safe_target = block_2

    Checks:
    - Before interval 3 → safe_target = justified anchor
    - After interval 3  → safe_target = block_2
    - Attestations remain in "new" (migration at interval 4)
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
                    # Attestation still in "new" - interval 4 has not run.
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
    """Safe target does not advance when attestation weight < 2/3 threshold.

    Example (6 validators, threshold=4):
     3 validators attest to block_2 → below threshold

    Weights:
      block_1 = 3, block_2 = 3

    At interval 3, update_safe_target runs LMD-GHOST with min_score=4:
      justified → block_1 (3 < 4) → stop

    Result:
      safe_target remains at justified anchor (no advancement)

    Confirms threshold is strict (≥2/3 required), not best-effort.
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

    Example (4 validators, threshold=3):

    Round 1:
    - 3 attest to block_1 → weight: block_1=3
    - Walk stops at block_1 → safe_target = block_1

    Round 2:
    - 3 attest to block_2 (replaces prior votes)
    - Weight extends to block_2 → safe_target = block_2

    Round 3:
    - 3 attest to block_3
    - Weight extends to block_3 → safe_target = block_3

    Shows safe_target progresses only as supermajority support reaches deeper blocks.

    Note:
    Latest vote per validator is used, so newer attestations fully replace earlier ones.
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
            # Round 1: attest to block_1 only
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
            # Round 2: validators switch to attesting block_2
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
            # Round 3: validators switch to attesting block_3
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
    """Safe target follows the fork with ≥2/3 supermajority support.

    Example (6 validators, threshold=4):

    Fork A and Fork B both extend from block_1:
    - 4 validators → block_b
    - 2 validators → block_a

    Weights:
      block_b = 4 (meets threshold)
      block_a = 2 (below threshold)

    At interval 3, update_safe_target runs LMD-GHOST (min_score=4):
      justified → block_1 → block_b → stop

    Result:
      safe_target = block_b (supermajority fork)

    Shows safe_target correctly ignores weaker forks and follows the
    heaviest valid branch under threshold filtering.
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
    """Safe target is the deepest block with ≥ 2/3 validator support, and can be
    shallower than the LMD-GHOST head.

    Example:
    - 9 validators, threshold = 6
    - 6 vote for block_2, 3 vote for block_3

    Weights:
      block_1 = 9
      block_2 = 9
      block_3 = 3

    Safe walk (min_score=6):
      justified → block_1 → block_2 → stop → safe_target = block_2

    LMD-GHOST (no threshold):
      continues to block_3 → head = block_3

    Result:
      safe_target (block_2) < head (block_3), showing the conservative property.
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
    """At interval 3, safe_target must consider both "new" (gossip) and "known"
    (block/self) attestations, since migration to a single pool hasn’t happened.

    Example (6 validators, threshold=4):
    - "known" (from block body): 2 votes → block_2
    - "new" (from gossip):       2 votes → block_2
    - Individually: 2 < 4 (insufficient)
    - Combined:     4 ≥ 4 (meets threshold)

    Weight propagation:
      block_1 = 4 (all votes pass through)
      block_2 = 4 (all votes target or pass through)
      block_3 = 0

    Safe walk (min_score=4):
      justified → block_1 → block_2 → stop → safe_target = block_2

    Without merging pools, weight at block_2 = 2 < 4 → no advancement.

    Note:
    Attestations for block_2 appear in block_3’s body (not block_2) since
    validators can only attest to blocks they have already seen.
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
            # block_3's body carries attestations from validators 0 and 1
            # for block_2 (head=block_2, target=block_2).
            # on_block routes these directly into "known", they never pass
            # through the gossip/new pipeline.
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
            # Advance past the aggregation window (interval 2) while the
            # gossip pool is empty.
            TickStep(time=14),
            # Gossip 2 more attestations from validators 2 and 3 for block_2.
            # These land in "new" via on_gossip_aggregated_attestation.
            # Combined with the 2 in "known": total weight at block_2 = 4 = threshold.
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
            # Interval 3: update_safe_target merges "known" (validators 0, 1,
            # head=block_2) and "new" (validators 2, 3, head=block_2).
            # Combined weight: block_1=4, block_2=4, block_3=0.
            # min_score=4: walk reaches block_2, stops before block_3.
            # safe_target = block_2.
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
