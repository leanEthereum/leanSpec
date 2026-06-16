"""Checkpoint sync (non-genesis anchor) tests."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ExpectedRejection,
    ForkChoiceTestFiller,
    StoreChecks,
    TickStep,
    build_anchor,
)
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Interval, RejectionReason, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.config import INTERVALS_PER_SLOT, SECONDS_PER_SLOT
from lean_spec.spec.ssz import Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


ANCHOR_SLOT = Slot(10)
"""Slot at which every test in this module places the trust anchor."""

NUM_VALIDATORS = 4
"""Validator count. Three-of-four reaches the 2/3 justification threshold."""


def test_store_init_from_non_genesis_anchor(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A store seeded from a mid-chain anchor treats it as head and both checkpoints.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis(0) -> block(1) -> ... -> anchor(10)
    - the anchor is built by advancing genesis through empty blocks.
    - the store is seeded from the anchor state and block.

    When
    ----
    - the store starts and the clock ticks to the anchor slot boundary.

    Then
    ----
    - head is the anchor block at slot 10.
    - justified references the anchor root at slot 10.
    - finalized references the anchor root at slot 10.
    - the store clock sits at the anchor slot with no pre-anchor intervals.
    - the anchor block is the only entry in the store.
    - the anchor state's embedded checkpoints already name the anchor slot.
    """
    anchor_state, anchor_block = build_anchor(
        synced=True, num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    anchor_time_intervals = Interval(int(ANCHOR_SLOT) * int(INTERVALS_PER_SLOT))

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=anchor_block,
        steps=[
            TickStep(
                time=int(ANCHOR_SLOT) * int(SECONDS_PER_SLOT),
                checks=StoreChecks(
                    time=anchor_time_intervals,
                    head_slot=ANCHOR_SLOT,
                    head_root_label="genesis",
                    latest_justified_slot=ANCHOR_SLOT,
                    latest_justified_root_label="genesis",
                    latest_finalized_slot=ANCHOR_SLOT,
                    latest_finalized_root_label="genesis",
                    safe_target_root_label="genesis",
                    labels_in_store=["genesis"],
                ),
            ),
        ],
    )


def test_head_recompute_on_anchor_below_its_finalized_slot(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Appending a block above a mid-chain anchor whose finalized sits below it does not crash.

    Given
    -----
    - 4 validators.
    - a mid-chain anchor at slot 10 built without rebasing its checkpoints.
    - the anchor state's finalized stays at the genesis boundary, slot 0.
    - slot 0 sits below the anchor block slot.
    - the store holds only the anchor block.

    When
    ----
    - one block is appended above the anchor, recomputing the head over the anchor chain.

    Then
    ----
    - head advances to the appended block at slot 11.
    - finalized stays at the trusted anchor at slot 10.
    - the parent walk stops at the anchor, so head recomputation does not raise.
    """
    anchor_state, anchor_block = build_anchor(
        synced=False, num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=anchor_block,
        steps=[
            BlockStep(
                block=BlockSpec(
                    slot=Slot(11),
                    parent_label="genesis",
                    label="block_11",
                ),
                checks=StoreChecks(
                    head_slot=Slot(11),
                    head_root_label="block_11",
                    latest_finalized_slot=ANCHOR_SLOT,
                    latest_finalized_root_label="genesis",
                ),
            ),
        ],
    )


def test_extend_chain_from_non_genesis_anchor(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Blocks above the anchor extend the chain and keep the checkpoints pinned.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        anchor(10) -> block_11(11) -> block_12(12) -> block_13(13)
    - the store is seeded from a mid-chain anchor at slot 10.
    - no appended block carries any vote.

    When
    ----
    - three empty blocks are appended above the anchor.

    Then
    ----
    - head advances to each newly added block.
    - justified stays pinned to the anchor root at slot 10.
    - finalized stays pinned to the anchor root at slot 10.
    - every appended block is retained in the store.
    """
    anchor_state, anchor_block = build_anchor(
        synced=True, num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=anchor_block,
        steps=[
            BlockStep(
                block=BlockSpec(
                    slot=Slot(11),
                    parent_label="genesis",
                    label="block_11",
                ),
                checks=StoreChecks(
                    head_slot=Slot(11),
                    head_root_label="block_11",
                    latest_justified_slot=ANCHOR_SLOT,
                    latest_justified_root_label="genesis",
                    latest_finalized_slot=ANCHOR_SLOT,
                    latest_finalized_root_label="genesis",
                    labels_in_store=["genesis", "block_11"],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(12),
                    parent_label="block_11",
                    label="block_12",
                ),
                checks=StoreChecks(
                    head_slot=Slot(12),
                    head_root_label="block_12",
                    latest_justified_slot=ANCHOR_SLOT,
                    latest_justified_root_label="genesis",
                    latest_finalized_slot=ANCHOR_SLOT,
                    latest_finalized_root_label="genesis",
                    labels_in_store=["genesis", "block_11", "block_12"],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(13),
                    parent_label="block_12",
                    label="block_13",
                ),
                checks=StoreChecks(
                    head_slot=Slot(13),
                    head_root_label="block_13",
                    latest_justified_slot=ANCHOR_SLOT,
                    latest_justified_root_label="genesis",
                    latest_finalized_slot=ANCHOR_SLOT,
                    latest_finalized_root_label="genesis",
                    labels_in_store=["genesis", "block_11", "block_12", "block_13"],
                ),
            ),
        ],
    )


def test_fork_off_non_genesis_anchor(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Forks rooted at a checkpoint-synced anchor resolve by weight as usual.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the store is seeded from a mid-chain anchor at slot 10.
    - the chain:
        anchor(10)
        - fork_a_11(11)
        - fork_b_11(11) -> fork_b_12(12)
    - fork_b_12 includes 3 votes for fork_b_11.

    When
    ----
    - both siblings are added, then fork_b extends to slot 12 with votes.

    Then
    ----
    - after fork_b_11 the siblings have equal weight.
    - the tiebreaker picks the head by lexicographic root.
    - fork_b_12 gives the fork_b subtree a decisive weight advantage.
    - head switches to fork_b_12.
    - all four blocks remain in the store.
    """
    anchor_state, anchor_block = build_anchor(
        synced=True, num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=anchor_block,
        steps=[
            BlockStep(
                block=BlockSpec(
                    slot=Slot(11),
                    parent_label="genesis",
                    label="fork_a_11",
                ),
                checks=StoreChecks(
                    head_slot=Slot(11),
                    head_root_label="fork_a_11",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(11),
                    parent_label="genesis",
                    label="fork_b_11",
                ),
                checks=StoreChecks(
                    head_slot=Slot(11),
                    lexicographic_head_among=["fork_a_11", "fork_b_11"],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(12),
                    parent_label="fork_b_11",
                    label="fork_b_12",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(11),
                            source_root_label="genesis",
                            target_slot=Slot(11),
                            target_root_label="fork_b_11",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(12),
                    head_root_label="fork_b_12",
                    labels_in_store=["genesis", "fork_a_11", "fork_b_11", "fork_b_12"],
                ),
            ),
        ],
    )


def test_non_genesis_anchor_is_internally_consistent(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A helper-built anchor meets every precondition the store seeding requires.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - a mid-chain anchor at slot 10 built by the helper.

    When
    ----
    - the anchor state and block are inspected, then used to seed the store.

    Then
    ----
    - the anchor block's recorded post state matches the hash of the anchor state.
    - the justified and finalized checkpoints are the same checkpoint at the anchor slot.
    - that checkpoint names the anchor block as the chain produced it.
    - the recorded block history covers every slot from 0 up to the anchor.
    - the store accepts the anchor and a no-op step runs cleanly.
    """
    anchor_state, anchor_block = build_anchor(
        synced=True, num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    assert anchor_block.state_root == hash_tree_root(anchor_state)

    assert anchor_state.latest_justified == anchor_state.latest_finalized
    assert anchor_state.latest_finalized.slot == ANCHOR_SLOT

    assert len(anchor_state.historical_block_hashes) == int(ANCHOR_SLOT)

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=anchor_block,
        steps=[
            TickStep(
                time=int(ANCHOR_SLOT) * int(SECONDS_PER_SLOT),
                checks=StoreChecks(head_root_label="genesis"),
            ),
        ],
    )


def test_store_from_anchor_rejects_mismatched_state_root(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Store seeding aborts when the anchor block and state disagree on the post state.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - a valid mid-chain anchor at slot 10.
    - the anchor block's recorded post state is replaced with an unrelated value.
    - the block and state no longer agree on the post state.

    When
    ----
    - the store is seeded from the mismatched pair, with no steps.

    Then
    ----
    - seeding aborts before any step could run.
    - the failure pins to the post-state check, not a later crash.
    - no store is returned to the caller.
    """
    anchor_state, anchor_block = build_anchor(
        synced=True, num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    assert anchor_block.state_root == hash_tree_root(anchor_state)

    bad_anchor_block = anchor_block.model_copy(update={"state_root": Bytes32(b"\xff" * 32)})

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=bad_anchor_block,
        anchor_valid=False,
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.ANCHOR_STATE_ROOT_MISMATCH,
            exact_message="Anchor block state root must match anchor state hash",
        ),
        steps=[],
    )
