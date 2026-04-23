"""Checkpoint sync (non-genesis anchor) tests."""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
    TickStep,
    build_anchor,
)

from lean_spec.subspecs.chain.config import INTERVALS_PER_SLOT, SECONDS_PER_SLOT
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64

pytestmark = pytest.mark.valid_until("Devnet")


ANCHOR_SLOT = Slot(10)
"""Slot at which every test in this module places the trust anchor."""

NUM_VALIDATORS = 4
"""Validator count. Three-of-four reaches the 2/3 justification threshold."""


def test_store_init_from_non_genesis_anchor(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Store exposes the anchor as head, justified, and finalized on startup.

    Scenario
    --------
    Build a real mid-chain anchor by advancing the genesis state through
    empty blocks. Seed the store from the resulting (state, block) pair.

    Chain shape at initialization::

        genesis(0) -> block(1) -> ... -> anchor(10)
                                            ^
                                         head = justified = finalized

    Invariants checked at startup
    -----------------------------

    - Head points to the anchor block.
    - Latest justified and latest finalized both reference the anchor root
      at the anchor's own slot (beacon-chain seeding convention).
    - Store clock is at the anchor slot (no pre-anchor intervals tracked).
    - The anchor block is the only entry in the store's block map.

    Why This Matters
    ----------------
    A newly checkpoint-synced node must refuse to extend history below the
    anchor. The first check on that contract is that the anchor is all the
    store knows about, and is simultaneously treated as the current head and
    as the deepest trusted checkpoint.
    """
    anchor_state, anchor_block = build_anchor(
        num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    # Derive the expected store.time from the anchor slot.
    # The store clock is in intervals since genesis, not seconds.
    anchor_time_intervals = Uint64(int(ANCHOR_SLOT) * int(INTERVALS_PER_SLOT))

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=anchor_block,
        steps=[
            TickStep(
                # Unix time equal to the anchor slot's boundary. With 4s/slot
                # and genesis_time=0, slot 10 starts at t=40s.
                time=int(ANCHOR_SLOT) * int(SECONDS_PER_SLOT),
                checks=StoreChecks(
                    time=anchor_time_intervals,
                    head_slot=ANCHOR_SLOT,
                    head_root_label="genesis",
                    # Both checkpoints are seeded from the anchor itself:
                    # slot = anchor.slot, root = anchor_root. The anchor
                    # state's embedded checkpoint slots are intentionally ignored.
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


def test_extend_chain_from_non_genesis_anchor(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Blocks at slots above the anchor extend the canonical chain.

    Scenario
    --------
    Start from a mid-chain anchor at slot 10 and append three blocks::

        anchor(10) -> block_11 -> block_12 -> block_13
                                                  ^
                                                 head

    Invariants checked after each block
    -----------------------------------

    - Head advances to the newly added block.
    - Justified and finalized checkpoints stay pinned to the anchor root.
      None of these empty blocks carry supermajority attestations, so no
      justification advance is possible.
    - Every block built on the anchor is retained in the store.

    Why This Matters
    ----------------
    Post-anchor blocks must resolve their parents through the store's
    anchor-rooted block map. This exercises the state lookup, the state
    transition, and the head recomputation against a non-genesis base.
    """
    anchor_state, anchor_block = build_anchor(
        num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
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
                    # Empty blocks carry no attestations, so neither checkpoint
                    # advances past the anchor seeding.
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
    """Forks rooted at a checkpoint-synced anchor are tracked and resolvable.

    Scenario
    --------
    Two siblings extend the anchor at slot 11, then fork_b pulls ahead at
    slot 12 with a supermajority attestation::

        anchor(10) -> fork_a_11
                   \\-> fork_b_11 -> fork_b_12 (3/4 attestations)

    Phase 1: Equal weight
        After fork_b_11, neither sibling has received an attestation
        yet. LMD-GHOST falls back to the lexicographic-root tiebreaker.

    Phase 2: Supermajority
        fork_b_12 carries three attestations targeting fork_b_11. That
        gives the fork_b subtree a decisive weight advantage, and the
        head must switch to fork_b_12 regardless of the tiebreaker.

    Why This Matters
    ----------------
    Checkpoint sync does not change how forks are resolved above the
    anchor. LMD-GHOST must run from the anchor as the starting root and
    correctly select the heavier subtree.
    """
    anchor_state, anchor_block = build_anchor(
        num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
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
            # Sibling of fork_a_11; equal weight triggers the tiebreaker.
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
            # Three attestations out of four push fork_b_11 past
            # the 2/3 threshold: the fork_b subtree becomes
            # unambiguously heavier.
            #
            # Source is pinned to the anchor block because the store
            # only knows about blocks at or after the anchor, and the
            # store's latest_justified checkpoint is seeded at
            # (anchor.slot, anchor_root).
            BlockStep(
                block=BlockSpec(
                    slot=Slot(12),
                    parent_label="fork_b_11",
                    label="fork_b_12",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
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
    """The helper-built anchor satisfies Store.from_anchor's preconditions.

    Documents the invariants any valid non-genesis anchor must meet before
    seeding the store:

    - The anchor block's state_root equals the hash of the anchor state.
    - Both checkpoints in the anchor state have slots not greater than the
      anchor slot. Justified and finalized cannot lie in the future.
    - The anchor state's historical block hashes cover slots 0 through
      anchor_slot - 1. Attestations for pre-anchor slots can then be
      topology-checked against the anchor state's recorded history.

    If any invariant breaks, downstream tests fail with confusing symptoms.
    We assert them explicitly here to surface setup errors early.
    """
    anchor_state, anchor_block = build_anchor(
        num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    # Block points at the state: Store.from_anchor asserts this.
    assert anchor_block.state_root == hash_tree_root(anchor_state)

    # Checkpoints cannot reference future slots.
    assert anchor_state.latest_justified.slot <= ANCHOR_SLOT
    assert anchor_state.latest_finalized.slot <= ANCHOR_SLOT

    # History covers every pre-anchor slot.
    assert len(anchor_state.historical_block_hashes) == int(ANCHOR_SLOT)

    # Sanity: the fixture accepts this anchor and runs a no-op step.
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
    """Store.from_anchor aborts when the anchor block's state_root disagrees
    with the hash of the anchor state.

    Scenario
    --------
    Build a valid mid-chain anchor, then replace the anchor block's state_root
    with an unrelated value. The block and state no longer agree on the post
    state, so the store must refuse the pair.

    Key Assertions
    --------------

    - The fixture is marked anchor_valid=False and carries no steps: init
      aborts before any step could run.
    - Store.from_anchor raises an AssertionError whose message contains the
      exact precondition text from the spec, pinning the failure to the
      state-root check rather than any later crash.
    - No Store is returned to the caller; initialization fails cleanly.

    Why This Matters
    ----------------
    A block and state that disagree on the state root are structurally
    inconsistent. Seeding a store from that pair would corrupt every future
    lookup that resolves a block root to its post state. Clients must refuse
    the anchor at init time, not silently repair or ignore it.
    """
    anchor_state, anchor_block = build_anchor(
        num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    # Sanity: the helper-built pair is consistent to begin with. Makes the
    # mismatch below the only difference between this test and the happy path.
    assert anchor_block.state_root == hash_tree_root(anchor_state)

    bad_anchor_block = anchor_block.model_copy(update={"state_root": Bytes32(b"\xff" * 32)})

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=bad_anchor_block,
        anchor_valid=False,
        expected_anchor_error="Anchor block state root must match anchor state hash",
        steps=[],
    )
