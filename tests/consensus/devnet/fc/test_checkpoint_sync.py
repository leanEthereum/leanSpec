"""Checkpoint sync (non-genesis anchor) tests."""

import pytest
from consensus_testing import (
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
    TickStep,
    generate_pre_state,
)

from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32

pytestmark = pytest.mark.valid_until("Devnet")


def test_store_from_non_genesis_anchor(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """Store initializes correctly from a non-genesis anchor block and state.

    Scenario
    --------
    Clients don't always start from genesis. Checkpoint sync lets a node
    start from a recent finalized state and block. This test simulates that
    by creating a synthetic anchor at slot 10, then building blocks on top.

    Setup:
        - Generate a genesis pre-state and advance it to slot 10
        - Set justified and finalized checkpoints at slot 10
        - Use this (state, block) pair as the anchor for a new Store

    Steps:
        - Build blocks at slots 11, 12, 13 on top of the anchor
        - After each block, verify:
            - Head advances to the new block
            - Justified checkpoint stays at slot 10 (no new justification)
            - Finalized checkpoint stays at slot 10

    Why This Matters
    ----------------
    Checkpoint sync is essential for fast node onboarding. A node that just
    joined the network should not need to replay the entire history from
    genesis. Instead it trusts a recent finalized checkpoint.

    The Store must:
      - Accept the non-genesis anchor as its starting point
      - Correctly set justified/finalized checkpoints from the anchor state
      - Process subsequent blocks that build on the anchor
      - Advance the head through those blocks
    """
    # Generate a base genesis state, then modify it to represent a mid-chain anchor.
    base_state = generate_pre_state(num_validators=4)

    anchor_slot = Slot(10)
    fake_anchor_root = Bytes32(b'\xaa' * 32)
    fake_parent_root = Bytes32(b'\xbb' * 32)

    anchor_state = base_state.model_copy(
        update={
            "slot": anchor_slot,
            "latest_block_header": base_state.latest_block_header.model_copy(
                update={
                    "slot": anchor_slot,
                    "parent_root": fake_parent_root,
                }
            ),
            "latest_justified": Checkpoint(root=fake_anchor_root, slot=anchor_slot),
            "latest_finalized": Checkpoint(root=fake_anchor_root, slot=anchor_slot),
        }
    )

    # Initialize the store from the non-genesis anchor and build blocks on top.
    fork_choice_test(
        anchor_state=anchor_state,
        steps=[
            # Initial verification: Store is configured correctly from anchor
            TickStep(
                time=40,  # Slot 10 * 4 seconds/slot = 40s
                checks=StoreChecks(
                    head_slot=anchor_slot,
                    latest_justified_slot=anchor_slot,
                    latest_finalized_slot=anchor_slot,
                ),
            ),
            # Block 11: first block after the anchor
            BlockStep(
                block=BlockSpec(
                    slot=Slot(11),
                    label="block_11",
                    parent_label="genesis",
                ),
                checks=StoreChecks(
                    head_slot=Slot(11),
                    head_root_label="block_11",
                    latest_justified_slot=anchor_slot,
                    latest_finalized_slot=anchor_slot,
                ),
            ),
            # Block 12: extends the chain
            BlockStep(
                block=BlockSpec(
                    slot=Slot(12),
                    parent_label="block_11",
                    label="block_12",
                ),
                checks=StoreChecks(
                    head_slot=Slot(12),
                    head_root_label="block_12",
                    latest_justified_slot=anchor_slot,
                    latest_finalized_slot=anchor_slot,
                ),
            ),
            # Block 13: further extends the chain
            BlockStep(
                block=BlockSpec(
                    slot=Slot(13),
                    parent_label="block_12",
                    label="block_13",
                ),
                checks=StoreChecks(
                    head_slot=Slot(13),
                    head_root_label="block_13",
                    latest_justified_slot=anchor_slot,
                    latest_finalized_slot=anchor_slot,
                ),
            ),
        ],
    )
