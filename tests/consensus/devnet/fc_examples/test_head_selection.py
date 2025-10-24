"""Fork choice head selection tests for the devnet fork."""

import pytest
from consensus_testing import (
    BlockBuilder,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State
from lean_spec.subspecs.ssz.hash import hash_tree_root

pytestmark = pytest.mark.valid_until("Devnet")


def test_head_updates_after_single_block(
    fork_choice_test: ForkChoiceTestFiller,
    genesis: State,
) -> None:
    """
    Test that head updates correctly after processing a single block.

    With no attestations, fork choice should select the latest block
    on the canonical chain.
    """
    # Create a block at slot 1
    block1 = BlockBuilder(genesis).build(Slot(1))
    block1_root = hash_tree_root(block1.message)

    # Generate the test fixture
    # After processing block 1, the head should point to block 1
    fork_choice_test(
        anchor_state=genesis,
        steps=[
            BlockStep(
                block=block1,
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root=block1_root,
                ),
            ),
        ],
    )


def test_head_advances_with_sequential_blocks(
    fork_choice_test: ForkChoiceTestFiller,
    genesis: State,
) -> None:
    """
    Test head selection advances through sequential blocks.

    Each new block should become the new head since there are no forks.
    """
    # Create blocks
    block1 = BlockBuilder(genesis).build(Slot(1))
    block1_root = hash_tree_root(block1.message)

    state_after_block1 = genesis.state_transition(block1)
    block2 = BlockBuilder(state_after_block1).build(Slot(2))
    block2_root = hash_tree_root(block2.message)

    # Generate the test fixture
    # Head should advance from block 1 to block 2
    fork_choice_test(
        anchor_state=genesis,
        steps=[
            BlockStep(
                block=block1,
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root=block1_root,
                ),
            ),
            BlockStep(
                block=block2,
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root=block2_root,
                ),
            ),
        ],
    )
