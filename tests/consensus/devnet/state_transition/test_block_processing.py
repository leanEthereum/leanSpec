"""State Transition: Block Processing"""

import pytest
from consensus_testing import (
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, Uint64

pytestmark = pytest.mark.valid_until("Devnet")


def test_process_first_block_after_genesis(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test processing the first block after genesis.

    Scenario
    --------
    Process a single block at slot 1 immediately after genesis.

    Expected Behavior
    -----------------
    1. State advances from slot 0 to slot 1
    2. Block header is validated and processed
    3. Latest block header updated to new block
    4. Historical roots updated with genesis
    5. Post-state at slot 1

    This is the foundation for all subsequent blocks.
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1)),
        ],
        post=StateExpectation(
            slot=Slot(1),
            latest_block_header_slot=Slot(1),
            latest_block_header_state_root=Bytes32(b"\x00" * 32),
            historical_block_hashes_count=1,
        ),
    )


def test_linear_chain_multiple_blocks(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test building a linear chain of multiple blocks.

    Scenario
    --------
    Build a 5-block linear chain:
    genesis → block1 → block2 → block3 → block4 → block5

    Expected Behavior
    -----------------
    1. Each block processes in sequence
    2. Parent linkage maintained throughout
    3. State advances monotonically
    4. Historical roots accumulate
    5. Final state at slot 5
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(slot=Slot(3), parent_label="block_2", label="block_3"),
            BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
            BlockSpec(slot=Slot(5), parent_label="block_4", label="block_5"),
        ],
        post=StateExpectation(slot=Slot(5)),
    )


def test_blocks_with_gaps(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test blocks separated by empty slots.

    Scenario
    --------
    Build chain with gaps:
    - Slot 1: Block
    - Slots 2-3: Empty
    - Slot 4: Block
    - Slots 5-7: Empty
    - Slot 8: Block

    Expected Behavior
    -----------------
    1. Blocks process at specified slots
    2. Empty slots handled automatically
    3. Parent linkage spans gaps correctly
    4. State advances to slot 8

    Why This Matters
    ----------------
    Missed proposals are common:
    - Validators offline
    - Network partitions
    - Missed attestations

    This validates resilience to gaps.
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(4), parent_label="block_1", label="block_4"),
            BlockSpec(slot=Slot(8), parent_label="block_4", label="block_8"),
        ],
        post=StateExpectation(
            slot=Slot(8),
            latest_block_header_slot=Slot(8),
            latest_block_header_state_root=Bytes32(b"\x00" * 32),
            historical_block_hashes_count=8,
        ),
    )


def test_block_at_large_slot_number(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test block processing at high slot numbers.

    Scenario
    --------
    Jump directly from genesis to slot 100, simulating:
    - Network bootstrap after long downtime
    - Test environment with artificial time jump
    - Integer overflow boundary testing

    Expected Behavior
    -----------------
    1. Process 99 empty slots: 1→2→...→99→100
    2. Block at slot 100 processes correctly
    3. No integer overflow or wraparound
    4. State remains consistent
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(100)),
        ],
        post=StateExpectation(slot=Slot(100)),
    )


def test_block_with_invalid_proposer(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that blocks from wrong proposer are rejected.

    Scenario
    --------
    Attempt to process a block where proposer index doesn't match
    the expected proposer for that slot.

    Expected Behavior
    -----------------
    Block processing fails with AssertionError: "Incorrect block proposer"

    Why This Matters
    ----------------
    Prevents unauthorized block production:
    - Only designated proposer can produce blocks
    - Prevents validator impersonation
    - Maintains protocol security
    - Essential for consensus integrity

    Without this check, any validator could produce blocks for any slot.
    """
    # Manually specify wrong proposer (not matching slot % validators)
    #
    # For slot 1:
    # - expected proposer is Uint64(1),
    # - we'll try to use Uint64(5) instead
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(
                slot=Slot(1),
                proposer_index=Uint64(3),  # Wrong proposer
            ),
        ],
        post=None,  # Expect failure
        expect_exception=AssertionError,
    )


def test_block_with_invalid_parent_root(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that blocks with wrong parent root are rejected.

    Scenario
    --------
    Attempt to process a block where parent root doesn't match
    hash_tree_root(state.latest block header).

    Expected Behavior
    -----------------
    Block processing fails with AssertionError: "Block parent root mismatch"

    Why This Matters
    ----------------
    Maintains chain integrity:
    - Blocks must reference correct parent
    - Prevents chain history forgery
    - Ensures linear chain continuity
    - Critical for fork resolution

    Without this check, attackers could create invalid chain branches.
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(
                slot=Slot(1),
                parent_root=Bytes32(b"\xde\xad" * 16),  # Invalid parent
            ),
        ],
        post=None,
        expect_exception=AssertionError,
    )


def test_block_with_invalid_state_root(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that blocks with wrong state root commitment are rejected.

    Scenario
    --------
    Create a block with state root that doesn't match the actual
    post-state hash.

    Expected Behavior
    -----------------
    Block processing fails with AssertionError: "Invalid block state root"

    Why This Matters
    ----------------
    Cryptographic state commitment is fundamental:
    - Proves correct state execution
    - Prevents state manipulation

    This is a critical validation - without it, proposers could claim any arbitrary state.
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(
                slot=Slot(1),
                state_root=Bytes32(b"\xba\xad" * 16),  # Wrong state root
            ),
        ],
        post=None,
        expect_exception=AssertionError,
    )


def test_block_with_wrong_slot(state_transition_test: StateTransitionTestFiller) -> None:
    """
    Test that blocks with mismatched slot are rejected.

    Scenario
    --------
    Attempt to process a block at slot 1, but the block claims to be
    at slot 2.

    Expected Behavior
    -----------------
    Block processing fails with AssertionError: "Block slot mismatch"

    Why This Matters
    ----------------
    Ensures temporal consistency:
    - Blocks can't lie about their slot
    - Prevents time manipulation attacks
    - Maintains protocol timing integrity
    - Essential for slot-based consensus
    """
    pre_state = generate_pre_state()
    pre_state = pre_state.process_slots(Slot(1))

    state_transition_test(
        pre=pre_state,
        blocks=[
            BlockSpec(
                slot=Slot(2),
                skip_slot_processing=True,
            ),
        ],
        post=None,
        expect_exception=AssertionError,
        expect_exception_message="Block slot mismatch",
    )


def test_block_extends_deep_chain(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that blocks can extend already-deep chains.

    Scenario
    --------
    Build a 20-block chain to simulate a mature blockchain state,
    then verify new blocks can still extend it correctly.

    Expected Behavior
    -----------------
    1. All 20 blocks process successfully
    2. Parent linkage maintained throughout
    3. State advances to slot 20
    4. Historical roots accumulate correctly
    5. No degradation in processing
    """
    blocks = [BlockSpec(slot=Slot(1), label="block_1")]
    blocks.extend(
        [
            BlockSpec(slot=Slot(i), parent_label=f"block_{i - 1}", label=f"block_{i}")
            for i in range(2, 21)
        ]
    )

    state_transition_test(
        pre=generate_pre_state(),
        blocks=blocks,
        post=StateExpectation(slot=Slot(20)),
    )


def test_empty_blocks(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test processing blocks with empty body (no attestations).

    Scenario
    --------
    Build chain of blocks with empty body:
    - Slot 1: Block, Empty body
    - Slot 2: Block, Empty body
    - Slot 3: Block, Empty body
    - Slot 4: Block, Empty body
    - Slot 5: Block, Empty body
    - Slot 6: Block, Empty body

    Expected Behavior
    -----------------
    1. Blocks process as expected
    2. State advances to slot 6

    """
    blocks = [
        BlockSpec(slot=Slot(1), body=None, label="block_1"),
        *[
            BlockSpec(
                slot=Slot(slot),
                body=None,
                parent_label=f"block_{slot - 1}",
                label=f"block_{slot}",
            )
            for slot in range(2, 7)
        ],
    ]

    state_transition_test(
        pre=generate_pre_state(),
        blocks=blocks,
        post=StateExpectation(
            slot=Slot(6), latest_block_header_slot=Slot(6), historical_block_hashes_count=6
        ),
    )


def test_empty_blocks_with_missed_slots(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test processing blocks with empty body (no attestations) combined with missed slots.

    Scenario
     --------
     Build chain of blocks with empty body + missed slot:
     - Slot 1: Block
     - Slot 2: Block, Empty body
     - Slot 3: BLock, Empty body
     - Slot 4: Missed
     - Slot 5: Block, Empty body
     - Slot 6: Block

     Expected Behavior
     -----------------
     1. Blocks process at specified slots
     2. Empty slots handled automatically
     3. State advances to slot 6

    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), body=None, parent_label="block_1", label="block_2"),
            BlockSpec(slot=Slot(3), body=None, parent_label="block_2", label="block_3"),
            # slot = 4 missed
            BlockSpec(slot=Slot(5), body=None, parent_label="block_3", label="block_5"),
            BlockSpec(slot=Slot(6), parent_label="block_5", label="block_6"),
        ],
        post=StateExpectation(
            slot=Slot(6), latest_block_header_slot=Slot(6), historical_block_hashes_count=6
        ),
    )
