"""
State Transition: Block Processing
===================================

Overview
--------
Tests for block header validation and block processing through the state transition
function. Block processing is the core mechanism by which the blockchain state evolves,
incorporating new transactions, attestations, and consensus decisions into the canonical state.

What is Block Processing?
--------------------------
Block processing validates and integrates a proposed block into the chain's state:

1. **Header Validation**: Verify block structure, proposer, parent linkage
2. **State Transition**: Execute block operations on current state
3. **Root Verification**: Validate state root commitment
4. **Attestation Processing**: Handle included attestations
5. **State Finalization**: Produce new post-block state

Block Processing Phases
------------------------

**Phase 1: Slot Advancement**
   If `block.slot > state.slot`, advance state through empty slots
   to reach the block's slot. This ensures time moves forward.

**Phase 2: Header Processing**
   Validate block header fields:
   - Slot matches state slot
   - Proposer index matches expected proposer for slot
   - Parent root matches hash of latest block header
   - Signatures are valid (if signatures enabled)

**Phase 3: Body Processing**
   Execute block body operations:
   - Process attestations included in block
   - Update justification/finalization
   - Apply any other block operations

**Phase 4: Root Verification**
   Compute post-state root and verify it matches block state root.
   This cryptographic commitment proves the state transition was
   executed correctly.
"""

import pytest
from consensus_testing import (
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, ValidatorIndex

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
    # - expected proposer is ValidatorIndex(1),
    # - we'll try to use ValidatorIndex(5) instead
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(
                slot=Slot(1),
                proposer_index=ValidatorIndex(3),  # Wrong proposer
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
