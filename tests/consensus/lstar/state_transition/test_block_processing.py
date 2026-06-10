"""State Transition: Block Processing"""

import pytest

from consensus_testing import (
    BlockSpec,
    ExpectedRejection,
    StateExpectation,
    StateTransitionTestFiller,
    generate_pre_state,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import JustifiedSlots
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Boolean, Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_process_first_block_after_genesis(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Processing the first block advances the state from genesis to slot 1.

    Given
    -----
    - the default genesis state.
    - the chain:
        genesis -> block(1)

    When
    ----
    - the chain processes the block at slot 1.

    Then
    ----
    - the state slot is 1.
    - the chain tip header sits at slot 1.
    - the chain tip header state root is zero.
    - the history holds one entry.
    """
    state_transition_test(
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
    A linear chain of five blocks advances the state to slot 5.

    Given
    -----
    - the default genesis state.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)

    When
    ----
    - the chain processes all five blocks in order.

    Then
    ----
    - the state slot is 5.
    """
    state_transition_test(
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
    Parent linkage spans empty slots when proposals are missed.

    Given
    -----
    - the default genesis state.
    - the chain:
        genesis -> block_1(1) -> block_4(4) -> block_8(8)
    - slots 2, 3, 5, 6, and 7 carry no block.

    When
    ----
    - the chain processes block_1, block_4, and block_8.

    Then
    ----
    - the state slot is 8.
    - the chain tip header sits at slot 8.
    - the chain tip header state root is zero.
    - the history holds eight entries.
    """
    state_transition_test(
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
    A block at a high slot number processes across many empty slots.

    Given
    -----
    - the default genesis state.
    - the chain:
        genesis -> block(100)
    - slots 1 through 99 carry no block.

    When
    ----
    - the chain processes the block at slot 100.

    Then
    ----
    - the state slot is 100.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(100)),
        ],
        post=StateExpectation(slot=Slot(100)),
    )


def test_block_at_very_large_slot_with_many_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A block at slot 500 processes hundreds of empty slots without error.

    Given
    -----
    - the default genesis state.
    - the chain:
        genesis -> block(500)
    - slots 1 through 499 carry no block.

    When
    ----
    - the chain processes the block at slot 500.

    Then
    ----
    - the state slot is 500.
    - the history holds 500 entries.
    - the justified-slots bitfield holds 499 entries, all unjustified.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(500)),
        ],
        post=StateExpectation(
            slot=Slot(500),
            historical_block_hashes_count=500,
            justified_slots=JustifiedSlots(data=[Boolean(False)] * 499),
        ),
    )


def test_block_with_invalid_proposer(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Only the designated proposer may produce a block for a slot.

    Given
    -----
    - the default genesis state.
    - the proposer for slot 1 is V1, from 1 modulo 4.

    When
    ----
    - a block at slot 1 claims proposer V3.

    Then
    ----
    - the proposer does not match the slot.
    - the block is rejected as the wrong proposer.
    """
    state_transition_test(
        blocks=[
            BlockSpec(
                slot=Slot(1),
                proposer_index=ValidatorIndex(3),
            ),
        ],
        post=None,
        expected_rejection=ExpectedRejection(reason=RejectionReason.WRONG_PROPOSER),
    )


def test_block_with_invalid_parent_root(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A block must reference the root of the current chain tip header.

    Given
    -----
    - the default genesis state.

    When
    ----
    - a block at slot 1 claims a parent root that is not the chain tip header root.

    Then
    ----
    - the parent root does not match the chain tip header.
    - the block is rejected as a parent root mismatch.
    """
    state_transition_test(
        blocks=[
            BlockSpec(
                slot=Slot(1),
                parent_root=Bytes32(b"\xde\xad" * 16),
            ),
        ],
        post=None,
        expected_rejection=ExpectedRejection(reason=RejectionReason.PARENT_ROOT_MISMATCH),
    )


def test_block_with_invalid_state_root(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A block must commit to the actual post-state root.

    Given
    -----
    - the default genesis state.

    When
    ----
    - a block at slot 1 claims a state root that is not the actual post-state root.

    Then
    ----
    - the claimed state root does not match the computed post-state.
    - the block is rejected as a state root mismatch.
    """
    state_transition_test(
        blocks=[
            BlockSpec(
                slot=Slot(1),
                state_root=Bytes32(b"\xba\xad" * 16),
            ),
        ],
        post=None,
        expected_rejection=ExpectedRejection(reason=RejectionReason.STATE_ROOT_MISMATCH),
    )


def test_block_with_wrong_slot(state_transition_test: StateTransitionTestFiller) -> None:
    """
    A block must claim the slot the state has been advanced to.

    Given
    -----
    - the state is pre-advanced to slot 1.

    When
    ----
    - a block claiming slot 2 is processed while slot processing is skipped.

    Then
    ----
    - the block slot does not match the state slot.
    - the block is rejected as a block slot mismatch.
    """
    pre_state = generate_pre_state()
    pre_state = LstarSpec().process_slots(pre_state, Slot(1))

    state_transition_test(
        pre=pre_state,
        blocks=[
            BlockSpec(
                slot=Slot(2),
                skip_slot_processing=True,
            ),
        ],
        post=None,
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.BLOCK_SLOT_MISMATCH,
            message_substring="Block slot mismatch",
        ),
    )


def test_block_extends_deep_chain(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A deep linear chain of twenty blocks advances the state to slot 20.

    Given
    -----
    - the default genesis state.
    - the chain:
        genesis -> block_1(1) -> ... -> block_20(20)

    When
    ----
    - the chain processes all twenty blocks in order.

    Then
    ----
    - the state slot is 20.
    """
    blocks = [BlockSpec(slot=Slot(1), label="block_1")]
    blocks.extend(
        [
            BlockSpec(slot=Slot(i), parent_label=f"block_{i - 1}", label=f"block_{i}")
            for i in range(2, 21)
        ]
    )

    state_transition_test(
        blocks=blocks,
        post=StateExpectation(slot=Slot(20)),
    )


def test_empty_blocks(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A chain of blocks with empty bodies advances the state to slot 6.

    Given
    -----
    - the default genesis state.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5) -> block_6(6)
    - every block carries an empty body.

    When
    ----
    - the chain processes all six blocks in order.

    Then
    ----
    - the state slot is 6.
    - the chain tip header sits at slot 6.
    - the history holds six entries.
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
        blocks=blocks,
        post=StateExpectation(
            slot=Slot(6), latest_block_header_slot=Slot(6), historical_block_hashes_count=6
        ),
    )


def test_empty_blocks_with_missed_slots(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Empty-body blocks process across a missed slot up to slot 6.

    Given
    -----
    - the default genesis state.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_5(5) -> block_6(6)
    - block_2, block_3, and block_5 carry empty bodies.
    - slot 4 carries no block.

    When
    ----
    - the chain processes block_1, block_2, block_3, block_5, and block_6.

    Then
    ----
    - the state slot is 6.
    - the chain tip header sits at slot 6.
    - the history holds six entries.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), body=None, parent_label="block_1", label="block_2"),
            BlockSpec(slot=Slot(3), body=None, parent_label="block_2", label="block_3"),
            BlockSpec(slot=Slot(5), body=None, parent_label="block_3", label="block_5"),
            BlockSpec(slot=Slot(6), parent_label="block_5", label="block_6"),
        ],
        post=StateExpectation(
            slot=Slot(6), latest_block_header_slot=Slot(6), historical_block_hashes_count=6
        ),
    )
