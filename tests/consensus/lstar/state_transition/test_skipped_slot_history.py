"""State Transition: Skipped Slot History"""

import pytest

from consensus_testing import (
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
    generate_pre_state,
)
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import HistoricalBlockHashes
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import ZERO_HASH, Uint64

pytestmark = pytest.mark.valid_until("Lstar")


def test_multi_slot_gap_materializes_zero_hash_history(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A multi-slot gap fills the history with the parent root then zero hashes.

    Given
    -----
    - the default 4-validator genesis state.
    - the chain:
        genesis -> block_1(1) -> block(4)
    - block(4) skips slots 2 and 3, a gap of two empty slots.
    - the anchor root is the chain tip header at slot 1 before block_1.
    - the parent root is block_1's stored header after advancing to slot 4.

    When
    ----
    - the chain processes block_1 and block(4).

    Then
    ----
    - the state slot is 4.
    - the history holds the anchor root at slot 0.
    - the history holds the parent root at slot 1.
    - the history holds the zero hash at slot 2.
    - the history holds the zero hash at slot 3.
    """
    pre = generate_pre_state()
    spec = LstarSpec()
    anchor_state = spec.process_slots(pre, Slot(1))
    anchor_root = hash_tree_root(anchor_state.latest_block_header)
    block_1 = spec.block_class(
        slot=Slot(1),
        proposer_index=ValidatorIndex.proposer_for_slot(Slot(1), Uint64(len(pre.validators))),
        parent_root=anchor_root,
        state_root=ZERO_HASH,
        body=spec.block_body_class(attestations=spec.aggregated_attestations_class(data=[])),
    )
    state_after_block_1 = spec.process_block(anchor_state, block_1)
    state_at_slot_4 = spec.process_slots(state_after_block_1, Slot(4))
    parent_root = hash_tree_root(state_at_slot_4.latest_block_header)

    state_transition_test(
        pre=pre,
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(4), parent_label="block_1"),
        ],
        post=StateExpectation(
            slot=Slot(4),
            historical_block_hashes=HistoricalBlockHashes(
                data=[anchor_root, parent_root, ZERO_HASH, ZERO_HASH]
            ),
        ),
    )
