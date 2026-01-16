"""Tests for `State.justified_slots` finalized-relative storage.

These tests cover the invariant introduced for zeam#450:
- `justified_slots` is stored starting at `(latest_finalized.slot + 1)`.
- When finalization advances, the bitfield is rebased to the new boundary.
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.types import Boolean, Uint64
from tests.lean_spec.helpers import (
    make_aggregated_attestation,
    make_block,
    make_bytes32,
    make_validators,
)


def test_justified_slots_do_not_include_finalized_boundary() -> None:
    state = State.generate_genesis(genesis_time=Uint64(0), validators=make_validators(4))

    # First post-genesis block at slot 1.
    state_slot_1 = state.process_slots(Slot(1))
    block_1 = make_block(state_slot_1, Slot(1), attestations=[])
    post_1 = state_slot_1.process_block_header(block_1)

    # latest_finalized.slot is 0, so justified_slots starts at slot 1.
    # Processing block_1 only materializes the parent slot 0, which must not be stored.
    assert len(post_1.justified_slots) == 0

    # Second block at slot 2 materializes parent slot 1, which is the first bit.
    post_1_slot_2 = post_1.process_slots(Slot(2))
    block_2 = make_block(post_1_slot_2, Slot(2), attestations=[])
    post_2 = post_1_slot_2.process_block_header(block_2)

    assert len(post_2.justified_slots) == 1
    assert bool(post_2.justified_slots[0]) is False


def test_justified_slots_rebases_when_finalization_advances() -> None:
    # Use 3 validators so a 2-of-3 aggregation is a supermajority.
    state = State.generate_genesis(genesis_time=Uint64(0), validators=make_validators(3))

    # Block 1 (slot 1): initializes history (stores slot 0 root), but no justified_slots bits yet.
    state = state.process_slots(Slot(1))
    block_1 = make_block(state, Slot(1), attestations=[])
    state = state.process_block(block_1)

    # Block 2 (slot 2): justify slot 1 with source=0 -> target=1.
    state = state.process_slots(Slot(2))
    block_2 = make_block(state, Slot(2), attestations=[])

    source_0 = Checkpoint(root=block_1.parent_root, slot=Slot(0))
    target_1 = Checkpoint(root=block_2.parent_root, slot=Slot(1))
    att_0_to_1 = make_aggregated_attestation(
        participant_ids=[0, 1],
        attestation_slot=Slot(2),
        source=source_0,
        target=target_1,
    )

    block_2 = make_block(state, Slot(2), attestations=[att_0_to_1])
    state = state.process_block(block_2)

    # Block 3 (slot 3): justify slot 2 with source=1 -> target=2, which finalizes slot 1.
    state = state.process_slots(Slot(3))
    block_3 = make_block(state, Slot(3), attestations=[])

    source_1 = Checkpoint(root=block_2.parent_root, slot=Slot(1))
    target_2 = Checkpoint(root=block_3.parent_root, slot=Slot(2))
    att_1_to_2 = make_aggregated_attestation(
        participant_ids=[0, 1],
        attestation_slot=Slot(3),
        source=source_1,
        target=target_2,
    )

    block_3 = make_block(state, Slot(3), attestations=[att_1_to_2])
    state = state.process_block(block_3)

    assert state.latest_finalized.slot == Slot(1)

    # After finalization advances to slot 1, the bitfield base becomes slot 2.
    # Slot 2 remains stored as index 0 and must be justified.
    assert len(state.justified_slots) == 1
    assert bool(state.justified_slots[0]) is True

    assert state.justified_slots.is_slot_justified(state.latest_finalized.slot, Slot(1))
    assert state.justified_slots.is_slot_justified(state.latest_finalized.slot, Slot(2))
    assert Slot(2).justified_index_after(state.latest_finalized.slot) == 0


def test_is_slot_justified_raises_on_out_of_bounds() -> None:
    # For slots > finalized_slot, the bitfield must be long enough to cover the slot.
    # If it is not, this indicates an inconsistent state and should fail fast.
    with pytest.raises(IndexError):
        State.generate_genesis(Uint64(0), make_validators(1)).justified_slots.is_slot_justified(
            Slot(0), Slot(1)
        )


def test_pruning_with_duplicate_roots_keeps_pending_justification() -> None:
    validators = make_validators(3)
    state = State.generate_genesis(genesis_time=Uint64(0), validators=validators)

    # Historical roots with a duplicate value at multiple slots.
    dup_root = make_bytes32(9)
    history = [
        make_bytes32(0),
        make_bytes32(1),
        dup_root,  # slot 2
        make_bytes32(3),  # slot 3
        dup_root,  # slot 4 (duplicate)
        make_bytes32(5),
    ]

    # Finalized boundary at slot 1, slot 2 already justified.
    state = state.model_copy(
        update={
            "latest_finalized": Checkpoint(root=history[1], slot=Slot(1)),
            "latest_justified": Checkpoint(root=history[1], slot=Slot(1)),
            "historical_block_hashes": HistoricalBlockHashes(data=history),
            "justified_slots": JustifiedSlots(
                data=[Boolean(True), Boolean(False), Boolean(False), Boolean(False)]
            ),
            "justifications_roots": JustificationRoots(data=[dup_root]),
            "justifications_validators": JustificationValidators(
                data=[Boolean(False)] * len(validators)
            ),
        }
    )

    # Justify slot 3 from source slot 2, which advances finalization to slot 2.
    attestation = make_aggregated_attestation(
        participant_ids=[0, 1],
        attestation_slot=Slot(3),
        source=Checkpoint(root=history[2], slot=Slot(2)),
        target=Checkpoint(root=history[3], slot=Slot(3)),
    )

    post_state = state.process_attestations([attestation])

    assert post_state.latest_finalized.slot == Slot(2)
    assert list(post_state.justifications_roots) == [dup_root]
