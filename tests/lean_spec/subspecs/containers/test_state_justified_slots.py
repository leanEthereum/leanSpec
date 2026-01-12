"""Tests for `State.justified_slots` finalized-relative storage.

These tests cover the invariant introduced for zeam#450:
- `justified_slots` is stored starting at `(latest_finalized.slot + 1)`.
- When finalization advances, the bitfield is rebased to the new boundary.
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.containers.attestation import (
    AggregatedAttestation,
    AggregationBits,
    AttestationData,
)
from lean_spec.subspecs.containers.block import Block, BlockBody
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Bytes52, Uint64


def _mk_validators(n: int) -> Validators:
    return Validators(data=[Validator(pubkey=Bytes52.zero(), index=Uint64(i)) for i in range(n)])


def _mk_block(state: State, slot: Slot, attestations: list[AggregatedAttestation]) -> Block:
    body = BlockBody(attestations=AggregatedAttestations(data=attestations))

    parent_root = hash_tree_root(state.latest_block_header)
    proposer_index = Uint64(int(slot) % len(state.validators))

    return Block(
        slot=slot,
        proposer_index=proposer_index,
        parent_root=parent_root,
        state_root=Bytes32.zero(),
        body=body,
    )


def _mk_aggregated_attestation(
    *,
    participant_ids: list[int],
    attestation_slot: Slot,
    source: Checkpoint,
    target: Checkpoint,
) -> AggregatedAttestation:
    data = AttestationData(
        slot=attestation_slot,
        head=Checkpoint(root=target.root, slot=target.slot),
        target=target,
        source=source,
    )

    return AggregatedAttestation(
        aggregation_bits=AggregationBits.from_validator_indices(
            [Uint64(i) for i in participant_ids]
        ),
        data=data,
    )


def test_justified_slots_do_not_include_finalized_boundary() -> None:
    state = State.generate_genesis(genesis_time=Uint64(0), validators=_mk_validators(4))

    # First post-genesis block at slot 1.
    state_slot_1 = state.process_slots(Slot(1))
    block_1 = _mk_block(state_slot_1, Slot(1), attestations=[])
    post_1 = state_slot_1.process_block_header(block_1)

    # latest_finalized.slot is 0, so justified_slots starts at slot 1.
    # Processing block_1 only materializes the parent slot 0, which must not be stored.
    assert len(post_1.justified_slots) == 0

    # Second block at slot 2 materializes parent slot 1, which is the first bit.
    post_1_slot_2 = post_1.process_slots(Slot(2))
    block_2 = _mk_block(post_1_slot_2, Slot(2), attestations=[])
    post_2 = post_1_slot_2.process_block_header(block_2)

    assert len(post_2.justified_slots) == 1
    assert bool(post_2.justified_slots[0]) is False


def test_justified_slots_rebases_when_finalization_advances() -> None:
    # Use 3 validators so a 2-of-3 aggregation is a supermajority.
    state = State.generate_genesis(genesis_time=Uint64(0), validators=_mk_validators(3))

    # Block 1 (slot 1): initializes history (stores slot 0 root), but no justified_slots bits yet.
    state = state.process_slots(Slot(1))
    block_1 = _mk_block(state, Slot(1), attestations=[])
    state = state.process_block(block_1)

    # Block 2 (slot 2): justify slot 1 with source=0 -> target=1.
    state = state.process_slots(Slot(2))
    block_2 = _mk_block(state, Slot(2), attestations=[])

    source_0 = Checkpoint(root=block_1.parent_root, slot=Slot(0))
    target_1 = Checkpoint(root=block_2.parent_root, slot=Slot(1))
    att_0_to_1 = _mk_aggregated_attestation(
        participant_ids=[0, 1],
        attestation_slot=Slot(2),
        source=source_0,
        target=target_1,
    )

    block_2 = _mk_block(state, Slot(2), attestations=[att_0_to_1])
    state = state.process_block(block_2)

    # Block 3 (slot 3): justify slot 2 with source=1 -> target=2, which finalizes slot 1.
    state = state.process_slots(Slot(3))
    block_3 = _mk_block(state, Slot(3), attestations=[])

    source_1 = Checkpoint(root=block_2.parent_root, slot=Slot(1))
    target_2 = Checkpoint(root=block_3.parent_root, slot=Slot(2))
    att_1_to_2 = _mk_aggregated_attestation(
        participant_ids=[0, 1],
        attestation_slot=Slot(3),
        source=source_1,
        target=target_2,
    )

    block_3 = _mk_block(state, Slot(3), attestations=[att_1_to_2])
    state = state.process_block(block_3)

    assert state.latest_finalized.slot == Slot(1)

    # After finalization advances to slot 1, the bitfield base becomes slot 2.
    # Slot 2 remains stored as index 0 and must be justified.
    assert len(state.justified_slots) == 1
    assert bool(state.justified_slots[0]) is True

    assert State._is_slot_justified(state.latest_finalized.slot, state.justified_slots, Slot(1))
    assert State._is_slot_justified(state.latest_finalized.slot, state.justified_slots, Slot(2))
    assert State._justified_slots_index(state.latest_finalized.slot, Slot(2)) == 0


def test_is_slot_justified_raises_on_out_of_bounds() -> None:
    # For slots > finalized_slot, the bitfield must be long enough to cover the slot.
    # If it is not, this indicates an inconsistent state and should fail fast.
    with pytest.raises(IndexError):
        State._is_slot_justified(
            Slot(0),
            justified_slots=State.generate_genesis(Uint64(0), _mk_validators(1)).justified_slots,
            slot=Slot(1),
        )
