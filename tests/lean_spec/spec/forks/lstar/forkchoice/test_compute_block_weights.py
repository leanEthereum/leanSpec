"""Tests for Store.compute_block_weights."""

from __future__ import annotations

import pytest

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import AggregationBits, Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.containers import AttestationData, SingleMessageAggregate
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz.byte_arrays import ByteList512KiB, Bytes32
from tests.lean_spec.helpers import make_bytes32, make_signed_block


def _make_empty_proof(participants: list[ValidatorIndex]) -> SingleMessageAggregate:
    """Create a placeholder single-message aggregate proof carrying a participant bitfield."""
    placeholder = ByteList512KiB(data=b"")
    return SingleMessageAggregate(
        participants=AggregationBits.from_indices(participants),
        proof=placeholder,
    )


def _add_two_block_chain(base_store: Store) -> tuple[Bytes32, Bytes32, Bytes32]:
    genesis_root = base_store.head

    block1 = make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=genesis_root,
        state_root=make_bytes32(10),
    )
    block1_root = hash_tree_root(block1.block)

    block2 = make_signed_block(
        slot=Slot(2),
        proposer_index=ValidatorIndex(1),
        parent_root=block1_root,
        state_root=make_bytes32(20),
    )
    block2_root = hash_tree_root(block2.block)

    base_store.blocks = {
        **base_store.blocks,
        block1_root: block1.block,
        block2_root: block2.block,
    }
    genesis_state = base_store.states[genesis_root]
    base_store.states = {
        **base_store.states,
        block1_root: genesis_state,
        block2_root: genesis_state,
    }
    base_store.head = block2_root

    return genesis_root, block1_root, block2_root


def _add_finalized_fork(base_store: Store) -> tuple[Bytes32, Bytes32, Bytes32, Bytes32]:
    genesis_root = base_store.head

    block1 = make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=genesis_root,
        state_root=make_bytes32(10),
    )
    block1_root = hash_tree_root(block1.block)

    child_a = make_signed_block(
        slot=Slot(2),
        proposer_index=ValidatorIndex(1),
        parent_root=block1_root,
        state_root=make_bytes32(20),
    )
    child_a_root = hash_tree_root(child_a.block)

    child_b = make_signed_block(
        slot=Slot(2),
        proposer_index=ValidatorIndex(2),
        parent_root=block1_root,
        state_root=make_bytes32(30),
    )
    child_b_root = hash_tree_root(child_b.block)

    voted_root, tie_break_root = sorted([child_a_root, child_b_root])

    genesis_state = base_store.states[genesis_root]
    base_store.blocks = {
        **base_store.blocks,
        block1_root: block1.block,
        child_a_root: child_a.block,
        child_b_root: child_b.block,
    }
    base_store.states = {
        **base_store.states,
        block1_root: genesis_state,
        child_a_root: genesis_state,
        child_b_root: genesis_state,
    }
    base_store.head = tie_break_root
    assert tie_break_root > voted_root

    return genesis_root, block1_root, voted_root, tie_break_root


def test_genesis_only_store_returns_empty_weights(spec: LstarSpec, base_store: Store) -> None:
    """A genesis-only store with no attestations has no block weights."""
    assert spec.compute_block_weights(base_store) == {}


def test_linear_chain_weight_accumulates_upward(spec: LstarSpec, base_store: Store) -> None:
    """Weights walk up from the attested head through all ancestors above finalized slot."""
    genesis_root = base_store.head

    block1 = make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=genesis_root,
        state_root=make_bytes32(10),
    )
    block1_root = hash_tree_root(block1.block)

    block2 = make_signed_block(
        slot=Slot(2),
        proposer_index=ValidatorIndex(1),
        parent_root=block1_root,
        state_root=make_bytes32(20),
    )
    block2_root = hash_tree_root(block2.block)

    new_blocks = dict(base_store.blocks)
    new_blocks[block1_root] = block1.block
    new_blocks[block2_root] = block2.block

    new_states = dict(base_store.states)
    genesis_state = base_store.states[genesis_root]
    new_states[block1_root] = genesis_state
    new_states[block2_root] = genesis_state

    attestation_data = AttestationData(
        slot=Slot(2),
        head=Checkpoint(root=block2_root, slot=Slot(2)),
        target=Checkpoint(root=block2_root, slot=Slot(2)),
        source=Checkpoint(root=genesis_root, slot=Slot(0)),
    )
    proof = _make_empty_proof([ValidatorIndex(0)])
    aggregated_payloads = {
        attestation_data: {proof},
    }

    base_store.blocks = new_blocks
    base_store.states = new_states
    base_store.head = block2_root
    base_store.latest_known_aggregated_payloads = aggregated_payloads
    store = base_store

    weights = spec.compute_block_weights(store)

    # Validator 0 attests to block2 as head.
    # Walking up: block2 (slot 2 > 0) gets +1, block1 (slot 1 > 0) gets +1.
    # Genesis (slot 0) is at finalized_slot so it does NOT get weight.
    assert weights == {block2_root: 1, block1_root: 1}


def test_stale_latest_message_does_not_mask_fresh_weight(
    spec: LstarSpec, base_store: Store
) -> None:
    """A stale post-finalization message must not hide a validator's fresh vote."""
    genesis_root = base_store.head

    block1 = make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=genesis_root,
        state_root=make_bytes32(10),
    )
    block1_root = hash_tree_root(block1.block)

    block2 = make_signed_block(
        slot=Slot(2),
        proposer_index=ValidatorIndex(1),
        parent_root=block1_root,
        state_root=make_bytes32(20),
    )
    block2_root = hash_tree_root(block2.block)

    base_store.blocks = {
        **base_store.blocks,
        block1_root: block1.block,
        block2_root: block2.block,
    }
    genesis_state = base_store.states[genesis_root]
    base_store.states = {
        **base_store.states,
        block1_root: genesis_state,
        block2_root: genesis_state,
    }
    base_store.head = block2_root
    base_store.latest_finalized = Checkpoint(root=block1_root, slot=Slot(1))

    fresh_vote = AttestationData(
        slot=Slot(2),
        head=Checkpoint(root=block2_root, slot=Slot(2)),
        target=Checkpoint(root=block2_root, slot=Slot(2)),
        source=Checkpoint(root=block1_root, slot=Slot(1)),
    )
    stale_vote = AttestationData(
        slot=Slot(3),
        head=Checkpoint(root=block1_root, slot=Slot(1)),
        target=Checkpoint(root=block1_root, slot=Slot(1)),
        source=Checkpoint(root=genesis_root, slot=Slot(0)),
    )

    base_store.latest_known_aggregated_payloads = {
        fresh_vote: {_make_empty_proof([ValidatorIndex(0)])},
        stale_vote: {_make_empty_proof([ValidatorIndex(0)])},
    }

    weights = spec.compute_block_weights(base_store)

    assert weights == {block2_root: 1}


def test_fresh_head_with_finalized_target_still_counts(spec: LstarSpec, base_store: Store) -> None:
    """A vote with head above finalization still counts when its target is finalized."""
    genesis_root, block1_root, block2_root = _add_two_block_chain(base_store)
    base_store.latest_finalized = Checkpoint(root=block1_root, slot=Slot(1))

    fresh_vote_with_finalized_target = AttestationData(
        slot=Slot(2),
        head=Checkpoint(root=block2_root, slot=Slot(2)),
        target=Checkpoint(root=block1_root, slot=Slot(1)),
        source=Checkpoint(root=genesis_root, slot=Slot(0)),
    )
    base_store.latest_known_aggregated_payloads = {
        fresh_vote_with_finalized_target: {_make_empty_proof([ValidatorIndex(0)])},
    }

    weights = spec.compute_block_weights(base_store)

    assert weights == {block2_root: 1}


def test_finalized_target_vote_can_drive_head_selection(spec: LstarSpec, base_store: Store) -> None:
    """A weighted head above finalization wins over the zero-weight tie break branch."""
    genesis_root, block1_root, voted_root, tie_break_root = _add_finalized_fork(base_store)
    finalized = Checkpoint(root=block1_root, slot=Slot(1))
    base_store.latest_justified = finalized
    base_store.latest_finalized = finalized

    vote = AttestationData(
        slot=Slot(2),
        head=Checkpoint(root=voted_root, slot=Slot(2)),
        target=finalized,
        source=Checkpoint(root=genesis_root, slot=Slot(0)),
    )
    base_store.latest_known_aggregated_payloads = {
        vote: {_make_empty_proof([ValidatorIndex(0)])},
    }

    store = spec.update_head(base_store)

    assert tie_break_root != voted_root
    assert store.head == voted_root


def test_finalized_target_vote_can_advance_safe_target(spec: LstarSpec, base_store: Store) -> None:
    """Safe target counts new-pool votes whose head is above finalization."""
    genesis_root, block1_root, block2_root = _add_two_block_chain(base_store)
    finalized = Checkpoint(root=block1_root, slot=Slot(1))
    base_store.latest_justified = finalized
    base_store.latest_finalized = finalized
    base_store.safe_target = block1_root

    vote = AttestationData(
        slot=Slot(2),
        head=Checkpoint(root=block2_root, slot=Slot(2)),
        target=finalized,
        source=Checkpoint(root=genesis_root, slot=Slot(0)),
    )
    base_store.latest_new_aggregated_payloads = {
        vote: {_make_empty_proof([ValidatorIndex(0), ValidatorIndex(1)])},
    }

    store = spec.update_safe_target(base_store)

    assert store.safe_target == block2_root


def test_multiple_attestations_accumulate(spec: LstarSpec, base_store: Store) -> None:
    """Multiple validators attesting to the same head accumulate weight."""
    genesis_root = base_store.head

    block1 = make_signed_block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=genesis_root,
        state_root=make_bytes32(10),
    )
    block1_root = hash_tree_root(block1.block)

    new_blocks = dict(base_store.blocks)
    new_blocks[block1_root] = block1.block

    new_states = dict(base_store.states)
    new_states[block1_root] = base_store.states[genesis_root]

    attestation_data = AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=block1_root, slot=Slot(1)),
        target=Checkpoint(root=block1_root, slot=Slot(1)),
        source=Checkpoint(root=genesis_root, slot=Slot(0)),
    )

    proof = _make_empty_proof([ValidatorIndex(0), ValidatorIndex(1)])
    aggregated_payloads = {
        attestation_data: {proof},
    }

    base_store.blocks = new_blocks
    base_store.states = new_states
    base_store.head = block1_root
    base_store.latest_known_aggregated_payloads = aggregated_payloads
    store = base_store

    weights = spec.compute_block_weights(store)

    # Both validators contribute weight to block1
    assert weights == {block1_root: 2}


def test_compute_lmd_ghost_head_rejects_unknown_start_root(
    spec: LstarSpec, base_store: Store
) -> None:
    """An anchor missing from the store fails the head-walk invariant loudly."""
    # A 32-byte root that is guaranteed not to be in the store.
    unknown_root = Bytes32(b"\xee" * 32)
    assert unknown_root not in base_store.blocks

    with pytest.raises(AssertionError, match="not in store.blocks"):
        spec._compute_lmd_ghost_head(base_store, start_root=unknown_root, attestations={})
