"""Tests for the lstar fork choice rule."""

from __future__ import annotations

import pytest
from consensus_testing.keys import XmssKeyManager
from hypothesis import given, settings, strategies as st

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import AggregationBits, Checkpoint, Interval, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import AttestationSignatureEntry, Store
from lean_spec.spec.forks.lstar.config import (
    GOSSIP_DISPARITY_INTERVALS,
    INTERVALS_PER_SLOT,
    JUSTIFICATION_LOOKBACK_SLOTS,
)
from lean_spec.spec.forks.lstar.containers import (
    Attestation,
    AttestationData,
    Block,
    MultiMessageAggregate,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    SingleMessageAggregate,
    Validators,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Uint64
from lean_spec.spec.ssz.byte_arrays import ByteList512KiB, Bytes32
from tests.lean_spec.helpers import (
    TEST_VALIDATOR_INDEX,
    make_aggregated_proof,
    make_attestation_data,
    make_bytes32,
    make_checkpoint,
    make_empty_block_body,
    make_mock_signature,
    make_signed_block,
    make_signed_block_from_store,
    make_store,
    make_store_with_attestation_data,
)


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


# Slot used by every time-check case below.
ATTESTATION_SLOT = Slot(2)
"""Slot of the attestation under test."""

ATTESTATION_START_INTERVAL = Interval.from_slot(ATTESTATION_SLOT)
"""First interval at which ATTESTATION_SLOT begins."""

DISPARITY_BOUNDARY_INTERVAL = ATTESTATION_START_INTERVAL - Interval(int(GOSSIP_DISPARITY_INTERVALS))
"""Latest local interval that still admits the attestation."""

JUST_BEYOND_DISPARITY_BOUNDARY_INTERVAL = DISPARITY_BOUNDARY_INTERVAL - Interval(1)
"""First local interval that rejects the attestation."""

ONE_FULL_SLOT_BEHIND_INTERVAL = ATTESTATION_START_INTERVAL - Interval(int(INTERVALS_PER_SLOT))
"""Local interval one full slot behind the attestation's slot start."""


class TestValidateAttestationHeadChecks:
    """Head checkpoint must be consistent and at least as recent as source and target."""

    def test_head_checkpoint_slot_mismatch_rejected(
        self,
        spec: LstarSpec,
        observer_store: Store,
    ) -> None:
        """Head checkpoint slot must match the actual block slot."""
        store = observer_store

        # Build a one-block chain on top of genesis.
        # This gives us a real block whose actual slot is 1.
        slot_1 = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = spec.produce_block_with_signatures(store, slot_1, proposer)
        block_root = hash_tree_root(block)

        genesis_root = store.latest_justified.root

        # Craft an attestation where the head checkpoint claims slot 999.
        # The block actually lives at slot 1.
        # This violates the consistency check: checkpoint slot must match block slot.
        attestation = Attestation(
            validator_index=ValidatorIndex(0),
            data=AttestationData(
                slot=slot_1,
                head=Checkpoint(root=block_root, slot=Slot(999)),
                target=Checkpoint(root=block_root, slot=slot_1),
                source=Checkpoint(root=genesis_root, slot=Slot(0)),
            ),
        )

        with pytest.raises(AssertionError, match="Head checkpoint slot mismatch"):
            spec.validate_attestation(store, attestation.data)

    def test_head_slot_less_than_source_rejected(
        self,
        spec: LstarSpec,
        observer_store: Store,
    ) -> None:
        """Head cannot be older than the justified source."""
        store = observer_store

        # Build two blocks so we have three known slots: genesis (0), slot 1, slot 2.
        slot_1 = Slot(1)
        slot_2 = Slot(2)
        proposer = ValidatorIndex(1)
        store, block_1, _ = spec.produce_block_with_signatures(store, slot_1, proposer)
        block_1_root = hash_tree_root(block_1)

        store, block_2, _ = spec.produce_block_with_signatures(store, slot_2, ValidatorIndex(2))
        block_2_root = hash_tree_root(block_2)

        genesis_root = store.latest_justified.root

        # Point the head back to genesis (slot 0) while source is at slot 1.
        # Time flows forward: the chain tip cannot be older than the justified source.
        # Since source <= target is enforced first, head < source also means head < target.
        # The topology check catches this via the head >= target assertion.
        attestation = Attestation(
            validator_index=ValidatorIndex(0),
            data=AttestationData(
                slot=slot_2,
                head=Checkpoint(root=genesis_root, slot=Slot(0)),
                target=Checkpoint(root=block_2_root, slot=slot_2),
                source=Checkpoint(root=block_1_root, slot=slot_1),
            ),
        )

        with pytest.raises(AssertionError, match="Head checkpoint must not be older than target"):
            spec.validate_attestation(store, attestation.data)

    def test_head_slot_less_than_target_rejected(
        self,
        spec: LstarSpec,
        observer_store: Store,
    ) -> None:
        """Head cannot be older than the target."""
        store = observer_store

        # Two blocks again: slot 1 and slot 2.
        slot_1 = Slot(1)
        slot_2 = Slot(2)
        proposer = ValidatorIndex(1)
        store, block_1, _ = spec.produce_block_with_signatures(store, slot_1, proposer)
        block_1_root = hash_tree_root(block_1)

        store, block_2, _ = spec.produce_block_with_signatures(store, slot_2, ValidatorIndex(2))
        block_2_root = hash_tree_root(block_2)

        genesis_root = store.latest_justified.root

        # Head at slot 1, target at slot 2.
        # The head is the chain tip a validator votes for.
        # It must be at least as recent as the target checkpoint.
        # Slot 1 < slot 2 violates this ordering.
        attestation = Attestation(
            validator_index=ValidatorIndex(0),
            data=AttestationData(
                slot=slot_2,
                head=Checkpoint(root=block_1_root, slot=slot_1),
                target=Checkpoint(root=block_2_root, slot=slot_2),
                source=Checkpoint(root=genesis_root, slot=Slot(0)),
            ),
        )

        with pytest.raises(AssertionError, match="Head checkpoint must not be older than target"):
            spec.validate_attestation(store, attestation.data)

    def test_valid_attestation_with_correct_head_passes(
        self,
        spec: LstarSpec,
        observer_store: Store,
    ) -> None:
        """An attestation with all checkpoints consistent should pass."""
        store = observer_store

        # Produce a single block at slot 1.
        slot_1 = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = spec.produce_block_with_signatures(store, slot_1, proposer)
        block_root = hash_tree_root(block)

        genesis_root = store.latest_justified.root

        # All checkpoints are well-ordered and consistent:
        #
        # - Source: genesis at slot 0 (justified ancestor)
        # - Target: block at slot 1 (finalization target)
        # - Head: same block at slot 1 (chain tip)
        #
        # Source <= target <= head, and all slots match their blocks.
        # This should pass every validation stage.
        attestation = Attestation(
            validator_index=ValidatorIndex(0),
            data=AttestationData(
                slot=slot_1,
                head=Checkpoint(root=block_root, slot=slot_1),
                target=Checkpoint(root=block_root, slot=slot_1),
                source=Checkpoint(root=genesis_root, slot=Slot(0)),
            ),
        )

        spec.validate_attestation(store, attestation.data)

    def test_head_equal_to_source_and_target_passes(
        self,
        spec: LstarSpec,
        observer_store: Store,
    ) -> None:
        """All three checkpoints pointing to genesis (slot 0) is valid."""
        store = observer_store

        genesis_root = store.latest_justified.root

        # All three checkpoints reference the same genesis block at slot 0.
        # This is the degenerate case: no chain progress yet.
        # The ordering source <= target <= head holds trivially (0 <= 0 <= 0).
        genesis_checkpoint = Checkpoint(root=genesis_root, slot=Slot(0))

        attestation = Attestation(
            validator_index=ValidatorIndex(0),
            data=AttestationData(
                slot=Slot(0),
                head=genesis_checkpoint,
                target=genesis_checkpoint,
                source=genesis_checkpoint,
            ),
        )

        spec.validate_attestation(store, attestation.data)


def _add_known_block(
    store: Store,
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_seed: int,
) -> Bytes32:
    """Insert a block at the given slot into the store, reusing the justified state."""
    block = make_signed_block(
        slot=slot,
        proposer_index=proposer_index,
        parent_root=parent_root,
        state_root=make_bytes32(state_seed),
    ).block
    block_root = hash_tree_root(block)
    store.blocks = {**store.blocks, block_root: block}
    store.states = {**store.states, block_root: store.states[store.latest_justified.root]}
    return block_root


class TestValidateAttestationAncestryChecks:
    """Source, target, and head must lie on one parent chain."""

    def test_proper_ancestor_chain_passes(
        self,
        spec: LstarSpec,
        observer_store: Store,
    ) -> None:
        """A vote whose checkpoints form one chain across three slots validates."""
        store = observer_store
        genesis_root = store.latest_justified.root
        target_root = _add_known_block(store, Slot(1), ValidatorIndex(1), genesis_root, 1)
        head_root = _add_known_block(store, Slot(2), ValidatorIndex(2), target_root, 2)
        store.time = Interval.from_slot(Slot(2))

        attestation_data = AttestationData(
            slot=Slot(2),
            source=Checkpoint(root=genesis_root, slot=Slot(0)),
            target=Checkpoint(root=target_root, slot=Slot(1)),
            head=Checkpoint(root=head_root, slot=Slot(2)),
        )

        spec.validate_attestation(store, attestation_data)

    def test_target_must_be_ancestor_of_head(
        self,
        spec: LstarSpec,
        observer_store: Store,
    ) -> None:
        """A head on a sibling fork must not validate against this target."""
        store = observer_store
        genesis_root = store.latest_justified.root
        target_root = _add_known_block(store, Slot(1), ValidatorIndex(1), genesis_root, 1)
        sibling_head_root = _add_known_block(store, Slot(2), ValidatorIndex(2), genesis_root, 2)
        store.time = Interval.from_slot(Slot(2))

        attestation_data = AttestationData(
            slot=Slot(2),
            source=Checkpoint(root=genesis_root, slot=Slot(0)),
            target=Checkpoint(root=target_root, slot=Slot(1)),
            head=Checkpoint(root=sibling_head_root, slot=Slot(2)),
        )

        with pytest.raises(AssertionError, match="Target checkpoint must be ancestor of head"):
            spec.validate_attestation(store, attestation_data)

    def test_source_must_be_ancestor_of_target(
        self,
        spec: LstarSpec,
        observer_store: Store,
    ) -> None:
        """A source on a sibling fork must not validate against this target."""
        store = observer_store
        genesis_root = store.latest_justified.root
        source_root = _add_known_block(store, Slot(1), ValidatorIndex(1), genesis_root, 1)
        target_parent_root = _add_known_block(store, Slot(1), ValidatorIndex(2), genesis_root, 2)
        target_root = _add_known_block(store, Slot(2), ValidatorIndex(2), target_parent_root, 3)
        store.time = Interval.from_slot(Slot(2))

        attestation_data = AttestationData(
            slot=Slot(2),
            source=Checkpoint(root=source_root, slot=Slot(1)),
            target=Checkpoint(root=target_root, slot=Slot(2)),
            head=Checkpoint(root=target_root, slot=Slot(2)),
        )

        with pytest.raises(AssertionError, match="Source checkpoint must be ancestor of target"):
            spec.validate_attestation(store, attestation_data)

    def test_head_with_unknown_parent_chain_rejected(
        self,
        spec: LstarSpec,
        observer_store: Store,
    ) -> None:
        """A head whose parent chain leaves the store cannot prove ancestry."""
        store = observer_store
        genesis_root = store.latest_justified.root
        target_root = _add_known_block(store, Slot(1), ValidatorIndex(1), genesis_root, 1)
        orphan_head_root = _add_known_block(store, Slot(2), ValidatorIndex(2), make_bytes32(99), 2)
        store.time = Interval.from_slot(Slot(2))

        attestation_data = AttestationData(
            slot=Slot(2),
            source=Checkpoint(root=genesis_root, slot=Slot(0)),
            target=Checkpoint(root=target_root, slot=Slot(1)),
            head=Checkpoint(root=orphan_head_root, slot=Slot(2)),
        )

        with pytest.raises(AssertionError, match="Target checkpoint must be ancestor of head"):
            spec.validate_attestation(store, attestation_data)


class TestValidateAttestationTimeCheck:
    """
    Time check boundaries.

    Each case sets `store.time` explicitly to isolate the time check from
    on_tick side effects (aggregation, safe-target update, acceptance).
    """

    @staticmethod
    def _build_two_block_chain(spec: LstarSpec, store: Store) -> tuple[Store, AttestationData]:
        """Produce blocks at slots 1 and ATTESTATION_SLOT; return ATTESTATION_SLOT data."""
        store, _, _ = spec.produce_block_with_signatures(store, Slot(1), ValidatorIndex(1))
        store, block_2, _ = spec.produce_block_with_signatures(
            store, ATTESTATION_SLOT, ValidatorIndex(int(ATTESTATION_SLOT))
        )
        block_2_root = hash_tree_root(block_2)
        genesis_root = store.latest_justified.root

        attestation_data = AttestationData(
            slot=ATTESTATION_SLOT,
            head=Checkpoint(root=block_2_root, slot=ATTESTATION_SLOT),
            target=Checkpoint(root=block_2_root, slot=ATTESTATION_SLOT),
            source=Checkpoint(root=genesis_root, slot=Slot(0)),
        )
        return store, attestation_data

    def test_attestation_at_current_slot_passes(
        self, spec: LstarSpec, observer_store: Store
    ) -> None:
        """A vote at the current slot is always accepted, every interval."""
        store, attestation_data = self._build_two_block_chain(spec, observer_store)

        # Sweep every interval in the attestation's slot.
        for offset in range(int(INTERVALS_PER_SLOT)):
            store.time = ATTESTATION_START_INTERVAL + Interval(offset)
            local = store
            spec.validate_attestation(local, attestation_data)

    def test_attestation_in_past_passes(self, spec: LstarSpec, observer_store: Store) -> None:
        """A vote from a past slot is always accepted."""
        store, attestation_data = self._build_two_block_chain(spec, observer_store)

        # Place the local clock several slots ahead.
        far_future = ATTESTATION_START_INTERVAL + Interval(int(INTERVALS_PER_SLOT) * 10)
        store.time = far_future
        spec.validate_attestation(store, attestation_data)

    def test_attestation_at_disparity_boundary_passes(
        self, spec: LstarSpec, observer_store: Store
    ) -> None:
        """At the disparity boundary the attestation is still accepted."""
        store, attestation_data = self._build_two_block_chain(spec, observer_store)

        store.time = DISPARITY_BOUNDARY_INTERVAL
        spec.validate_attestation(store, attestation_data)

    def test_attestation_just_beyond_disparity_boundary_rejected(
        self, spec: LstarSpec, observer_store: Store
    ) -> None:
        """One interval past the disparity boundary the attestation is rejected."""
        store, attestation_data = self._build_two_block_chain(spec, observer_store)

        store.time = JUST_BEYOND_DISPARITY_BOUNDARY_INTERVAL

        with pytest.raises(AssertionError, match="Attestation too far in future"):
            spec.validate_attestation(store, attestation_data)

    def test_attestation_one_full_slot_in_future_rejected(
        self, spec: LstarSpec, observer_store: Store
    ) -> None:
        """
        Regression: a full-slot future window must be rejected.

        An earlier rule admitted votes up to a full slot ahead.
        That window let an adversary pre-publish next-slot aggregates
        before any honest validator could produce them.
        """
        store, attestation_data = self._build_two_block_chain(spec, observer_store)

        store.time = ONE_FULL_SLOT_BEHIND_INTERVAL

        with pytest.raises(AssertionError, match="Attestation too far in future"):
            spec.validate_attestation(store, attestation_data)


def test_prunes_entries_with_head_at_finalized(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify entries with head.slot == finalized slot are pruned."""
    store = pruning_store

    # Create attestation data with head.slot == 5
    attestation_data = make_attestation_data(
        slot=Slot(5),
        target_slot=Slot(5),
        target_root=make_bytes32(1),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )

    # Set up store with attestation data and finalized slot at 5
    store.attestation_signatures = {
        attestation_data: {AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())},
    }
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify data exists before pruning
    assert attestation_data in store.attestation_signatures

    # Prune should remove entries where head.slot <= finalized.slot
    pruned_store = spec.prune_stale_attestation_data(store)

    assert attestation_data not in pruned_store.attestation_signatures


def test_prunes_entries_with_head_before_finalized(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify entries with head.slot < finalized slot are pruned."""
    store = pruning_store

    # Create attestation data with head.slot == 3
    attestation_data = make_attestation_data(
        slot=Slot(3),
        target_slot=Slot(3),
        target_root=make_bytes32(1),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )

    # Set up store with finalized slot at 5 (greater than head.slot)
    store.attestation_signatures = {
        attestation_data: {AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())},
    }
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify data exists before pruning
    assert attestation_data in store.attestation_signatures

    # Prune should remove entries where head.slot <= finalized.slot
    pruned_store = spec.prune_stale_attestation_data(store)

    assert attestation_data not in pruned_store.attestation_signatures


def test_keeps_entries_with_head_after_finalized(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify entries with head.slot > finalized slot are kept."""
    store = pruning_store

    # Create attestation data with head.slot == 10
    attestation_data = make_attestation_data(
        slot=Slot(10),
        target_slot=Slot(10),
        target_root=make_bytes32(1),
        source_slot=Slot(5),
        source_root=make_bytes32(2),
    )

    # Set up store with finalized slot at 5 (less than head.slot)
    store.attestation_signatures = {
        attestation_data: {AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())},
    }
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify data exists before pruning
    assert attestation_data in store.attestation_signatures

    # Prune should keep entries where head.slot > finalized.slot
    pruned_store = spec.prune_stale_attestation_data(store)

    assert attestation_data in pruned_store.attestation_signatures


def test_keeps_finalized_target_when_head_after_finalized(
    spec: LstarSpec, pruning_store: Store
) -> None:
    """A finalized target is still useful while the attested head is unfinalized."""
    store = pruning_store
    finalized = make_checkpoint(root_seed=1, slot=5)
    head = make_checkpoint(root_seed=2, slot=6)
    attestation_data = AttestationData(
        slot=Slot(6),
        head=head,
        target=finalized,
        source=make_checkpoint(root_seed=0, slot=0),
    )

    placeholder = ByteList512KiB(data=b"")
    mock_proof = SingleMessageAggregate(
        participants=AggregationBits.from_indices([ValidatorIndex(1)]),
        proof=placeholder,
    )
    signature = AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())

    store.attestation_signatures = {attestation_data: {signature}}
    store.latest_new_aggregated_payloads = {attestation_data: {mock_proof}}
    store.latest_known_aggregated_payloads = {attestation_data: {mock_proof}}
    store.latest_finalized = finalized

    pruned_store = spec.prune_stale_attestation_data(store)

    assert attestation_data in pruned_store.attestation_signatures
    assert attestation_data in pruned_store.latest_new_aggregated_payloads
    assert attestation_data in pruned_store.latest_known_aggregated_payloads


def test_prunes_related_structures_together(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify all three data structures are pruned atomically."""
    store = pruning_store

    # Create stale attestation data
    stale_attestation = make_attestation_data(
        slot=Slot(3),
        target_slot=Slot(3),
        target_root=make_bytes32(1),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )

    # Create fresh attestation data
    fresh_attestation = make_attestation_data(
        slot=Slot(10),
        target_slot=Slot(10),
        target_root=make_bytes32(2),
        source_slot=Slot(5),
        source_root=make_bytes32(255),
    )

    # Create mock aggregated proof (empty proof data for testing)
    placeholder = ByteList512KiB(data=b"")
    mock_proof = SingleMessageAggregate(
        participants=AggregationBits.from_indices([ValidatorIndex(1)]),
        proof=placeholder,
    )

    # Set up store with both stale and fresh entries in all structures
    store.attestation_signatures = {
        stale_attestation: {AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature())},
        fresh_attestation: {AttestationSignatureEntry(ValidatorIndex(2), make_mock_signature())},
    }
    store.latest_new_aggregated_payloads = {
        stale_attestation: {mock_proof},
        fresh_attestation: {mock_proof},
    }
    store.latest_known_aggregated_payloads = {
        stale_attestation: {mock_proof},
        fresh_attestation: {mock_proof},
    }
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify all data exists before pruning
    assert stale_attestation in store.attestation_signatures
    assert stale_attestation in store.latest_new_aggregated_payloads
    assert stale_attestation in store.latest_known_aggregated_payloads
    assert fresh_attestation in store.attestation_signatures
    assert fresh_attestation in store.latest_new_aggregated_payloads
    assert fresh_attestation in store.latest_known_aggregated_payloads

    pruned_store = spec.prune_stale_attestation_data(store)

    # Stale entries should be removed from all structures
    assert stale_attestation not in pruned_store.attestation_signatures
    assert stale_attestation not in pruned_store.latest_new_aggregated_payloads
    assert stale_attestation not in pruned_store.latest_known_aggregated_payloads

    # Fresh entries should be preserved in all structures
    assert fresh_attestation in pruned_store.attestation_signatures
    assert fresh_attestation in pruned_store.latest_new_aggregated_payloads
    assert fresh_attestation in pruned_store.latest_known_aggregated_payloads


def test_handles_empty_attestation_signatures(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify pruning works correctly when attestation_signatures is empty."""
    store = pruning_store

    # Ensure store has empty gossip signatures
    assert len(store.attestation_signatures) == 0

    # Pruning should not fail
    pruned_store = spec.prune_stale_attestation_data(store)

    assert len(pruned_store.attestation_signatures) == 0


def test_prunes_multiple_validators_same_attestation_data(
    spec: LstarSpec, pruning_store: Store
) -> None:
    """Verify pruning removes entries for multiple validators with same attestation data."""
    store = pruning_store

    # Create stale attestation data
    stale_attestation = make_attestation_data(
        slot=Slot(3),
        target_slot=Slot(3),
        target_root=make_bytes32(1),
        source_slot=Slot(0),
        source_root=Bytes32.zero(),
    )

    # Multiple validators signed the same attestation data
    store.attestation_signatures = {
        stale_attestation: {
            AttestationSignatureEntry(ValidatorIndex(1), make_mock_signature()),
            AttestationSignatureEntry(ValidatorIndex(2), make_mock_signature()),
        },
    }
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify data exists before pruning
    assert stale_attestation in store.attestation_signatures
    assert len(store.attestation_signatures[stale_attestation]) == 2

    pruned_store = spec.prune_stale_attestation_data(store)

    # All validators' signatures should be removed (whole entry pruned)
    assert stale_attestation not in pruned_store.attestation_signatures


def test_mixed_stale_and_fresh_entries(spec: LstarSpec, pruning_store: Store) -> None:
    """Verify correct pruning behavior with a mix of stale and fresh entries."""
    store = pruning_store

    # Create multiple attestations at different slots
    attestations = [
        make_attestation_data(
            slot=Slot(i),
            target_slot=Slot(i),
            target_root=Bytes32(bytes([i]) * 32),
            source_slot=Slot(0),
            source_root=Bytes32.zero(),
        )
        for i in range(1, 11)  # Slots 1-10
    ]

    gossip_signatures = {
        attestation: {AttestationSignatureEntry(ValidatorIndex(i), make_mock_signature())}
        for i, attestation in enumerate(attestations, start=1)
    }

    # Finalized at slot 5 means slots 1-5 are stale, 6-10 are fresh
    store.attestation_signatures = gossip_signatures
    store.latest_finalized = make_checkpoint(root_seed=255, slot=5)

    # Verify all data exists before pruning
    for attestation in attestations:
        assert attestation in store.attestation_signatures

    pruned_store = spec.prune_stale_attestation_data(store)

    # Entries with head.slot <= 5 should be pruned (slots 1-5)
    for attestation in attestations[:5]:
        assert attestation not in pruned_store.attestation_signatures

    # Entries with head.slot > 5 should be kept (slots 6-10)
    for attestation in attestations[5:]:
        assert attestation in pruned_store.attestation_signatures


class TestSafeTargetAdvancement:
    """Tests for safe target advancement with 2/3 majority attestations."""

    def test_safe_target_requires_supermajority(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Safe target should only advance with 2/3+ attestation support."""
        store = keyed_store

        # Produce a block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)
        block_root = hash_tree_root(block)

        # Add attestations from fewer than 2/3 of validators
        num_validators = len(store.states[block_root].validators)
        threshold = (num_validators * 2 + 2) // 3  # Ceiling of 2/3

        attestation_data = spec.produce_attestation_data(store, slot)

        # Create signed attestations and process them
        for i in range(threshold - 1):
            validator_index = ValidatorIndex(i)
            signature = key_manager.sign_attestation_data(validator_index, attestation_data)
            signed_attestation = SignedAttestation(
                validator_index=validator_index,
                data=attestation_data,
                signature=signature,
            )
            # Process as gossip (requires aggregator flag)
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        # Aggregate the signatures
        store, _ = spec.aggregate(store)

        # Update safe target (uses latest_new_aggregated_payloads)
        store = spec.update_safe_target(store)

        # Safe target should still be at genesis (insufficient votes)
        current_safe_slot = store.blocks[store.safe_target].slot

        # Without enough attestations, safe_target should not have advanced
        # significantly past genesis
        assert current_safe_slot <= Slot(1)

    def test_safe_target_advances_with_supermajority(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Safe target should advance when 2/3+ validators attest to same target."""
        store = keyed_store

        # Produce a block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, _, _ = spec.produce_block_with_signatures(store, slot, proposer)

        # Get attestation data for slot 1
        attestation_data = spec.produce_attestation_data(store, slot)

        # Add attestations from at least 2/3 of validators
        num_validators = len(store.states[store.head].validators)
        threshold = (num_validators * 2 + 2) // 3

        # Create signed attestations and process them
        for i in range(threshold + 1):
            validator_index = ValidatorIndex(i)
            signature = key_manager.sign_attestation_data(validator_index, attestation_data)
            signed_attestation = SignedAttestation(
                validator_index=validator_index,
                data=attestation_data,
                signature=signature,
            )
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        # Aggregate the signatures
        store, _ = spec.aggregate(store)

        # Update safe target
        store = spec.update_safe_target(store)

        # Verify the aggregation produced payloads and safe target was updated.
        # Safe target advancement depends on the full 3SF-mini justification rules,
        # which may require multiple slots. This test verifies the pipeline works.
        assert store.safe_target in store.blocks

    def test_update_safe_target_uses_new_attestations(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """update_safe_target should use new aggregated payloads."""
        store = keyed_store

        # Produce block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)

        attestation_data = spec.produce_attestation_data(store, slot)
        num_validators = len(store.states[store.head].validators)

        # Create signed attestations and process them
        for i in range(num_validators):
            validator_index = ValidatorIndex(i)
            signature = key_manager.sign_attestation_data(validator_index, attestation_data)
            signed_attestation = SignedAttestation(
                validator_index=validator_index,
                data=attestation_data,
                signature=signature,
            )
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        # Aggregate into new payloads
        store, _ = spec.aggregate(store)

        # Update safe target should use new aggregated payloads
        store = spec.update_safe_target(store)

        # Verify update_safe_target processes new aggregated payloads without error
        assert store.safe_target in store.blocks


class TestJustificationLogic:
    """Tests for justification when 2/3 of validators attest to the same target."""

    def test_justification_with_supermajority_attestations(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Justification should occur when 2/3 validators attest to the same target."""
        store = keyed_store

        # Produce block at slot 1
        slot_1 = Slot(1)
        proposer_1 = ValidatorIndex(1)
        store, block_1, _ = spec.produce_block_with_signatures(store, slot_1, proposer_1)
        block_1_root = hash_tree_root(block_1)

        # Produce block at slot 2 with attestations to slot 1
        slot_2 = Slot(2)
        proposer_2 = ValidatorIndex(2)

        # Create attestation data targeting slot 1 block
        num_validators = len(store.states[block_1_root].validators)
        threshold = (num_validators * 2 + 2) // 3  # Ceiling of 2/3

        attestation_data = AttestationData(
            slot=slot_1,
            head=Checkpoint(root=block_1_root, slot=slot_1),
            target=Checkpoint(root=block_1_root, slot=slot_1),
            source=store.latest_justified,
        )

        # Add attestations from threshold validators using the new workflow
        for i in range(threshold + 1):
            validator_index = ValidatorIndex(i)
            signature = key_manager.sign_attestation_data(validator_index, attestation_data)
            signed_attestation = SignedAttestation(
                validator_index=validator_index,
                data=attestation_data,
                signature=signature,
            )
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        # Aggregate signatures before producing the next block
        store, _ = spec.aggregate(store)

        # Produce block 2 which includes these attestations
        store, block_2, signatures = spec.produce_block_with_signatures(store, slot_2, proposer_2)

        # Check that attestations were included
        assert len(block_2.body.attestations) > 0

        # The state should have updated justification
        block_2_root = hash_tree_root(block_2)
        post_state = store.states[block_2_root]

        # Justification should be present in the post-state
        assert post_state.latest_justified.root in store.blocks

    def test_justification_requires_valid_source(
        self,
        observer_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Attestations must have a valid (already justified) source."""
        store = observer_store

        # Produce block at slot 1
        slot = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)
        block_root = hash_tree_root(block)

        # Create attestation with invalid source (not justified)
        invalid_source = Checkpoint(
            root=Bytes32(b"invalid" + b"\x00" * 25),
            slot=Slot(999),
        )

        attestation = Attestation(
            validator_index=ValidatorIndex(5),
            data=AttestationData(
                slot=slot,
                head=Checkpoint(root=block_root, slot=slot),
                target=Checkpoint(root=block_root, slot=slot),
                source=invalid_source,
            ),
        )

        # This attestation should fail validation because source is unknown
        with pytest.raises(AssertionError, match="Unknown source block"):
            spec.validate_attestation(store, attestation.data)

    def test_justification_tracking_with_multiple_targets(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Justification should track votes for multiple potential targets."""
        store = keyed_store

        # Build a chain of blocks
        for slot_num in range(1, 4):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = spec.produce_block_with_signatures(store, slot, proposer)

        # Create attestations to different targets from different validators
        head_block = store.blocks[store.head]
        num_validators = len(store.states[store.head].validators)

        # Half validators attest to head
        attestation_data_head = spec.produce_attestation_data(store, head_block.slot)

        for i in range(num_validators // 2):
            validator_index = ValidatorIndex(i)
            signature = key_manager.sign_attestation_data(validator_index, attestation_data_head)
            signed_attestation = SignedAttestation(
                validator_index=validator_index,
                data=attestation_data_head,
                signature=signature,
            )
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        store, _ = spec.aggregate(store)
        store = spec.update_safe_target(store)

        # With only half the validators, safe target should not advance past genesis
        assert store.blocks[store.safe_target].slot == Slot(0)


class TestFinalizationFollowsJustification:
    """Tests for finalization behavior following justification."""

    def test_finalization_after_consecutive_justification(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Finalization should follow when justification advances without gaps."""
        store = keyed_store
        num_validators = len(store.states[store.head].validators)
        threshold = (num_validators * 2 + 2) // 3

        initial_finalized = store.latest_finalized

        # Build several blocks with full attestation support
        for slot_num in range(1, 5):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % num_validators)

            # Create attestations from all validators for the previous block
            if slot_num > 1:
                previous_head = store.head
                previous_block = store.blocks[previous_head]
                attestation_data = AttestationData(
                    slot=previous_block.slot,
                    head=Checkpoint(root=previous_head, slot=previous_block.slot),
                    target=Checkpoint(root=previous_head, slot=previous_block.slot),
                    source=store.latest_justified,
                )

                for i in range(threshold + 1):
                    validator_index = ValidatorIndex(i)
                    signature = key_manager.sign_attestation_data(validator_index, attestation_data)
                    signed_attestation = SignedAttestation(
                        validator_index=validator_index,
                        data=attestation_data,
                        signature=signature,
                    )
                    store = spec.on_gossip_attestation(
                        store, signed_attestation, is_aggregator=True
                    )

            store, block, _ = spec.produce_block_with_signatures(store, slot, proposer)

        # After processing blocks with attestations, check finalization
        # The exact finalization behavior depends on 3SF-mini rules
        final_finalized = store.latest_finalized

        # Finalization can advance if justification conditions are met
        assert final_finalized.slot >= initial_finalized.slot


class TestAttestationTargetEdgeCases:
    """Tests for edge cases in attestation target computation."""

    def test_attestation_target_with_skipped_slots(
        self,
        observer_store: Store,
        spec: LstarSpec,
    ) -> None:
        """Attestation target should handle chains with skipped slots."""
        store = observer_store

        # Produce blocks with gaps (skipped slots)
        store, _, _ = spec.produce_block_with_signatures(store, Slot(1), ValidatorIndex(1))
        # Skip slot 2, 3
        store, _, _ = spec.produce_block_with_signatures(store, Slot(4), ValidatorIndex(4))

        target = spec.get_attestation_target(store)

        # Target should still be valid despite skipped slots
        assert target.root in store.blocks
        assert target.slot.is_justifiable_after(store.latest_finalized.slot)

    def test_attestation_target_single_validator(
        self,
        spec: LstarSpec,
        key_manager: XmssKeyManager,
    ) -> None:
        """Attestation target computation should work with single validator."""
        store = make_store(num_validators=1, key_manager=key_manager, validator_index=None)

        # Should be able to get attestation target
        target = spec.get_attestation_target(store)
        assert target.root == store.head

    def test_attestation_target_at_justification_lookback_boundary(
        self,
        observer_store: Store,
        spec: LstarSpec,
    ) -> None:
        """Test target when head is exactly JUSTIFICATION_LOOKBACK_SLOTS ahead."""
        store = observer_store

        # Build chain to exactly JUSTIFICATION_LOOKBACK_SLOTS + 1 blocks
        lookback = int(JUSTIFICATION_LOOKBACK_SLOTS)
        for slot_num in range(1, lookback + 2):
            slot = Slot(slot_num)
            proposer = ValidatorIndex(slot_num % len(store.states[store.head].validators))
            store, _, _ = spec.produce_block_with_signatures(store, slot, proposer)

        target = spec.get_attestation_target(store)
        head_slot = store.blocks[store.head].slot

        # Target should not be more than JUSTIFICATION_LOOKBACK_SLOTS behind head
        assert int(target.slot) >= int(head_slot) - int(JUSTIFICATION_LOOKBACK_SLOTS)


class TestIntegrationScenarios:
    """Integration tests combining attestation target, justification, and finalization."""

    def test_full_attestation_cycle(
        self,
        keyed_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Test complete cycle: produce block, attest, justify."""
        store = keyed_store

        # Phase 1: Produce initial block
        slot_1 = Slot(1)
        proposer_1 = ValidatorIndex(1)
        store, block_1, _ = spec.produce_block_with_signatures(store, slot_1, proposer_1)
        block_1_root = hash_tree_root(block_1)

        # Phase 2: Create attestations from multiple validators
        attestation_data = spec.produce_attestation_data(store, slot_1)

        num_validators = len(store.states[block_1_root].validators)
        for i in range(num_validators):
            validator_index = ValidatorIndex(i)
            signature = key_manager.sign_attestation_data(validator_index, attestation_data)
            signed_attestation = SignedAttestation(
                validator_index=validator_index,
                data=attestation_data,
                signature=signature,
            )
            # Process as gossip
            store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        # Phase 3: Aggregate signatures into payloads
        store, _ = spec.aggregate(store)

        # Phase 4: Update safe target
        store = spec.update_safe_target(store)

        # Verify the full cycle completed: safe target is a valid block in the store
        assert store.safe_target in store.blocks

        # Phase 5: Produce another block including attestations
        slot_2 = Slot(2)
        proposer_2 = ValidatorIndex(2)
        store, block_2, _ = spec.produce_block_with_signatures(store, slot_2, proposer_2)

        # Verify final state
        assert len(store.blocks) >= 3  # Genesis + 2 blocks
        assert store.head in store.blocks
        assert store.safe_target in store.blocks

    def test_attestation_target_after_on_block(
        self,
        observer_store: Store,
        key_manager: XmssKeyManager,
        spec: LstarSpec,
    ) -> None:
        """Test attestation target is correct after processing a block via on_block."""
        store = observer_store

        # Produce a block
        slot_1 = Slot(1)
        proposer_1 = ValidatorIndex(1)
        store, block, signatures = spec.produce_block_with_signatures(store, slot_1, proposer_1)
        block_root = hash_tree_root(block)

        # Wrap the proposer's signature into a singleton single-message aggregate.
        # Merge it with the per-attestation single-message aggregates
        # into the block-level multi-message aggregate.
        proposer_signature = key_manager.sign_block_root(proposer_1, slot_1, block_root)
        proposer_public_key = key_manager.get_public_keys(proposer_1)[1]
        proposer_single_message_aggregate = SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=[(proposer_1, proposer_public_key, proposer_signature)],
            message=block_root,
            slot=slot_1,
        )

        head_state = store.states[store.head]
        public_keys_per_aggregate: list[list] = [
            [
                head_state.validators[validator_index].get_attestation_public_key()
                for validator_index in proof.participants.to_validator_indices()
            ]
            for proof in signatures
        ]
        public_keys_per_aggregate.append([proposer_public_key])

        merged = MultiMessageAggregate.aggregate(
            [*signatures, proposer_single_message_aggregate],
            public_keys_per_aggregate=public_keys_per_aggregate,
        )
        signed_block = SignedBlock(
            block=block,
            proof=merged,
        )

        # Process block via on_block on a fresh consumer store
        consumer_store = observer_store
        target_interval = Interval.from_slot(block.slot)
        consumer_store, _ = spec.on_tick(consumer_store, target_interval, has_proposal=True)
        consumer_store = spec.on_block(consumer_store, signed_block)

        # Get attestation target after on_block
        target = spec.get_attestation_target(consumer_store)

        # Target should be valid
        assert target.root in consumer_store.blocks
        assert target.slot.is_justifiable_after(consumer_store.latest_finalized.slot)


def test_on_block_processes_multi_validator_aggregations(
    key_manager: XmssKeyManager, spec: LstarSpec
) -> None:
    """Ensure Store.on_block handles aggregated attestations with many validators."""
    base_store = make_store(num_validators=3, key_manager=key_manager)

    # Producer view knows about attestations from validators 1 and 2
    attestation_slot = Slot(1)
    attestation_data = spec.produce_attestation_data(base_store, attestation_slot)

    participants = [ValidatorIndex(1), ValidatorIndex(2)]

    proof = make_aggregated_proof(key_manager, participants, attestation_data)

    aggregated_payloads = {attestation_data: {proof}}

    base_store.latest_known_aggregated_payloads = aggregated_payloads
    producer_store = base_store

    proposer_index = ValidatorIndex(1)
    consumer_store, signed_block = make_signed_block_from_store(
        producer_store, key_manager, attestation_slot, proposer_index
    )

    updated_store = spec.on_block(consumer_store, signed_block)

    # Verify attestations can be extracted from aggregated payloads
    extracted_attestations = spec.extract_attestations_from_aggregated_payloads(
        updated_store, updated_store.latest_known_aggregated_payloads
    )
    assert ValidatorIndex(1) in extracted_attestations
    assert ValidatorIndex(2) in extracted_attestations
    assert extracted_attestations[ValidatorIndex(1)] == attestation_data
    assert extracted_attestations[ValidatorIndex(2)] == attestation_data


def test_on_block_preserves_immutability_of_aggregated_payloads(
    key_manager: XmssKeyManager,
    spec: LstarSpec,
) -> None:
    """Verify that Store.on_block doesn't mutate previous store's latest_new_aggregated_payloads."""
    base_store = make_store(
        num_validators=3, key_manager=key_manager, validator_index=TEST_VALIDATOR_INDEX
    )

    # First block with attestations from validators 1 and 2
    attestation_slot_1 = Slot(1)
    attestation_data_1 = spec.produce_attestation_data(base_store, attestation_slot_1)

    gossip_signatures_1 = {
        attestation_data_1: {
            AttestationSignatureEntry(
                validator_index,
                key_manager.sign_attestation_data(validator_index, attestation_data_1),
            )
            for validator_index in (ValidatorIndex(1), ValidatorIndex(2))
        },
    }

    base_store.attestation_signatures = gossip_signatures_1
    producer_store_1 = base_store

    consumer_store_1, signed_block_1 = make_signed_block_from_store(
        producer_store_1, key_manager, attestation_slot_1, ValidatorIndex(1)
    )
    store_after_block_1 = spec.on_block(consumer_store_1, signed_block_1)

    # Second block with attestations for the SAME validators
    attestation_slot_2 = Slot(2)
    attestation_data_2 = spec.produce_attestation_data(store_after_block_1, attestation_slot_2)

    gossip_signatures_2 = {
        attestation_data_2: {
            AttestationSignatureEntry(
                validator_index,
                key_manager.sign_attestation_data(validator_index, attestation_data_2),
            )
            for validator_index in (ValidatorIndex(1), ValidatorIndex(2))
        },
    }

    store_after_block_1.attestation_signatures = gossip_signatures_2
    producer_store_2 = store_after_block_1

    store_before_block_2, signed_block_2 = make_signed_block_from_store(
        producer_store_2, key_manager, attestation_slot_2, ValidatorIndex(2)
    )

    # Capture the original list lengths for keys that already exist
    new_payloads_before = store_before_block_2.latest_new_aggregated_payloads
    original_signature_lengths = {
        attestation_data: len(signatures)
        for attestation_data, signatures in new_payloads_before.items()
    }

    # Process the second block
    store_after_block_2 = spec.on_block(store_before_block_2, signed_block_2)

    # Verify immutability: the list lengths in store_before_block_2 should not have changed
    for key, original_length in original_signature_lengths.items():
        current_length = len(store_before_block_2.latest_new_aggregated_payloads[key])
        assert current_length == original_length, (
            f"Immutability violated: list for key {key} grew from {original_length} to "
            f"{current_length}"
        )

    # Verify that the updated store has new keys (different attestation data in block 2)
    # The key point is that store_before_block_2 wasn't mutated
    assert len(store_after_block_2.latest_new_aggregated_payloads) >= len(
        store_before_block_2.latest_new_aggregated_payloads
    )


class TestOnGossipAttestationImportGating:
    """
    Unit tests for on_gossip_attestation import gating.

    Subnet filtering happens at the p2p subscription layer — only attestations
    from subscribed subnets are delivered to the store. The store's sole gate
    is is_aggregator: aggregators store everything they receive, non-aggregators
    drop everything.
    """

    def test_aggregator_stores_received_attestation(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """Aggregator stores any attestation that reaches the store."""
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(1)

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=8, validator_index=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_index=attester_validator,
            data=attestation_data,
            signature=key_manager.sign_attestation_data(attester_validator, attestation_data),
        )

        assert attestation_data not in store.attestation_signatures, (
            "Precondition: no signatures before processing"
        )

        updated_store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=True)

        signatures = updated_store.attestation_signatures.get(attestation_data, set())
        assert attester_validator in {
            stored_signature.validator_index for stored_signature in signatures
        }, "Aggregator should store any attestation it receives"

    def test_aggregator_stores_multiple_attestations(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """Aggregator stores all attestations regardless of which validator sent them."""
        current_validator = ValidatorIndex(0)
        attesters = [ValidatorIndex(1), ValidatorIndex(2), ValidatorIndex(3)]

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=8, validator_index=current_validator
        )

        def make_signed(attester: ValidatorIndex) -> SignedAttestation:
            return SignedAttestation(
                validator_index=attester,
                data=attestation_data,
                signature=key_manager.sign_attestation_data(attester, attestation_data),
            )

        updated_store = store
        for attester in attesters:
            updated_store = spec.on_gossip_attestation(
                updated_store, make_signed(attester), is_aggregator=True
            )

        stored_validator_indices = {
            stored_signature.validator_index
            for stored_signature in updated_store.attestation_signatures.get(
                attestation_data, set()
            )
        }
        assert stored_validator_indices == set(attesters), (
            "Aggregator should store attestations from all received validators"
        )

    def test_non_aggregator_never_stores_signature(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """Non-aggregator nodes drop all gossip attestations regardless of sender."""
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(1)

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=8, validator_index=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_index=attester_validator,
            data=attestation_data,
            signature=key_manager.sign_attestation_data(attester_validator, attestation_data),
        )

        updated_store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=False)

        signatures = updated_store.attestation_signatures.get(attestation_data, set())
        assert attester_validator not in {
            stored_signature.validator_index for stored_signature in signatures
        }, "Non-aggregator should never store gossip signatures"

    def test_non_aggregator_does_not_create_signatures_entry(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """Non-aggregator leaves attestation_signatures unchanged."""
        current_validator = ValidatorIndex(0)
        attester_validator = ValidatorIndex(1)

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=8, validator_index=current_validator
        )

        signed_attestation = SignedAttestation(
            validator_index=attester_validator,
            data=attestation_data,
            signature=key_manager.sign_attestation_data(attester_validator, attestation_data),
        )

        updated_store = spec.on_gossip_attestation(store, signed_attestation, is_aggregator=False)

        assert attestation_data not in updated_store.attestation_signatures, (
            "Non-aggregator should not create any attestation_signatures entry"
        )


class TestOnGossipAggregatedAttestation:
    """
    Unit tests for on_gossip_aggregated_attestation.

    Tests aggregated proof verification and storage in latest_new_aggregated_payloads.
    """

    def test_valid_proof_stored_correctly(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """
        Valid aggregated attestation is verified and stored.

        The proof should be stored in latest_new_aggregated_payloads
        keyed by attestation data.
        """
        participants = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=4, validator_index=ValidatorIndex(0)
        )

        data_root = hash_tree_root(attestation_data)

        # Create valid aggregated proof
        raw_xmss = [
            (
                validator_index,
                key_manager[validator_index].attestation_keypair.public_key,
                key_manager.sign_attestation_data(validator_index, attestation_data),
            )
            for validator_index in participants
        ]
        proof = SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=raw_xmss,
            message=data_root,
            slot=attestation_data.slot,
        )

        signed_aggregated = SignedAggregatedAttestation(
            data=attestation_data,
            proof=proof,
        )

        updated_store = spec.on_gossip_aggregated_attestation(store, signed_aggregated)

        # Verify proof is stored keyed by attestation data
        assert attestation_data in updated_store.latest_new_aggregated_payloads, (
            "Proof should be stored for this attestation data"
        )
        proofs = updated_store.latest_new_aggregated_payloads[attestation_data]
        assert len(proofs) == 1
        assert proof in proofs

    def test_attestation_data_used_as_key(
        self, key_manager: XmssKeyManager, spec: LstarSpec
    ) -> None:
        """
        Attestation data is used directly as the key in aggregated payloads.

        Proofs are accessible by looking up the attestation data.
        """
        participants = [ValidatorIndex(1)]

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=4, validator_index=ValidatorIndex(0)
        )

        data_root = hash_tree_root(attestation_data)

        raw_xmss = [
            (
                validator_index,
                key_manager[validator_index].attestation_keypair.public_key,
                key_manager.sign_attestation_data(validator_index, attestation_data),
            )
            for validator_index in participants
        ]
        proof = SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=raw_xmss,
            message=data_root,
            slot=attestation_data.slot,
        )

        signed_aggregated = SignedAggregatedAttestation(
            data=attestation_data,
            proof=proof,
        )

        updated_store = spec.on_gossip_aggregated_attestation(store, signed_aggregated)

        assert attestation_data in updated_store.latest_new_aggregated_payloads
        assert proof in updated_store.latest_new_aggregated_payloads[attestation_data]

    def test_invalid_proof_rejected(self, key_manager: XmssKeyManager, spec: LstarSpec) -> None:
        """
        Corrupted aggregated proof is rejected with AssertionError.

        A proof with tampered bytes should fail verification.
        """
        signers = [ValidatorIndex(1), ValidatorIndex(2)]

        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=4, validator_index=ValidatorIndex(0)
        )

        data_root = hash_tree_root(attestation_data)

        raw_xmss = [
            (
                validator_index,
                key_manager[validator_index].attestation_keypair.public_key,
                key_manager.sign_attestation_data(validator_index, attestation_data),
            )
            for validator_index in signers
        ]
        proof = SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=raw_xmss,
            message=data_root,
            slot=attestation_data.slot,
        )

        # Corrupt the proof data
        corrupted_data = bytearray(proof.proof.data)
        corrupted_data[10] ^= 0xFF
        corrupted_data[20] ^= 0xFF
        corrupted_proof = SingleMessageAggregate(
            participants=proof.participants,
            proof=ByteList512KiB(data=bytes(corrupted_data)),
        )

        signed_aggregated = SignedAggregatedAttestation(
            data=attestation_data,
            proof=corrupted_proof,
        )

        with pytest.raises(AssertionError, match="signature verification failed"):
            spec.on_gossip_aggregated_attestation(store, signed_aggregated)

    def test_multiple_proofs_accumulate(self, key_manager: XmssKeyManager, spec: LstarSpec) -> None:
        """
        Multiple aggregated proofs for same validator accumulate.

        When a validator appears in multiple aggregated attestations,
        all proofs should be stored in the list.
        """
        store, attestation_data = make_store_with_attestation_data(
            key_manager, num_validators=4, validator_index=ValidatorIndex(0)
        )

        data_root = hash_tree_root(attestation_data)

        # First proof: validators 1 and 2
        participants_1 = [ValidatorIndex(1), ValidatorIndex(2)]
        raw_xmss_1 = [
            (
                validator_index,
                key_manager[validator_index].attestation_keypair.public_key,
                key_manager.sign_attestation_data(validator_index, attestation_data),
            )
            for validator_index in participants_1
        ]
        proof_1 = SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=raw_xmss_1,
            message=data_root,
            slot=attestation_data.slot,
        )

        # Second proof: validators 1 and 3 (validator 1 overlaps)
        participants_2 = [ValidatorIndex(1), ValidatorIndex(3)]
        raw_xmss_2 = [
            (
                validator_index,
                key_manager[validator_index].attestation_keypair.public_key,
                key_manager.sign_attestation_data(validator_index, attestation_data),
            )
            for validator_index in participants_2
        ]
        proof_2 = SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=raw_xmss_2,
            message=data_root,
            slot=attestation_data.slot,
        )

        store = spec.on_gossip_aggregated_attestation(
            store, SignedAggregatedAttestation(data=attestation_data, proof=proof_1)
        )
        store = spec.on_gossip_aggregated_attestation(
            store, SignedAggregatedAttestation(data=attestation_data, proof=proof_2)
        )

        # Both proofs should be stored under the same attestation data
        stored_proofs = store.latest_new_aggregated_payloads[attestation_data]
        assert len(stored_proofs) == 2
        assert proof_1 in stored_proofs, "First proof should be stored"
        assert proof_2 in stored_proofs, "Second proof should be stored"


class TestGetForkchoiceStore:
    """Test Store.from_anchor() time initialization."""

    @settings(max_examples=100)
    @given(anchor_slot=st.integers(min_value=0, max_value=10000))
    def test_store_time_from_anchor_slot(self, anchor_slot: int) -> None:
        """spec.create_store sets time = anchor_slot * INTERVALS_PER_SLOT."""
        # Must create its own state and block instead of using sample_store()
        # because sample_store() bypasses create_store() with hardcoded time.
        spec = LstarSpec()
        state = spec.generate_genesis(
            genesis_time=Uint64(1000),
            validators=Validators(data=[]),
        )
        state_root = hash_tree_root(state)

        anchor_block = Block(
            slot=Slot(anchor_slot),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=state_root,
            body=make_empty_block_body(),
        )

        store = spec.create_store(
            state,
            anchor_block,
            validator_index=TEST_VALIDATOR_INDEX,
        )

        assert store.time == Interval(int(INTERVALS_PER_SLOT) * anchor_slot)


class TestAttestationProcessingTiming:
    """Test timing of attestation processing."""

    def test_accept_new_attestations_basic(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test basic new attestation processing moves aggregated payloads."""
        # The method now processes aggregated payloads, not attestations directly
        # Just verify the method runs without error
        initial_known_payloads = len(sample_store.latest_known_aggregated_payloads)

        # Accept new attestations (which processes aggregated payloads)
        sample_store = spec.accept_new_attestations(sample_store)

        # New payloads should move to known payloads
        assert len(sample_store.latest_new_aggregated_payloads) == 0
        assert len(sample_store.latest_known_aggregated_payloads) >= initial_known_payloads

    def test_accept_new_attestations_multiple(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test accepting multiple new aggregated payloads."""
        # Aggregated payloads are now the source of attestations
        # The test is simplified to just test the migration logic
        sample_store = spec.accept_new_attestations(sample_store)

        # All new payloads should move to known payloads
        assert len(sample_store.latest_new_aggregated_payloads) == 0

    def test_accept_new_attestations_empty(self, sample_store: Store, spec: LstarSpec) -> None:
        """Test accepting new attestations when there are none."""
        initial_known_payloads = len(sample_store.latest_known_aggregated_payloads)

        # Accept attestations when there are no new payloads
        sample_store = spec.accept_new_attestations(sample_store)

        # Should be no-op
        assert len(sample_store.latest_new_aggregated_payloads) == 0
        assert len(sample_store.latest_known_aggregated_payloads) == initial_known_payloads
