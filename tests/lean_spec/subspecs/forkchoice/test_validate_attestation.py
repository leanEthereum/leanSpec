"""Tests for head checkpoint validation in validate_attestation."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.chain.config import GOSSIP_DISPARITY_INTERVALS, INTERVALS_PER_SLOT
from lean_spec.subspecs.containers import Attestation, AttestationData, Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root

# Slot used by every time-check case below.
ATTESTATION_SLOT = Slot(2)
"""Slot of the attestation under test."""

ATTESTATION_START_INTERVAL = Interval.from_slot(ATTESTATION_SLOT)
"""First interval at which ATTESTATION_SLOT begins."""

DISPARITY_BOUNDARY_INTERVAL = ATTESTATION_START_INTERVAL - GOSSIP_DISPARITY_INTERVALS
"""Latest local interval that still admits the attestation."""

JUST_BEYOND_DISPARITY_BOUNDARY_INTERVAL = DISPARITY_BOUNDARY_INTERVAL - Interval(1)
"""First local interval that rejects the attestation."""

ONE_FULL_SLOT_BEHIND_INTERVAL = ATTESTATION_START_INTERVAL - INTERVALS_PER_SLOT
"""Local interval one full slot behind the attestation's slot start."""


class TestValidateAttestationHeadChecks:
    """Head checkpoint must be consistent and at least as recent as source and target."""

    def test_head_checkpoint_slot_mismatch_rejected(
        self,
        observer_store: Store,
    ) -> None:
        """Head checkpoint slot must match the actual block slot."""
        store = observer_store

        # Build a one-block chain on top of genesis.
        # This gives us a real block whose actual slot is 1.
        slot_1 = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = store.produce_block_with_signatures(slot_1, proposer)
        block_root = hash_tree_root(block)

        genesis_root = store.latest_justified.root

        # Craft an attestation where the head checkpoint claims slot 999.
        # The block actually lives at slot 1.
        # This violates the consistency check: checkpoint slot must match block slot.
        attestation = Attestation(
            validator_id=ValidatorIndex(0),
            data=AttestationData(
                slot=slot_1,
                head=Checkpoint(root=block_root, slot=Slot(999)),
                target=Checkpoint(root=block_root, slot=slot_1),
                source=Checkpoint(root=genesis_root, slot=Slot(0)),
            ),
        )

        with pytest.raises(AssertionError, match="Head checkpoint slot mismatch"):
            store.validate_attestation(attestation.data)

    def test_head_slot_less_than_source_rejected(
        self,
        observer_store: Store,
    ) -> None:
        """Head cannot be older than the justified source."""
        store = observer_store

        # Build two blocks so we have three known slots: genesis (0), slot 1, slot 2.
        slot_1 = Slot(1)
        slot_2 = Slot(2)
        proposer = ValidatorIndex(1)
        store, block_1, _ = store.produce_block_with_signatures(slot_1, proposer)
        block_1_root = hash_tree_root(block_1)

        store, block_2, _ = store.produce_block_with_signatures(slot_2, ValidatorIndex(2))
        block_2_root = hash_tree_root(block_2)

        genesis_root = store.latest_justified.root

        # Point the head back to genesis (slot 0) while source is at slot 1.
        # Time flows forward: the chain tip cannot be older than the justified source.
        # Since source <= target is enforced first, head < source also means head < target.
        # The topology check catches this via the head >= target assertion.
        attestation = Attestation(
            validator_id=ValidatorIndex(0),
            data=AttestationData(
                slot=slot_2,
                head=Checkpoint(root=genesis_root, slot=Slot(0)),
                target=Checkpoint(root=block_2_root, slot=slot_2),
                source=Checkpoint(root=block_1_root, slot=slot_1),
            ),
        )

        with pytest.raises(AssertionError, match="Head checkpoint must not be older than target"):
            store.validate_attestation(attestation.data)

    def test_head_slot_less_than_target_rejected(
        self,
        observer_store: Store,
    ) -> None:
        """Head cannot be older than the target."""
        store = observer_store

        # Two blocks again: slot 1 and slot 2.
        slot_1 = Slot(1)
        slot_2 = Slot(2)
        proposer = ValidatorIndex(1)
        store, block_1, _ = store.produce_block_with_signatures(slot_1, proposer)
        block_1_root = hash_tree_root(block_1)

        store, block_2, _ = store.produce_block_with_signatures(slot_2, ValidatorIndex(2))
        block_2_root = hash_tree_root(block_2)

        genesis_root = store.latest_justified.root

        # Head at slot 1, target at slot 2.
        # The head is the chain tip a validator votes for.
        # It must be at least as recent as the target checkpoint.
        # Slot 1 < slot 2 violates this ordering.
        attestation = Attestation(
            validator_id=ValidatorIndex(0),
            data=AttestationData(
                slot=slot_2,
                head=Checkpoint(root=block_1_root, slot=slot_1),
                target=Checkpoint(root=block_2_root, slot=slot_2),
                source=Checkpoint(root=genesis_root, slot=Slot(0)),
            ),
        )

        with pytest.raises(AssertionError, match="Head checkpoint must not be older than target"):
            store.validate_attestation(attestation.data)

    def test_valid_attestation_with_correct_head_passes(
        self,
        observer_store: Store,
    ) -> None:
        """An attestation with all checkpoints consistent should pass."""
        store = observer_store

        # Produce a single block at slot 1.
        slot_1 = Slot(1)
        proposer = ValidatorIndex(1)
        store, block, _ = store.produce_block_with_signatures(slot_1, proposer)
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
            validator_id=ValidatorIndex(0),
            data=AttestationData(
                slot=slot_1,
                head=Checkpoint(root=block_root, slot=slot_1),
                target=Checkpoint(root=block_root, slot=slot_1),
                source=Checkpoint(root=genesis_root, slot=Slot(0)),
            ),
        )

        store.validate_attestation(attestation.data)

    def test_head_equal_to_source_and_target_passes(
        self,
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
            validator_id=ValidatorIndex(0),
            data=AttestationData(
                slot=Slot(0),
                head=genesis_checkpoint,
                target=genesis_checkpoint,
                source=genesis_checkpoint,
            ),
        )

        store.validate_attestation(attestation.data)


class TestValidateAttestationTimeCheck:
    """
    Time check boundaries.

    Each case sets `store.time` explicitly to isolate the time check from
    on_tick side effects (aggregation, safe-target update, acceptance).
    """

    @staticmethod
    def _build_two_block_chain(store: Store) -> tuple[Store, AttestationData]:
        """Produce blocks at slots 1 and ATTESTATION_SLOT; return ATTESTATION_SLOT data."""
        store, _, _ = store.produce_block_with_signatures(Slot(1), ValidatorIndex(1))
        store, block_2, _ = store.produce_block_with_signatures(
            ATTESTATION_SLOT, ValidatorIndex(int(ATTESTATION_SLOT))
        )
        block_2_root = hash_tree_root(block_2)
        genesis_root = store.latest_justified.root

        data = AttestationData(
            slot=ATTESTATION_SLOT,
            head=Checkpoint(root=block_2_root, slot=ATTESTATION_SLOT),
            target=Checkpoint(root=block_2_root, slot=ATTESTATION_SLOT),
            source=Checkpoint(root=genesis_root, slot=Slot(0)),
        )
        return store, data

    def test_attestation_at_current_slot_passes(self, observer_store: Store) -> None:
        """A vote at the current slot is always accepted, every interval."""
        store, data = self._build_two_block_chain(observer_store)

        # Sweep every interval in the attestation's slot.
        for offset in range(int(INTERVALS_PER_SLOT)):
            local = store.model_copy(update={"time": ATTESTATION_START_INTERVAL + Interval(offset)})
            local.validate_attestation(data)

    def test_attestation_in_past_passes(self, observer_store: Store) -> None:
        """A vote from a past slot is always accepted."""
        store, data = self._build_two_block_chain(observer_store)

        # Place the local clock several slots ahead.
        far_future = ATTESTATION_START_INTERVAL + INTERVALS_PER_SLOT * Interval(10)
        store = store.model_copy(update={"time": far_future})
        store.validate_attestation(data)

    def test_attestation_at_disparity_boundary_passes(self, observer_store: Store) -> None:
        """At the disparity boundary the attestation is still accepted."""
        store, data = self._build_two_block_chain(observer_store)

        store = store.model_copy(update={"time": DISPARITY_BOUNDARY_INTERVAL})
        store.validate_attestation(data)

    def test_attestation_just_beyond_disparity_boundary_rejected(
        self, observer_store: Store
    ) -> None:
        """One interval past the disparity boundary the attestation is rejected."""
        store, data = self._build_two_block_chain(observer_store)

        store = store.model_copy(update={"time": JUST_BEYOND_DISPARITY_BOUNDARY_INTERVAL})

        with pytest.raises(AssertionError, match="Attestation too far in future"):
            store.validate_attestation(data)

    def test_attestation_one_full_slot_in_future_rejected(self, observer_store: Store) -> None:
        """
        Regression: a full-slot future window must be rejected.

        An earlier rule admitted votes up to a full slot ahead.
        That window let an adversary pre-publish next-slot aggregates
        before any honest validator could produce them.
        """
        store, data = self._build_two_block_chain(observer_store)

        store = store.model_copy(update={"time": ONE_FULL_SLOT_BEHIND_INTERVAL})

        with pytest.raises(AssertionError, match="Attestation too far in future"):
            store.validate_attestation(data)
