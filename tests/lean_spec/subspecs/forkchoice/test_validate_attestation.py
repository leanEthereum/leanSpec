"""Tests for head checkpoint validation in validate_attestation."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.containers import Attestation, AttestationData, Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root


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
            store.validate_attestation(attestation)

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
            store.validate_attestation(attestation)

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
            store.validate_attestation(attestation)

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

        store.validate_attestation(attestation)

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

        store.validate_attestation(attestation)
