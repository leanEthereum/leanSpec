"""Tests for the lstar state transition function."""

from __future__ import annotations

from lean_spec.spec.forks import AggregationBits, Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AttestationData,
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import ZERO_HASH, Boolean
from tests.lean_spec.helpers import (
    make_aggregated_attestation,
    make_block,
    make_bytes32,
    make_genesis_state,
)


class TestProcessAttestationsBoundsCheck:
    """Verify attestations with out-of-bounds slot references are rejected safely."""

    def test_attestation_with_target_beyond_history_is_silently_rejected(
        self, spec: LstarSpec
    ) -> None:
        """
        Reject attestations whose target slot exceeds history bounds.

        Scenario
        --------

        A validator creates an attestation for slot 10 (the target).
        The state only has 5 entries in the historical block hashes.
        Index 10 does not exist. Without bounds checking, this crashes.

        Expected Behavior
        -----------------

        - No IndexError raised
        - Attestation silently rejected
        - Justification tracking remains empty
        - Checkpoints unchanged
        """
        # Create a minimal genesis state with 3 validators.
        state = make_genesis_state(num_validators=3)

        # Build a controlled state with limited history.
        #
        # Key setup:
        #
        # - historical_block_hashes has 5 entries (indices 0-4)
        # - justified_slots has 10 entries (covers slots up to 10)
        #
        # This simulates an edge case: the justified_slots bitfield was
        # extended, but historical hashes were not fully populated.
        # This can happen with certain block arrival patterns.
        source_root = make_bytes32(1)
        state.slot = Slot(5)
        # History covers indices 0-4 only.
        state.historical_block_hashes = HistoricalBlockHashes(
            data=[source_root] + [make_bytes32(i) for i in range(2, 6)]
        )
        # Extend justified_slots to avoid is_slot_justified throwing.
        #
        # Index calculation: slot - finalized_slot - 1 = 10 - 0 - 1 = 9
        # Need at least 10 entries to cover slot 10.
        state.justified_slots = JustifiedSlots(data=[Boolean(False)] * 10)

        # Verify the history length matches our setup.
        assert len(state.historical_block_hashes) == 5

        # Create an attestation referencing slot 10.
        #
        # Slot 10 is beyond the 5-entry history.
        # Without bounds checking: IndexError at historical_block_hashes[10].
        target_slot = Slot(10)
        target_root = make_bytes32(99)

        attestation_data = AttestationData(
            slot=target_slot,
            head=Checkpoint(root=target_root, slot=target_slot),
            target=Checkpoint(root=target_root, slot=target_slot),
            # Source at slot 0 is valid (implicitly justified as genesis).
            source=Checkpoint(root=source_root, slot=Slot(0)),
        )

        attestation = AggregatedAttestation(
            # Two validators participate in this attestation.
            aggregation_bits=AggregationBits.from_indices([ValidatorIndex(0), ValidatorIndex(1)]),
            data=attestation_data,
        )

        # Process the attestation.
        #
        # This is the critical line: it must NOT raise IndexError.
        result_state = spec.process_attestations(state, [attestation])

        # Verify the attestation was silently rejected.
        #
        # Reason: target slot (10) exceeds historical_block_hashes length (5).
        # The bounds check catches this and skips the attestation.
        assert len(result_state.justifications_roots) == 0
        assert len(result_state.justifications_validators) == 0

        # Checkpoints must remain unchanged.
        #
        # A rejected attestation should not affect consensus state.
        assert result_state.latest_justified == state.latest_justified
        assert result_state.latest_finalized == state.latest_finalized

    def test_attestation_with_source_beyond_history_is_silently_rejected(
        self, spec: LstarSpec
    ) -> None:
        """
        Reject attestations where history lookup would fail for any referenced slot.

        Scenario
        --------

        Even if the source slot appears valid (slot 0), the target slot (10)
        exceeds the history bounds (only 3 entries).

        This tests the general case: any slot reference that exceeds history
        length should fail the bounds check.

        Expected Behavior
        -----------------

        - No IndexError raised
        - Attestation silently rejected
        - Justification tracking remains empty

        Note: The source root (make_bytes32(42)) does not match the actual
        history at slot 0 (make_bytes32(0)), so the source_matches check
        would also fail. This test primarily verifies the target bounds check.
        """
        # Create a minimal genesis state with 3 validators.
        state = make_genesis_state(num_validators=3)

        # Build a state with very limited history.
        #
        # Only 3 entries in historical_block_hashes (indices 0-2).
        state.slot = Slot(5)
        # Minimal history: only 3 blocks recorded.
        state.historical_block_hashes = HistoricalBlockHashes(
            data=[make_bytes32(i) for i in range(3)]
        )
        # Extend justified_slots to cover target slot.
        state.justified_slots = JustifiedSlots(data=[Boolean(False)] * 10)

        # Create attestation with target beyond history.
        #
        # Source at slot 0 is implicitly justified (<= finalized).
        # Target at slot 10 is beyond history (length 3).
        source_slot = Slot(0)
        target_slot = Slot(10)
        some_root = make_bytes32(42)

        attestation_data = AttestationData(
            slot=target_slot,
            head=Checkpoint(root=some_root, slot=target_slot),
            target=Checkpoint(root=some_root, slot=target_slot),
            source=Checkpoint(root=some_root, slot=source_slot),
        )

        attestation = AggregatedAttestation(
            aggregation_bits=AggregationBits.from_indices([ValidatorIndex(0), ValidatorIndex(1)]),
            data=attestation_data,
        )

        # Process the attestation.
        #
        # Must NOT raise IndexError.
        result_state = spec.process_attestations(state, [attestation])

        # Verify the attestation was silently rejected.
        #
        # Multiple reasons for rejection:
        #
        # - Source root mismatch: make_bytes32(42) != make_bytes32(0)
        # - Target out of bounds: slot 10 >= history length 3
        #
        # Either check would reject this attestation.
        # The bounds check prevents the crash before root comparison.
        assert len(result_state.justifications_roots) == 0
        assert len(result_state.justifications_validators) == 0


class TestProcessAttestationsHeadChecks:
    """Verify attestations whose head checkpoint is off the canonical chain are rejected."""

    def test_attestation_with_head_root_mismatch_is_silently_rejected(
        self, spec: LstarSpec
    ) -> None:
        """
        Reject attestations whose head checkpoint is not on the canonical history.

        Source and target match the local chain, but the head root names a
        different block at the head slot. The vote must not justify the target.
        """
        state = make_genesis_state(num_validators=3)

        source_root = make_bytes32(1)
        target_root = make_bytes32(2)
        canonical_head_root = make_bytes32(3)
        sibling_head_root = make_bytes32(4)

        state.slot = Slot(3)
        state.historical_block_hashes = HistoricalBlockHashes(
            data=[source_root, target_root, canonical_head_root]
        )
        state.justified_slots = JustifiedSlots(data=[Boolean(False), Boolean(False)])

        attestation_data = AttestationData(
            slot=Slot(2),
            source=Checkpoint(root=source_root, slot=Slot(0)),
            target=Checkpoint(root=target_root, slot=Slot(1)),
            head=Checkpoint(root=sibling_head_root, slot=Slot(2)),
        )
        attestation = AggregatedAttestation(
            aggregation_bits=AggregationBits.from_indices([ValidatorIndex(0), ValidatorIndex(1)]),
            data=attestation_data,
        )

        result_state = spec.process_attestations(state, [attestation])

        assert result_state.latest_justified == state.latest_justified
        assert result_state.latest_finalized == state.latest_finalized
        assert len(result_state.justifications_roots) == 0
        assert len(result_state.justifications_validators) == 0

    def test_attestation_with_zero_hash_head_is_silently_rejected(self, spec: LstarSpec) -> None:
        """
        Reject attestations whose head checkpoint carries the zero hash.

        A zero-hash head names an empty slot, not a block.
        Source and target match the local chain, so only the head guard fires.
        """
        state = make_genesis_state(num_validators=3)

        source_root = make_bytes32(1)
        target_root = make_bytes32(2)
        canonical_head_root = make_bytes32(3)

        state.slot = Slot(3)
        state.historical_block_hashes = HistoricalBlockHashes(
            data=[source_root, target_root, canonical_head_root]
        )
        state.justified_slots = JustifiedSlots(data=[Boolean(False), Boolean(False)])

        attestation_data = AttestationData(
            slot=Slot(2),
            source=Checkpoint(root=source_root, slot=Slot(0)),
            target=Checkpoint(root=target_root, slot=Slot(1)),
            head=Checkpoint(root=ZERO_HASH, slot=Slot(2)),
        )
        attestation = AggregatedAttestation(
            aggregation_bits=AggregationBits.from_indices([ValidatorIndex(0), ValidatorIndex(1)]),
            data=attestation_data,
        )

        result_state = spec.process_attestations(state, [attestation])

        assert result_state.latest_justified == state.latest_justified
        assert result_state.latest_finalized == state.latest_finalized
        assert len(result_state.justifications_roots) == 0
        assert len(result_state.justifications_validators) == 0

    def test_attestation_with_head_beyond_history_is_silently_rejected(
        self, spec: LstarSpec
    ) -> None:
        """
        Reject attestations whose head slot exceeds history bounds.

        Source and target sit inside the chain view, only the head does not.
        The bounds guard must reject the vote instead of raising IndexError.
        """
        state = make_genesis_state(num_validators=3)

        source_root = make_bytes32(1)
        target_root = make_bytes32(2)

        state.slot = Slot(3)
        state.historical_block_hashes = HistoricalBlockHashes(
            data=[source_root, target_root, make_bytes32(3)]
        )
        state.justified_slots = JustifiedSlots(data=[Boolean(False)] * 10)

        attestation_data = AttestationData(
            slot=Slot(2),
            source=Checkpoint(root=source_root, slot=Slot(0)),
            target=Checkpoint(root=target_root, slot=Slot(1)),
            head=Checkpoint(root=make_bytes32(10), slot=Slot(10)),
        )
        attestation = AggregatedAttestation(
            aggregation_bits=AggregationBits.from_indices([ValidatorIndex(0), ValidatorIndex(1)]),
            data=attestation_data,
        )

        result_state = spec.process_attestations(state, [attestation])

        assert result_state.latest_justified == state.latest_justified
        assert result_state.latest_finalized == state.latest_finalized
        assert len(result_state.justifications_roots) == 0
        assert len(result_state.justifications_validators) == 0


def test_justified_slots_do_not_include_finalized_boundary(spec: LstarSpec) -> None:
    state = make_genesis_state(num_validators=4)

    # First post-genesis block at slot 1.
    state_slot_1 = spec.process_slots(state, Slot(1))
    block_1 = make_block(state_slot_1, Slot(1), attestations=[])
    post_1 = spec.process_block_header(state_slot_1, block_1)

    # latest_finalized.slot is 0, so justified_slots starts at slot 1.
    # Processing block_1 only materializes the parent slot 0, which must not be stored.
    assert len(post_1.justified_slots) == 0

    # Second block at slot 2 materializes parent slot 1, which is the first bit.
    post_1_slot_2 = spec.process_slots(post_1, Slot(2))
    block_2 = make_block(post_1_slot_2, Slot(2), attestations=[])
    post_2 = spec.process_block_header(post_1_slot_2, block_2)

    assert len(post_2.justified_slots) == 1
    assert bool(post_2.justified_slots[0]) is False


def test_justified_slots_rebases_when_finalization_advances(spec: LstarSpec) -> None:
    # Use 3 validators so a 2-of-3 aggregation is a supermajority.
    state = make_genesis_state(num_validators=3)

    # Block 1 (slot 1): initializes history (stores slot 0 root), but no justified_slots bits yet.
    state = spec.process_slots(state, Slot(1))
    block_1 = make_block(state, Slot(1), attestations=[])
    state = spec.process_block(state, block_1)

    # Block 2 (slot 2): justify slot 1 with source=0 -> target=1.
    state = spec.process_slots(state, Slot(2))
    block_2 = make_block(state, Slot(2), attestations=[])

    source_0 = Checkpoint(root=block_1.parent_root, slot=Slot(0))
    target_1 = Checkpoint(root=block_2.parent_root, slot=Slot(1))
    attestation_0_to_1 = make_aggregated_attestation(
        participant_ids=[ValidatorIndex(0), ValidatorIndex(1)],
        attestation_slot=Slot(2),
        source=source_0,
        target=target_1,
    )

    block_2 = make_block(state, Slot(2), attestations=[attestation_0_to_1])
    state = spec.process_block(state, block_2)

    # Block 3 (slot 3): justify slot 2 with source=1 -> target=2, which finalizes slot 1.
    state = spec.process_slots(state, Slot(3))
    block_3 = make_block(state, Slot(3), attestations=[])

    source_1 = Checkpoint(root=block_2.parent_root, slot=Slot(1))
    target_2 = Checkpoint(root=block_3.parent_root, slot=Slot(2))
    attestation_1_to_2 = make_aggregated_attestation(
        participant_ids=[ValidatorIndex(0), ValidatorIndex(1)],
        attestation_slot=Slot(3),
        source=source_1,
        target=target_2,
    )

    block_3 = make_block(state, Slot(3), attestations=[attestation_1_to_2])
    state = spec.process_block(state, block_3)

    assert state.latest_finalized.slot == Slot(1)

    # After finalization advances to slot 1, the bitfield base becomes slot 2.
    # Slot 2 remains stored as index 0 and must be justified.
    assert len(state.justified_slots) == 1
    assert bool(state.justified_slots[0]) is True

    assert state.justified_slots.is_slot_justified(state.latest_finalized.slot, Slot(1))
    assert state.justified_slots.is_slot_justified(state.latest_finalized.slot, Slot(2))
    assert Slot(2).justified_index_after(state.latest_finalized.slot) == 0


def test_pruning_keeps_pending_justifications(spec: LstarSpec) -> None:
    """
    Verify pruning keeps pending justifications after finalization advances.

    Test strategy:

    1. Build a chain with a justified checkpoint
    2. Add a pending justification that should survive pruning
    3. Trigger finalization to run the pruning logic
    4. Verify the pending justification survives correctly
    """
    # Two of three validators form a supermajority.
    state = make_genesis_state(num_validators=3)

    # Phase 1: Build a chain and justify slot 1.
    #
    # We need an existing justified checkpoint before we can test pruning.

    state = spec.process_slots(state, Slot(1))
    block_1 = make_block(state, Slot(1), attestations=[])
    state = spec.process_block(state, block_1)

    state = spec.process_slots(state, Slot(2))
    block_2 = make_block(state, Slot(2), attestations=[])
    source_0 = Checkpoint(root=block_1.parent_root, slot=Slot(0))
    target_1 = Checkpoint(root=block_2.parent_root, slot=Slot(1))
    attestation_0_to_1 = make_aggregated_attestation(
        participant_ids=[ValidatorIndex(0), ValidatorIndex(1)],
        attestation_slot=Slot(2),
        source=source_0,
        target=target_1,
    )
    block_2 = make_block(state, Slot(2), attestations=[attestation_0_to_1])
    state = spec.process_block(state, block_2)

    assert state.latest_finalized.slot == Slot(0)
    assert state.latest_justified.slot == Slot(1)

    # Phase 2: Extend chain to populate more history entries.

    state = spec.process_slots(state, Slot(3))
    block_3 = make_block(state, Slot(3), attestations=[])
    state = spec.process_block(state, block_3)

    state = spec.process_slots(state, Slot(4))
    block_4 = make_block(state, Slot(4), attestations=[])
    state = spec.process_block(state, block_4)

    state = spec.process_slots(state, Slot(5))
    block_5 = make_block(state, Slot(5), attestations=[])
    state = spec.process_block_header(state, block_5)

    slot_3_root = state.historical_block_hashes[3]

    # Register a pending justification for slot 3.
    #
    # This justification should survive pruning because slot 3
    # comes after the finalized boundary.
    pending_votes = [Boolean(True), Boolean(False), Boolean(False)]

    state.justifications_roots = JustificationRoots(data=[slot_3_root])
    state.justifications_validators = JustificationValidators(data=pending_votes)

    # Sanity check: slot 3 root is present in history.
    assert state.historical_block_hashes[3] == slot_3_root

    # Phase 4: Trigger finalization to exercise pruning.
    #
    # This attestation justifies slot 2 and finalizes slot 1.
    # Finalization triggers pruning of stale justifications.

    source_1 = Checkpoint(root=state.historical_block_hashes[1], slot=Slot(1))
    target_2 = Checkpoint(root=state.historical_block_hashes[2], slot=Slot(2))
    attestation_1_to_2 = make_aggregated_attestation(
        participant_ids=[ValidatorIndex(0), ValidatorIndex(1)],
        attestation_slot=Slot(5),
        source=source_1,
        target=target_2,
    )

    # Processing this attestation runs the pruning logic.
    #
    # Pruning iterates over all slots for each root in history.
    # Duplicate roots must map to multiple slots, not just one.
    state = spec.process_attestations(state, [attestation_1_to_2])

    # Verify finalization succeeded.
    assert state.latest_finalized.slot == Slot(1)
    assert state.latest_justified.slot == Slot(2)

    # The pending justification for slot 3 must survive.
    #
    # Slot 3 is beyond the finalized boundary, so pruning keeps it.
    assert slot_3_root in list(state.justifications_roots)
