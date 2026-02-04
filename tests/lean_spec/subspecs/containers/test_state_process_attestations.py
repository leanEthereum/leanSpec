"""
Test suite for State attestation processing bounds checks.

Problem
-------

Attestations carry checkpoint references: a source slot and a target slot.
During processing, the state looks up the corresponding block roots in
`historical_block_hashes` using these slots as indices.

If an attestation references a slot beyond the current history length, a naive
implementation would crash with an IndexError.

Why This Happens in Practice
----------------------------

This scenario occurs in two real-world situations:

1. **Gossip timing mismatches**: Validators receive attestations from peers
   before processing all the blocks that justify them. The gossip network
   delivers messages out of order.

2. **Interoperability testing**: External clients may send attestations
   with future targets. During interop tests, clients stress each other
   with edge-case messages to verify robustness.

The Fix
-------

The attestation processor now checks slot bounds before array access:

    source_slot_int < len(self.historical_block_hashes)
    target_slot_int < len(self.historical_block_hashes)

Invalid attestations are silently rejected rather than crashing.
This matches the Ethereum philosophy of accepting valid messages and
ignoring malformed ones.
"""

from __future__ import annotations

from lean_spec.subspecs.containers.attestation import (
    AggregatedAttestation,
    AggregationBits,
    AttestationData,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustifiedSlots,
)
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Boolean, Uint64
from tests.lean_spec.helpers import make_bytes32, make_validators


class TestProcessAttestationsBoundsCheck:
    """Verify attestations with out-of-bounds slot references are rejected safely."""

    def test_attestation_with_target_beyond_history_is_silently_rejected(self) -> None:
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
        state = State.generate_genesis(genesis_time=Uint64(0), validators=make_validators(3))

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
        state = state.model_copy(
            update={
                "slot": Slot(5),
                # History covers indices 0-4 only.
                "historical_block_hashes": HistoricalBlockHashes(
                    data=[source_root] + [make_bytes32(i) for i in range(2, 6)]
                ),
                # Extend justified_slots to avoid is_slot_justified throwing.
                #
                # Index calculation: slot - finalized_slot - 1 = 10 - 0 - 1 = 9
                # Need at least 10 entries to cover slot 10.
                "justified_slots": JustifiedSlots(data=[Boolean(False)] * 10),
            }
        )

        # Verify the history length matches our setup.
        assert len(state.historical_block_hashes) == 5

        # Create an attestation referencing slot 10.
        #
        # Slot 10 is beyond the 5-entry history.
        # Without bounds checking: IndexError at historical_block_hashes[10].
        target_slot = Slot(10)
        target_root = make_bytes32(99)

        att_data = AttestationData(
            slot=target_slot,
            head=Checkpoint(root=target_root, slot=target_slot),
            target=Checkpoint(root=target_root, slot=target_slot),
            # Source at slot 0 is valid (implicitly justified as genesis).
            source=Checkpoint(root=source_root, slot=Slot(0)),
        )

        attestation = AggregatedAttestation(
            # Two validators participate in this attestation.
            aggregation_bits=AggregationBits.from_validator_indices(
                [ValidatorIndex(0), ValidatorIndex(1)]
            ),
            data=att_data,
        )

        # Process the attestation.
        #
        # This is the critical line: it must NOT raise IndexError.
        result_state = state.process_attestations([attestation])

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

    def test_attestation_with_source_beyond_history_is_silently_rejected(self) -> None:
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
        state = State.generate_genesis(genesis_time=Uint64(0), validators=make_validators(3))

        # Build a state with very limited history.
        #
        # Only 3 entries in historical_block_hashes (indices 0-2).
        state = state.model_copy(
            update={
                "slot": Slot(5),
                # Minimal history: only 3 blocks recorded.
                "historical_block_hashes": HistoricalBlockHashes(
                    data=[make_bytes32(i) for i in range(3)]
                ),
                # Extend justified_slots to cover target slot.
                "justified_slots": JustifiedSlots(data=[Boolean(False)] * 10),
            }
        )

        # Create attestation with target beyond history.
        #
        # Source at slot 0 is implicitly justified (<= finalized).
        # Target at slot 10 is beyond history (length 3).
        source_slot = Slot(0)
        target_slot = Slot(10)
        some_root = make_bytes32(42)

        att_data = AttestationData(
            slot=target_slot,
            head=Checkpoint(root=some_root, slot=target_slot),
            target=Checkpoint(root=some_root, slot=target_slot),
            source=Checkpoint(root=some_root, slot=source_slot),
        )

        attestation = AggregatedAttestation(
            aggregation_bits=AggregationBits.from_validator_indices(
                [ValidatorIndex(0), ValidatorIndex(1)]
            ),
            data=att_data,
        )

        # Process the attestation.
        #
        # Must NOT raise IndexError.
        result_state = state.process_attestations([attestation])

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
