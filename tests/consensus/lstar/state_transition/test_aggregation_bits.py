"""State Transition: Aggregation Bits Validation"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    ExpectedRejection,
    StateExpectation,
    StateTransitionTestFiller,
)
from lean_spec.spec.forks import AggregationBits, RejectionReason, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import JustificationRoots, JustificationValidators
from lean_spec.spec.ssz import Boolean

pytestmark = pytest.mark.valid_until("Lstar")


def test_aggregation_bit_beyond_validator_registry_rejects_block(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A set aggregation bit past the validator registry rejects the block.

    Given
    -----
    - 4 validators (indices 0-3); the vote tally has one flag per validator.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) carries an attestation for block_1 naming V0, V1, and V4.
    - index 4 is within the bitfield limit but one past the registry.

    When
    ----
    - the chain processes block(2).

    Then
    ----
    - the block is rejected with VALIDATOR_INDEX_OUT_OF_RANGE.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(4),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=None,
        expected_rejection=ExpectedRejection(reason=RejectionReason.VALIDATOR_INDEX_OUT_OF_RANGE),
    )


def test_all_false_aggregation_bits_rejects_block(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    An attestation whose aggregation bits are all false rejects the block.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) carries an attestation for block_1 with a registry-sized
      bitfield where no bit is set.

    When
    ----
    - the chain processes block(2).

    Then
    ----
    - the block is rejected with EMPTY_AGGREGATION_BITS.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[],
                        aggregation_bits=AggregationBits(data=[Boolean(False)] * 4),
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=None,
        expected_rejection=ExpectedRejection(reason=RejectionReason.EMPTY_AGGREGATION_BITS),
    )


def test_zero_length_aggregation_bits_rejects_block(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    An attestation with a zero-length bitfield rejects the block.

    Given
    -----
    - 4 validators.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) carries an attestation for block_1 whose aggregation bits
      hold no bits at all.
    - a zero-length bitfield is a distinct SSZ encoding from an all-false one.

    When
    ----
    - the chain processes block(2).

    Then
    ----
    - the block is rejected with EMPTY_AGGREGATION_BITS.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[],
                        aggregation_bits=AggregationBits(data=[]),
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=None,
        expected_rejection=ExpectedRejection(reason=RejectionReason.EMPTY_AGGREGATION_BITS),
    )


def test_oversized_aggregation_bits_with_in_range_votes_processes_normally(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Trailing unset bits past the registry do not invalidate a vote.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) carries an attestation for block_1.
    - the bitfield is 6 bits long with only V0, V1, V2 set.
    - bits 4 and 5 are unset padding past the registry.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - block_1's slot is justified.
    - the pending tally for block_1 is cleared.
    - finalization stays at genesis.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[],
                        aggregation_bits=AggregationBits(
                            data=[Boolean(True)] * 3 + [Boolean(False)] * 3
                        ),
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(2),
            latest_justified_slot=Slot(1),
            latest_finalized_slot=Slot(0),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )
