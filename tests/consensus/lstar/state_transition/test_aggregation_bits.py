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
    - block(2) carries an attestation for block_1 whose aggregation bits
      name V0 and V1 plus nonexistent validator 4.

    When
    ----
    - the chain processes block(2).

    Then
    ----
    - the block is rejected with VALIDATOR_INDEX_OUT_OF_RANGE.
    - a client that silently skips the attestation instead would accept a
      block the rest of the network refuses: a consensus split on a single
      crafted block.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                forced_attestations=[
                    # Bits 0, 1, and 4 are set.
                    # Bit 4 points one past the 4-validator registry.
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
    - a client that processes the attestation as a no-op instead leaves an
      all-false tally entry in its post-state, diverging from clients that
      reject the block.
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

    When
    ----
    - the chain processes block(2).

    Then
    ----
    - the block is rejected with EMPTY_AGGREGATION_BITS.
    - the zero-length bitfield is a distinct SSZ encoding from an all-false
      bitfield of registry size; both name no voter and both must reject
      the block identically across clients.
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
    - block(2) carries an attestation for block_1 whose bitfield is 6 bits
      long (two bits past the registry) with only V0, V1, and V2 set.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - the attestation is processed normally: every set bit addresses a real
      validator, and the trailing unset padding is harmless.
    - block_1's slot is justified and its pending tally is cleared.
    - a client that skips the attestation because of the bitfield length
      computes a different post-state for a valid block; the pinned
      post-state root catches that divergence directly.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                forced_attestations=[
                    # Bits 0-2 are set; bits 3-5 are unset.
                    # Bits 4 and 5 pad past the 4-validator registry.
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
