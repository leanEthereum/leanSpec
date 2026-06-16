"""State Transition: Justification"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
    generate_pre_state,
)
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.spec.ssz import ZERO_HASH, Boolean, Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_supermajority_attestations_justify_block(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A supermajority of votes justifies the target slot.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0, V1, V2's votes for block_1.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - block_1's slot is justified.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
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
        ),
    )


def test_even_validator_threshold_boundary(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Exactly two-thirds support justifies the target slot.

    Given
    -----
    - 6 validators; a slot needs 4 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0, V1, V2, V3's votes for block_1.
    - 4 of 6 meets the threshold exactly.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - block_1's slot is justified.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=6),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                            ValidatorIndex(3),
                        ],
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
        ),
    )


def test_below_threshold_support_does_not_justify(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Support below two-thirds does not justify the target slot.

    Given
    -----
    - 6 validators; a slot needs 4 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0, V1, V2's votes for block_1.
    - 3 of 6 falls below the threshold.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - justified stays at slot 0.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=6),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(2),
            latest_justified_slot=Slot(0),
        ),
    )


def test_votes_accumulate_across_blocks(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Pending votes for one target accumulate across blocks until justified.

    Given
    -----
    - 6 validators; a slot needs 4 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block(3)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2's tally of 3 is below the threshold.
    - block(3) includes V3's vote for block_1.
    - the votes accumulate to 4 of 6, reaching the threshold.

    When
    ----
    - the chain processes block_1, block_2, and block(3).

    Then
    ----
    - block_1's slot is justified.
    - no pending votes remain.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=6),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(3),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(3),
            latest_justified_slot=Slot(1),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_repeated_validators_do_not_double_count_across_blocks(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Repeating the same voters across blocks does not add weight.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3)
    - block_2 includes V0, V1's votes for block_1.
    - block_3 includes V0, V1's votes for block_1 again.
    - unique support stays at 2 of 4, below the threshold.

    When
    ----
    - the chain processes block_1, block_2, and block_3.

    Then
    ----
    - justified stays at slot 0.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(3),
            latest_justified_slot=Slot(0),
        ),
    )


def test_repeated_validator_does_not_double_count_within_same_block(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    The same voter counts once across distinct votes in one block.

    Given
    -----
    - 6 validators; a slot needs 4 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0, V1, V2's votes for block_1.
    - block(2) also includes V0's vote for block_1 again.
    - tallies are keyed by target, so V0 counts once.
    - unique support stays at 3 of 6, below the threshold.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - justified stays at slot 0.
    - the pending tally marks V0, V1, V2 only.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=6),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(1),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(2),
            latest_justified_slot=Slot(0),
            latest_finalized_slot=Slot(0),
            justified_slots=JustifiedSlots(data=[Boolean(False)]),
            justifications_validators=JustificationValidators(
                data=[
                    Boolean(True),
                    Boolean(True),
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                ]
            ),
        ),
    )


def test_pronic_boundary_acceptance(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A target at a pronic distance is justifiable.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_7(7)
    - block_7 includes V0, V1, V2's votes for block_6.
    - slot 6 is justifiable, since delta 6 from finalized 0 is pronic.

    When
    ----
    - the chain processes block_1 through block_7.

    Then
    ----
    - block_6's slot is justified.
    - finalized stays at slot 0.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(slot=Slot(3), parent_label="block_2", label="block_3"),
            BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
            BlockSpec(slot=Slot(5), parent_label="block_4", label="block_5"),
            BlockSpec(slot=Slot(6), parent_label="block_5", label="block_6"),
            BlockSpec(
                slot=Slot(7),
                parent_label="block_6",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(7),
                        target_slot=Slot(6),
                        target_root_label="block_6",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(7),
            latest_justified_slot=Slot(6),
            latest_finalized_slot=Slot(0),
        ),
    )


def test_non_justifiable_boundary_rejection(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A target at a non-justifiable distance is ignored even with supermajority support.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_8(8)
    - block_8 includes V0, V1, V2's votes for block_7.
    - slot 7 is not justifiable, since delta 7 from finalized 0 is neither square nor pronic.
    - the vote is ignored despite reaching the threshold.

    When
    ----
    - the chain processes block_1 through block_8.

    Then
    ----
    - justified stays at slot 0.
    - finalized stays at slot 0.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(slot=Slot(3), parent_label="block_2", label="block_3"),
            BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
            BlockSpec(slot=Slot(5), parent_label="block_4", label="block_5"),
            BlockSpec(slot=Slot(6), parent_label="block_5", label="block_6"),
            BlockSpec(slot=Slot(7), parent_label="block_6", label="block_7"),
            BlockSpec(
                slot=Slot(8),
                parent_label="block_7",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(8),
                        target_slot=Slot(7),
                        target_root_label="block_7",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(8),
            latest_justified_slot=Slot(0),
            latest_finalized_slot=Slot(0),
        ),
    )


def test_square_boundary_acceptance(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A target at a perfect-square distance is justifiable.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_10(10)
    - block_10 includes V0, V1, V2's votes for block_9.
    - slot 9 is justifiable, since delta 9 from finalized 0 is a perfect square.

    When
    ----
    - the chain processes block_1 through block_10.

    Then
    ----
    - block_9's slot is justified.
    - finalized stays at slot 0.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(slot=Slot(3), parent_label="block_2", label="block_3"),
            BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
            BlockSpec(slot=Slot(5), parent_label="block_4", label="block_5"),
            BlockSpec(slot=Slot(6), parent_label="block_5", label="block_6"),
            BlockSpec(slot=Slot(7), parent_label="block_6", label="block_7"),
            BlockSpec(slot=Slot(8), parent_label="block_7", label="block_8"),
            BlockSpec(slot=Slot(9), parent_label="block_8", label="block_9"),
            BlockSpec(
                slot=Slot(10),
                parent_label="block_9",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(10),
                        target_slot=Slot(9),
                        target_root_label="block_9",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(10),
            latest_justified_slot=Slot(9),
            latest_finalized_slot=Slot(0),
        ),
    )


def test_split_supermajority_aggregations_in_same_block_justify(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Two split aggregates for one target combine within a single block to justify.

    Given
    -----
    - 6 validators; a slot needs 4 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0, V1's votes for block_1.
    - block(2) includes V2, V3's votes for block_1.
    - neither aggregate alone reaches the threshold.
    - the two aggregates merge to 4 of 6, reaching the threshold.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - block_1's slot is justified.
    - finalized stays at slot 0.
    - no pending votes remain.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=6),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(2),
                            ValidatorIndex(3),
                        ],
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
            justified_slots=JustifiedSlots(data=[Boolean(True)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_odd_validator_threshold_boundary_justifies(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Four of five validators clears the two-thirds threshold and justifies.

    Given
    -----
    - 5 validators; a slot needs 4 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0, V1, V2, V3's votes for block_1.
    - 4 of 5 clears the threshold, since 4*3 = 12 is at least 5*2 = 10.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - block_1's slot is justified.
    - finalized stays at slot 0.
    - no pending votes remain.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=5),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                            ValidatorIndex(3),
                        ],
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
            justified_slots=JustifiedSlots(data=[Boolean(True)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_odd_validator_threshold_boundary_does_not_justify(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Three of five validators falls below the two-thirds threshold.

    Given
    -----
    - 5 validators; a slot needs 4 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0, V1, V2's votes for block_1.
    - 3 of 5 falls below the threshold, since 3*3 = 9 is less than 5*2 = 10.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - justified stays at slot 0.
    - finalized stays at slot 0.
    - the pending tally marks V0, V1, V2 only.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=5),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(2),
            latest_justified_slot=Slot(0),
            latest_finalized_slot=Slot(0),
            justified_slots=JustifiedSlots(data=[Boolean(False)]),
            justifications_validators=JustificationValidators(
                data=[
                    Boolean(True),
                    Boolean(True),
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                ]
            ),
        ),
    )


def test_supermajority_with_mismatched_target_root_is_ignored(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A supermajority for a target slot with the wrong root is ignored.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block(3)
    - block(3) includes V0, V1, V2's votes for target slot 1 using block_2's root.
    - the attested root does not match the canonical block at slot 1.
    - the vote is ignored despite reaching the threshold.

    When
    ----
    - the chain processes block_1, block_2, and block(3).

    Then
    ----
    - justified stays at slot 0.
    - finalized stays at slot 0.
    - no pending votes remain.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(1),
                        target_root_label="block_2",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(3),
            latest_justified_slot=Slot(0),
            latest_finalized_slot=Slot(0),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_attestation_with_target_root_not_in_historical_hashes_is_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote whose target root is absent from chain history is silently skipped.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0, V1, V2's votes for target slot 1 with a fabricated root.
    - the head stays canonical, so the vote reaches state processing.
    - the target root is absent from chain history, so the vote is skipped.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - justified stays at slot 0.
    - finalized stays at slot 0.
    - no pending votes remain.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root=Bytes32(b"\x42" * 32),
                        head_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(2),
            latest_justified_slot=Slot(0),
            latest_finalized_slot=Slot(0),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_attestation_with_off_canonical_head_does_not_justify_target(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote whose head is off the canonical chain is skipped before any tally.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) carries a forced V0, V1, V2 vote from genesis to block_1.
    - the source and target roots match the canonical chain.
    - the head root is a sibling at slot 1, where block_1 is canonical.
    - the head does not match, so the whole vote is skipped.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - justified stays at slot 0.
    - finalized stays at slot 0.
    - no pending votes remain.
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
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                        head_root=Bytes32(b"\x99" * 32),
                        head_slot=Slot(1),
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(2),
            latest_justified_slot=Slot(0),
            latest_finalized_slot=Slot(0),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_justification_clears_only_the_resolved_target_votes(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Justifying one target clears only that target's pending votes.

    Given
    -----
    - 6 validators; a slot needs 4 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block(4)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_3 includes V0, V1's votes for block_2.
    - block(4) includes V3's vote for block_1.
    - block_1 reaches 4 of 6 and is justified.
    - the pending tally for block_2 is unrelated and stays.

    When
    ----
    - the chain processes block_1, block_2, block_3, and block(4).

    Then
    ----
    - block_1's slot is justified.
    - finalized stays at slot 0.
    - the pending tally for block_2 marks V0, V1 only.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=6),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(4),
                parent_label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(3),
                        ],
                        slot=Slot(4),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(4),
            latest_justified_slot=Slot(1),
            latest_finalized_slot=Slot(0),
            justified_slots=JustifiedSlots(data=[Boolean(True), Boolean(False), Boolean(False)]),
            justifications_validators=JustificationValidators(
                data=[
                    Boolean(True),
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                ]
            ),
        ),
    )


def test_target_at_or_before_source_is_ignored(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote whose target is at or before its source is ignored.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4)
          -> block_5(5) -> block(6)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2 justifies slot 1.
    - block_3 includes V0, V1's votes for block_2.
    - block_3's partial tally for block_2 stays pending.
    - block_5 includes V0, V1, V2's votes for block_4.
    - block_5 justifies slot 4, so the source advances to slot 4.
    - block(6) includes V2's vote for the older block_2.
    - target slot 2 is not after source slot 4, so the vote is ignored.

    When
    ----
    - the chain processes block_1 through block(6).

    Then
    ----
    - justified stays at slot 4.
    - finalized stays at slot 0.
    - the pending tally for block_2 marks V0, V1 only.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(4),
                parent_label="block_3",
                label="block_4",
            ),
            BlockSpec(
                slot=Slot(5),
                parent_label="block_4",
                label="block_5",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(5),
                        target_slot=Slot(4),
                        target_root_label="block_4",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(6),
                parent_label="block_5",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(2),
                        ],
                        slot=Slot(6),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(6),
            latest_justified_slot=Slot(4),
            latest_finalized_slot=Slot(0),
            justified_slots=JustifiedSlots(
                data=[
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(True),
                    Boolean(False),
                ]
            ),
            justifications_validators=JustificationValidators(
                data=[
                    Boolean(True),
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                ]
            ),
        ),
    )


def test_attestation_with_already_justified_target_is_silently_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote for an already-justified slot is ignored without error.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block(3)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2 justifies slot 1.
    - block(3) includes V3's vote for block_1, which is already justified.
    - the duplicate vote is skipped with no state change.

    When
    ----
    - the chain processes block_1, block_2, and block(3).

    Then
    ----
    - block_1's slot stays justified.
    - finalized stays at slot 0.
    - the justified-slots bitfield marks slot 1 alone.
    - no pending votes remain.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(3),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(3),
            latest_justified_slot=Slot(1),
            latest_finalized_slot=Slot(0),
            justified_slots=JustifiedSlots(data=[Boolean(True), Boolean(False)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_attestation_with_zero_hash_source_root_is_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote with a zero-hash source root has no effect, and the valid vote justifies.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes a malformed V0, V1, V2 vote for block_1 with a zero-hash source root.
    - block(2) includes a valid V0, V1, V2 vote for block_1.
    - the malformed vote has no effect.
    - the valid vote justifies slot 1.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - block_1's slot is justified.
    - finalized stays at slot 0.
    - the justified-slots bitfield marks slot 1 alone.
    - no pending votes remain.

    Note
    ----
    Two guards both reject the malformed vote.
    One is the zero-hash early exit on the source root.
    The other is the absence of a zero hash from chain history.
    The post-state is the same regardless of which fires first.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                        source_root=ZERO_HASH,
                    ),
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
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
            justified_slots=JustifiedSlots(data=[Boolean(True)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_attestation_with_zero_hash_target_root_is_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote with a zero-hash target root has no effect, and the valid vote justifies.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes a malformed V0, V1, V2 vote for target slot 1 with a zero-hash root.
    - block(2) includes a valid V0, V1, V2 vote for block_1.
    - the malformed vote has no effect.
    - the valid vote justifies slot 1.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - block_1's slot is justified.
    - finalized stays at slot 0.
    - the justified-slots bitfield marks slot 1 alone.
    - no pending votes remain.

    Note
    ----
    Two guards both reject the malformed vote.
    One is the zero-hash early exit on the target root.
    The other is the absence of a zero hash from chain history.
    The post-state is the same regardless of which fires first.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root=ZERO_HASH,
                    ),
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
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
            justified_slots=JustifiedSlots(data=[Boolean(True)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_attestation_with_unjustified_source_is_silently_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote whose source slot is not justified is ignored without error.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block(4)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2 justifies slot 1.
    - block_3 carries no votes, so slot 2 stays unjustified.
    - block(4) includes V0, V1's vote from block_1 to block_2.
    - block(4) carries a forced V2, V3 vote from block_2 to block_3.
    - the forced vote bypasses the builder, which would otherwise filter it.
    - the forced vote passes every guard except the source-justified check.
    - its source slot 2 is not justified, so it is skipped at the first guard.

    When
    ----
    - the chain processes block_1, block_2, block_3, and block(4).

    Then
    ----
    - block_1's slot stays justified.
    - finalized stays at slot 0.
    - the valid vote is 2 of 4, below the threshold, so it only adds pending votes.
    - the pending roots hold one target, block_2.
    - the pending tally marks V0, V1 only.
    - the skip leaves 4 tally entries, not the 8 a second target would add.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                label="block_3",
            ),
            BlockSpec(
                slot=Slot(4),
                parent_label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                        ],
                        slot=Slot(4),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                ],
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(2),
                            ValidatorIndex(3),
                        ],
                        slot=Slot(4),
                        target_slot=Slot(3),
                        target_root_label="block_3",
                        source_root_label="block_2",
                        source_slot=Slot(2),
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(4),
            latest_justified_slot=Slot(1),
            latest_finalized_slot=Slot(0),
            justified_slots=JustifiedSlots(data=[Boolean(True), Boolean(False), Boolean(False)]),
            justifications_roots_count=1,
            justifications_validators_count=4,
            justifications_validators=JustificationValidators(
                data=[
                    Boolean(True),
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                ]
            ),
        ),
    )


def test_same_block_multi_target_attestations_advance_to_highest_slot(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Several supermajorities in one block advance justified to the highest target.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_9(9) -> block(10)
    - block(10) includes V0, V1, V2's votes for block_4.
    - slot 4 is justifiable, since delta 4 from finalized 0 is in the immediate window.
    - block(10) includes V0, V1, V2's votes for block_9.
    - slot 9 is justifiable, since delta 9 from finalized 0 is a perfect square.
    - block(10) carries a forced V0, V1, V2 vote for block_6.
    - slot 6 is justifiable, since delta 6 from finalized 0 is pronic.
    - the on-chain body order is target slot 4, then 9, then 6.

    When
    ----
    - the chain processes block_1 through block(10).

    Then
    ----
    - the justified-slots bitfield marks slots 4, 6, and 9 alone.
    - justified slot is 9, the highest target, not the last one processed.
    - finalized stays at slot 0.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(slot=Slot(3), parent_label="block_2", label="block_3"),
            BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
            BlockSpec(slot=Slot(5), parent_label="block_4", label="block_5"),
            BlockSpec(slot=Slot(6), parent_label="block_5", label="block_6"),
            BlockSpec(slot=Slot(7), parent_label="block_6", label="block_7"),
            BlockSpec(slot=Slot(8), parent_label="block_7", label="block_8"),
            BlockSpec(slot=Slot(9), parent_label="block_8", label="block_9"),
            BlockSpec(
                slot=Slot(10),
                parent_label="block_9",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(10),
                        target_slot=Slot(4),
                        target_root_label="block_4",
                    ),
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(10),
                        target_slot=Slot(9),
                        target_root_label="block_9",
                    ),
                ],
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(10),
                        target_slot=Slot(6),
                        target_root_label="block_6",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(10),
            latest_justified_slot=Slot(9),
            latest_finalized_slot=Slot(0),
            justified_slots=JustifiedSlots(
                data=[
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(True),
                    Boolean(False),
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(True),
                ]
            ),
        ),
    )
