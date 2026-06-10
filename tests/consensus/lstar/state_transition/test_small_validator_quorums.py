"""State Transition: Small Validator Quorums"""

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
from lean_spec.spec.ssz import Boolean

pytestmark = pytest.mark.valid_until("Lstar")


def test_two_validators_single_vote_does_not_justify(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    With two validators, one vote falls below the two-thirds threshold.

    Given
    -----
    - 2 validators; a slot needs 2 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0's vote for block_1.
    - 1 of 2 falls below the threshold, since 1*3 = 3 is less than 2*2 = 4.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - justified stays at slot 0.
    - finalized stays at slot 0.
    - the pending tally marks V0 only.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=2),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
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
                    Boolean(False),
                ]
            ),
        ),
    )


def test_two_validators_unanimous_votes_justify(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    With two validators, unanimity clears the two-thirds threshold.

    Given
    -----
    - 2 validators; a slot needs 2 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0, V1's votes for block_1.
    - 2 of 2 clears the threshold, since 2*3 = 6 is at least 2*2 = 4.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - block_1's slot is justified.
    - finalized stays at slot 0.
    - the justified-slots bitfield marks slot 1 alone.
    - no pending votes remain.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=2),
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


def test_three_validators_two_votes_justify(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    With three validators, two votes clear the two-thirds threshold.

    Given
    -----
    - 3 validators; a slot needs 2 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) includes V0, V1's votes for block_1.
    - 2 of 3 clears the threshold, since 2*3 = 6 is at least 3*2 = 6.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - block_1's slot is justified.
    - finalized stays at slot 0.
    - the justified-slots bitfield marks slot 1 alone.
    - no pending votes remain.
    """
    state_transition_test(
        pre=generate_pre_state(num_validators=3),
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
