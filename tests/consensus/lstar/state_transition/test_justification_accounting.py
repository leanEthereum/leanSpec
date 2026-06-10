"""State Transition: Justification Accounting"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
)
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.spec.ssz import Boolean, Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_lower_target_justifies_while_higher_stays_pending(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    One block justifies a lower target while a higher target stays pending.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_6(6) -> block(7)
    - block(7) includes V0, V1, V2's votes for block_1.
    - slot 1 is justifiable, since delta 1 from finalized 0 is in the immediate window.
    - block(7) includes V0, V1's votes for block_6.
    - slot 6 is justifiable, since delta 6 from finalized 0 is pronic.
    - the lower target reaches 3 of 4 and is justified.
    - the higher target reaches only 2 of 4 and stays pending.

    When
    ----
    - the chain processes block_1 through block(7).

    Then
    ----
    - justified advances to slot 1, the lower target.
    - justified does not advance to slot 6, the higher target.
    - finalized stays at slot 0.
    - the pending tally for block_6 marks V0, V1 only.
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
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
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
            latest_justified_slot=Slot(1),
            latest_finalized_slot=Slot(0),
            justifications_roots_count=1,
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


def test_vote_for_already_justified_slot_with_different_root_is_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote for an already-justified slot is skipped even with a different target root.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block(3)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2 justifies slot 1.
    - block(3) carries a forced V0, V1, V2 vote for target slot 1 with an off-canonical root.
    - the off-canonical root differs from block_1, the canonical block at slot 1.
    - the already-justified guard is keyed by slot, not by root.
    - slot 1 is already justified, so the vote is skipped before any tally.

    When
    ----
    - the chain processes block_1, block_2, and block(3).

    Then
    ----
    - block_1's slot stays justified.
    - finalized stays at slot 0.
    - the justified-slots bitfield marks slot 1 alone.
    - no pending tally is created for the off-canonical root.
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
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(1),
                        target_root=Bytes32(b"\x33" * 32),
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
