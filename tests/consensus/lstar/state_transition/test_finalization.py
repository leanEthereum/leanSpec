"""State Transition: Finalization"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
    generate_pre_state,
)
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Boolean

pytestmark = pytest.mark.valid_until("Lstar")


def test_finalization_on_next_justifiable_step(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Adjacent justifications finalize the earlier slot.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2 justifies slot 1.
    - block_3 includes V0, V1, V2's votes for block_2.
    - block_3 justifies slot 2.
    - block_3 then finalizes slot 1.

    When
    ----
    - the chain processes block_1, block_2, and block_3.

    Then
    ----
    - the state slot is 3.
    - justified slot is 2, rooted at block_2.
    - finalized slot is 1, rooted at block_1.
    - the justified-slots bitfield marks slot 2 alone.
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
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(3),
            latest_justified_slot=Slot(2),
            latest_justified_root_label="block_2",
            latest_finalized_slot=Slot(1),
            latest_finalized_root_label="block_1",
            justified_slots=JustifiedSlots(data=[Boolean(True)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_pending_justification_survives_finalization_rebase(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A pending vote survives the window rebase that follows finalization.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2 justifies slot 1.
    - block_5 includes V0's vote for block_3.
    - block_5 includes V0, V1, V2's votes for block_2.
    - block_5's supermajority justifies slot 2.
    - block_5 then finalizes slot 1, which rebases the window.

    When
    ----
    - the chain processes block_1 through block_5.

    Then
    ----
    - the state slot is 5.
    - justified slot is 2, rooted at block_2.
    - finalized slot is 1, rooted at block_1.
    - the justified-slots bitfield is [True, False, False] relative to slot 1.
    - the pending-vote roots hold block_3.
    - the pending tally for block_3 is 1 of 4.
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
                label="block_4",
            ),
            BlockSpec(
                slot=Slot(5),
                parent_label="block_4",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                        ],
                        slot=Slot(4),
                        target_slot=Slot(3),
                        target_root_label="block_3",
                    ),
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(5),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(5),
            latest_justified_slot=Slot(2),
            latest_justified_root_label="block_2",
            latest_finalized_slot=Slot(1),
            latest_finalized_root_label="block_1",
            justified_slots=JustifiedSlots(data=[Boolean(True), Boolean(False), Boolean(False)]),
            justifications_roots_labels=["block_3"],
            justifications_validators=JustificationValidators(
                data=[
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                ]
            ),
        ),
    )


def test_no_finalization_when_intermediate_justifiable_slot_exists(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A non-adjacent justification leaves an intermediate slot, so finalization stays.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> block_5(5)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2 justifies slot 1.
    - block_5 includes V0, V1, V2's votes for block_4.
    - block_5 justifies slot 4.
    - slot 1 to slot 4 is not adjacent, so no slot is finalized.
    - the anchor root is the chain tip header at slot 1 before block_1.

    When
    ----
    - the chain processes block_1 through block_5.

    Then
    ----
    - the state slot is 5.
    - justified slot is 4, rooted at block_4.
    - finalized stays at slot 0.
    - the finalized root is the anchor root.
    - the justified-slots bitfield marks slots 1 and 4.
    - no pending votes remain.
    """
    pre = generate_pre_state()
    anchor_state = LstarSpec().process_slots(pre, Slot(1))
    anchor_root = hash_tree_root(anchor_state.latest_block_header)

    state_transition_test(
        pre=pre,
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
                label="block_4",
            ),
            BlockSpec(
                slot=Slot(5),
                parent_label="block_4",
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
        ],
        post=StateExpectation(
            slot=Slot(5),
            latest_justified_slot=Slot(4),
            latest_justified_root_label="block_4",
            latest_finalized_slot=Slot(0),
            latest_finalized_root=anchor_root,
            justified_slots=JustifiedSlots(
                data=[Boolean(True), Boolean(False), Boolean(False), Boolean(True)]
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_mid_block_finalized_slot_visibility(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    One block carrying two supermajorities justifies two slots and finalizes one.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4)
          -> block_5(5) -> block_6(6) -> block_7(7) -> block_8(8)
    - block_3 includes V0, V1, V2's votes for block_1.
    - block_3 justifies slot 1.
    - block_8 includes V0, V1, V2's votes for block_2.
    - block_8 includes V0, V1, V2's votes for block_7.
    - block_8 justifies slot 2 and slot 7.
    - block_8 then finalizes slot 1.

    When
    ----
    - the chain processes block_1 through block_8.

    Then
    ----
    - the state slot is 8.
    - justified slot is 7, rooted at block_7.
    - finalized slot is 1, rooted at block_1.
    - the justified-slots bitfield marks slots 2 and 7 relative to slot 1.
    - no pending votes remain.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
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
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
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
            latest_justified_slot=Slot(7),
            latest_justified_root_label="block_7",
            latest_finalized_slot=Slot(1),
            latest_finalized_root_label="block_1",
            justified_slots=JustifiedSlots(
                data=[
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(True),
                ]
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_finalization_prunes_stale_pending_votes_and_rebases_window(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Finalizing slot 4 prunes stale pending votes and rebases the window.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4)
          -> block_5(5) -> block_6(6)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2 justifies slot 1.
    - block_3 includes V0, V1's votes for block_2.
    - block_3's partial tally for block_2 stays pending.
    - block_5 includes V0, V1, V2's votes for block_4.
    - block_5 justifies slot 4.
    - block_6 includes V0, V1, V2's votes for block_5.
    - block_6 justifies slot 5.
    - block_6 then finalizes slot 4, which prunes the stale tally.

    When
    ----
    - the chain processes block_1 through block_6.

    Then
    ----
    - the state slot is 6.
    - justified slot is 5, rooted at block_5.
    - finalized slot is 4, rooted at block_4.
    - the justified-slots bitfield marks slot 5 alone.
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
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(6),
                        target_slot=Slot(5),
                        target_root_label="block_5",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(6),
            latest_justified_slot=Slot(5),
            latest_justified_root_label="block_5",
            latest_finalized_slot=Slot(4),
            latest_finalized_root_label="block_4",
            justified_slots=JustifiedSlots(data=[Boolean(True)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_stale_finalized_source_justifies_without_rewinding_finalization(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote whose source is behind the finalized boundary justifies but never refinalizes.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4)
          -> block_5(5) -> block_6(6) -> block_7(7)
    - block_2, block_5, and block_6 carry supermajorities that finalize slot 4.
    - block_7 includes V0, V1, V2's vote from block_1 to block_6.
    - the source slot 1 sits behind the finalized slot 4.
    - block_7 justifies slot 6.

    When
    ----
    - the chain processes block_1 through block_7.

    Then
    ----
    - the state slot is 7.
    - justified slot is 6, rooted at block_6.
    - finalized stays at slot 4, rooted at block_4.
    - the justified-slots bitfield marks slots 5 and 6.
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
            BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
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
                label="block_6",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(6),
                        target_slot=Slot(5),
                        target_root_label="block_5",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(7),
                parent_label="block_6",
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(7),
                        source_slot=Slot(1),
                        source_root_label="block_1",
                        target_slot=Slot(6),
                        target_root_label="block_6",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(7),
            latest_justified_slot=Slot(6),
            latest_justified_root_label="block_6",
            latest_finalized_slot=Slot(4),
            latest_finalized_root_label="block_4",
            justified_slots=JustifiedSlots(data=[Boolean(True), Boolean(True)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_source_at_finalized_boundary_justifies_without_refinalizing(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote whose source sits exactly at the finalized boundary justifies but never refinalizes.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4)
          -> block_5(5) -> block_6(6) -> block_7(7)
    - block_2, block_5, and block_6 carry supermajorities that finalize slot 4.
    - block_7 includes V0, V1, V2's vote from block_4 to block_6.
    - the source slot 4 equals the finalized slot, which is already final.
    - block_7 justifies slot 6.

    When
    ----
    - the chain processes block_1 through block_7.

    Then
    ----
    - the state slot is 7.
    - justified slot is 6, rooted at block_6.
    - finalized stays at slot 4, rooted at block_4.
    - the justified-slots bitfield marks slots 5 and 6.
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
            BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
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
                label="block_6",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(6),
                        target_slot=Slot(5),
                        target_root_label="block_5",
                    ),
                ],
            ),
            BlockSpec(
                slot=Slot(7),
                parent_label="block_6",
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(7),
                        source_slot=Slot(4),
                        source_root_label="block_4",
                        target_slot=Slot(6),
                        target_root_label="block_6",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(7),
            latest_justified_slot=Slot(6),
            latest_justified_root_label="block_6",
            latest_finalized_slot=Slot(4),
            latest_finalized_root_label="block_4",
            justified_slots=JustifiedSlots(data=[Boolean(True), Boolean(True)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_non_adjacent_justification_finalizes_across_non_justifiable_gap(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Finalization spans a non-justifiable gap between two justified slots.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4)
          -> block_5(5) -> block_6(6) -> block_7(7) -> block_8(8)
          -> block_9(9) -> block_10(10)
    - block_7 includes V0, V1, V2's votes for block_6.
    - block_7 justifies slot 6.
    - block_10 includes V0, V1, V2's votes for block_9.
    - block_10 justifies slot 9.
    - block_10 then finalizes slot 6 across the non-justifiable gap.

    When
    ----
    - the chain processes block_1 through block_10.

    Then
    ----
    - the state slot is 10.
    - justified slot is 9, rooted at block_9.
    - finalized slot is 6, rooted at block_6.
    - the justified-slots bitfield is [False, False, True] relative to slot 6.
    - no pending votes remain.
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
                label="block_7",
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
            latest_justified_root_label="block_9",
            latest_finalized_slot=Slot(6),
            latest_finalized_root_label="block_6",
            justified_slots=JustifiedSlots(data=[Boolean(False), Boolean(False), Boolean(True)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_no_finalization_when_rebased_boundary_exposes_intermediate_justifiable_slot(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A rebased window exposes an intermediate justifiable slot, so finalization stays.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_14(14)
    - block_3 includes V0, V1, V2's votes for block_1.
    - block_3 justifies slot 1.
    - block_8 includes V0, V1, V2's votes for block_2.
    - block_8 includes V0, V1, V2's votes for block_7.
    - block_8 justifies slots 2 and 7 and finalizes slot 1.
    - block_14 includes V0, V1, V2's votes for block_13.
    - block_14 justifies slot 13.
    - an intermediate justifiable slot blocks further finalization.

    When
    ----
    - the chain processes block_1 through block_14.

    Then
    ----
    - the state slot is 14.
    - justified slot is 13, rooted at block_13.
    - finalized stays at slot 1, rooted at block_1.
    - the justified-slots bitfield marks slots 2, 7, and 13.
    - no pending votes remain.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
            BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
            BlockSpec(slot=Slot(5), parent_label="block_4", label="block_5"),
            BlockSpec(slot=Slot(6), parent_label="block_5", label="block_6"),
            BlockSpec(slot=Slot(7), parent_label="block_6", label="block_7"),
            BlockSpec(
                slot=Slot(8),
                parent_label="block_7",
                label="block_8",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(8),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
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
            BlockSpec(slot=Slot(9), parent_label="block_8", label="block_9"),
            BlockSpec(slot=Slot(10), parent_label="block_9", label="block_10"),
            BlockSpec(slot=Slot(11), parent_label="block_10", label="block_11"),
            BlockSpec(slot=Slot(12), parent_label="block_11", label="block_12"),
            BlockSpec(slot=Slot(13), parent_label="block_12", label="block_13"),
            BlockSpec(
                slot=Slot(14),
                parent_label="block_13",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(14),
                        target_slot=Slot(13),
                        target_root_label="block_13",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(14),
            latest_justified_slot=Slot(13),
            latest_justified_root_label="block_13",
            latest_finalized_slot=Slot(1),
            latest_finalized_root_label="block_1",
            justified_slots=JustifiedSlots(
                data=[
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(True),
                ]
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_mid_block_finalized_slot_rejects_target_that_loses_justifiability(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A target that loses justifiability after the rebase is dropped, leaving slot 9 unresolved.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_10(10)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2 justifies slot 1.
    - block_10 includes V0, V1, V2's votes for block_2.
    - block_10 includes V0, V1, V2's votes for block_9.
    - block_10 justifies slot 2 and finalizes slot 1.
    - slot 9 loses justifiability after the window rebases to slot 1.

    When
    ----
    - the chain processes block_1 through block_10.

    Then
    ----
    - the state slot is 10.
    - justified slot is 2, rooted at block_2.
    - finalized slot is 1, rooted at block_1.
    - the justified-slots bitfield marks slot 2 alone relative to slot 1.
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
                        target_slot=Slot(2),
                        target_root_label="block_2",
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
            ),
        ],
        post=StateExpectation(
            slot=Slot(10),
            latest_justified_slot=Slot(2),
            latest_justified_root_label="block_2",
            latest_finalized_slot=Slot(1),
            latest_finalized_root_label="block_1",
            justified_slots=JustifiedSlots(
                data=[
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                ]
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_merged_attestations_for_same_target_justify_and_finalize_cleanly(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Two votes for the same target merge, then justify and finalize cleanly.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3)
    - block_2 includes V0, V1, V2's votes for block_1.
    - block_2 justifies slot 1.
    - block_3 includes V0, V1, V2's votes for block_2.
    - block_3 includes V3's vote for block_2.
    - both votes share one target, so the builder merges them into one tally.
    - block_3 justifies slot 2.
    - block_3 then finalizes slot 1.

    When
    ----
    - the chain processes block_1, block_2, and block_3.

    Then
    ----
    - the state slot is 3.
    - justified slot is 2, rooted at block_2.
    - finalized slot is 1, rooted at block_1.
    - the justified-slots bitfield marks slot 2 alone.
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
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(3),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(3),
            latest_justified_slot=Slot(2),
            latest_justified_root_label="block_2",
            latest_finalized_slot=Slot(1),
            latest_finalized_root_label="block_1",
            justified_slots=JustifiedSlots(data=[Boolean(True)]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_rebased_finalization_prunes_stale_votes_and_preserves_future_votes(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A second rebase prunes stale votes but keeps a future pending tally.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_14(14)
    - block_3 includes V0, V1, V2's votes for block_1.
    - block_3 justifies slot 1.
    - block_5 includes V0, V1's votes for block_4.
    - block_5's partial tally for block_4 stays pending.
    - block_8 includes V0, V1, V2's votes for block_2.
    - block_8 includes V0, V1, V2's votes for block_7.
    - block_8 justifies slots 2 and 7 and finalizes slot 1.
    - block_14 includes V0's vote for block_13.
    - block_14 includes V0, V1, V2's votes for block_10.
    - block_14 justifies slot 10 and finalizes slot 7, which rebases again.

    When
    ----
    - the chain processes block_1 through block_14.

    Then
    ----
    - the state slot is 14.
    - justified slot is 10, rooted at block_10.
    - finalized slot is 7, rooted at block_7.
    - the justified-slots bitfield is [False, False, True, False, False, False] relative to slot 7.
    - the pending-vote roots hold block_13.
    - the pending tally for block_13 is 1 of 4.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                ],
            ),
            BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
            BlockSpec(
                slot=Slot(5),
                parent_label="block_4",
                label="block_5",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                        ],
                        slot=Slot(5),
                        target_slot=Slot(4),
                        target_root_label="block_4",
                    ),
                ],
            ),
            BlockSpec(slot=Slot(6), parent_label="block_5", label="block_6"),
            BlockSpec(slot=Slot(7), parent_label="block_6", label="block_7"),
            BlockSpec(
                slot=Slot(8),
                parent_label="block_7",
                label="block_8",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(8),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
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
            BlockSpec(slot=Slot(9), parent_label="block_8", label="block_9"),
            BlockSpec(slot=Slot(10), parent_label="block_9", label="block_10"),
            BlockSpec(slot=Slot(11), parent_label="block_10", label="block_11"),
            BlockSpec(slot=Slot(12), parent_label="block_11", label="block_12"),
            BlockSpec(slot=Slot(13), parent_label="block_12", label="block_13"),
            BlockSpec(
                slot=Slot(14),
                parent_label="block_13",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                        ],
                        slot=Slot(14),
                        target_slot=Slot(13),
                        target_root_label="block_13",
                    ),
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(14),
                        target_slot=Slot(10),
                        target_root_label="block_10",
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(14),
            latest_justified_slot=Slot(10),
            latest_justified_root_label="block_10",
            latest_finalized_slot=Slot(7),
            latest_finalized_root_label="block_7",
            justified_slots=JustifiedSlots(
                data=[
                    Boolean(False),
                    Boolean(False),
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                ]
            ),
            justifications_roots_labels=["block_13"],
            justifications_validators=JustificationValidators(
                data=[
                    Boolean(True),
                    Boolean(False),
                    Boolean(False),
                    Boolean(False),
                ]
            ),
        ),
    )
