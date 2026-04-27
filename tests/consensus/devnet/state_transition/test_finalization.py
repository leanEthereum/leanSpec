"""State Transition: Finalization"""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
    generate_pre_state,
)

from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.state.types import (
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Boolean

pytestmark = pytest.mark.valid_until("Lstar")


def test_finalization_on_next_justifiable_step(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test the post-state after adjacent justifications finalize slot 1.

    Scenario
    --------
    1. Build block_1 at slot 1
    2. Build block_2 at slot 2 with a supermajority attesting to block_1
    3. Build block_3 at slot 3 with a supermajority attesting to block_2

    Expected Behavior
    -----------------
    1. The post-state slot is 3
    2. latest_justified_slot is 2
    3. latest_justified_root is block_2
    4. latest_finalized_slot is 1
    5. latest_finalized_root is block_1
    6. justified_slots contains a single justified entry for slot 2
    7. There are no pending justifications
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(update={"data": [Boolean(True)]}),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_pending_justification_survives_finalization_rebase(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test the post-state when one pending justification remains after a rebase.

    Scenario
    --------
    1. Justify block_1 by block_2
    2. Extend the chain through block_4
    3. Process block_5 with one partial attestation to block_3
       and one supermajority attestation to block_2

    Expected Behavior
    -----------------
    1. The post-state slot is 5
    2. latest_justified_slot is 2
    3. latest_justified_root is block_2
    4. latest_finalized_slot is 1
    5. latest_finalized_root is block_1
    6. justified_slots equals [True, False, False] relative to finalized slot 1
    7. justifications_roots contains block_3
    8. justifications_validators contains a single 1-of-4 pending tally
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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
                        validator_ids=[
                            ValidatorIndex(0),
                        ],
                        slot=Slot(4),
                        target_slot=Slot(3),
                        target_root_label="block_3",
                    ),
                    AggregatedAttestationSpec(
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={"data": [Boolean(True), Boolean(False), Boolean(False)]}
            ),
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
    Test the post-state when slot 4 is justified and finalization stays at genesis.

    Scenario
    --------
    1. Justify block_1 by block_2
    2. Extend the chain through block_4
    3. Process block_5 with a supermajority attesting to block_4

    Expected Behavior
    -----------------
    1. The post-state slot is 5
    2. latest_justified_slot is 4
    3. latest_justified_root is block_4
    4. latest_finalized_slot remains 0
    5. latest_finalized_root stays at the parent root of block 1
    6. justified_slots marks slots 1 and 4 as justified
    7. There are no pending justifications
    """
    pre = generate_pre_state()
    anchor_root = hash_tree_root(pre.process_slots(Slot(1)).latest_block_header)

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
                        validator_ids=[
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
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={"data": [Boolean(True), Boolean(False), Boolean(False), Boolean(True)]}
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_mid_block_finalized_slot_visibility(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test the post-state after block 8 justifies slots 2 and 7 and finalizes slot 1.

    Scenario
    --------
    1. Justify block_1 by block_3
    2. Extend the chain through block_7
    3. Process block_8 with supermajority attestations to block_2 and block_7

    Expected Behavior
    -----------------
    1. The post-state slot is 8
    2. latest_justified_slot is 7
    3. latest_justified_root is block_7
    4. latest_finalized_slot is 1
    5. latest_finalized_root is block_1
    6. justified_slots marks slots 2 and 7 as justified relative to slot 1
    7. There are no pending justifications
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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
                        validator_ids=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(8),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                    AggregatedAttestationSpec(
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={
                    "data": [
                        Boolean(True),
                        Boolean(False),
                        Boolean(False),
                        Boolean(False),
                        Boolean(False),
                        Boolean(True),
                    ]
                }
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_finalization_prunes_stale_pending_votes_and_rebases_window(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test the post-state after finalizing slot 4 and clearing pending votes.

    Scenario
    --------
    1. Justify block_1 in block_2
    2. Create a pending tally for block_2 in block_3
    3. Justify block_4 in block_5
    4. Justify block_5 in block_6

    Expected Behavior
    -----------------
    1. The post-state slot is 6
    2. latest_justified_slot is 5
    3. latest_justified_root is block_5
    4. latest_finalized_slot is 4
    5. latest_finalized_root is block_4
    6. justified_slots contains a single justified entry for slot 5
    7. There are no pending justifications
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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
                        validator_ids=[
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
                        validator_ids=[
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
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(update={"data": [Boolean(True)]}),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_non_adjacent_justification_finalizes_across_non_justifiable_gap(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test the post-state after finalizing slot 6 and justifying slot 9.

    Scenario
    --------
    1. Build the chain through block_6
    2. Justify block_6 in block_7
    3. Extend the chain through block_9
    4. Process block_10 with a supermajority attesting to block_9

    Expected Behavior
    -----------------
    1. The post-state slot is 10
    2. latest_justified_slot is 9
    3. latest_justified_root is block_9
    4. latest_finalized_slot is 6
    5. latest_finalized_root is block_6
    6. justified_slots equals [False, False, True] relative to slot 6
    7. There are no pending justifications
    """
    state_transition_test(
        pre=generate_pre_state(),
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
                        validator_ids=[
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
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={"data": [Boolean(False), Boolean(False), Boolean(True)]}
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_no_finalization_when_rebased_boundary_exposes_intermediate_justifiable_slot(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test the post-state when slot 13 is justified and finalization remains at slot 1.

    Scenario
    --------
    1. Justify slot 1 in block_3
    2. Process block_8 so slots 2 and 7 become justified and slot 1 becomes finalized
    3. Extend the chain through block_13
    4. Process block_14 with a supermajority attesting to block_13

    Expected Behavior
    -----------------
    1. The post-state slot is 14
    2. latest_justified_slot is 13
    3. latest_justified_root is block_13
    4. latest_finalized_slot is 1
    5. latest_finalized_root is block_1
    6. justified_slots contains justified entries for slots 2, 7, and 13
    7. There are no pending justifications
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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
                        validator_ids=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(8),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                    AggregatedAttestationSpec(
                        validator_ids=[
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
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={
                    "data": [
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
                }
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_mid_block_finalized_slot_rejects_target_that_loses_justifiability(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test the post-state when block 10 finalizes slot 1 and leaves slot 9 unresolved.

    Scenario
    --------
    1. Justify block_1 in block_2
    2. Extend the chain through block_9
    3. Process block_10 with supermajority attestations to block_2 and block_9

    Expected Behavior
    -----------------
    1. The post-state slot is 10
    2. latest_justified_slot is 2
    3. latest_justified_root is block_2
    4. latest_finalized_slot is 1
    5. latest_finalized_root is block_1
    6. justified_slots contains a single justified entry for slot 2 relative to slot 1
    7. There are no pending justifications
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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
                        validator_ids=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(10),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                    AggregatedAttestationSpec(
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={
                    "data": [
                        Boolean(True),
                        Boolean(False),
                        Boolean(False),
                        Boolean(False),
                        Boolean(False),
                        Boolean(False),
                        Boolean(False),
                        Boolean(False),
                    ]
                }
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_merged_attestations_for_same_target_justify_and_finalize_cleanly(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test the post-state when block 3 justifies slot 2 and leaves no pending votes.

    Scenario
    --------
    1. Justify block_1 in block_2
    2. Process block_3 with two attestation specs both targeting block_2:
       one supermajority (V0-V2) and one single-validator (V3)

    The block builder merges both specs into a single aggregated
    attestation covering all 4 validators (same AttestationData).
    The merged attestation justifies slot 2 and finalizes slot 1
    in one step. No pending votes remain.

    Expected Behavior
    -----------------
    1. The post-state slot is 3
    2. latest_justified_slot is 2
    3. latest_justified_root is block_2
    4. latest_finalized_slot is 1
    5. latest_finalized_root is block_1
    6. justified_slots contains a single justified entry for slot 2
    7. There are no pending justifications
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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
                        validator_ids=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(3),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                    AggregatedAttestationSpec(
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(update={"data": [Boolean(True)]}),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_rebased_finalization_prunes_stale_votes_and_preserves_future_votes(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test the post-state when a second rebase leaves one future pending tally.

    Scenario
    --------
    1. Justify block_1 in block_3
    2. Record a pending tally for block_4 in block_5
    3. Process block_8 so slots 2 and 7 are justified and slot 1 is finalized
    4. Build the chain through block_13
    5. Process block_14 with a partial attestation to block_13
       and a supermajority attestation to block_10

    Expected Behavior
    -----------------
    1. The post-state slot is 14
    2. latest_justified_slot is 10
    3. latest_justified_root is block_10
    4. latest_finalized_slot is 7
    5. latest_finalized_root is block_7
    6. justified_slots equals [False, False, True, False, False, False] relative to slot 7
    7. justifications_roots contains block_13
    8. justifications_validators contains a single 1-of-4 pending tally
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                label="block_3",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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
                        validator_ids=[
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
                        validator_ids=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(8),
                        target_slot=Slot(2),
                        target_root_label="block_2",
                    ),
                    AggregatedAttestationSpec(
                        validator_ids=[
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
                        validator_ids=[
                            ValidatorIndex(0),
                        ],
                        slot=Slot(14),
                        target_slot=Slot(13),
                        target_root_label="block_13",
                    ),
                    AggregatedAttestationSpec(
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={
                    "data": [
                        Boolean(False),
                        Boolean(False),
                        Boolean(True),
                        Boolean(False),
                        Boolean(False),
                        Boolean(False),
                    ]
                }
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
