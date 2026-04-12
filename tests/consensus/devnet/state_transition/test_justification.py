"""State Transition: Justification"""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
    generate_pre_state,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state.types import (
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Boolean, Bytes32

pytestmark = pytest.mark.valid_until("Devnet")


def test_supermajority_attestations_justify_block(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that aggregated attestations advance justification end to end.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Process block_1 at slot 1
    3. Process a block at slot 2 with attestations from validators 0, 1, and 2
       targeting block_1 at slot 1

    Expected Behavior
    -----------------
    1. Slot 1 is a justifiable target after finalized slot 0
    2. Three of four validators form a supermajority
    3. The attestation target resolves to block_1 and matches chain history
    4. latest_justified_slot advances to slot 1
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
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
    Test that exact two-thirds support is sufficient for justification.

    Scenario
    --------
    1. Start from genesis with 6 validators
    2. Process block_1 at slot 1
    3. Process a block at slot 2 with attestations from validators 0, 1, 2,
       and 3 targeting block_1 at slot 1

    Expected Behavior
    -----------------
    1. Slot 1 is a justifiable target after finalized slot 0
    2. Four of six validators meet the exact two-thirds threshold
    3. The >= supermajority rule applies at the boundary
    4. latest_justified_slot advances to slot 1
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
                        validator_ids=[
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
    Test that support below two-thirds does not justify a target.

    Scenario
    --------
    1. Start from genesis with 6 validators
    2. Process block_1 at slot 1
    3. Process a block at slot 2 with attestations from validators 0, 1, and 2
       targeting block_1 at slot 1

    Expected Behavior
    -----------------
    1. Slot 1 is a justifiable target after finalized slot 0
    2. Three of six validators are below the two-thirds threshold
    3. The pending tally remains below supermajority
    4. latest_justified_slot stays at genesis
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
    Test that pending justification votes persist across multiple blocks.

    Scenario
    --------
    1. Start from genesis with 6 validators
    2. Process block_1 at slot 1
    3. Process a block at slot 2 with attestations from validators 0, 1, and 2
       targeting block_1 at slot 1
    4. Process a block at slot 3 with a new attestation from validator 3
       targeting the same block_1 at slot 1

    Expected Behavior
    -----------------
    1. The first attestation set is below threshold on its own
    2. The later attestation reuses the same target and preserves prior votes
    3. Four of six validators are accumulated for block_1 across blocks
    4. latest_justified_slot advances to slot 1
    5. Pending vote tracking is cleared after justification
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
    Test that repeated validator votes do not count twice across blocks.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Process block_1 at slot 1
    3. Process block_2 at slot 2 with attestations from validators 0 and 1
       targeting block_1 at slot 1
    4. Process block_3 at slot 3 with the same validators 0 and 1 targeting
       block_1 again

    Expected Behavior
    -----------------
    1. The first attestation set is below threshold on its own
    2. Repeating the same validators in a later block does not add new weight
    3. Unique support remains two of four validators, which is below two-thirds
    4. latest_justified_slot stays at genesis
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
    Test that the same validator is counted once even across distinct attestations.

    Scenario
    --------
    1. Start from genesis with 6 validators
    2. Process block_1 at slot 1
    3. Process block_2 at slot 2 with two attestations targeting block_1:
       - validators 0, 1, and 2 attest with attestation slot 1
       - validator 0 attests again with attestation slot 2

    Expected Behavior
    -----------------
    1. Justification tallies are keyed by target root, not by raw attestation count
    2. Validator 0 contributes only one unit of support toward block_1
    3. Unique support remains three of six validators, below the threshold
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
                        validator_ids=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(1),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                    AggregatedAttestationSpec(
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(update={"data": [Boolean(False)]}),
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


def test_finalization_on_next_justifiable_step(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that justification of the next justifiable step finalizes the source.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Process block_1 at slot 1
    3. Process block_2 at slot 2 with attestations from validators 0, 1, and 2
       targeting block_1 at slot 1
    4. Process block_3 at slot 3 with attestations from validators 0, 1, and 2
       targeting block_2 at slot 2

    Expected Behavior
    -----------------
    1. The block at slot 1 becomes justified first
    2. The block at slot 2 is justified from source slot 1
    3. There is no intermediate justifiable slot between source 1 and target 2
    4. latest_finalized_slot advances to slot 1
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
            latest_finalized_slot=Slot(1),
        ),
    )


def test_pending_justification_survives_finalization_rebase(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that finalization rebasing preserves pending votes beyond the new boundary.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Process block_1 at slot 1 and justify it in block_2 at slot 2
    3. Extend the chain through block_4 at slot 4
    4. Process block_5 at slot 5 with two attestations:
       - validator 0 targets block_3 at slot 3, leaving a pending vote
       - validators 0, 1, and 2 target block_2 at slot 2, justifying it

    Expected Behavior
    -----------------
    1. The second attestation justifies slot 2 and finalizes slot 1
    2. justified_slots rebases to the new finalized boundary at slot 1
    3. The pending vote for block_3 survives because its target lies beyond slot 1
    4. Pending justification tracking is preserved after pruning
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
            latest_finalized_slot=Slot(1),
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={"data": [Boolean(True), Boolean(False), Boolean(False)]}
            ),
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
    Test that finalization does not advance across an intermediate justifiable slot.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Process block_1 at slot 1 and justify it in block_2 at slot 2
    3. Extend the chain through block_4 at slot 4
    4. Process block_5 at slot 5 with attestations from validators 0, 1, and 2
       targeting block_4 at slot 4

    Expected Behavior
    -----------------
    1. The source checkpoint for the later attestation is slot 1
    2. Slot 4 is a valid justifiable target after finalized slot 0
    3. Slots 2 and 3 are intermediate justifiable positions
    4. latest_justified_slot advances to slot 4 while latest_finalized_slot stays at 0
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
            latest_finalized_slot=Slot(0),
        ),
    )


def test_mid_block_finalized_slot_visibility(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that later attestations in a block see finalized-slot updates immediately.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Process block_1 at slot 1 and block_2 at slot 2
    3. Process block_3 at slot 3 with attestations from validators 0, 1, and 2
       targeting block_1 at slot 1
    4. Extend the chain through block_7 at slot 7
    5. Process block_8 at slot 8 with two attestations:
       - validators 0, 1, and 2 target block_2 at slot 2
       - validators 0, 1, and 2 target block_7 at slot 7

    Expected Behavior
    -----------------
    1. The first attestation justifies slot 2 and finalizes slot 1
    2. The second attestation evaluates justifiability after finalized slot advances
    3. Slot 7 becomes a valid target because delta 6 from finalized slot 1 is pronic
    4. latest_justified_slot advances to slot 7 and latest_finalized_slot to slot 1
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
            latest_finalized_slot=Slot(1),
        ),
    )


def test_pronic_boundary_acceptance(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that a pronic-distance target is accepted for justification.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Build a linear chain through block_7 at slot 7
    3. Process block_7 with attestations from validators 0, 1, and 2
       targeting block_6 at slot 6

    Expected Behavior
    -----------------
    1. latest_finalized_slot remains at genesis
    2. Slot 6 is a valid target because delta 6 is pronic
    3. Three of four validators form a supermajority
    4. latest_justified_slot advances to slot 6
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
    Test that a non-justifiable boundary target is rejected.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Build a linear chain through block_8 at slot 8
    3. Process block_8 with attestations from validators 0, 1, and 2
       targeting block_7 at slot 7

    Expected Behavior
    -----------------
    1. latest_finalized_slot remains at genesis
    2. Slot 7 is not justifiable after finalized slot 0
    3. Even with supermajority support, the attestation is ignored
    4. latest_justified_slot stays at genesis
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
    Test that a square-distance target is accepted for justification.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Build a linear chain through block_10 at slot 10
    3. Process block_10 with attestations from validators 0, 1, and 2
       targeting block_9 at slot 9

    Expected Behavior
    -----------------
    1. latest_finalized_slot remains at genesis
    2. Slot 9 is a valid target because delta 9 is a perfect square
    3. Three of four validators form a supermajority
    4. latest_justified_slot advances to slot 9
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
    Test that two aggregates for the same target combine within a single block.

    Scenario
    --------
    1. Start from genesis with 6 validators
    2. Process block_1 at slot 1
    3. Process a block at slot 2 with two separate attestations targeting
       block_1 at slot 1: validators 0-1 in one aggregate, validators 2-3
       in another

    Expected Behavior
    -----------------
    1. Neither aggregate alone reaches the two-thirds threshold
    2. The implementation merges both aggregates toward the same tally
    3. Four of six validators form a supermajority when combined
    4. latest_justified_slot advances to slot 1
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
                        validator_ids=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                    ),
                    AggregatedAttestationSpec(
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(update={"data": [Boolean(True)]}),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_odd_validator_threshold_boundary_justifies(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that four of five validators meet the two-thirds threshold.

    Scenario
    --------
    1. Start from genesis with 5 validators
    2. Process block_1 at slot 1
    3. Process a block at slot 2 with attestations from validators 0, 1, 2,
       and 3 targeting block_1 at slot 1

    Expected Behavior
    -----------------
    1. Four of five validators is 80%, above the two-thirds threshold
    2. The integer math check passes: 4 * 3 = 12 >= 5 * 2 = 10
    3. latest_justified_slot advances to slot 1
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
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(update={"data": [Boolean(True)]}),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_odd_validator_threshold_boundary_does_not_justify(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that three of five validators do not meet the two-thirds threshold.

    Scenario
    --------
    1. Start from genesis with 5 validators
    2. Process block_1 at slot 1
    3. Process a block at slot 2 with attestations from validators 0, 1,
       and 2 targeting block_1 at slot 1

    Expected Behavior
    -----------------
    1. Three of five validators is 60%, below the two-thirds threshold
    2. The integer math check fails: 3 * 3 = 9 < 5 * 2 = 10
    3. latest_justified_slot stays at genesis
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
        ],
        post=StateExpectation(
            slot=Slot(2),
            latest_justified_slot=Slot(0),
            latest_finalized_slot=Slot(0),
            justified_slots=JustifiedSlots(data=[]).model_copy(update={"data": [Boolean(False)]}),
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
    Test that a supermajority cannot justify a slot with the wrong canonical root.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Process block_1 at slot 1 and block_2 at slot 2
    3. Process a block at slot 3 with attestations from validators 0, 1, and 2
       targeting slot 1 but using block_2's root instead of block_1's root

    Expected Behavior
    -----------------
    1. The attested root does not match the canonical block at slot 1
    2. Even with supermajority support, the attestation is rejected
    3. latest_justified_slot stays at genesis
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
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
    Test that an attestation with a fabricated target root is silently skipped.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Process block_1 at slot 1
    3. Process block_2 at slot 2 with attestations from validators 0, 1, and 2
       targeting slot 1 with a valid Bytes32 root that does not match block_1

    Expected Behavior
    -----------------
    1. The block at slot 2 is processed successfully
    2. The attestation reaches state processing because its head stays canonical
    3. The target root fails the historical_block_hashes check and is skipped
    4. latest_justified_slot stays at genesis
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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


def test_justification_clears_only_the_resolved_target_votes(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that justifying one target clears only that target's pending votes.

    Scenario
    --------
    1. Start from genesis with 6 validators
    2. Process block_1 at slot 1
    3. Process block_2 at slot 2 with validators 0, 1, and 2 voting for block_1
    4. Process block_3 at slot 3 with validators 0 and 1 voting for block_2
    5. Process block_4 at slot 4 with validator 3 voting for block_1 again

    Expected Behavior
    -----------------
    1. Votes for block_1 and block_2 are tracked independently
    2. The later vote from validator 3 brings block_1 to the two-thirds threshold
    3. Pending votes for block_1 are cleared once slot 1 becomes justified
    4. The unrelated pending votes for block_2 remain tracked
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
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={"data": [Boolean(True), Boolean(False), Boolean(False)]}
            ),
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


def test_finalization_prunes_stale_pending_votes_and_rebases_window(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that advancing finalization drops stale pending votes and shifts the window.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Justify block_1 at slot 1 in block_2
    3. Create a pending vote tally for block_2 in block_3 with validators 0 and 1
    4. Justify block_4 at slot 4 in block_5 using source slot 1
    5. Justify block_5 at slot 5 in block_6, which finalizes source slot 4

    Expected Behavior
    -----------------
    1. Finalizing slot 4 rebases the tracked justification window to start after slot 4
    2. Pending votes for block_2 are stale once slot 4 is finalized and are pruned
    3. Only the new justified status for slot 5 remains in the rebased window
    4. latest_justified_slot becomes 5 and latest_finalized_slot becomes 4
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
            latest_finalized_slot=Slot(4),
            justified_slots=JustifiedSlots(data=[]).model_copy(update={"data": [Boolean(True)]}),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_target_at_or_before_source_is_ignored(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    Test that a vote cannot move backward to a target at or before its source.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Justify block_1 at slot 1 in block_2
    3. Create a pending vote tally for block_2 in block_3 with validators 0 and 1
    4. Justify block_4 at slot 4 in block_5 so the source advances to slot 4
    5. Process block_6 with validator 2 voting for the older block_2 target

    Expected Behavior
    -----------------
    1. The block_6 attestation uses source slot 4 from the current justified checkpoint
    2. Its target slot 2 is not strictly after the source slot and is ignored
    3. The old pending votes for block_2 do not gain validator 2's support
    4. latest_justified_slot remains at slot 4
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
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={
                    "data": [
                        Boolean(True),
                        Boolean(False),
                        Boolean(False),
                        Boolean(True),
                        Boolean(False),
                    ]
                }
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
    Attestation targeting an already-justified slot is ignored without error.

    Scenario
    --------
    1. Start from genesis with 4 validators
    2. Process block_1 at slot 1
    3. Process block_2 at slot 2 with attestations from validators 0, 1, and 2
       targeting block_1 at slot 1, justifying slot 1
    4. Process block_3 at slot 3 with an attestation from validator 3
       targeting block_1 at slot 1 (already justified)

    Expected Behavior
    -----------------
    1. Slot 1 becomes justified after block_2
    2. The attestation in block_3 targets an already-justified slot
    3. The duplicate attestation is silently skipped with no state change
    4. The block containing the duplicate attestation is accepted as valid
    """
    state_transition_test(
        pre=generate_pre_state(),
        blocks=[
            # Step 1 — Build chain and justify slot X
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
            # Step 2 — Include duplicate attestation targeting slot X
            # Step 3 — Apply state transition
            # Assertion C — No errors during processing
            BlockSpec(
                slot=Slot(3),
                parent_label="block_2",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[
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
            # Assertion A — Justification preserved
            latest_justified_slot=Slot(1),
            latest_finalized_slot=Slot(0),
            # Assertion B — No additional state change from the duplicate attestation
            justified_slots=JustifiedSlots(data=[]).model_copy(
                update={"data": [Boolean(True), Boolean(False)]}
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )
