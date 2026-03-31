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
from lean_spec.subspecs.containers.validator import ValidatorIndex

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


def test_exact_two_thirds_threshold_justifies(
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
