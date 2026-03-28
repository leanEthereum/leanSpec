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
