"""Fork Choice: Finalization advances mid-attestation processing.

This test verifies that attestations see updated finalized_slot during processing,
as required by the 3sf-mini specification.

Reference: https://github.com/leanEthereum/leanSpec/pull/443
"""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)

from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_finalization_advances_mid_attestation_processing(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Verify attestations see updated finalized_slot during processing.

    Scenario
    --------
    Process two attestations (both with supermajority) in the same block:

    - Attestation A: source=1, target=2 -> justifies slot 2, finalizes slot 1
    - Attestation B: source=1, target=7 -> only justifiable after finalization

    Justifiability
    --------------
    Slot 7 justifiability depends on finalized_slot:

    - finalized=0: delta=7, NOT justifiable (7 > 5, not square, not pronic)
    - finalized=1: delta=6, IS justifiable (pronic = 2*3)

    Expected Behavior
    ----------------------------

    1. Attestation A justifies slot 2 and finalizes slot 1
    2. Attestation B sees updated finalized_slot=1, is justifiable, gets processed
    3. Attestation B justifies slot 7 (supermajority)
    4. latest_justified_slot = 7 (B processed after A)

    Reference
    ---------
    https://github.com/leanEthereum/leanSpec/pull/443
    """
    fork_choice_test(
        steps=[
            # Build chain through slot 7
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            # Slot 3: Justify slot 1 (source=0 -> target=1)
            # Need 3/4 validators for supermajority (3*3=9 >= 2*4=8)
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
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
                checks=StoreChecks(
                    head_slot=Slot(3),
                    latest_justified_slot=Slot(1),
                    latest_finalized_slot=Slot(0),
                ),
            ),
            # Extend chain to slot 7
            BlockStep(
                block=BlockSpec(slot=Slot(4), label="block_4"),
                checks=StoreChecks(head_slot=Slot(4)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), label="block_5"),
                checks=StoreChecks(head_slot=Slot(5)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6), label="block_6"),
                checks=StoreChecks(head_slot=Slot(6)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7), label="block_7"),
                checks=StoreChecks(head_slot=Slot(7)),
            ),
            # Slot 8: The critical block with both attestations
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    attestations=[
                        # Attestation A: Justify slot 2 and finalize slot 1
                        # Source will be slot 1 (latest_justified from parent state)
                        # Target is slot 2
                        # Finalization: range(1+1, 2) = empty -> finalizes slot 1
                        # Need 3/4 validators for supermajority
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
                        # Attestation B: Target slot 7 - ALSO needs supermajority
                        # With finalized=0: delta=7, NOT justifiable -> SKIPPED
                        # With finalized=1: delta=6, IS justifiable (pronic) -> PROCESSED
                        #
                        # If processed, slot 7 becomes justified and latest_justified=7
                        # If skipped, latest_justified stays at 2
                        # This is how we detect the bug!
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
                checks=StoreChecks(
                    head_slot=Slot(8),
                    # B is processed -> slot 7 justified -> latest_justified=7
                    latest_justified_slot=Slot(7),
                    latest_finalized_slot=Slot(1),
                ),
            ),
        ],
    )
