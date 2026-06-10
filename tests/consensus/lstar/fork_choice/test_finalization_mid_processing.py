"""Fork Choice: Finalization advances mid-attestation processing."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)
from lean_spec.spec.forks import Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_finalization_advances_mid_attestation_processing(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A later vote in a block sees the finalized slot advanced by an earlier vote.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_7(7) -> (8)
    - block_3 includes 3 votes for block_1.
    - block_3 justifies slot 1.
    - vote A targets block_2 from V0, V1, V2.
    - vote B targets block_7 from V0, V1, V2.
    - both votes ride in the block at slot 8.

    When
    ----
    - the block at slot 8 processes vote A, then vote B.

    Then
    ----
    - vote A justifies slot 2 and finalizes slot 1.
    - vote B sees finalized at slot 1, which makes slot 7 justifiable.
    - vote B justifies slot 7.
    - justified reaches slot 7.
    - finalized reaches slot 1.

    Justifiability
    --------------
    - slot 7 at delta 7 from finalized 0 is not justifiable.
    - slot 7 at delta 6 from finalized 1 is justifiable (pronic 2*3).
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
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
                checks=StoreChecks(
                    head_slot=Slot(3),
                    latest_justified_slot=Slot(1),
                    latest_finalized_slot=Slot(0),
                ),
            ),
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
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
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
                checks=StoreChecks(
                    head_slot=Slot(8),
                    latest_justified_slot=Slot(7),
                    latest_finalized_slot=Slot(1),
                ),
            ),
        ],
    )
