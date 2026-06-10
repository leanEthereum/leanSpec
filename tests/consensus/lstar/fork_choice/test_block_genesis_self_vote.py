"""Fork Choice: Genesis self-vote inclusion in a produced block."""

import pytest

from consensus_testing import (
    AggregatedAttestationCheck,
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)
from lean_spec.spec.forks import Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_block_includes_genesis_self_vote(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A genesis self-vote survives block production despite slot 0 being justified.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1)
    - V0, V1 vote with source, target, and head all at the genesis block.
    - genesis is already justified, so this vote justifies nothing.
    - the vote carries head weight for fork choice.

    When
    ----
    - block_1 is produced carrying that self-vote.

    Then
    ----
    - the builder keeps the self-vote under the genesis exemption.
    - the block body holds 1 aggregated vote.
    - the vote covers V0 and V1 at target slot 0.
    - justified stays at slot 0.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(
                    slot=Slot(1),
                    label="block_1",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0), ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(0),
                            target_root_label="genesis",
                            source_slot=Slot(0),
                            source_root_label="genesis",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="block_1",
                    latest_justified_slot=Slot(0),
                    block_attestation_count=1,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={0, 1},
                            attestation_slot=Slot(1),
                            target_slot=Slot(0),
                        ),
                    ],
                ),
            ),
        ],
    )
