"""Block processing edge case tests."""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
)

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_block_with_duplicate_attestation_data_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Block containing two aggregated attestations with identical data is rejected.

    Scenario
    --------
    - Slot 1: anchor block accepted by the store, labeled for later reference.
    - Slot 2: proposer builds a block whose body carries two aggregated
      attestations that resolve to byte-identical AttestationData:
        - same attestation slot
        - same target checkpoint (root and slot)
        - same head checkpoint (defaults to target when not overridden)
        - same source checkpoint (both resolve from the same parent state)
      The two entries are appended via forced_attestations so the block
      builder's merge-by-data pass does not collapse them into one.

    Expected Behavior
    -----------------
    Fork-choice store rejects the block with an AssertionError containing:
    "Block contains duplicate AttestationData"

    Why This Matters
    ----------------
    Each unique AttestationData must appear at most once per block:

    - Prevents a malicious proposer from inflating attestation weight by
      repeating the same vote under a different validator bitfield.
    - Keeps the one-to-one relationship between attestation entries and
      aggregated signature proofs intact.
    - Without this check, double-counting votes from a single validator set
      would be possible by simply repeating the entry.
    """
    fork_choice_test(
        steps=[
            BlockStep(block=BlockSpec(slot=Slot(1), label="block_1")),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    forced_attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0)],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(1)],
                            slot=Slot(2),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                valid=False,
                expected_error="Block contains duplicate AttestationData",
            ),
        ],
    )
