"""Fork Choice: Duplicate AttestationData Rejection."""

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

pytestmark = pytest.mark.valid_until("Devnet")


def test_block_with_duplicate_aggregated_attestation_data_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Blocks containing two aggregated attestations with identical data are rejected.

    Scenario
    --------
    - Slot 1: common ancestor block accepted by the store.
    - Slot 2: proposer builds a block whose body contains two aggregated
      attestations that reference identical data:
        - same slot
        - same target
        - same source
        - same validator set
      The two entries are appended via forced attestations so the builder's
      merge-by-data pass does not collapse them.

    Expected Behavior
    -----------------
    Fork-choice store rejects the block with AssertionError containing:
    "Block contains duplicate AttestationData"

    Why This Matters
    ----------------
    Each unique AttestationData must appear at most once per block:

    - Prevents inflating attestation weight by repeating the same vote.
    - Keeps signature-aggregation accounting one-to-one with data.
    - Without this check, a proposer could double-count votes from a single
      validator set just by repeating the entry.
    """
    duplicated_spec = AggregatedAttestationSpec(
        validator_ids=[ValidatorIndex(0)],
        slot=Slot(1),
        target_slot=Slot(1),
        target_root_label="block_1",
    )

    fork_choice_test(
        steps=[
            # Common ancestor at slot 1
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="block_1",
                ),
            ),
            # Slot 2 block carrying two byte-identical aggregated attestations
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="block_1",
                    forced_attestations=[duplicated_spec, duplicated_spec],
                ),
                valid=False,
                expected_error="Block contains duplicate AttestationData",
            ),
        ],
    )
