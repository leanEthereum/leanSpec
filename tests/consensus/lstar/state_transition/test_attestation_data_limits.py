"""State Transition: Attestation Data Limits"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    ExpectedRejection,
    StateTransitionTestFiller,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.config import MAX_ATTESTATIONS_DATA

pytestmark = pytest.mark.valid_until("Lstar")


def _justifiable_slots(count: int) -> list[Slot]:
    """Return the first COUNT justifiable slots after finalized genesis (slot 0)."""
    justifiable_slots: list[Slot] = []
    candidate_slot = Slot(1)
    while len(justifiable_slots) < count:
        if candidate_slot.is_justifiable_after(Slot(0)):
            justifiable_slots.append(candidate_slot)
        candidate_slot = Slot(candidate_slot + Slot(1))
    return justifiable_slots


def test_block_exceeding_distinct_attestation_data_cap_rejects_block(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A block carrying more distinct attestation data than the cap rejects in the transition.

    Given
    -----
    - 4 validators.
    - the cap on distinct attestation data per block is 8.
    - the chain:
        genesis -> one block per justifiable slot, one more than the cap allows
    - the final block carries one forced vote per distinct target.
    - the forced votes bypass the proposer-side builder cap.

    When
    ----
    - the chain processes the final block.

    Then
    ----
    - the block is rejected with TOO_MANY_ATTESTATION_DATA.
    - the count over the cap is 9 distinct entries against a maximum of 8.
    """
    over_cap_count = int(MAX_ATTESTATIONS_DATA) + 1
    target_slots = _justifiable_slots(over_cap_count)
    proposal_slot = Slot(target_slots[-1] + Slot(1))

    chain: list[BlockSpec] = [
        BlockSpec(
            slot=target_slot,
            label=f"block_{target_slot}",
            parent_label=f"block_{target_slots[position - 1]}" if position > 0 else None,
        )
        for position, target_slot in enumerate(target_slots)
    ]

    chain.append(
        BlockSpec(
            slot=proposal_slot,
            parent_label=f"block_{target_slots[-1]}",
            forced_attestations=[
                AggregatedAttestationSpec(
                    validator_indices=[ValidatorIndex(position % 4)],
                    slot=proposal_slot,
                    target_slot=target_slot,
                    target_root_label=f"block_{target_slot}",
                )
                for position, target_slot in enumerate(target_slots)
            ],
        )
    )

    state_transition_test(
        blocks=chain,
        post=None,
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.TOO_MANY_ATTESTATION_DATA,
            exact_message=(
                f"Block contains {over_cap_count} distinct AttestationData "
                f"entries; maximum is {MAX_ATTESTATIONS_DATA}"
            ),
        ),
    )
