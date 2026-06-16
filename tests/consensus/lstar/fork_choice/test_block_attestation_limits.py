"""Fork Choice: Block attestation data limits."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceStep,
    ForkChoiceTestFiller,
    StoreChecks,
)
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.config import MAX_ATTESTATIONS_DATA

pytestmark = pytest.mark.valid_until("Lstar")


def _justifiable_slots(n: int) -> list[Slot]:
    """Return the first N justifiable slots after finalized genesis (slot 0)."""
    slots: list[Slot] = []
    candidate = Slot(1)
    while len(slots) < n:
        if candidate.is_justifiable_after(Slot(0)):
            slots.append(candidate)
        candidate = Slot(candidate + Slot(1))
    return slots


def test_block_with_maximum_attestations(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A block holding exactly the maximum number of distinct votes is accepted.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> one block per justifiable slot after genesis
    - the justifiable slots are the immediate, square, and pronic distances from slot 0.
    - the chain holds exactly the maximum number of distinct attestation data entries.

    When
    ----
    - a final block carries one vote per justifiable slot.

    Then
    ----
    - the store accepts the block.
    - head advances to the final block.
    """
    n = int(MAX_ATTESTATIONS_DATA)
    targets = _justifiable_slots(n)
    proposal_slot = Slot(targets[-1] + Slot(1))

    chain: list[ForkChoiceStep] = [
        BlockStep(
            block=BlockSpec(
                slot=s,
                label=f"b_{s}",
                parent_label=f"b_{targets[i - 1]}" if i > 0 else None,
            )
        )
        for i, s in enumerate(targets)
    ]

    chain.append(
        BlockStep(
            block=BlockSpec(
                slot=proposal_slot,
                parent_label=f"b_{targets[-1]}",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[ValidatorIndex(i % 4)],
                        slot=proposal_slot,
                        target_slot=s,
                        target_root_label=f"b_{s}",
                    )
                    for i, s in enumerate(targets)
                ],
            ),
            checks=StoreChecks(head_slot=proposal_slot),
        )
    )

    fork_choice_test(
        steps=chain,
    )
