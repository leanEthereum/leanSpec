"""Fork Choice: Block attestation data limits."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ExpectedRejection,
    ForkChoiceStep,
    ForkChoiceTestFiller,
    StoreChecks,
)
from lean_spec.spec.forks import RejectionReason, Slot, ValidatorIndex
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


def test_block_exceeding_maximum_attestations_is_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A block holding one more than the maximum number of distinct votes is rejected.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> one block per justifiable slot after genesis
    - the chain holds one more justifiable slot than the maximum allows.

    When
    ----
    - a final block carries the maximum number of votes from the builder.
    - one forced vote pushes the count one over the limit.

    Then
    ----
    - the store rejects the block for exceeding the distinct attestation data limit.
    """
    n = int(MAX_ATTESTATIONS_DATA)
    targets = _justifiable_slots(n + 1)
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

    builder_targets = targets[:n]
    forced_target = targets[n]

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
                    for i, s in enumerate(builder_targets)
                ],
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[ValidatorIndex(0)],
                        slot=proposal_slot,
                        target_slot=forced_target,
                        target_root_label=f"b_{forced_target}",
                    ),
                ],
            ),
            valid=False,
            expected_rejection=ExpectedRejection(
                reason=RejectionReason.TOO_MANY_ATTESTATION_DATA,
                exact_message=(
                    f"Block contains {n + 1} distinct AttestationData entries; "
                    f"maximum is {MAX_ATTESTATIONS_DATA}"
                ),
            ),
        )
    )

    fork_choice_test(
        steps=chain,
    )
