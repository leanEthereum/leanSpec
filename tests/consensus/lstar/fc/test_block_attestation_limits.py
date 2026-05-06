"""Fork Choice: Block attestation data limits."""

import pytest
from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceStep,
    ForkChoiceTestFiller,
    StoreChecks,
    generate_pre_state,
)
from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.chain.config import MAX_ATTESTATIONS_DATA
from lean_spec.types import Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


@pytest.fixture(autouse=True)
def _reset_xmss_signing_state():
    """Reset XMSS signing state around each test in this module.

    Tests here sign at high slots (50+). Without resetting, the advanced
    key state poisons the shared manager for later tests on the same
    worker that need low-slot signatures.
    """
    XmssKeyManager.reset_signing_state()
    yield
    XmssKeyManager.reset_signing_state()


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
    Block with MAX_ATTESTATIONS_DATA distinct entries is accepted by the store.

    Scenario
    --------
    1. Compute the first MAX_ATTESTATIONS_DATA justifiable slots after genesis
       (immediate, square, and pronic distances from finalized slot 0)
    2. Build a linear chain with one block per justifiable slot
    3. A final block includes one attestation per target, each with a single
       validator vote

    Expected Behavior
    -----------------
    1. Store accepts the block without errors
    2. Head advances to the final block slot
    """
    n = int(MAX_ATTESTATIONS_DATA)
    targets = _justifiable_slots(n)
    proposal_slot = Slot(targets[-1] + Slot(1))

    # Linear chain: one block per justifiable slot.
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

    # Final block carrying exactly MAX_ATTESTATIONS_DATA distinct attestations.
    chain.append(
        BlockStep(
            block=BlockSpec(
                slot=proposal_slot,
                parent_label=f"b_{targets[-1]}",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[ValidatorIndex(i % 4)],
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
        anchor_state=generate_pre_state(),
        steps=chain,
    )


def test_block_exceeding_maximum_attestations_is_rejected(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Block with MAX_ATTESTATIONS_DATA + 1 distinct entries is rejected by the store.

    Scenario
    --------
    1. Build the same chain as the maximum test, but with one extra justifiable
       target slot
    2. The final block carries MAX_ATTESTATIONS_DATA entries through the normal
       builder, plus one forced attestation that pushes the count over the limit

    Expected Behavior
    -----------------
    Store rejects the block with an assertion about exceeding the maximum
    number of distinct AttestationData entries.
    """
    n = int(MAX_ATTESTATIONS_DATA)
    targets = _justifiable_slots(n + 1)
    proposal_slot = Slot(targets[-1] + Slot(1))

    # Linear chain: one block per justifiable slot (N + 1 blocks).
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

    # Final block: N attestations through the builder (hits MAX cap),
    # plus 1 forced attestation targeting the extra slot.
    builder_targets = targets[:n]
    forced_target = targets[n]

    chain.append(
        BlockStep(
            block=BlockSpec(
                slot=proposal_slot,
                parent_label=f"b_{targets[-1]}",
                attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[ValidatorIndex(i % 4)],
                        slot=proposal_slot,
                        target_slot=s,
                        target_root_label=f"b_{s}",
                    )
                    for i, s in enumerate(builder_targets)
                ],
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_ids=[ValidatorIndex(0)],
                        slot=proposal_slot,
                        target_slot=forced_target,
                        target_root_label=f"b_{forced_target}",
                    ),
                ],
            ),
            valid=False,
            expected_error=(
                f"Block contains {n + 1} distinct AttestationData entries; "
                f"maximum is {MAX_ATTESTATIONS_DATA}"
            ),
        )
    )

    fork_choice_test(
        anchor_state=generate_pre_state(),
        steps=chain,
    )
