"""Fork Choice: Attestation Source Under Justified Divergence"""

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


def test_justified_divergence_self_heals_in_next_block(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Store justified advances from a minority fork; the next block catches up.

    Scenario
    --------
    Four validators. Two forks diverge from a common ancestor::

        genesis -> common(1) -> block_2(2) -> block_3(3)   (head, V0 weight)
                              \\
                               -> fork_4(4)                (V1+V2+V3 justify slot 1)

    After fork_4:

    - store.latest_justified = slot 1 (from fork B)
    - head = block_3 (fork A)
    - head_state.latest_justified = slot 0 (divergence)

    Self-healing
    ------------
    Block 5 is built on the head chain (no explicit attestations).
    The tiered scorer resolves the divergence:

    1. Pool contains fork B's attestation (source=0, target=1)
    2. Builder projects from head state justified=0
    3. Fork B's attestation matches (source=0). Selected. Projects slot 1 justified.
    4. Divergence closed in one block.

    Expected post-state
    -------------------
    - After fork_4: store justified=1, head state justified=0
    - After block_5: both agree on justified=1
    """
    fork_choice_test(
        steps=[
            # Fork point for both chains.
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            # Fork A: head chain
            #
            #   common(1) -> block_2(2) -> block_3(3)
            #
            # V0 attests in block_3 targeting block_2.
            # This keeps fork A as head after fork B arrives.
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="common", label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_2",
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[ValidatorIndex(0)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            # Fork B: minority fork that justifies slot 1
            #
            #   common(1) -> fork_4(4)
            #
            # V1+V2+V3 attest to slot 1.
            # Threshold: 3*3=9 >= 2*4=8 -> justifies slot 1.
            #
            # The store propagates: justified = max(1, 0) = 1.
            # Head stays on block_3 (V0 weight).
            #
            # This creates the divergence:
            #   store justified = 1, head state justified = 0.
            #
            # Why: the attestations that justified slot 1 are in fork_4's
            # block body. The head chain never processed them.
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="common",
                    label="fork_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_ids=[
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                                ValidatorIndex(3),
                            ],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="common",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="block_3",
                    # Store justified advanced from fork B.
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="common",
                ),
            ),
            # Self-healing block on the head chain.
            #
            # No explicit attestations. The builder reads from the pool.
            #
            # The pool has fork B's attestation (source=0, target=1)
            # because on_block added it when processing fork_4.
            #
            # The tiered scorer projects justification forward:
            #   Round 1: source=0 is justified -> V1+V2+V3 target slot 1
            #            3/4 supermajority -> projects slot 1 justified
            #   Later rounds: nothing new scores -> stop
            #
            # Divergence closed: head state justified = 1 = store justified.
            #
            # The produced block MUST carry the justifying attestation so that
            # other nodes processing it also advance their justified checkpoint.
            # Block production asserts this invariant.
            BlockStep(
                block=BlockSpec(slot=Slot(5), label="block_5"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="block_5",
                    # Both store and head agree: justified = slot 1.
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="common",
                    # The block body carries the one attestation that advances
                    # the chain: V1+V2+V3 targeting slot 1, the minority fork's
                    # justifying vote that closes the divergence.
                    #
                    # V0 targeting slot 2 is also in the pool (originally in
                    # block_3's body), but every one of its voters is already
                    # recorded on the head chain for that target. It adds no new
                    # voters, so the scorer omits it rather than re-stating a
                    # vote the post-state already holds.
                    block_attestation_count=1,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={1, 2, 3},
                            target_slot=Slot(1),
                        ),
                    ],
                ),
            ),
        ],
    )
