"""Fork Choice: Attestation Source Under Justified Divergence"""

import pytest

from consensus_testing import (
    AggregatedAttestationCheck,
    AggregatedAttestationSpec,
    AttestationCheck,
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    GossipAttestationSpec,
    StoreChecks,
)
from lean_spec.spec.forks import Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_justified_divergence_self_heals_in_next_block(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A block adopts the votes that justify a slot from a fork it did not extend.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis
        - common(1)
          - block_2(2) -> block_3(3)
          - fork_4(4)
    - block_3 includes V0's vote for block_2.
    - fork_4 includes V1, V2, V3's votes for common.
    - fork_4 reaches 3 votes, so it justifies slot 1.
    - block_3 has only 1 vote, so it justifies nothing.
    - the views diverge: node = slot 1, head chain = slot 0.

    When
    ----
    - block_5 is built on block_3, carrying no votes of its own.

    Then
    ----
    - block_5 pulls the slot-1 votes from the pool and includes them.
    - the head chain justifies slot 1, matching the node.
    - finalized stays at slot 0.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
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
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="common",
                    label="fork_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
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
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="common",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), label="block_5"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="block_5",
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="common",
                    block_attestation_count=2,
                    block_attestations=[
                        AggregatedAttestationCheck(
                            participants={1, 2, 3},
                            target_slot=Slot(1),
                        ),
                        AggregatedAttestationCheck(
                            participants={0},
                            target_slot=Slot(2),
                        ),
                    ],
                ),
            ),
        ],
    )


def test_honest_vote_sources_from_head_chain_not_store(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An honest vote sources from the head chain's justified, not the store's.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis
        - common(1)
          - block_2(2) -> block_3(3)
          - fork_4(4)
    - block_3 includes V0's vote for block_2.
    - fork_4 includes V1, V2, V3's votes for common.
    - fork_4 reaches 3 votes, so it justifies slot 1.
    - block_3 has only 1 vote, so it justifies nothing.
    - the views diverge: store = common (slot 1), block_3 state = genesis (slot 0).
    - head stays on block_3.

    When
    ----
    - V0 gossips an honest vote at slot 4, produced from attestation duties on the block_3 head.

    Then
    ----
    - the vote sits in the raw signature pool.
    - its head is block_3 (slot 3), the current head.
    - its source is genesis (slot 0), the head chain's own justified.
    - its source is not common (slot 1), the store's justified.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
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
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(head_slot=Slot(3)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="common",
                    label="fork_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
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
                    latest_justified_slot=Slot(1),
                    latest_justified_root_label="common",
                ),
            ),
            AttestationStep(
                attestation=GossipAttestationSpec(
                    validator_index=ValidatorIndex(0),
                    slot=Slot(4),
                    target_slot=Slot(3),
                ),
                is_aggregator=True,
                checks=StoreChecks(
                    attestation_checks=[
                        AttestationCheck(
                            validator=ValidatorIndex(0),
                            location="signatures",
                            head_slot=Slot(3),
                            source_slot=Slot(0),
                            source_root_label="genesis",
                        ),
                    ],
                ),
            ),
        ],
    )
