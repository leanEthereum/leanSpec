"""Checkpoint sync: the justifiability window rebases onto the trusted anchor."""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
    build_anchor,
)
from lean_spec.spec.forks import Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


ANCHOR_SLOT = Slot(10)
"""Slot at which every test in this module places the trust anchor."""

NUM_VALIDATORS = 4
"""Validator count. Three-of-four reaches the 2/3 justification threshold."""


def test_post_anchor_vote_justifies_first_slot_above_anchor(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A supermajority vote for the first post-anchor slot justifies it after sync.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the store is seeded from a checkpoint-synced anchor at slot 10.
    - the anchor state names the anchor as both justified and finalized at slot 10.
    - the chain:
        anchor(10) -> target_11(11) -> voter_12(12)
    - voter_12 carries V0, V1, V2 voting for target_11.
    - the votes name the anchor at slot 10 as their source.
    - target_11 sits one slot above the anchor, a delta of 1.

    When
    ----
    - the vote that justifies target_11 is imported in voter_12.

    Then
    ----
    - head is voter_12 at slot 12.
    - justified advances to target_11 at slot 11.
    - finalized stays at the anchor at slot 10.
    """
    anchor_state, anchor_block = build_anchor(
        synced=True, num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=anchor_block,
        steps=[
            BlockStep(
                block=BlockSpec(
                    slot=Slot(11),
                    parent_label="genesis",
                    label="target_11",
                ),
                checks=StoreChecks(
                    head_slot=Slot(11),
                    head_root_label="target_11",
                    latest_justified_slot=ANCHOR_SLOT,
                    latest_finalized_slot=ANCHOR_SLOT,
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(12),
                    parent_label="target_11",
                    label="voter_12",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(12),
                            target_slot=Slot(11),
                            target_root_label="target_11",
                            source_root_label="genesis",
                            source_slot=ANCHOR_SLOT,
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(12),
                    head_root_label="voter_12",
                    latest_justified_slot=Slot(11),
                    latest_justified_root_label="target_11",
                    latest_finalized_slot=ANCHOR_SLOT,
                    latest_finalized_root_label="genesis",
                ),
            ),
        ],
    )


def test_post_anchor_votes_can_finalize_above_anchor(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Consecutive post-anchor justifications finalize the source above the anchor.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the store is seeded from a checkpoint-synced anchor at slot 10.
    - the anchor state names the anchor as both justified and finalized at slot 10.
    - the chain:
        anchor(10) -> source_11(11) -> target_12(12) -> voter_13(13)
    - source_11 carries V0, V1, V2 voting for slot 11 with source the anchor at slot 10.
    - target_12 carries no votes.
    - voter_13 carries V0, V1, V2 voting for slot 12 with source slot 11.
    - slot 11 is justified before slot 12, so slot 11 may finalize.

    When
    ----
    - the vote justifying slot 11 is imported, then the vote justifying slot 12.

    Then
    ----
    - head is voter_13 at slot 13.
    - justified advances to target_12 at slot 12.
    - finalized advances to source_11 at slot 11.
    """
    anchor_state, anchor_block = build_anchor(
        synced=True, num_validators=NUM_VALIDATORS, anchor_slot=ANCHOR_SLOT
    )

    fork_choice_test(
        anchor_state=anchor_state,
        anchor_block=anchor_block,
        steps=[
            BlockStep(
                block=BlockSpec(
                    slot=Slot(11),
                    parent_label="genesis",
                    label="source_11",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(11),
                            target_slot=ANCHOR_SLOT,
                            target_root_label="genesis",
                            source_root_label="genesis",
                            source_slot=ANCHOR_SLOT,
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(11),
                    head_root_label="source_11",
                    latest_justified_slot=ANCHOR_SLOT,
                    latest_finalized_slot=ANCHOR_SLOT,
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(12),
                    parent_label="source_11",
                    label="target_12",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(12),
                            target_slot=Slot(11),
                            target_root_label="source_11",
                            source_root_label="genesis",
                            source_slot=ANCHOR_SLOT,
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(12),
                    head_root_label="target_12",
                    latest_justified_slot=Slot(11),
                    latest_justified_root_label="source_11",
                    latest_finalized_slot=ANCHOR_SLOT,
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(13),
                    parent_label="target_12",
                    label="voter_13",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(13),
                            target_slot=Slot(12),
                            target_root_label="target_12",
                            source_root_label="source_11",
                            source_slot=Slot(11),
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(13),
                    head_root_label="voter_13",
                    latest_justified_slot=Slot(12),
                    latest_justified_root_label="target_12",
                    latest_finalized_slot=Slot(11),
                    latest_finalized_root_label="source_11",
                ),
            ),
        ],
    )
