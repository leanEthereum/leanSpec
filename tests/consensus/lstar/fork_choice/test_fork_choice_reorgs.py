"""Fork Choice Chain Reorganizations (Reorgs)"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
    generate_pre_state,
)
from lean_spec.spec.forks import Slot, ValidatorIndex

pytestmark = pytest.mark.valid_until("Lstar")


def test_simple_one_block_reorg(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Extending a fork makes it heavier and triggers a one-block reorg.

    Given
    -----
    - 4 validators.
    - the chain:
        chain_base(1)
        - fork_a_2(2)
        - fork_b_3(3)
    - fork_a_2 and fork_b_3 share chain_base as parent.
    - fork_a_2 is the head while it stands alone.
    - fork_b_3 ties fork_a_2 on weight, so the tiebreaker decides the head.

    When
    ----
    - fork_b_4 extends fork_b_3, carrying V2's vote for fork_b_3.

    Then
    ----
    - head switches to fork_b_4.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="chain_base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="chain_base",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="chain_base",
                    label="fork_a_2",
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="chain_base",
                    label="fork_b_3",
                ),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a_2", "fork_b_3"],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_b_3",
                    label="fork_b_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_b_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_b_4",
                ),
            ),
        ],
    )


def test_two_block_reorg_progressive_building(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A late-starting fork overtakes a leading fork by gathering more votes.

    Given
    -----
    - 4 validators.
    - the chain:
        base(1)
        - fork_a_2(2) -> fork_a_3(3)
        - fork_b_4(4) -> fork_b_5(5) -> fork_b_6(6)
    - fork_a_3 carries V0's vote for fork_a_2, giving fork A weight 1.
    - fork B starts late at slot 4 and builds with no votes through slot 5.
    - fork A leads while fork B has weight 0.

    When
    ----
    - fork_b_6 extends fork B, carrying V1, V3's votes for fork_b_5.

    Then
    ----
    - fork B reaches weight 2, above fork A's weight 1.
    - head switches to fork_b_6, reverting fork_a_2 and fork_a_3.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="fork_a_2",
                    label="fork_a_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="fork_a_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="base", label="fork_b_4"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_b_4", label="fork_b_5"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_b_5",
                    label="fork_b_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(1), ValidatorIndex(3)],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_b_5",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_b_6",
                ),
            ),
        ],
    )


def test_three_block_deep_reorg(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A shorter fork wins a three-block reorg when a voter switches sides.

    Given
    -----
    - 6 validators.
    - the chain:
        base(1)
        - fork_a_2(2) -> fork_a_3(3) -> fork_a_4(4)
        - fork_b_5(5) -> fork_b_6(6)
    - fork_a_4 carries V2, V3's votes for fork_a_3, giving fork A weight 2.
    - fork B branches from base at slot 5 with weight 0.
    - fork A leads while fork B has no votes.

    When
    ----
    - fork_b_6 extends fork B, carrying V0, V2, V5's votes for fork_b_5.
    - V2 switches its vote from fork A to fork B.

    Then
    ----
    - fork A drops to weight 1, held by V3 alone.
    - fork B reaches weight 3.
    - head switches to fork_b_6, reverting three fork A blocks.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=6),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="fork_a_2", label="fork_a_3"),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_a_3",
                    label="fork_a_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2), ValidatorIndex(3)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_a_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="base", label="fork_b_5"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_b_5",
                    label="fork_b_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(2),
                                ValidatorIndex(5),
                            ],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_b_5",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_b_6",
                ),
            ),
        ],
    )


def test_reorg_with_slot_gaps(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    A reorg resolves by vote weight even when the chain skips slots.

    Given
    -----
    - 8 validators.
    - the chain:
        base(1)
        - fork_a_3(3) -> fork_a_7(7)
        - fork_b_4(4) -> fork_b_8(8) -> fork_b_9(9)
    - slots 2, 5, 6 produce no blocks.
    - fork_a_7 carries V3's vote for fork_a_3, giving fork A weight 1.
    - fork B leads with no votes until slot 8.

    When
    ----
    - fork_b_8 carries V0, V2, V5, V6's votes for fork_b_4.
    - fork_b_9 extends fork B further.

    Then
    ----
    - fork B reaches weight 4, above fork A's weight 1.
    - head switches to fork_b_9 despite the missed slots.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="base",
                    label="fork_a_3",
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="base",
                    label="fork_b_4",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(7),
                    parent_label="fork_a_3",
                    label="fork_a_7",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(3)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_a_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="fork_a_7",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    parent_label="fork_b_4",
                    label="fork_b_8",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(2),
                                ValidatorIndex(5),
                                ValidatorIndex(6),
                            ],
                            slot=Slot(4),
                            target_slot=Slot(4),
                            target_root_label="fork_b_4",
                        ),
                    ],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(9),
                    parent_label="fork_b_8",
                    label="fork_b_9",
                ),
                checks=StoreChecks(
                    head_slot=Slot(9),
                    head_root_label="fork_b_9",
                ),
            ),
        ],
    )


def test_three_way_fork_competition(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Three competing forks resolve to the one that gathers the most votes.

    Given
    -----
    - 8 validators.
    - the chain:
        base(1)
        - fork_a_2(2)
        - fork_b_3(3) -> fork_b_6(6) -> fork_b_7(7)
        - fork_c_4(4) -> fork_c_5(5)
    - forks A, B, C branch from base at slots 2, 3, 4 with equal weight.
    - the three-way tie is broken by the tiebreaker.
    - fork_c_5 carries V0's vote for fork_c_4, so fork C leads.
    - fork_b_6 extends fork B with no votes, so fork C still leads.

    When
    ----
    - fork_b_7 extends fork B, carrying V1, V2's votes for fork_b_6.

    Then
    ----
    - fork B reaches weight 2, above fork C's weight 1.
    - head switches to fork_b_7.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="base",
                    label="fork_b_3",
                ),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a_2", "fork_b_3"],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="base",
                    label="fork_c_4",
                ),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a_2", "fork_b_3", "fork_c_4"],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    parent_label="fork_c_4",
                    label="fork_c_5",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(4),
                            target_slot=Slot(4),
                            target_root_label="fork_c_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_c_5",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6), parent_label="fork_b_3", label="fork_b_6"),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_c_5",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(7),
                    parent_label="fork_b_6",
                    label="fork_b_7",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(1), ValidatorIndex(2)],
                            slot=Slot(6),
                            target_slot=Slot(6),
                            target_root_label="fork_b_6",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    head_root_label="fork_b_7",
                ),
            ),
        ],
    )


def test_reorg_prevention_heavy_fork_resists_light_competition(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    An established heavy fork resists a lighter fork that arrives late.

    Given
    -----
    - 8 validators.
    - the chain:
        base(1)
        - fork_a_2(2) -> fork_a_3(3) -> fork_a_4(4) -> fork_a_5(5) -> fork_a_6(6)
        - fork_b_2(7) -> fork_b_3(8) -> fork_b_4(9)
    - fork A gathers V2, V3, V4, V5's votes across its chain, reaching weight 4.
    - fork B branches from base at slot 7 and builds with no votes.

    When
    ----
    - fork B extends to three blocks at slots 7, 8, 9.

    Then
    ----
    - fork B stays below fork A's weight at every step.
    - head stays at fork_a_6 throughout.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="base",
                    label="fork_a_2",
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="fork_a_2",
                    label="fork_a_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="fork_a_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_a_3",
                    label="fork_a_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(3)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_a_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_4",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    parent_label="fork_a_4",
                    label="fork_a_5",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(4)],
                            slot=Slot(4),
                            target_slot=Slot(4),
                            target_root_label="fork_a_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    head_root_label="fork_a_5",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_a_5",
                    label="fork_a_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(5)],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_a_5",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7), parent_label="base", label="fork_b_2"),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(8), parent_label="fork_b_2", label="fork_b_3"),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(9), parent_label="fork_b_3", label="fork_b_4"),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",
                ),
            ),
        ],
    )


def test_back_and_forth_reorg_oscillation(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The head oscillates between two forks as each alternately gathers votes.

    Given
    -----
    - 8 validators.
    - the chain:
        base(1)
        - fork_a_2(2) -> fork_a_5(5) -> fork_a_6(6)
        - fork_b_3(3) -> fork_b_4(4) -> fork_b_7(7) -> fork_b_8(8)
    - fork_a_2 leads while it stands alone.
    - fork_b_3 ties fork_a_2, so the tiebreaker decides the head.

    When
    ----
    - fork_b_4 carries V0's vote for fork_b_3.
    - fork_a_5 extends fork A with no votes.
    - fork_a_6 carries V6, V7's votes for fork_a_5.
    - fork_b_7 extends fork B with no votes.
    - fork_b_8 carries V1, V7's votes for fork_b_7.

    Then
    ----
    - fork_b_4 takes the head with weight 1.
    - fork_a_6 takes the head back with weight 2.
    - fork_b_8 takes the head again with weight 2.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="base", label="fork_a_2"),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3), parent_label="base", label="fork_b_3"),
                checks=StoreChecks(
                    lexicographic_head_among=["fork_a_2", "fork_b_3"],
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_b_3",
                    label="fork_b_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="fork_b_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_b_4",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="fork_a_2", label="fork_a_5"),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_b_4",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_a_5",
                    label="fork_a_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(7), ValidatorIndex(6)],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_a_5",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7), parent_label="fork_b_4", label="fork_b_7"),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_a_6",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    parent_label="fork_b_7",
                    label="fork_b_8",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(1), ValidatorIndex(7)],
                            slot=Slot(7),
                            target_slot=Slot(7),
                            target_root_label="fork_b_7",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(8),
                    head_root_label="fork_b_8",
                ),
            ),
        ],
    )


def test_reorg_depth_across_deep_chain_split(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Switching to a heavier competing fork reverts ten blocks at once.

    Given
    -----
    - 8 validators.
    - the chain:
        common(1)
        - a_2(2) -> ... -> a_11(11)
        - b_2(2) -> ... -> b_11(11) -> b_12(12)
    - a_11 carries V7's vote for common, giving fork A weight 1.
    - fork A leads while fork B carries no votes.
    - both forks stay in the store, since nothing is finalized.

    When
    ----
    - b_12 carries V0 through V5's votes for b_11.

    Then
    ----
    - fork B reaches weight 6, above fork A's weight 1.
    - head switches to b_12, reverting ten fork A blocks.
    - both fork tips remain in the store.

    Note
    ----
    - fork A targets common at slot 1 to keep its vote within the justified range.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="common"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="common",
                ),
            ),
            *[
                BlockStep(
                    block=BlockSpec(
                        slot=Slot(i),
                        parent_label="common" if i == 2 else f"a_{i - 1}",
                        label=f"a_{i}",
                    ),
                )
                for i in range(2, 11)
            ],
            BlockStep(
                block=BlockSpec(
                    slot=Slot(11),
                    parent_label="a_10",
                    label="a_11",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(7)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="common",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(11),
                    head_root_label="a_11",
                ),
            ),
            *[
                BlockStep(
                    block=BlockSpec(
                        slot=Slot(i),
                        parent_label="common" if i == 2 else f"b_{i - 1}",
                        label=f"b_{i}",
                    ),
                )
                for i in range(2, 12)
            ],
            BlockStep(
                block=BlockSpec(
                    slot=Slot(12),
                    parent_label="b_11",
                    label="b_12",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                                ValidatorIndex(3),
                                ValidatorIndex(4),
                                ValidatorIndex(5),
                            ],
                            slot=Slot(11),
                            target_slot=Slot(11),
                            target_root_label="b_11",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(12),
                    head_root_label="b_12",
                    reorg_depth=10,
                    labels_in_store=[
                        "a_2",
                        "a_11",
                        "b_2",
                        "b_11",
                    ],
                ),
            ),
        ],
    )


def test_reorg_on_newly_justified_slot(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    Fork choice switches to a justified fork even when it is lighter and shorter.

    Given
    -----
    - 8 validators; a slot needs 6 votes (2/3) to be justified.
    - the chain:
        base(1)
        - fork_a_1(2) -> fork_a_2(3) -> fork_a_3(4)
        - fork_b_1(5) -> fork_b_2(6)
    - fork_a_2 carries V2's vote for fork_a_1, giving fork A weight 1.
    - fork A leads on weight and length while fork B is light.
    - fork A branches from base, so it does not descend from fork_b_1.

    When
    ----
    - fork_b_2 carries V0, V1, V3, V5, V6, V7's votes for fork_b_1.
    - those 6 votes justify fork_b_1 at slot 5.

    Then
    ----
    - the justified checkpoint moves to fork_b_1 at slot 5.
    - fork A is discarded, since it does not descend from the new checkpoint.
    - head becomes fork_b_2.
    """
    fork_choice_test(
        anchor_state=generate_pre_state(num_validators=8),
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="base"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    head_root_label="base",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    parent_label="base",
                    label="fork_a_1",
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    head_root_label="fork_a_1",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="fork_a_1",
                    label="fork_a_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="fork_a_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    head_root_label="fork_a_2",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    parent_label="fork_a_2",
                    label="fork_a_3",
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    parent_label="base",
                    label="fork_b_1",
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    head_root_label="fork_a_3",
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    parent_label="fork_b_1",
                    label="fork_b_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(3),
                                ValidatorIndex(5),
                                ValidatorIndex(6),
                                ValidatorIndex(7),
                            ],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="fork_b_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    head_root_label="fork_b_2",
                    latest_justified_slot=Slot(5),
                    latest_justified_root_label="fork_b_1",
                ),
            ),
        ],
    )
