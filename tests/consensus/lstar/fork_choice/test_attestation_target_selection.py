"""Attestation Target Selection and Safe Target Computation"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    BlockStep,
    ForkChoiceTestFiller,
    StoreChecks,
)
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.config import JUSTIFICATION_LOOKBACK_SLOTS

pytestmark = pytest.mark.valid_until("Lstar")


def test_attestation_target_at_genesis_initially(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The attestation target stays at genesis until the safe target advances.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2)
    - no block carries any vote.
    - the safe target is still at genesis.

    When
    ----
    - blocks are added at slots 1 and 2 with empty bodies.

    Then
    ----
    - head follows the latest block.
    - the attestation target stays at slot 0 after each block.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2)),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_target_slot=Slot(0),
                ),
            ),
        ],
    )


def test_attestation_target_advances_with_attestations(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The attestation target advances as votes accumulate behind the head.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block_2(2) -> block_3(3) -> block_4(4) -> (5)
    - each block after slot 1 carries one vote for its parent.

    When
    ----
    - blocks are added one per slot through slot 5.

    Then
    ----
    - head follows the latest block.
    - the target stays at slot 0 through slot 3.
    - the target advances to slot 1 after slot 4.
    - the target advances to slot 2 after slot 5.
    - the target always lags behind the head.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    label="block_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    label="block_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(3)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="block_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    attestation_target_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(4),
                            target_slot=Slot(4),
                            target_root_label="block_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_target_slot=Slot(2),
                ),
            ),
        ],
    )


def test_attestation_target_with_slot_gaps(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The attestation target tolerates missed slots in the chain.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block(1) -> block(3) -> block(5)
    - slots 2 and 4 carry no block.
    - no block carries any vote.

    When
    ----
    - blocks are added at slots 1, 3, and 5.

    Then
    ----
    - head follows the latest block.
    - the target stays at slot 0 after each block.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1)),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(3)),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5)),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_target_slot=Slot(0),
                ),
            ),
        ],
    )


def test_attestation_target_with_extended_chain(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The attestation target advances gradually over a longer chain.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_7(7) -> (8)
    - each block after slot 1 carries one vote for its parent.

    When
    ----
    - blocks are added one per slot through slot 8.

    Then
    ----
    - head follows the latest block.
    - the target stays at slot 0 through slot 3.
    - the target then advances one slot per block: 1, 2, 3, 4, 5.
    - the target always lags behind the head.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(
                    head_slot=Slot(1),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(2),
                    label="block_2",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(1)],
                            slot=Slot(1),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(2),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2)],
                            slot=Slot(2),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    attestation_target_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(4),
                    label="block_4",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(3)],
                            slot=Slot(3),
                            target_slot=Slot(3),
                            target_root_label="block_3",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(4),
                    attestation_target_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(5),
                    label="block_5",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(0)],
                            slot=Slot(4),
                            target_slot=Slot(4),
                            target_root_label="block_4",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(5),
                    attestation_target_slot=Slot(2),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(6),
                    label="block_6",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(1)],
                            slot=Slot(5),
                            target_slot=Slot(5),
                            target_root_label="block_5",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(6),
                    attestation_target_slot=Slot(3),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(7),
                    label="block_7",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(2)],
                            slot=Slot(6),
                            target_slot=Slot(6),
                            target_root_label="block_6",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(7),
                    attestation_target_slot=Slot(4),
                ),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[ValidatorIndex(3)],
                            slot=Slot(7),
                            target_slot=Slot(7),
                            target_root_label="block_7",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(8),
                    attestation_target_slot=Slot(5),
                ),
            ),
        ],
    )


def test_attestation_target_justifiable_constraint(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The attestation target only ever lands on a justifiable slot.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_15(15)
    - each block after slot 1 carries one vote for its parent.
    - finalized stays at slot 0.

    When
    ----
    - blocks are added one per slot through slot 15.

    Then
    ----
    - head follows the latest block.
    - the target follows the expected sequence below.
    - the target never lands on a non-justifiable slot.

    Justifiability
    --------------
    - the target starts from the head and walks back at most 3 slots.
    - a slot at distance delta from finalized is justifiable when delta is at most 5.
    - or when delta is a perfect square (1, 4, 9, 16, ...).
    - or when delta is a pronic number (2, 6, 12, 20, ...).
    - sparse slots beyond the immediate window block long-range attacks.
    """
    num_validators = 4
    expected_targets = {
        1: 0,
        2: 0,
        3: 0,
        4: 1,
        5: 2,
        6: 3,
        7: 4,
        8: 5,
        9: 6,
        10: 6,
        11: 6,
        12: 9,
        13: 9,
        14: 9,
        15: 12,
    }

    steps = []
    for i in range(1, 16):
        steps.append(
            BlockStep(
                block=BlockSpec(
                    slot=Slot(i),
                    label=f"block_{i}",
                    attestations=(
                        [
                            AggregatedAttestationSpec(
                                validator_indices=[ValidatorIndex((i - 1) % num_validators)],
                                slot=Slot(i - 1),
                                target_slot=Slot(i - 1),
                                target_root_label=f"block_{i - 1}",
                            ),
                        ]
                        if i >= 2
                        else None
                    ),
                ),
                checks=StoreChecks(
                    head_slot=Slot(i),
                    attestation_target_slot=Slot(expected_targets[i]),
                ),
            )
        )

    fork_choice_test(steps=steps)


def test_attestation_target_walkback_bounded_by_lookback(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The attestation target walks back no more than the lookback bound from the head.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_head(head)
    - no block carries any vote.
    - the safe target stays at genesis.
    - the head is the smallest one where (head - lookback) is justifiable from genesis.

    When
    ----
    - blocks are added one per slot up to the chosen head.

    Then
    ----
    - head sits far ahead of the safe target.
    - the safe target stays at slot 0.
    - the target lands on (head - lookback).
    - the target does not fall back to the safe target at slot 0.
    """
    lookback = int(JUSTIFICATION_LOOKBACK_SLOTS)

    head = 10
    while not Slot(head - lookback).is_justifiable_after(Slot(0)):
        head += 1
    head_slot = Slot(head)
    target_slot = Slot(head - lookback)

    steps = [
        BlockStep(
            block=BlockSpec(slot=Slot(s), label=f"block_{s}"),
            checks=(
                StoreChecks(head_slot=head_slot, attestation_target_slot=target_slot)
                if Slot(s) == head_slot
                else None
            ),
        )
        for s in range(1, head + 1)
    ]
    fork_choice_test(steps=steps)


def test_attestation_target_selection_after_finality_has_moved(
    fork_choice_test: ForkChoiceTestFiller,
) -> None:
    """
    The attestation target respects a finalized boundary above genesis.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> ... -> block_8(8) -> ... -> block_11(11)
    - block_3 includes 3 votes for block_1.
    - block_3 justifies slot 1.
    - block_8 includes 3 votes for block_2 and 3 votes for block_7.
    - block_8 justifies slots 2 and 7.
    - block_8 finalizes slot 1.
    - blocks 4 through 7 and 9 through 11 carry no votes.

    When
    ----
    - the chain extends past finality through block_11.

    Then
    ----
    - justified stays at slot 7.
    - finalized stays at slot 1.
    - the safe target settles on block_7.
    - the target slot pins to slot 7 as the head extends.
    - the target root pins to block_7 as the head extends.
    """
    fork_choice_test(
        steps=[
            BlockStep(
                block=BlockSpec(slot=Slot(1), label="block_1"),
                checks=StoreChecks(head_slot=Slot(1)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(2), parent_label="block_1", label="block_2"),
                checks=StoreChecks(head_slot=Slot(2)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(3),
                    parent_label="block_2",
                    label="block_3",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(3),
                            target_slot=Slot(1),
                            target_root_label="block_1",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(3),
                    latest_justified_slot=Slot(1),
                    latest_finalized_slot=Slot(0),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(4), parent_label="block_3", label="block_4"),
                checks=StoreChecks(head_slot=Slot(4)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(5), parent_label="block_4", label="block_5"),
                checks=StoreChecks(head_slot=Slot(5)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(6), parent_label="block_5", label="block_6"),
                checks=StoreChecks(head_slot=Slot(6)),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(7), parent_label="block_6", label="block_7"),
                checks=StoreChecks(head_slot=Slot(7)),
            ),
            BlockStep(
                block=BlockSpec(
                    slot=Slot(8),
                    parent_label="block_7",
                    label="block_8",
                    attestations=[
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(8),
                            target_slot=Slot(2),
                            target_root_label="block_2",
                        ),
                        AggregatedAttestationSpec(
                            validator_indices=[
                                ValidatorIndex(0),
                                ValidatorIndex(1),
                                ValidatorIndex(2),
                            ],
                            slot=Slot(8),
                            target_slot=Slot(7),
                            target_root_label="block_7",
                        ),
                    ],
                ),
                checks=StoreChecks(
                    head_slot=Slot(8),
                    latest_justified_slot=Slot(7),
                    latest_finalized_slot=Slot(1),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(9), parent_label="block_8", label="block_9"),
                checks=StoreChecks(
                    head_slot=Slot(9),
                    latest_justified_slot=Slot(7),
                    latest_finalized_slot=Slot(1),
                    safe_target_slot=Slot(7),
                    safe_target_root_label="block_7",
                    attestation_target_slot=Slot(7),
                    attestation_target_root_label="block_7",
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(10), parent_label="block_9", label="block_10"),
                checks=StoreChecks(
                    head_slot=Slot(10),
                    attestation_target_slot=Slot(7),
                ),
            ),
            BlockStep(
                block=BlockSpec(slot=Slot(11), parent_label="block_10", label="block_11"),
                checks=StoreChecks(
                    head_slot=Slot(11),
                    attestation_target_slot=Slot(7),
                ),
            ),
        ],
    )
