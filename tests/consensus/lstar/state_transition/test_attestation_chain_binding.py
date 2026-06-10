"""State Transition: Attestation Chain Binding"""

import pytest

from consensus_testing import (
    AggregatedAttestationSpec,
    BlockSpec,
    StateExpectation,
    StateTransitionTestFiller,
)
from lean_spec.spec.forks import Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    JustificationRoots,
    JustificationValidators,
)
from lean_spec.spec.ssz import ZERO_HASH, Bytes32

pytestmark = pytest.mark.valid_until("Lstar")


def test_vote_with_zero_hash_head_root_is_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote whose head root is the zero hash is skipped before any tally.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) carries a forced V0, V1, V2 vote from genesis to block_1.
    - the source root matches genesis on the canonical chain.
    - the target root matches block_1 on the canonical chain.
    - the head root is the zero hash.
    - the head leg of the zero-hash guard rejects the whole vote.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - justified stays at slot 0.
    - finalized stays at slot 0.
    - no pending votes remain.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                        head_root=ZERO_HASH,
                        head_slot=Slot(1),
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(2),
            latest_justified_slot=Slot(0),
            latest_finalized_slot=Slot(0),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_vote_with_head_slot_past_chain_view_is_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote whose head slot lands past the chain view is skipped before any tally.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - the chain view at processing spans slots 0 and 1, so its length is 2.
    - block(2) carries a forced V0, V1, V2 vote from genesis to block_1.
    - the source root matches genesis on the canonical chain.
    - the target root matches block_1 on the canonical chain.
    - the head slot is 2, which is at the end of the chain view.
    - the head leg of the range guard rejects the whole vote.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - justified stays at slot 0.
    - finalized stays at slot 0.
    - no pending votes remain.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                        head_root=Bytes32(b"\x77" * 32),
                        head_slot=Slot(2),
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(2),
            latest_justified_slot=Slot(0),
            latest_finalized_slot=Slot(0),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_vote_with_non_zero_source_root_off_chain_is_skipped(
    state_transition_test: StateTransitionTestFiller,
) -> None:
    """
    A vote whose non-zero source root disagrees with the chain is skipped.

    Given
    -----
    - 4 validators; a slot needs 3 votes (2/3) to be justified.
    - the chain:
        genesis -> block_1(1) -> block(2)
    - block(2) carries a forced V0, V1, V2 vote from slot 0 to block_1.
    - the source slot 0 is justified, so the source guard passes.
    - the source root is a fabricated non-zero value at slot 0.
    - the recorded root at slot 0 is genesis, so the source root disagrees.
    - the target root matches block_1 on the canonical chain.
    - the head root matches block_1 on the canonical chain.
    - the source leg of the chain-match check rejects the whole vote.

    When
    ----
    - the chain processes both blocks.

    Then
    ----
    - justified stays at slot 0.
    - finalized stays at slot 0.
    - no pending votes remain.
    """
    state_transition_test(
        blocks=[
            BlockSpec(slot=Slot(1), label="block_1"),
            BlockSpec(
                slot=Slot(2),
                parent_label="block_1",
                forced_attestations=[
                    AggregatedAttestationSpec(
                        validator_indices=[
                            ValidatorIndex(0),
                            ValidatorIndex(1),
                            ValidatorIndex(2),
                        ],
                        slot=Slot(2),
                        target_slot=Slot(1),
                        target_root_label="block_1",
                        head_root_label="block_1",
                        source_root=Bytes32(b"\x55" * 32),
                        source_slot=Slot(0),
                    ),
                ],
            ),
        ],
        post=StateExpectation(
            slot=Slot(2),
            latest_justified_slot=Slot(0),
            latest_finalized_slot=Slot(0),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )
