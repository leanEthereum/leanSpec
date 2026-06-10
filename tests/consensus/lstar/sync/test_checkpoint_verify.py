"""Checkpoint-sync state verification known-answer vectors."""

import pytest

from consensus_testing import SyncTestFiller, VerifyCheckpoint

pytestmark = pytest.mark.valid_until("Lstar")


def test_checkpoint_verify_rejects_empty_validator_set(
    sync_test: SyncTestFiller,
) -> None:
    """
    A checkpoint state with zero validators is rejected.

    Given
    -----
    - an anchor state fetched from a checkpoint provider.
    - the state carries zero validators.

    When
    ----
    - the state is verified before seeding a fork-choice store.

    Then
    ----
    - the state is rejected.
    - the reason is that a state with no validators cannot produce blocks.
    """
    sync_test(
        operation=VerifyCheckpoint(num_validators=0),
    )


def test_checkpoint_verify_accepts_small_validator_set(
    sync_test: SyncTestFiller,
) -> None:
    """
    A checkpoint state with a small in-range validator set is accepted.

    Given
    -----
    - an anchor state with 4 validators (the baseline test size).

    When
    ----
    - the state is verified before seeding a fork-choice store.

    Then
    ----
    - the state is accepted.
    """
    sync_test(
        operation=VerifyCheckpoint(num_validators=4),
    )


def test_checkpoint_verify_accepts_eight_validator_set(
    sync_test: SyncTestFiller,
) -> None:
    """
    An eight-validator anchor state is accepted at the key-manager limit.

    Given
    -----
    - an anchor state with 8 validators (the upper test envelope).

    When
    ----
    - the state is verified before seeding a fork-choice store.

    Then
    ----
    - the state is accepted.
    """
    sync_test(
        operation=VerifyCheckpoint(num_validators=8),
    )
