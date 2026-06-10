"""Checkpoint-sync verification vectors at post-genesis anchor slots."""

import pytest

from consensus_testing import SyncTestFiller, VerifyCheckpoint

pytestmark = pytest.mark.valid_until("Lstar")


def test_checkpoint_verify_advanced_slot_three(sync_test: SyncTestFiller) -> None:
    """
    An advanced anchor state at slot 3 with four validators is accepted.

    Given
    -----
    - 4 validators.
    - the chain walks through three empty blocks to slot 3.
    - the resulting state carries non-empty historical block hashes.
    - the resulting state carries a non-zero latest block header.

    When
    ----
    - the anchor state is verified before seeding a fork-choice store.

    Then
    ----
    - the state is accepted.
    - the exact serialized state bytes are pinned.
    """
    sync_test(
        operation=VerifyCheckpoint(num_validators=4, anchor_slot=3),
    )


def test_checkpoint_verify_advanced_slot_ten(sync_test: SyncTestFiller) -> None:
    """
    An advanced anchor state at slot 10 with four validators is accepted.

    Given
    -----
    - 4 validators.
    - the chain walks through ten empty blocks to slot 10.
    - the longer history fills the block-hash and justified-slot lists.

    When
    ----
    - the anchor state is verified before seeding a fork-choice store.

    Then
    ----
    - the state is accepted.
    - the exact serialized state bytes are pinned.
    """
    sync_test(
        operation=VerifyCheckpoint(num_validators=4, anchor_slot=10),
    )


def test_checkpoint_verify_advanced_eight_validators(sync_test: SyncTestFiller) -> None:
    """
    An advanced anchor state at slot 5 with eight validators is accepted.

    Given
    -----
    - 8 validators.
    - the chain walks through five empty blocks to slot 5.

    When
    ----
    - the anchor state is verified before seeding a fork-choice store.

    Then
    ----
    - the state is accepted.
    - the exact serialized state bytes are pinned.
    """
    sync_test(
        operation=VerifyCheckpoint(num_validators=8, anchor_slot=5),
    )
