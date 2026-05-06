"""Checkpoint-sync verification vectors at post-genesis anchor slots.

Existing verify_checkpoint vectors run against fresh genesis states.
These pin the verdict after the chain has advanced through empty
blocks, so clients' state deserialisation is exercised on the non-zero
historical_block_hashes path that real checkpoint-sync downloads hit.
"""

import pytest
from consensus_testing import SyncTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


def test_checkpoint_verify_advanced_slot_three(sync: SyncTestFiller) -> None:
    """Advanced anchor state at slot 3 with four validators is accepted.

    The chain walks through three empty blocks. The resulting state
    carries non-empty historical_block_hashes and a non-zero latest
    block header. Pins the accepted verdict plus the exact SSZ bytes.
    """
    sync(
        operation="verify_checkpoint",
        input={"numValidators": 4, "anchorSlot": 3},
    )


def test_checkpoint_verify_advanced_slot_ten(sync: SyncTestFiller) -> None:
    """Advanced anchor state at slot 10 with four validators is accepted.

    Ten empty blocks populate historical_block_hashes and justified_slots
    with longer lists. Pins the verdict and state bytes at a larger
    history than the slot-three case.
    """
    sync(
        operation="verify_checkpoint",
        input={"numValidators": 4, "anchorSlot": 10},
    )


def test_checkpoint_verify_advanced_eight_validators(sync: SyncTestFiller) -> None:
    """Advanced anchor state at slot 5 with eight validators is accepted.

    Exercises the combination of larger validator set with a non-zero
    anchor slot so clients diff both axes in a single vector.
    """
    sync(
        operation="verify_checkpoint",
        input={"numValidators": 8, "anchorSlot": 5},
    )
