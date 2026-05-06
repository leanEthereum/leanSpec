"""Checkpoint-sync state verification: known-answer vectors.

Pins the structural-validity verdict each client must produce when
fetching an anchor state from a checkpoint provider. The verdict is a
defence-in-depth check applied before the state seeds a fork-choice
store.
"""

import pytest
from consensus_testing import SyncTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


def test_checkpoint_verify_rejects_empty_validator_set(
    sync: SyncTestFiller,
) -> None:
    """A checkpoint state with zero validators is rejected.

    A state without validators cannot produce blocks, so seeding a
    fork-choice store with it would be useless and mask configuration
    errors. Clients must refuse the anchor before any store setup.
    """
    sync(
        operation="verify_checkpoint",
        input={"numValidators": 0},
    )


def test_checkpoint_verify_accepts_small_validator_set(
    sync: SyncTestFiller,
) -> None:
    """A checkpoint state with a small in-range validator set is accepted.

    Four validators is the baseline size used throughout the consensus
    test suite. Pins the happy path of the verifier so clients observe
    the accepted branch in addition to the rejection branch above.
    """
    sync(
        operation="verify_checkpoint",
        input={"numValidators": 4},
    )


def test_checkpoint_verify_accepts_eight_validator_set(
    sync: SyncTestFiller,
) -> None:
    """Eight-validator anchor state is accepted at the key-manager limit.

    Matches the maximum-validator setup used by the existing fork-choice
    and signature-verification suites. Pins the verdict at the upper
    end of the practical test envelope.
    """
    sync(
        operation="verify_checkpoint",
        input={"numValidators": 8},
    )
