"""
Genesis initialization tests for the devnet fork.
"""

import pytest
from lean_spec_tests import GenesisTestFiller

from lean_spec.types import Uint64

pytestmark = pytest.mark.valid_until("Devnet")


@pytest.mark.parametrize(
    "genesis_time,num_validators",
    [
        (1000000, 4),  # Minimal validator set
        (0, 64),  # Medium validator set, genesis at epoch 0
        (1704067200, 256),  # Large validator set, 2024-01-01 00:00:00 UTC
        (2**32 - 1, 16),  # Far future timestamp (near max uint32)
        (2**64 - 1, 128),  # Max Uint64 timestamp
        (0, 1),  # Single validator edge case
    ],
)
def test_genesis_initialization(
    genesis_test: GenesisTestFiller,
    genesis_time: int,
    num_validators: int,
) -> None:
    """
    Test genesis state initialization with various parameters.

    leanSpec has simplified genesis (no deposits, balances, or eth1 data),
    so we just test that State.generate_genesis() works with different
    validator counts and timestamps.
    """
    genesis_test(
        genesis_time=Uint64(genesis_time),
        num_validators=Uint64(num_validators),
    )
