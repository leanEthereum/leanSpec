"""Tests for the Slot container and its methods."""

import pytest

from lean_spec.subspecs.containers.slot import Slot


def test_is_justifiable_after_raises_on_invalid_order() -> None:
    """
    Tests that `is_justifiable_after` raises an AssertionError if the
    candidate slot is earlier than the finalized slot.
    """
    finalized_slot = Slot(10)
    candidate_slot = Slot(9)

    # Verify that calling the method with a candidate slot before the
    # finalized slot raises an error.
    with pytest.raises(AssertionError, match="Candidate slot must not be before finalized slot"):
        candidate_slot.is_justifiable_after(finalized_slot)


@pytest.mark.parametrize(
    "finalized_slot_val, candidate_slot_val, expected",
    [
        # --- Rule 1: delta <= 5 ---
        pytest.param(10, 10, True, id="delta_0_is_justifiable"),
        pytest.param(10, 11, True, id="delta_1_is_justifiable"),
        pytest.param(10, 15, True, id="delta_5_is_justifiable"),
        # --- Rule 2: delta is a perfect square (x^2) ---
        # Note: delta=4 is already covered by Rule 1
        pytest.param(10, 14, True, id="delta_4_perfect_square_is_justifiable"),
        pytest.param(20, 29, True, id="delta_9_perfect_square_is_justifiable"),
        pytest.param(50, 66, True, id="delta_16_perfect_square_is_justifiable"),
        pytest.param(100, 200, True, id="delta_100_perfect_square_is_justifiable"),
        # --- Rule 3: delta is a pronic number (x^2 + x) ---
        pytest.param(10, 16, True, id="delta_6_pronic_is_justifiable"),
        pytest.param(20, 32, True, id="delta_12_pronic_is_justifiable"),
        pytest.param(50, 70, True, id="delta_20_pronic_is_justifiable"),
        pytest.param(100, 130, True, id="delta_30_pronic_is_justifiable"),
        # --- Unjustifiable slots (that don't match any rule) ---
        pytest.param(10, 17, False, id="delta_7_is_not_justifiable"),
        pytest.param(10, 18, False, id="delta_8_is_not_justifiable"),
        pytest.param(20, 30, False, id="delta_10_is_not_justifiable"),
        pytest.param(20, 31, False, id="delta_11_is_not_justifiable"),
        pytest.param(50, 63, False, id="delta_13_is_not_justifiable"),
        pytest.param(100, 117, False, id="delta_17_is_not_justifiable"),
    ],
)
def test_is_justifiable_after(
    finalized_slot_val: int, candidate_slot_val: int, expected: bool
) -> None:
    """
    Tests the `is_justifiable_after` logic with a comprehensive set of
    scenarios covering all three justification rules and cases that should fail.
    """
    # Create Slot instances from the integer parameters.
    finalized_slot = Slot(finalized_slot_val)
    candidate_slot = Slot(candidate_slot_val)

    # Call the method and assert that the result matches the expected boolean value.
    assert candidate_slot.is_justifiable_after(finalized_slot) == expected
