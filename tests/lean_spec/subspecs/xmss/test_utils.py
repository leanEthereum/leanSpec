"""Tests for the utility functions in the XMSS signature scheme."""

import secrets
from typing import List

import pytest

from lean_spec.subspecs.koalabear.field import Fp, P
from lean_spec.subspecs.xmss.utils import int_to_base_p


@pytest.mark.parametrize(
    "value, num_limbs, expected_values",
    [
        (0, 4, [0, 0, 0, 0]),
        (123, 4, [123, 0, 0, 0]),
        (P, 4, [0, 1, 0, 0]),
        (P - 1, 4, [P - 1, 0, 0, 0]),
        (3 * (P**2) + 2 * P + 1, 4, [1, 2, 3, 0]),
        (P**3 - 1, 3, [P - 1, P - 1, P - 1]),
    ],
)
def test_int_to_base_p(value: int, num_limbs: int, expected_values: List[int]) -> None:
    """Validates the base-P decomposition of an integer with known-answer tests."""
    # Convert the list of expected integer values to a list of Fp objects for comparison.
    expected_limbs = [Fp(value=v) for v in expected_values]
    # Perform the decomposition.
    actual_limbs = int_to_base_p(value, num_limbs)
    # Assert that the result matches the expected output.
    assert actual_limbs == expected_limbs


def test_int_to_base_p_roundtrip() -> None:
    """Ensures that the base-P decomposition is perfectly reversible."""
    # Create a large, random multi-limb integer.
    num_limbs = 5
    original_limbs = [secrets.randbelow(P) for _ in range(num_limbs)]
    original_value = sum(val * (P**i) for i, val in enumerate(original_limbs))

    # Decompose the integer into base-P limbs using the function under test.
    decomposed_limbs_fp = int_to_base_p(original_value, num_limbs)
    decomposed_limbs = [fp.value for fp in decomposed_limbs_fp]

    # Reconstruct the integer from the decomposed limbs.
    reconstructed_value = sum(val * (P**i) for i, val in enumerate(decomposed_limbs))

    # Assert that the original and reconstructed values are identical.
    assert original_value == reconstructed_value
    # Also assert that the original and decomposed limbs match.
    assert original_limbs == decomposed_limbs
