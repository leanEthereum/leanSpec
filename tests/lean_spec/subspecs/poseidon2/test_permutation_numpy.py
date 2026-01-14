"""
Tests for the numpy-optimized Poseidon2 permutation.

Verifies that permute_numpy produces identical results to the reference implementation.
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from lean_spec.subspecs.koalabear.field import Fp, P
from lean_spec.subspecs.poseidon2.permutation import (
    PARAMS_16,
    PARAMS_24,
    Poseidon2Params,
    permute,
)
from lean_spec.subspecs.poseidon2.permutation_numpy import permute_numpy

from tests.lean_spec.subspecs.poseidon2.test_permutation import INPUT_16, INPUT_24


@pytest.mark.parametrize(
    "params, input_state",
    [
        (PARAMS_16, INPUT_16),
        (PARAMS_24, INPUT_24),
    ],
    ids=["width_16", "width_24"],
)
def test_numpy_matches_reference(params: Poseidon2Params, input_state: list) -> None:
    """Verify that the numpy implementation produces identical results to reference."""
    reference_output = permute(input_state, params)
    numpy_output = permute_numpy(input_state, params)

    assert numpy_output == reference_output, (
        f"Numpy permutation output for width {params.width} differs from reference."
    )


# Strategy for generating random field elements
fp_strategy = st.integers(min_value=0, max_value=P - 1).map(lambda v: Fp(value=v))


@given(values=st.lists(fp_strategy, min_size=16, max_size=16))
@settings(max_examples=100)
def test_numpy_matches_reference_random_width16(values: list) -> None:
    """Property test: numpy and reference produce identical results for width 16."""
    reference_output = permute(values, PARAMS_16)
    numpy_output = permute_numpy(values, PARAMS_16)
    assert numpy_output == reference_output


@given(values=st.lists(fp_strategy, min_size=24, max_size=24))
@settings(max_examples=100)
def test_numpy_matches_reference_random_width24(values: list) -> None:
    """Property test: numpy and reference produce identical results for width 24."""
    reference_output = permute(values, PARAMS_24)
    numpy_output = permute_numpy(values, PARAMS_24)
    assert numpy_output == reference_output
