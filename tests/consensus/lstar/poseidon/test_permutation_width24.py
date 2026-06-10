"""Poseidon permutation width-24 known-answer vectors over the KoalaBear field."""

import pytest

from consensus_testing import PoseidonPermutationTestFiller
from lean_spec.spec.crypto.koalabear import P

pytestmark = pytest.mark.valid_until("Lstar")

WIDTH: int = 24


def test_permutation_width24_all_zero(
    poseidon_permutation_test: PoseidonPermutationTestFiller,
) -> None:
    """
    An all-zero input pins the output that depends only on the round constants.

    Given
    -----
    - a width-24 input state of all zeros.

    When
    ----
    - the permutation runs once.

    Then
    ----
    - the output state equals the reference vector.
    - the output is a sensitive diff for any round-constant table drift.
    """
    poseidon_permutation_test(
        width=WIDTH,
        input_state=["0"] * WIDTH,
    )


def test_permutation_width24_all_one(
    poseidon_permutation_test: PoseidonPermutationTestFiller,
) -> None:
    """
    An all-one input exercises uniform non-zero entries.

    Given
    -----
    - a width-24 input state where every element is the smallest non-zero value.

    When
    ----
    - the permutation runs once.

    Then
    ----
    - the output state equals the reference vector.
    """
    poseidon_permutation_test(
        width=WIDTH,
        input_state=["1"] * WIDTH,
    )


def test_permutation_width24_incremental_index(
    poseidon_permutation_test: PoseidonPermutationTestFiller,
) -> None:
    """
    Distinct per-slot entries expose per-position behaviour.

    Given
    -----
    - a width-24 input state filled with 0, 1, 2, up to 23.

    When
    ----
    - the permutation runs once.

    Then
    ----
    - the output state equals the reference vector.
    - any off-by-one in row indexing or constant slicing perturbs the output.
    """
    poseidon_permutation_test(
        width=WIDTH,
        input_state=[str(i) for i in range(WIDTH)],
    )


def test_permutation_width24_p_minus_one_and_near_zero(
    poseidon_permutation_test: PoseidonPermutationTestFiller,
) -> None:
    """
    A mix of field-boundary and small values stresses the reduction path.

    Given
    -----
    - a width-24 input state alternating the maximum field element P minus 1 and small values.

    When
    ----
    - the permutation runs once.

    Then
    ----
    - the output state equals the reference vector.
    - the widest intermediates inside the S-box reduce correctly.
    """
    state = [str(P - 1) if i % 2 == 0 else str(i) for i in range(WIDTH)]
    poseidon_permutation_test(
        width=WIDTH,
        input_state=state,
    )
