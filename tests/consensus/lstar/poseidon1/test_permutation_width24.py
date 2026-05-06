"""Poseidon1 permutation: width-24 known-answer vectors.

Pins the output state of the Poseidon1 permutation over the KoalaBear
field at state width 24 for four structural input patterns. Mirrors
the width-16 coverage on the larger parameter set.
"""

import pytest
from consensus_testing import PoseidonPermutationTestFiller

from lean_spec.subspecs.koalabear.field import P

pytestmark = pytest.mark.valid_until("Lstar")

WIDTH: int = 24


def test_permutation_width24_all_zero(
    poseidon_permutation: PoseidonPermutationTestFiller,
) -> None:
    """Input state of all zeros pins the round-constant-only output at width 24.

    With a zero state the only contribution to every S-box input is the
    round-constants stream. The output state depends purely on the
    round constants and MDS matrix, making this vector sensitive to
    tables-of-constants drift at the larger width.
    """
    poseidon_permutation(
        width=WIDTH,
        input={"inputState": ["0"] * WIDTH},
    )


def test_permutation_width24_all_one(
    poseidon_permutation: PoseidonPermutationTestFiller,
) -> None:
    """Input state of all ones exercises uniform non-zero entries at width 24."""
    poseidon_permutation(
        width=WIDTH,
        input={"inputState": ["1"] * WIDTH},
    )


def test_permutation_width24_incremental_index(
    poseidon_permutation: PoseidonPermutationTestFiller,
) -> None:
    """Input state filled with 0, 1, 2, ..., 23 pins per-slot MDS behaviour."""
    poseidon_permutation(
        width=WIDTH,
        input={"inputState": [str(i) for i in range(WIDTH)]},
    )


def test_permutation_width24_p_minus_one_and_near_zero(
    poseidon_permutation: PoseidonPermutationTestFiller,
) -> None:
    """Alternating P - 1 and small positives stress reduction at width 24."""
    state = [str(P - 1) if i % 2 == 0 else str(i) for i in range(WIDTH)]
    poseidon_permutation(
        width=WIDTH,
        input={"inputState": state},
    )
