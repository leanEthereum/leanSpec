"""Poseidon1 permutation: width-16 known-answer vectors.

Pins the output state of the Poseidon1 permutation over the KoalaBear
field at state width 16 for four structural input patterns. Clients
must produce identical output states bit-for-bit.
"""

import pytest
from consensus_testing import PoseidonPermutationTestFiller

from lean_spec.subspecs.koalabear.field import P

pytestmark = pytest.mark.valid_until("Lstar")

WIDTH: int = 16


def test_permutation_width16_all_zero(
    poseidon_permutation: PoseidonPermutationTestFiller,
) -> None:
    """Input state of all zeros pins the round-constant-only output.

    With a zero state, the only contribution to every S-box input is the
    round-constants stream. The output state therefore depends purely on
    the round constants and the MDS matrix, making this vector a
    sensitive diff for tables-of-constants drift.
    """
    poseidon_permutation(
        width=WIDTH,
        input={"inputState": ["0"] * WIDTH},
    )


def test_permutation_width16_all_one(
    poseidon_permutation: PoseidonPermutationTestFiller,
) -> None:
    """Input state of all ones exercises uniform non-zero entries.

    Every element begins at the smallest non-zero field value. The MDS
    multiplications see a state vector whose entries all carry the same
    contribution, pinning the first-row linearity of the permutation.
    """
    poseidon_permutation(
        width=WIDTH,
        input={"inputState": ["1"] * WIDTH},
    )


def test_permutation_width16_incremental_index(
    poseidon_permutation: PoseidonPermutationTestFiller,
) -> None:
    """Input state filled with 0, 1, 2, ..., WIDTH - 1.

    Distinct entries per slot expose per-position behaviour: any
    off-by-one in MDS row indexing or round-constant slicing perturbs
    the output noticeably.
    """
    poseidon_permutation(
        width=WIDTH,
        input={"inputState": [str(i) for i in range(WIDTH)]},
    )


def test_permutation_width16_p_minus_one_and_near_zero(
    poseidon_permutation: PoseidonPermutationTestFiller,
) -> None:
    """Mix of field-boundary values P - 1 and small values across the state.

    Half the slots sit at the maximum representable field element, the
    other half at small positives. This pattern stresses the reduction
    path for the widest intermediates generated inside the S-box.
    """
    state = [str(P - 1) if i % 2 == 0 else str(i) for i in range(WIDTH)]
    poseidon_permutation(
        width=WIDTH,
        input={"inputState": state},
    )
