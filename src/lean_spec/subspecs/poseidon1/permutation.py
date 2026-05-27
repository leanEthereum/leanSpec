"""
A minimal Python specification for the Poseidon1 permutation.

Based on "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems".
See https://eprint.iacr.org/2019/458.

This is the original Hades-based design.

Uses Numba JIT compilation for native-speed permutation.
"""

from typing import Self

import numpy as np
from numba import njit
from numpy.typing import NDArray
from pydantic import Field, field_validator, model_validator

from ...types import StrictBaseModel
from ..koalabear.field import Fp, P
from .constants import (
    ROUND_CONSTANTS_16,
    ROUND_CONSTANTS_24,
)


@njit(cache=True)
def _mds_multiply_jit(
    state: NDArray[np.int64], mds: NDArray[np.int64], p: int
) -> NDArray[np.int64]:
    """
    Dense MDS matrix-vector multiplication.

    Computes y = MDS * x where MDS is the circulant MDS matrix.
    Each product is reduced mod p before accumulation to prevent overflow.
    """
    # State length doubles as the matrix dimension since MDS is square.
    n = state.shape[0]

    # Output buffer, written in place by the inner loop.
    result = np.empty(n, dtype=np.int64)

    # One iteration computes a single row of the matrix-vector product.
    for i in range(n):
        # Accumulator collects n pre-reduced contributions before the final fold.
        s = np.int64(0)

        for j in range(n):
            # Each factor sits below p, so the product fits in 62 bits.
            #
            # Without per-product reduction, summing n products would risk int64 overflow.
            s += (mds[i, j] * state[j]) % p

        # Final fold back into the field after n already-reduced terms.
        result[i] = s % p

    return result


@njit(cache=True)
def _permute_jit(
    state: NDArray[np.int64],
    round_constants: NDArray[np.int64],
    mds: NDArray[np.int64],
    width: int,
    half_rounds_f: int,
    rounds_p: int,
    p: int,
) -> None:
    """
    Full Poseidon1 permutation, compiled to native code.

    Modifies state array in-place.
    S-box: x^3 computed as (x*x % p) * x % p to avoid int64 overflow.

    - Round structure: AddRoundConstants -> S-box -> MDS multiply.
    - No initial linear layer is applied before the round structure begins.
    - This matches the original Poseidon1 design.
    """
    const_idx = 0

    # Phase 1: opening full rounds.
    #
    # Full S-boxes at the boundary maximize non-linearity where
    # attacker control over inputs is highest.
    for _ in range(half_rounds_f):
        # Add round constants to entire state.
        state[:] = (state + round_constants[const_idx : const_idx + width]) % p
        const_idx += width

        # Apply S-box (x -> x^d) to full state.
        #
        # Cubing in one shot would overflow int64 inside Numba.
        # Splitting into two modular multiplies keeps each intermediate below p squared.
        state[:] = (state * state % p) * state % p

        # Apply dense MDS multiply for diffusion.
        state[:] = _mds_multiply_jit(state, mds, p)

    # Phase 2: partial rounds.
    #
    # AddRoundConstants and the MDS multiply still run on the entire state.
    # Only the S-box layer is partial.
    # Applying the S-box to only one element is the central Hades optimization.
    # It still saturates algebraic degree while cutting SNARK constraint cost.
    for _ in range(rounds_p):
        # Add round constants to entire state.
        state[:] = (state + round_constants[const_idx : const_idx + width]) % p
        const_idx += width

        # Apply S-box to first element only.
        state[0] = (state[0] * state[0] % p) * state[0] % p

        # Apply dense MDS multiply.
        state[:] = _mds_multiply_jit(state, mds, p)

    # Phase 3: closing full rounds.
    #
    # A second wall of full S-boxes blocks algebraic attacks that could
    # unwind the partial-round middle.
    for _ in range(half_rounds_f):
        # Add round constants to entire state.
        state[:] = (state + round_constants[const_idx : const_idx + width]) % p
        const_idx += width

        # Apply S-box to full state.
        state[:] = (state * state % p) * state % p

        # Apply dense MDS multiply for diffusion.
        state[:] = _mds_multiply_jit(state, mds, p)


class Poseidon1Params(StrictBaseModel):
    """Parameters for a specific Poseidon1 instance.

    - The paper requires at least 6 full rounds for statistical-attack security.
    - Some regimes raise this bound to 10 per Eq. 2 of the paper.
    - This minimum is not enforced here. Callers must choose secure parameters.
    """

    width: int = Field(gt=0, description="The size of the state (t).")
    rounds_f: int = Field(gt=0, description="Total number of 'full' rounds.")
    rounds_p: int = Field(ge=0, description="Total number of 'partial' rounds.")
    mds_first_row: list[Fp] = Field(
        min_length=1,
        description="First row of the circulant MDS matrix.",
    )
    round_constants: list[Fp] = Field(
        min_length=1,
        description="The list of pre-computed constants for all rounds.",
    )

    @field_validator("rounds_f")
    @classmethod
    def _rounds_f_must_be_even(cls, value: int) -> int:
        """Require an even full-round count.

        - The permutation runs equal halves of full rounds before and after the partial middle.
        - An odd count silently drops one full round and orphans a width-sized block of constants.
        - The original Poseidon design assumes an even split.
        """
        if value % 2 != 0:
            raise ValueError("Full-round count must be even.")
        return value

    @model_validator(mode="after")
    def check_lengths(self) -> Self:
        """Ensures vector lengths match the configuration."""
        if len(self.mds_first_row) != self.width:
            raise ValueError("Length of mds_first_row must equal width.")

        expected_constants = (self.rounds_f + self.rounds_p) * self.width
        if len(self.round_constants) != expected_constants:
            raise ValueError("Incorrect number of round constants provided.")

        return self


class Poseidon1:
    """Execution engine for Poseidon1."""

    __slots__ = ("_width", "_half_rounds_f", "_rounds_p", "_mds", "_round_constants")

    _width: int
    """State size (t)."""

    _half_rounds_f: int
    """Full rounds divided by 2."""

    _rounds_p: int
    """Number of partial rounds."""

    _mds: NDArray[np.int64]
    """Dense circulant MDS matrix."""

    _round_constants: NDArray[np.int64]
    """Flattened array of all round constants."""

    def __init__(self, params: Poseidon1Params) -> None:
        """
        Initialize the engine with validated parameters.

        Converts Fp lists to int64 numpy arrays for speed.
        Builds the dense circulant MDS matrix from the first row.
        """
        self._width = params.width
        self._half_rounds_f = params.rounds_f // 2
        self._rounds_p = params.rounds_p

        # Expand the n-by-n circulant MDS matrix from its first row r.
        #
        # Row i is r rolled right by i positions.
        # Equivalently, C[i][j] = r[(j - i) mod n].
        first_row = [int(fp) for fp in params.mds_first_row]
        self._mds = (
            np.array([np.roll(first_row, i) for i in range(self._width)], dtype=np.int64) % P
        )

        # Pre-convert round constants to numpy array.
        self._round_constants = np.array([int(fp) for fp in params.round_constants], dtype=np.int64)

    def permute(self, current_state: list[Fp]) -> list[Fp]:
        """
        Perform the full Poseidon1 permutation.

        Structure:

        1. First half of full rounds
        2. Partial rounds
        3. Second half of full rounds

        Args:
            current_state: List of Fp elements representing the current state.

        Returns:
            New state after applying the permutation.
        """
        if len(current_state) != self._width:
            raise ValueError(f"Input state must have length {self._width}")

        state = np.array([int(fp) for fp in current_state], dtype=np.int64)

        _permute_jit(
            state,
            self._round_constants,
            self._mds,
            self._width,
            self._half_rounds_f,
            self._rounds_p,
            P,
        )

        return [Fp(value=int(x)) for x in state]


_MDS_FIRST_ROW_16: list[int] = [1, 1, 51, 1, 11, 17, 2, 1, 101, 63, 15, 2, 67, 22, 13, 3]
"""MDS first row for width-16 circulant matrix.

- From Plonky3: https://github.com/Plonky3/Plonky3/blob/main/koala-bear/src/mds.rs
- The paper recommends Cauchy matrices over the circulant family used here.
- The matrix must avoid invariant subspace trails per GRS21.
"""

_MDS_FIRST_ROW_24: list[int] = [
    0x2D0AAAAB,
    0x64850517,
    0x17F5551D,
    0x04ECBEB5,
    0x6D91A8D5,
    0x60703026,
    0x18D6F3CA,
    0x729601A7,
    0x77CDA9E2,
    0x3C0F5038,
    0x26D52A61,
    0x0360405D,
    0x68FC71C8,
    0x2495A71D,
    0x5D57AFC2,
    0x1689DD98,
    0x3C2C3DBE,
    0x0C23DC41,
    0x0524C7F2,
    0x6BE4DF69,
    0x0A6E572C,
    0x5C7790FA,
    0x17E118F6,
    0x0878A07F,
]
"""MDS first row for width-24 circulant matrix.

- From Plonky3: https://github.com/Plonky3/Plonky3/blob/main/koala-bear/src/mds.rs
- The paper recommends Cauchy matrices over the circulant family used here.
- The matrix must avoid invariant subspace trails per GRS21.
"""

PARAMS_16 = Poseidon1Params(
    width=16,
    rounds_f=8,
    rounds_p=20,
    mds_first_row=[Fp(value=v) for v in _MDS_FIRST_ROW_16],
    round_constants=ROUND_CONSTANTS_16,
)
"""Poseidon1 parameters for width-16 permutation (8 full rounds, 20 partial)."""

PARAMS_24 = Poseidon1Params(
    width=24,
    rounds_f=8,
    rounds_p=23,
    mds_first_row=[Fp(value=v) for v in _MDS_FIRST_ROW_24],
    round_constants=ROUND_CONSTANTS_24,
)
"""Poseidon1 parameters for width-24 permutation (8 full rounds, 23 partial)."""
