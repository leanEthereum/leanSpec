"""
A minimal Python specification for the Poseidon2 permutation.

Based on "Poseidon2: A Faster Version of the Poseidon Hash Function".
See https://eprint.iacr.org/2023/323.

Uses numpy arrays for vectorized field operations.
"""

from typing import Final, Self, TypeAlias

import numpy as np
from numpy.typing import NDArray
from pydantic import Field, model_validator

from ...types import StrictBaseModel
from ..koalabear.field import Fp, P
from .constants import (
    ROUND_CONSTANTS_16,
    ROUND_CONSTANTS_24,
)

# =================================================================
# Constants & Type Definitions
# =================================================================

State: TypeAlias = NDArray[np.int64]
"""State vector as signed 64-bit integers."""


_M4_T: Final[NDArray[np.int64]] = np.array(
    [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2],
    ],
    dtype=np.int64,
).T
"""
Base 4x4 MDS matrix, pre-transposed.

Pre-transposition enables efficient row-vector multiplication: `v @ M.T`.
"""


# =================================================================
# Poseidon2 Parameter Definitions
# =================================================================


class Poseidon2Params(StrictBaseModel):
    """Parameters for a specific Poseidon2 instance."""

    width: int = Field(gt=0, description="The size of the state (t).")
    rounds_f: int = Field(gt=0, description="Total number of 'full' rounds.")
    rounds_p: int = Field(ge=0, description="Total number of 'partial' rounds.")
    internal_diag_vectors: list[Fp] = Field(
        min_length=1,
        description=("Diagonal vectors for the efficient internal linear layer matrix (M_I)."),
    )
    round_constants: list[Fp] = Field(
        min_length=1,
        description="The list of pre-computed constants for all rounds.",
    )

    @model_validator(mode="after")
    def check_lengths(self) -> Self:
        """Ensures vector lengths match the configuration."""
        if len(self.internal_diag_vectors) != self.width:
            raise ValueError("Length of internal_diag_vectors must equal width.")

        expected_constants = (self.rounds_f * self.width) + self.rounds_p
        if len(self.round_constants) != expected_constants:
            raise ValueError("Incorrect number of round constants provided.")

        return self


# =================================================================
# The Engine
# =================================================================


class Poseidon2:
    """
    Optimized execution engine for Poseidon2.

    Pre-processes parameters into numpy arrays during initialization.
    Minimizes overhead during permute calls.
    """

    __slots__ = ("_width", "_half_rounds_f", "_rounds_p", "_diag_vector", "_round_constants")

    _width: int
    """State size (t)."""

    _half_rounds_f: int
    """Full rounds divided by 2."""

    _rounds_p: int
    """Number of partial rounds."""

    _diag_vector: NDArray[np.int64]
    """Diagonal vector for internal linear layer (M_I)."""

    _round_constants: NDArray[np.int64]
    """Flattened array of all round constants."""

    def __init__(self, params: Poseidon2Params) -> None:
        """
        Initialize the engine with validated parameters.

        Converts Fp lists to int64 numpy arrays for speed.
        """
        self._width = params.width
        self._half_rounds_f = params.rounds_f // 2
        self._rounds_p = params.rounds_p

        # Pre-convert to numpy arrays.
        # Avoids overhead in the hot loop.
        self._diag_vector = np.array(
            [fp.value for fp in params.internal_diag_vectors], dtype=np.int64
        )
        self._round_constants = np.array(
            [fp.value for fp in params.round_constants], dtype=np.int64
        )

    def permute(self, current_state: list[Fp]) -> list[Fp]:
        """
        Perform the full Poseidon2 permutation.

        Structure:

        1. Initial linear layer
        2. First half of full rounds
        3. Partial rounds
        4. Second half of full rounds

        Args:
            current_state: List of Fp elements representing the current state.

        Returns:
            New state after applying the permutation.
        """
        if len(current_state) != self._width:
            raise ValueError(f"Input state must have length {self._width}")

        # Local variable access is faster in Python loops.
        width = self._width
        p = P
        const_idx = 0
        constants = self._round_constants

        # Convert input Fp elements to numpy array.
        state = np.array([fp.value for fp in current_state], dtype=np.int64)

        # 1. Initial Linear Layer
        #
        # Prevents certain algebraic attacks.
        # Ensures the permutation begins with a diffusion layer.
        state = self._external_linear_layer(state)

        # 2. First Half of Full Rounds (R_F / 2)
        #
        # Note: for S_BOX_DEGREE=3, state**3 would overflow int64 before modulo.
        # Values reach up to 2^93, but int64 max is 2^63.
        # Expand S-box to `(state*state % P) * state % P` to stay in range.
        for _ in range(self._half_rounds_f):
            # Add round constants to entire state.
            state = (state + constants[const_idx : const_idx + width]) % p
            const_idx += width

            # Apply S-box (x -> x^d) to full state.
            state = (state * state % p) * state % p

            # Apply external linear layer for diffusion.
            state = self._external_linear_layer(state)

        # 3. Partial Rounds (R_P)
        for _ in range(self._rounds_p):
            # Add single round constant to first element.
            state[0] = (state[0] + constants[const_idx]) % p
            const_idx += 1

            # Apply S-box to first element only.
            # This is the main optimization of the Hades design.
            state[0] = (state[0] * state[0] % p) * state[0] % p

            # Apply internal linear layer.
            state = self._internal_linear_layer(state)

        # 4. Second Half of Full Rounds (R_F / 2)
        for _ in range(self._half_rounds_f):
            # Add round constants to entire state.
            state = (state + constants[const_idx : const_idx + width]) % p
            const_idx += width

            # Apply S-box to full state.
            state = (state * state % p) * state % p

            # Apply external linear layer for diffusion.
            state = self._external_linear_layer(state)

        # Convert back to Fp objects.
        return [Fp(value=int(x)) for x in state]

    def _external_linear_layer(self, state: State) -> State:
        """
        Apply the external linear layer (M_E).

        Provides strong diffusion across the entire state.
        Used in full rounds.

        For state size t=4k, constructed from M4 to form a circulant-like matrix.
        Efficient while ensuring any single element change affects all others.

        See Appendix B of the paper.
        """
        # Apply M4 to each 4-element chunk.
        # Provides strong local diffusion within each block.
        chunks = state.reshape(-1, 4)
        chunks = chunks @ _M4_T

        # Apply outer circulant structure for global diffusion.
        # Equivalent to multiplying by circ(2*I, I, ..., I) after M4 stage.
        sums = chunks.sum(axis=0)

        # Add corresponding sum to each element.
        return (chunks + sums).reshape(-1) % P

    def _internal_linear_layer(self, state: State) -> State:
        """
        Apply the internal linear layer (M_I).

        Used during partial rounds.
        Optimized for speed.

        Matrix structure: M_I = J + D

        - J is the all-ones matrix
        - D is a diagonal matrix

        This allows O(t) computation instead of O(t^2):

            M_I * s = J*s + D*s

        J*s is a vector where each element equals the sum of all elements in s.
        """
        # J*state: sum of all elements (broadcast to vector).
        # D*state: element-wise multiplication with diagonal.
        state_sum = state.sum()

        # new_state[i] = state_sum + diag_vector[i] * state[i]
        return (state_sum + (self._diag_vector * state)) % P


# =================================================================
# Pre-defined Configurations
# =================================================================

# Parameters for WIDTH = 16
PARAMS_16 = Poseidon2Params(
    width=16,
    rounds_f=8,
    rounds_p=20,
    internal_diag_vectors=[
        Fp(value=-2),
        Fp(value=1),
        Fp(value=2),
        Fp(value=1) / Fp(value=2),
        Fp(value=3),
        Fp(value=4),
        Fp(value=-1) / Fp(value=2),
        Fp(value=-3),
        Fp(value=-4),
        Fp(value=1) / Fp(value=2**8),
        Fp(value=1) / Fp(value=8),
        Fp(value=1) / Fp(value=2**24),
        Fp(value=-1) / Fp(value=2**8),
        Fp(value=-1) / Fp(value=8),
        Fp(value=-1) / Fp(value=16),
        Fp(value=-1) / Fp(value=2**24),
    ],
    round_constants=ROUND_CONSTANTS_16,
)

# Parameters for WIDTH = 24
PARAMS_24 = Poseidon2Params(
    width=24,
    rounds_f=8,
    rounds_p=23,
    internal_diag_vectors=[
        Fp(value=-2),
        Fp(value=1),
        Fp(value=2),
        Fp(value=1) / Fp(value=2),
        Fp(value=3),
        Fp(value=4),
        Fp(value=-1) / Fp(value=2),
        Fp(value=-3),
        Fp(value=-4),
        Fp(value=1) / Fp(value=2**8),
        Fp(value=1) / Fp(value=4),
        Fp(value=1) / Fp(value=8),
        Fp(value=1) / Fp(value=16),
        Fp(value=1) / Fp(value=32),
        Fp(value=1) / Fp(value=64),
        Fp(value=1) / Fp(value=2**24),
        Fp(value=-1) / Fp(value=2**8),
        Fp(value=-1) / Fp(value=8),
        Fp(value=-1) / Fp(value=16),
        Fp(value=-1) / Fp(value=32),
        Fp(value=-1) / Fp(value=64),
        Fp(value=-1) / Fp(value=2**7),
        Fp(value=-1) / Fp(value=2**9),
        Fp(value=-1) / Fp(value=2**24),
    ],
    round_constants=ROUND_CONSTANTS_24,
)
