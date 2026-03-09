"""
A minimal Python specification for the Poseidon2 permutation.

Based on "Poseidon2: A Faster Version of the Poseidon Hash Function".
See https://eprint.iacr.org/2023/323.

Uses Numba JIT compilation for native-speed permutation.
"""

from __future__ import annotations

from typing import Self

import numpy as np
from numba import njit
from numpy.typing import NDArray
from pydantic import Field, model_validator

from ...types import StrictBaseModel
from ..koalabear.field import Fp, P
from .constants import (
    ROUND_CONSTANTS_16,
    ROUND_CONSTANTS_24,
)


@njit(cache=True)
def _external_linear_layer_jit(state: NDArray[np.int64], width: int, p: int) -> None:
    """
    Apply the external linear layer (M_E) in-place.

    Multiplies each 4-element chunk by the M4 circulant matrix,
    then applies the outer circulant structure for global diffusion.
    """
    num_chunks = width // 4

    # Apply M4 to each 4-element chunk.
    for c in range(num_chunks):
        base = c * 4
        a = state[base]
        b = state[base + 1]
        c_val = state[base + 2]
        d = state[base + 3]

        s = (a + b + c_val + d) % p
        state[base] = (s + a + 2 * b) % p
        state[base + 1] = (s + b + 2 * c_val) % p
        state[base + 2] = (s + c_val + 2 * d) % p
        state[base + 3] = (s + 2 * a + d) % p

    # Outer circulant: sum corresponding positions across chunks, add to each.
    for i in range(4):
        col_sum = np.int64(0)
        for c in range(num_chunks):
            col_sum += state[c * 4 + i]
        for c in range(num_chunks):
            state[c * 4 + i] = (state[c * 4 + i] + col_sum) % p


@njit(cache=True)
def _internal_linear_layer_jit(
    state: NDArray[np.int64], diag_vector: NDArray[np.int64], width: int, p: int
) -> None:
    """
    Apply the internal linear layer (M_I) in-place.

    M_I = J + D where J is the all-ones matrix and D is diagonal.
    O(t) computation instead of O(t^2).
    """
    state_sum = np.int64(0)
    for i in range(width):
        state_sum += state[i]
    state_sum = state_sum % p

    for i in range(width):
        state[i] = (state_sum + diag_vector[i] * state[i] % p) % p


@njit(cache=True)
def _permute_jit(
    state: NDArray[np.int64],
    round_constants: NDArray[np.int64],
    diag_vector: NDArray[np.int64],
    width: int,
    half_rounds_f: int,
    rounds_p: int,
    p: int,
) -> None:
    """
    Full Poseidon2 permutation, compiled to native code.

    Modifies state array in-place.
    S-box: x^3 computed as (x*x % p) * x % p to avoid int64 overflow.
    """
    const_idx = 0

    # 1. Initial linear layer.
    _external_linear_layer_jit(state, width, p)

    # 2. First half of full rounds.
    for _ in range(half_rounds_f):
        for i in range(width):
            state[i] = (state[i] + round_constants[const_idx + i]) % p
        const_idx += width

        for i in range(width):
            x = state[i]
            state[i] = (x * x % p) * x % p

        _external_linear_layer_jit(state, width, p)

    # 3. Partial rounds.
    for _ in range(rounds_p):
        state[0] = (state[0] + round_constants[const_idx]) % p
        const_idx += 1

        x = state[0]
        state[0] = (x * x % p) * x % p

        _internal_linear_layer_jit(state, diag_vector, width, p)

    # 4. Second half of full rounds.
    for _ in range(half_rounds_f):
        for i in range(width):
            state[i] = (state[i] + round_constants[const_idx + i]) % p
        const_idx += width

        for i in range(width):
            x = state[i]
            state[i] = (x * x % p) * x % p

        _external_linear_layer_jit(state, width, p)


# Trigger compilation on import so the first real call is fast.
_permute_jit(
    np.zeros(16, dtype=np.int64),
    np.zeros(148, dtype=np.int64),
    np.zeros(16, dtype=np.int64),
    16,
    4,
    20,
    2130706433,
)


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

        state = np.array([fp.value for fp in current_state], dtype=np.int64)

        _permute_jit(
            state,
            self._round_constants,
            self._diag_vector,
            self._width,
            self._half_rounds_f,
            self._rounds_p,
            P,
        )

        return [Fp(value=int(x)) for x in state]


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
