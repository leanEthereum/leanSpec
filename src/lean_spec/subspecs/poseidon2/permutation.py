"""
A minimal Python specification for the Poseidon2 permutation.

The design is based on the paper "Poseidon2: A Faster Version of the Poseidon
Hash Function" (https://eprint.iacr.org/2023/323).

This implementation uses numpy arrays for vectorized field operations for efficiency.
"""

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
# Poseidon2 Parameter Definitions
# =================================================================

S_BOX_DEGREE = 3
"""
The S-box exponent `d`.

For fields where `gcd(d, p-1) = 1`, `x -> x^d` is a permutation.

For KoalaBear, `d=3` is chosen for its low degree.
"""


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
    def check_lengths(self) -> "Poseidon2Params":
        """Ensures vector lengths match the configuration."""
        if len(self.internal_diag_vectors) != self.width:
            raise ValueError("Length of internal_diag_vectors must equal width.")

        expected_constants = (self.rounds_f * self.width) + self.rounds_p
        if len(self.round_constants) != expected_constants:
            raise ValueError("Incorrect number of round constants provided.")

        return self


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

# Base 4x4 MDS matrix used in the external linear layer.
_M4 = np.array(
    [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2],
    ],
    dtype=np.int64,
)

# Caches numpy arrays to avoid converting hundreds of Fp objects on every permute() call.
_CACHE: dict[int, dict] = {}


def _precompute_params(params: Poseidon2Params) -> dict:
    """Convert Poseidon2Params to numpy arrays for efficient computation."""
    return {
        "width": params.width,
        "full_rounds": params.rounds_f,
        "partial_rounds": params.rounds_p,
        "diag_vector": np.array([fp.value for fp in params.internal_diag_vectors], dtype=np.int64),
        "round_constants": np.array([fp.value for fp in params.round_constants], dtype=np.int64),
    }


def _apply_m4(state: NDArray[np.int64]) -> NDArray[np.int64]:
    """
    Applies the 4x4 M4 MDS matrix to each 4-element chunk of the state.

    This is a helper function for the external linear layer.

    Args:
        state: State array with length divisible by 4.

    Returns:
        The transformed state after M4 applied to each chunk.
    """
    chunks = state.reshape(-1, 4)
    return (chunks @ _M4.T).reshape(-1) % P


def external_linear_layer(state: NDArray[np.int64], width: int) -> NDArray[np.int64]:
    """
    Applies the external linear layer (M_E).

    This layer provides strong diffusion across the entire state and is used
    in the full rounds. For a state of size t=4k, it's constructed from the
    base M4 matrix to form a larger circulant-like matrix, which is efficient
    while ensuring that a change in any single element affects all other
    elements after application.

    The process follows Appendix B of the paper.

    Args:
        state: The current state vector.
        width: The width `t` of the state.

    Returns:
        The state vector after applying the external linear layer.
    """
    # Apply the M4 matrix to each 4-element chunk of the state.
    #
    # This provides strong local diffusion within each block.
    state = _apply_m4(state)

    # Apply the outer circulant structure for global diffusion.
    #
    # This is equivalent to multiplying by circ(2*I, I, ..., I)
    # after the M4 stage.
    #
    # We precompute the four sums of elements at the same offset in each chunk.
    # For each k in 0..4:
    #       sums[k] = state[k] + state[4 + k] + state[8 + k] + ... up to width
    chunks = state.reshape(-1, 4)
    sums = chunks.sum(axis=0) % P

    # Add the corresponding sum to each element of the state.
    return (chunks + sums).reshape(-1) % P


def internal_linear_layer(
    state: NDArray[np.int64], diag_vector: NDArray[np.int64]
) -> NDArray[np.int64]:
    """
    Applies the internal linear layer (M_I).

    This layer is used during partial rounds and is optimized for speed. Its
    matrix is constructed as M_I = J + D, where J is the all-ones matrix and D
    is a diagonal matrix. This structure allows the matrix-vector product to be
    computed in O(t) time instead of O(t^2), as M_I * s = J*s + D*s.
    The term J*s is a vector where each element is the sum of
    all elements in s.

    Args:
        state: The current state vector.
        diag_vector: The diagonal vector for the internal matrix.

    Returns:
        The state vector after applying the internal linear layer.
    """
    # Compute M_I * state = (J + D) * state = J*state + D*state
    #
    # J*state is a vector where each element is the sum of all elements in state.
    # D*state is element-wise multiplication of diagonal with state.

    # Calculate the sum of all state elements once (for J*state)
    state_sum = state.sum() % P

    # Compute state[i] = state_sum + diag_vector[i] * state[i]
    # This is equivalent to (J + D) * state but much faster.
    return (state_sum + (diag_vector * state) % P) % P


def permute(current_state: list[Fp], params: Poseidon2Params) -> list[Fp]:
    """
    Performs the full Poseidon2 permutation on the given state.

    The permutation follows the structure:
    Initial Layer -> Full Rounds -> Partial Rounds -> Full Rounds

    Args:
        current_state: A list of Fp elements representing the current state.
        params: The object defining the permutation's configuration.

    Returns:
        The new state after applying the permutation.
    """
    # Ensure the input state has the correct dimensions.
    if len(current_state) != params.width:
        raise ValueError(f"Input state must have length {params.width}")

    # Get or compute cached numpy parameters
    key = id(params)
    if key not in _CACHE:
        _CACHE[key] = _precompute_params(params)
    cached = _CACHE[key]

    width = cached["width"]
    full_rounds = cached["full_rounds"]
    partial_rounds = cached["partial_rounds"]
    diag_vector = cached["diag_vector"]
    round_constants = cached["round_constants"]

    # The number of full rounds is split between the beginning and end.
    half_full_rounds = full_rounds // 2
    # Initialize index for accessing the flat list of round constants.
    const_idx = 0

    # Convert input Fp elements to numpy array for vectorized operations
    state = np.array([fp.value for fp in current_state], dtype=np.int64)

    # 1. Initial Linear Layer
    #
    # Another linear layer is applied at the start to prevent certain algebraic
    # attacks by ensuring the permutation begins with a diffusion layer.
    state = external_linear_layer(state, width)

    # 2. First Half of Full Rounds (R_F / 2)
    #
    # Note: for S_BOX_DEGREE=3, state**3 would overflow int64 before the modulo
    # (values up to 2^93, but int64 max is 2^63). So we expand the S-box to
    # `(state*state % P) * state % P` to keep values in range.
    for _round in range(half_full_rounds):
        # Add round constants to the entire state.
        state = (state + round_constants[const_idx : const_idx + width]) % P
        const_idx += width
        # Apply the S-box (x -> x^d) to the full state.
        state = (state * state % P) * state % P
        # Apply the external linear layer for diffusion.
        state = external_linear_layer(state, width)

    # 3. Partial Rounds (R_P)
    for _round in range(partial_rounds):
        # Add a single round constant to the first state element.
        state[0] = (state[0] + round_constants[const_idx]) % P
        const_idx += 1
        # Apply the S-box to the first state element only.
        #
        # This is the main optimization of the Hades design.
        state[0] = (state[0] * state[0] % P) * state[0] % P
        # Apply the internal linear layer.
        state = internal_linear_layer(state, diag_vector)

    # 4. Second Half of Full Rounds (R_F / 2)
    for _round in range(half_full_rounds):
        # Add round constants to the entire state.
        state = (state + round_constants[const_idx : const_idx + width]) % P
        const_idx += width
        # Apply the S-box to the full state.
        state = (state * state % P) * state % P
        # Apply the external linear layer for diffusion.
        state = external_linear_layer(state, width)

    # Convert back to Fp objects
    return [Fp(value=int(x)) for x in state]
