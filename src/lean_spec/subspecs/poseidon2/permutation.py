"""
A minimal Python specification for the Poseidon2 permutation.

The design is based on the paper "Poseidon2: A Faster Version of the Poseidon
Hash Function" (https://eprint.iacr.org/2023/323).
"""

from itertools import chain
from typing import List

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..koalabear.field import Fp
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


class Poseidon2Params(BaseModel):
    """Parameters for a specific Poseidon2 instance."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    width: int = Field(gt=0, description="The size of the state (t).")
    rounds_f: int = Field(gt=0, description="Total number of 'full' rounds.")
    rounds_p: int = Field(ge=0, description="Total number of 'partial' rounds.")
    internal_diag_vectors: List[Fp] = Field(
        min_length=1,
        description=("Diagonal vectors for the efficient internal linear layer matrix (M_I)."),
    )
    round_constants: List[Fp] = Field(
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

# Base 4x4 matrix, used in the external linear layer.
M4_MATRIX = [
    [Fp(value=2), Fp(value=3), Fp(value=1), Fp(value=1)],
    [Fp(value=1), Fp(value=2), Fp(value=3), Fp(value=1)],
    [Fp(value=1), Fp(value=1), Fp(value=2), Fp(value=3)],
    [Fp(value=3), Fp(value=1), Fp(value=1), Fp(value=2)],
]


def _apply_m4(chunk: List[Fp]) -> List[Fp]:
    """
    Applies the 4x4 M4 MDS matrix to a 4-element chunk of the state.
    This is a helper function for the external linear layer.

    Args:
        chunk: A list of 4 Fp elements.

    Returns:
        The transformed 4-element chunk.
    """
    # Initialize the result vector with zeros.
    result = [Fp(value=0)] * 4
    # Perform standard matrix-vector multiplication.
    for i in range(4):
        for j in range(4):
            result[i] += M4_MATRIX[i][j] * chunk[j]
    return result


def external_linear_layer(state: List[Fp], width: int) -> List[Fp]:
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
    state_after_m4 = list(
        chain.from_iterable(_apply_m4(state[i : i + 4]) for i in range(0, width, 4))
    )

    # Apply the outer circulant structure for global diffusion.
    #
    # This is equivalent to multiplying by circ(2*I, I, ..., I)
    # after the M4 stage.
    #
    # We precompute the four sums of elements at the same offset in each chunk.
    # For each k in 0..4:
    #       sums[k] = state[k] + state[4 + k] + state[8 + k] + ... up to width
    sums = [sum((state_after_m4[j + k] for j in range(0, width, 4)), Fp(value=0)) for k in range(4)]

    # Add the corresponding sum to each element of the state.
    state_after_circulant = [s + sums[i % 4] for i, s in enumerate(state_after_m4)]

    return state_after_circulant


def internal_linear_layer(state: List[Fp], params: Poseidon2Params) -> List[Fp]:
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
        params: The Poseidon2Params object containing the diagonal vectors.

    Returns:
        The state vector after applying the internal linear layer.
    """
    width = params.width
    diag_vector = params.internal_diag_vectors

    # Construct the M_I matrix explicitly.
    #
    # It has dimensions width x width.
    m_i = [[Fp(value=1) for _ in range(width)] for _ in range(width)]

    # Add the diagonal part (D) to the all-ones matrix (J)
    #
    # The result is M_I = J + D.
    for i in range(width):
        m_i[i][i] += diag_vector[i]

    # Perform standard matrix-vector multiplication: new_state = m_i * state
    #
    # Initialize the result vector with zeros.
    new_state = [Fp(value=0)] * width

    # For each row in the matrix, calculate the dot product of that row with the state vector.
    for i in range(width):
        for j in range(width):
            new_state[i] += m_i[i][j] * state[j]

    return new_state


def permute(state: List[Fp], params: Poseidon2Params) -> List[Fp]:
    """
    Performs the full Poseidon2 permutation on the given state.

    The permutation follows the structure:
    Initial Layer -> Full Rounds -> Partial Rounds -> Full Rounds

    Args:
        state: A list of Fp elements representing the current state.
        params: The object defining the permutation's configuration.

    Returns:
        The new state after applying the permutation.
    """
    # Ensure the input state has the correct dimensions.
    if len(state) != params.width:
        raise ValueError(f"Input state must have length {params.width}")

    # Generate the deterministic round constants for this parameter set.
    round_constants = params.round_constants
    # The number of full rounds is split between the beginning and end.
    half_rounds_f = params.rounds_f // 2
    # Initialize index for accessing the flat list of round constants.
    const_idx = 0

    # 1. Initial Linear Layer
    #
    # Another linear layer is applied at the start to prevent certain algebraic
    # attacks by ensuring the permutation begins with a diffusion layer.
    state = external_linear_layer(list(state), params.width)

    # 2. First Half of Full Rounds (R_F / 2)
    for _r in range(half_rounds_f):
        # Add round constants to the entire state.
        state = [s + round_constants[const_idx + i] for i, s in enumerate(state)]
        const_idx += params.width
        # Apply the S-box (x -> x^d) to the full state.
        state = [s**S_BOX_DEGREE for s in state]
        # Apply the external linear layer for diffusion.
        state = external_linear_layer(state, params.width)

    # 3. Partial Rounds (R_P)
    for _r in range(params.rounds_p):
        # Add a single round constant to the first state element.
        state[0] += round_constants[const_idx]
        const_idx += 1
        # Apply the S-box to the first state element only.
        #
        # This is the main optimization of the Hades design.
        state[0] = state[0] ** S_BOX_DEGREE
        # Apply the internal linear layer.
        state = internal_linear_layer(state, params)

    # 4. Second Half of Full Rounds (R_F / 2)
    for _r in range(half_rounds_f):
        # Add round constants to the entire state.
        state = [s + round_constants[const_idx + i] for i, s in enumerate(state)]
        const_idx += params.width
        # Apply the S-box to the full state.
        state = [s**S_BOX_DEGREE for s in state]
        # Apply the external linear layer for diffusion.
        state = external_linear_layer(state, params.width)

    return state
