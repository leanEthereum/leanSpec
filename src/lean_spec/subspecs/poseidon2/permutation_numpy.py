"""
Numpy-optimized Poseidon2 permutation.

This implementation provides a speedup over the reference implementation
by using numpy arrays for vectorized field operations. Both implementations
produce identical cryptographic outputs.

The speedup comes from:
1. Batch operations on numpy arrays instead of individual Fp objects
2. Contiguous memory layout enabling CPU cache efficiency
3. Reduced Python interpreter overhead

Not used by specs directly; available as a drop-in optimization when better
performance is required, e.g. key generation for testing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List

import numpy as np

from ..koalabear.field import Fp, P

if TYPE_CHECKING:
    from .permutation import Poseidon2Params

# Precomputed M4 matrix as numpy array
_M4 = np.array(
    [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2],
    ],
    dtype=np.int64,
)


def _precompute_params(params: "Poseidon2Params") -> dict:
    """Convert Poseidon2Params to numpy arrays for efficient computation."""
    return {
        "width": params.width,
        "rounds_f": params.rounds_f,
        "rounds_p": params.rounds_p,
        "diag": np.array([fp.value for fp in params.internal_diag_vectors], dtype=np.int64),
        "rc": np.array([fp.value for fp in params.round_constants], dtype=np.int64),
    }


# Cache for precomputed parameters
_CACHE: dict = {}


def _external_layer(state: np.ndarray, width: int) -> np.ndarray:
    """Apply external linear layer using vectorized numpy operations."""
    # Apply M4 to each 4-element chunk
    chunks = state.reshape(-1, 4)
    state = (chunks @ _M4.T).reshape(-1) % P

    # Circulant structure: add column sums
    chunks = state.reshape(-1, 4)
    sums = chunks.sum(axis=0) % P
    return (chunks + sums).reshape(-1) % P


def _internal_layer(state: np.ndarray, diag: np.ndarray) -> np.ndarray:
    """Apply internal linear layer: M_I * state = (J + D) * state."""
    state_sum = state.sum() % P
    return (state_sum + (diag * state) % P) % P


def _sbox(state: np.ndarray) -> np.ndarray:
    """Apply S-box (cubing) to all elements."""
    x2 = (state * state) % P
    return (x2 * state) % P


def permute_numpy(state: List[Fp], params: "Poseidon2Params") -> List[Fp]:
    """
    Poseidon2 permutation using numpy vectorization.

    Mathematically equivalent to permute() in permutation.py but ~6x faster.

    Args:
        state: Input state as Fp elements.
        params: Poseidon2 parameters.

    Returns:
        Output state as Fp elements.
    """
    if len(state) != params.width:
        raise ValueError(f"Input state must have length {params.width}")

    # Get or compute cached parameters
    key = id(params)
    if key not in _CACHE:
        _CACHE[key] = _precompute_params(params)
    p = _CACHE[key]

    width = p["width"]
    rounds_f = p["rounds_f"]
    rounds_p = p["rounds_p"]
    diag = p["diag"]
    rc = p["rc"]
    half_f = rounds_f // 2

    # Convert to numpy array
    s = np.array([fp.value for fp in state], dtype=np.int64)
    const_idx = 0

    # 1. Initial external layer
    s = _external_layer(s, width)

    # 2. First half of full rounds
    for _ in range(half_f):
        s = (s + rc[const_idx : const_idx + width]) % P
        const_idx += width
        s = _sbox(s)
        s = _external_layer(s, width)

    # 3. Partial rounds
    for _ in range(rounds_p):
        s[0] = (s[0] + rc[const_idx]) % P
        const_idx += 1
        s[0] = (s[0] * s[0] % P * s[0]) % P
        s = _internal_layer(s, diag)

    # 4. Second half of full rounds
    for _ in range(half_f):
        s = (s + rc[const_idx : const_idx + width]) % P
        const_idx += width
        s = _sbox(s)
        s = _external_layer(s, width)

    # Convert back to Fp objects
    return [Fp(value=int(x)) for x in s]
