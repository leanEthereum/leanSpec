"""
Implements the mathematical operations for hypercube-based encodings.

This module provides the core algorithms for working with vertices in a
v-dimensional hypercube where coordinates are in the range [0, w-1]. This is a
foundational component for the "Top of the Hypercube" signature schemes.

Core Concepts
-------------
1.  **Hypercube (`[w]^v`)**: The set of all possible coordinate vectors for a
    signature. The dimension `v` corresponds to the number of hash chains (and
    thus signature size), and the base `w` corresponds to the length of each
    hash chain.

2.  **Layers (`d`)**: The hypercube's vertices are partitioned into "layers" based
    on their **verification cost**. The layer `d` of a vertex is its distance
    from the sink vertex `(w-1, ..., w-1)`, calculated as:
    `d = (w-1)*v - sum(coordinates)`.
    A smaller `d` means a lower verification cost, making these "top layers"
    the most desirable for encoding messages into.

3.  **Mapping Problem**: The central challenge is to deterministically and
    efficiently map a single integer (derived from a message hash) to a unique
    coordinate vector within a specific layer or a set of top layers. This
    module provides the building blocks for that mapping.

This logic is a direct translation of the algorithms described in the paper
"At the top of the hypercube" (eprint 2025/889)
and the reference Rust implementation: https://github.com/b-wagn/hash-sig.
"""

from __future__ import annotations

import bisect
import math
from functools import lru_cache
from itertools import accumulate
from typing import List, Tuple

from pydantic import BaseModel, ConfigDict

MAX_DIMENSION = 100
"""The maximum dimension `v` for which layer sizes will be precomputed."""


class LayerInfo(BaseModel):
    """
    A data structure to store precomputed sizes and cumulative sums for the
    layers of a single hypercube configuration (fixed `w` and `v`).

    This object makes subsequent calculations, like finding the total size of a
    range of layers, highly efficient.
    """

    model_config = ConfigDict(frozen=True)
    sizes: List[int]
    """A list where `sizes[d]` is the number of vertices in layer `d`."""
    prefix_sums: List[int]
    """
    A list where `prefix_sums[d]` is the cumulative number of vertices from
    layer 0 up to and including layer `d`.

    Mathematically: `prefix_sums[d] = sizes[0] + ... + sizes[d]`.
    """

    def sizes_sum_in_range(self, start: int, end: int) -> int:
        """
        Calculates the sum of `sizes` in an inclusive range [start, end].

        This is an O(1) operation thanks to the precomputed `prefix_sums`.
        """
        # If the range is invalid, the sum is zero.
        if start > end:
            return 0
        # If the range starts from the beginning, the sum is simply the
        # prefix sum at the end of the range.
        if start == 0:
            return self.prefix_sums[end]
        # Otherwise, the sum is the difference between the prefix sum at the
        # end and the prefix sum of the elements just before the start.
        else:
            return self.prefix_sums[end] - self.prefix_sums[start - 1]


def _calculate_layer_size(w: int, v: int, d: int) -> int:
    """
    Calculates a hypercube layer's size using a direct combinatorial formula.

    This function answers the question: "How many unique coordinate vectors
    (vertices) exist in a specific layer `d`?"

    The problem is mathematically equivalent to finding the number of integer
    solutions to the equation:
        x_1 + x_2 + ... + x_v = k
    subject to the constraint that each coordinate `x_i` is in the range
    `0 <= x_i <= w-1`. The required sum `k` is derived from the layer's
    distance `d`.

    The solution uses two key combinatorial techniques:
    1.  **Stars and Bars**: To find the number of solutions without the
        upper-bound constraint (`x_i <= w-1`).

    2.  **Inclusion-Exclusion Principle**: To correct the count by systematically
        adding and subtracting the solutions that violate the upper bound.

    Args:
        w: The hypercube base (coordinates are `0` to `w-1`).
        v: The hypercube dimension (number of coordinates).
        d: The target layer's distance from the sink vertex `(w-1, ..., w-1)`.

    Returns:
        The total number of vertices in the specified layer.
    """
    # A vertex is in layer `d` if its coordinates sum to `k = v * (w - 1) - d`.
    #
    # This `coord_sum` is the `k` in our combinatorial problem.
    coord_sum = v * (w - 1) - d

    # This is the compact implementation of the inclusion-exclusion principle.
    #
    # It directly calculates the sum: Σ (-1)^s * C(v,s) * C(k - s*w + v-1, v-1)
    return sum(
        ((-1) ** s) * math.comb(v, s) * math.comb(coord_sum - s * w + v - 1, v - 1)
        for s in range(coord_sum // w + 1)
    )


@lru_cache(maxsize=None)
def prepare_layer_info(w: int) -> List[LayerInfo]:
    """
    Precomputes and caches layer information using a direct combinatorial formula.

    For each dimension `v` up to `MAX_DIMENSION`, this function calculates the
    size of every layer `d` directly, without relying on the results from
    smaller dimensions. While less computationally efficient than the recursive
    method, this implementation is more concise and mathematically direct.

    Args:
        w: The base of the hypercube.

    Returns:
        A list where `list[v]` is a `LayerInfo` object for a `v`-dim hypercube.
    """
    all_info = [LayerInfo(sizes=[], prefix_sums=[])] * (MAX_DIMENSION + 1)

    for v in range(1, MAX_DIMENSION + 1):
        # The maximum possible distance `d` in a v-dimensional hypercube.
        max_d = (w - 1) * v

        # Directly compute the size of each layer using the helper function.
        sizes = [_calculate_layer_size(w, v, d) for d in range(max_d + 1)]

        # Compute the cumulative sums from the list of sizes.
        prefix_sums = list(accumulate(sizes))

        # Store the complete layer info for the current dimension `v`.
        all_info[v] = LayerInfo(sizes=sizes, prefix_sums=prefix_sums)

    return all_info


def get_layer_size(w: int, v: int, d: int) -> int:
    """Returns the size of a specific layer `d` in a `(w, v)` hypercube."""
    return prepare_layer_info(w)[v].sizes[d]


def hypercube_part_size(w: int, v: int, d: int) -> int:
    """Returns the total size of layers 0 to `d` (inclusive)."""
    return prepare_layer_info(w)[v].prefix_sums[d]


def hypercube_find_layer(w: int, v: int, x: int) -> Tuple[int, int]:
    """
    Given a global index `x`, finds its layer `d` and local offset `remainder`.

    This function determines which "layer bucket" a global index falls into.

    Args:
        w: The hypercube base.
        v: The hypercube dimension.
        x: The global index of a vertex, from 0 to (w**v - 1).

    Returns:
        A tuple `(d, remainder)`, where `d` is the layer and `remainder` is
        the local index (offset) of the vertex within that layer.
    """
    prefix_sums = prepare_layer_info(w)[v].prefix_sums
    # Use binary search to efficiently find the correct layer.
    d = bisect.bisect_left(prefix_sums, x + 1)

    if d == 0:
        # `x` is in the very first layer (d=0).
        #
        # The remainder is `x` itself, as the cumulative size of
        # preceding layers is zero.
        remainder = x
    else:
        # The cumulative size of all layers up to `d-1` is
        # at `prefix_sums[d - 1]`.
        #
        # The remainder is `x` minus this cumulative size.
        remainder = x - prefix_sums[d - 1]

    return d, remainder


def map_to_vertex(w: int, v: int, d: int, x: int) -> List[int]:
    """
    Maps an integer index `x` to a unique vertex in a specific hypercube layer.

    This function provides a bijective mapping from a location `(d, x)` to a
    unique coordinate vector `[a_0, ..., a_{v-1}]`. The algorithm works
    iteratively, determining one coordinate at a time by reducing the problem
    to a smaller subproblem in a hypercube of one less dimension.

    Args:
        w: The hypercube base (coordinates are in `[0, w-1]`).
        v: The hypercube dimension (the number of coordinates).
        d: The target layer, defined by its distance from the sink vertex.
        x: The integer index (offset) within layer `d`. Must be `0 <= x < size(d)`.

    Returns:
        A list of `v` integers representing the coordinates of the vertex.
    """
    layer_info_cache = prepare_layer_info(w)

    # Validate that the input index `x` is valid for the target layer.
    layer_size = layer_info_cache[v].sizes[d]
    if x >= layer_size:
        raise ValueError("Index x is out of bounds for the given layer.")

    vertex: List[int] = []
    # Track remaining distance and index.
    d_curr, x_curr = d, x

    # Determine each of the first v-1 coordinates iteratively.
    for i in range(1, v):
        dim_remaining = v - i
        prev_dim_layer_info = layer_info_cache[dim_remaining]

        # This loop finds which block of sub-hypercubes the index `x_curr` falls into.
        #
        # It skips over full blocks by subtracting their size
        # from `x_curr` until the correct one is found.
        ji = -1  # Sentinel value
        range_start = max(0, d_curr - (w - 1) * dim_remaining)
        for j in range(range_start, min(w, d_curr + 1)):
            count = prev_dim_layer_info.sizes[d_curr - j]
            if x_curr >= count:
                x_curr -= count
            else:
                # Found the correct block.
                ji = j
                break

        if ji == -1:
            raise RuntimeError("Internal logic error: failed to find coordinate")

        # Convert the block's distance contribution `ji` to a coordinate `ai`.
        ai = w - 1 - ji
        vertex.append(ai)

        # Update the remaining distance for the next, smaller subproblem.
        d_curr -= ji

    # The final coordinate is uniquely determined by the remaining values.
    last_coord = w - 1 - x_curr - d_curr
    vertex.append(last_coord)

    return vertex
