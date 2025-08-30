"""
Implements the mathematical operations for hypercube layers.

This module provides the necessary functions to work with vertices in a
v-dimensional hypercube with coordinates in the range [0, w-1]. A key concept
is the partitioning of the hypercube's vertices into "layers". A vertex belongs
to layer `d`, where `d` is its distance from the sink vertex `(w-1, ..., w-1)`.

The core functionalities are:
1.  **Precomputation and Caching**: Efficiently calculates and caches the sizes
    of each layer for different hypercube configurations (`w` and `v`).
2.  **Mapping**: Provides bijective mappings between an integer index within a
    layer and the unique vertex (a list of coordinates) it represents.

This logic is a direct translation of the algorithms described in the paper
"At the top of the hypercube" (eprint 2025/889)
and the reference Rust implementation: https://github.com/b-wagn/hash-sig.
"""

from __future__ import annotations

import bisect
from functools import lru_cache
from typing import List, Tuple

from pydantic import BaseModel, ConfigDict

MAX_DIMENSION = 100
"""The maximum dimension `v` for which layer sizes will be precomputed."""


class LayerInfo(BaseModel):
    """
    Stores the precomputed sizes and cumulative sums for a
    hypercube's layers.
    """

    model_config = ConfigDict(frozen=True)
    sizes: List[int]
    """The number of vertices in each layer `d`."""
    prefix_sums: List[int]
    """
    The cumulative number of vertices up to and including layer `d`.

    `prefix_sums[d] = sizes[0] + ... + sizes[d]`.
    """

    def sizes_sum_in_range(self, start: int, end: int) -> int:
        """Calculates the sum of sizes in an inclusive range [start, end]."""
        if start > end:
            return 0
        if start == 0:
            return self.prefix_sums[end]
        else:
            return self.prefix_sums[end] - self.prefix_sums[start - 1]


@lru_cache(maxsize=None)
def prepare_layer_info(w: int) -> List[LayerInfo]:
    """
    Precomputes and caches the number of vertices in each layer of a hypercube.

    This function is a crucial precomputation step for the mapping algorithms
    used in the "Top Level Target Sum" encoding.
    It calculates the size of every layer for hypercubes with a given
    base `w` (where coordinates are in `[0, w-1]`) for all dimensions
    `v` up to `MAX_DIMENSION`.

    The calculation is inductive: the layer sizes for a `v`-dimensional
    hypercube are efficiently derived from the already-computed sizes
    of a `(v-1)`-dimensional hypercube, based on the recurrence relation from
    Lemma 8 of the paper "At the top of the hypercube" (eprint 2025/889).

    Args:
        w: The base of the hypercube.

    Returns:
        A list where the element at index `v` is a `LayerInfo` object
        containing the layer sizes for a `v`-dimensional hypercube.
    """
    # Initialize a list to store the results for each dimension `v`.
    #
    # Index 0 is unused to allow for direct indexing, e.g., `all_info[v]`.
    all_info = [LayerInfo(sizes=[], prefix_sums=[])] * (MAX_DIMENSION + 1)

    # BASE CASE
    #
    # For a 1-dimensional hypercube (v=1), which is just a line of `w` points
    # with coordinates [0], [1], ..., [w-1].
    # The distance `d` from the sink `[w-1]` is simply `(w-1) - coordinate`.

    # Each of the `w` possible layers contains exactly one vertex.
    dim1_sizes = [1] * w
    # The prefix sums (cumulative sizes) are therefore just [1, 2, 3, ..., w].
    dim1_prefix_sums = list(range(1, w + 1))
    # Store the result for v=1, which will seed the inductive step.
    all_info[1] = LayerInfo(sizes=dim1_sizes, prefix_sums=dim1_prefix_sums)

    # INDUCTIVE STEP
    #
    # Now, build the layer info for all higher dimensions up to the maximum.
    for v in range(2, MAX_DIMENSION + 1):
        # The maximum possible distance `d` in a v-dimensional hypercube.
        max_d = (w - 1) * v
        # Retrieve the already-computed data for the previous dimension (v-1).
        prev_layer_info = all_info[v - 1]

        # This list will store the computed size of each layer `d`
        # for dimension `v`.
        current_sizes: List[int] = []
        for d in range(max_d + 1):
            # Implements the recurrence l_d(v) = Σ l_{d-j}(v-1) from the paper.
            # `j` is one coordinate's distance contribution.

            # Calculate the valid range [j_min, j_max] for `j`.
            j_min = max(0, d - (w - 1) * (v - 1))
            j_max = min(w - 1, d)

            # Translate the sum over `j` to an index range `k`,
            # where k = d - j.
            # This allows for an efficient lookup using prefix sums.
            k_min = d - j_max
            k_max = d - j_min

            # Efficiently calculate the sum using the precomputed prefix sums
            # from the previous dimension's `LayerInfo`.
            layer_size = prev_layer_info.sizes_sum_in_range(k_min, k_max)
            current_sizes.append(layer_size)

        # After computing all layer sizes for dimension `v`, we compute their
        # prefix sums.
        # This is needed for the *next* iteration (for dimension v+1).
        current_prefix_sums: List[int] = []
        current_sum = 0
        for size in current_sizes:
            current_sum += size
            current_prefix_sums.append(current_sum)

        # Store the complete layer info for the current dimension `v`.
        all_info[v] = LayerInfo(
            sizes=current_sizes, prefix_sums=current_prefix_sums
        )

    # Return the complete table of layer information for the given base `w`.
    return all_info


def get_layer_size(w: int, v: int, d: int) -> int:
    """Returns the size of a specific layer `d` in a `(w, v)` hypercube."""
    return prepare_layer_info(w)[v].sizes[d]


def get_hypercube_part_size(w: int, v: int, d: int) -> int:
    """Returns the total size of layers 0 to `d` (inclusive)."""
    return prepare_layer_info(w)[v].prefix_sums[d]


def find_layer(w: int, v: int, x: int) -> Tuple[int, int]:
    """
    Given a global index `x`, finds the layer `d` it belongs to and its
    local index (`remainder`) within that layer.

    Args:
        w: The hypercube base.
        v: The hypercube dimension.
        x: The global index of a vertex (from 0 to w**v - 1).

    Returns:
        A tuple `(d, remainder)`.
    """
    prefix_sums = prepare_layer_info(w)[v].prefix_sums
    # Use binary search to efficiently find the correct layer.
    d = bisect.bisect_left(prefix_sums, x + 1)

    if d == 0:
        remainder = x
    else:
        remainder = x - prefix_sums[d - 1]

    return d, remainder


def map_to_vertex(w: int, v: int, d: int, x: int) -> List[int]:
    """
    Maps an integer index `x` to a unique vertex in a specific hypercube layer.

    This function provides a bijective mapping from an integer `x`
    (derived from a hash) to a unique list of `v` coordinates,
    `[a_0, ..., a_{v-1}]`.

    The algorithm works iteratively, determining one coordinate at a time.

    Args:
        w: The hypercube base (coordinates are in `[0, w-1]`).
        v: The hypercube dimension (the number of coordinates).
        d: The target layer, defined by its distance from the sink vertex.
        x: The integer index within the layer `d`, must be `0 <= x < size(d)`.

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

        # This loop finds which block of sub-hypercubes the index `x_curr`
        # falls into.
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
                ji = j  # Found the correct block.
                break

        if ji == -1:
            raise RuntimeError(
                "Internal logic error: failed to find coordinate"
            )

        # Convert the block's distance contribution `ji` to a coordinate `ai`.
        ai = w - 1 - ji
        vertex.append(ai)

        # Update the remaining distance for the next, smaller subproblem.
        d_curr -= ji

    # The final coordinate is uniquely determined by the remaining values.
    last_coord = w - 1 - x_curr - d_curr
    vertex.append(last_coord)

    return vertex
