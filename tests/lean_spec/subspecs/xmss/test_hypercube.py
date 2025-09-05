"""Tests for the hypercube mathematical operations."""

import math
from functools import lru_cache
from typing import List

import pytest

from lean_spec.subspecs.xmss.hypercube import (
    MAX_DIMENSION,
    get_layer_size,
    hypercube_find_layer,
    hypercube_part_size,
    map_to_vertex,
    prepare_layer_info,
)


def map_to_integer(w: int, v: int, d: int, a: List[int]) -> int:
    """
    Maps a vertex `a` in layer `d` back to its integer index.

    This is a direct translation of the reference Rust implementation.
    """
    if len(a) != v:
        raise ValueError("Vertex length must equal dimension v.")

    layer_info_cache = prepare_layer_info(w)
    x_curr = 0

    # Initialize `d_curr` with the distance contribution
    # of the last coordinate.
    d_curr = (w - 1) - a[v - 1]

    # Loop backwards from the second-to-last coordinate to the first.
    for i in range(v - 2, -1, -1):
        ji = (w - 1) - a[i]
        d_curr += ji

        # Dimension of the subproblem at this stage.
        rem_dim = v - 1 - i
        prev_dim_layer_info = layer_info_cache[rem_dim]

        # Calculate the start of the summation range for the subproblem.
        j_start = max(0, d_curr - (w - 1) * rem_dim)

        # Add the sizes of all blocks that come before the current one.
        sum_start = d_curr - (ji - 1)
        sum_end = d_curr - j_start
        x_curr += prev_dim_layer_info.sizes_sum_in_range(sum_start, sum_end)

    # At the end, the incrementally built distance must
    # equal the target distance.
    assert d_curr == d

    # The final accumulated value is the index.
    return x_curr


@lru_cache(maxsize=None)
def _binom(n: int, k: int) -> int:
    """A cached binomial coefficient calculator (n choose k)."""
    if k < 0 or k > n:
        return 0
    return math.comb(n, k)


def _nb(k: int, m: int, n: int) -> int:
    """
    Computes the number of integer vectors of dimension `n` with entries in
    [0, m] that sum to `k`. This is equivalent to the coefficient of x^k in
    the polynomial (1 + x + ... + x^m)^n.
    """
    total = 0
    for s in range(k // (m + 1) + 1):
        term = _binom(n, s) * _binom(k - s * (m + 1) + n - 1, n - 1)
        if s % 2 == 0:
            total += term
        else:
            total -= term
    return total


def _prepare_layer_sizes_by_binom(w: int) -> list[list[int]]:
    """
    A reference implementation to calculate layer sizes using binomial
    coefficients. It's slower but simpler, making it good for validation.
    """
    all_layers: List[List[int]] = [[] for _ in range(MAX_DIMENSION + 1)]
    for v in range(1, MAX_DIMENSION + 1):
        max_distance = (w - 1) * v
        layer_sizes: List[int] = []
        for d in range(max_distance + 1):
            # The sum of coordinates is `k = v * (w - 1) - d`.
            # We need to find the number of ways to write `k` as a sum of `v`
            # integers, each between 0 and `w-1`.
            coord_sum = v * (w - 1) - d
            layer_sizes.append(_nb(coord_sum, w - 1, v))
        all_layers[v] = layer_sizes
    return all_layers


def test_prepare_layer_sizes_against_reference() -> None:
    """
    Validates the optimized `prepare_layer_info` against the slower,
    math-based reference implementation for a range of `w` values.
    """
    for w in range(2, 7):
        expected_sizes_by_v = _prepare_layer_sizes_by_binom(w)
        actual_info_by_v = prepare_layer_info(w)

        for v in range(1, MAX_DIMENSION + 1):
            # Note: The reference implementation returns reversed layer sizes.
            # Layer `d` in our spec corresponds to sum `k = v*(w-1) - d`.
            expected_sizes_reordered = list(reversed(expected_sizes_by_v[v]))
            actual_sizes = actual_info_by_v[v].sizes
            assert expected_sizes_reordered == actual_sizes


@pytest.mark.parametrize(
    "w, v, d, expected_size",
    [
        (2, 1, 0, 1),
        (2, 1, 1, 2),
        (3, 2, 0, 1),
        (3, 2, 1, 3),
        (3, 2, 2, 6),
        (3, 2, 3, 8),
        (3, 2, 4, 9),
        (2, 3, 0, 1),
        (2, 3, 1, 4),
        (2, 3, 2, 7),
        (2, 3, 3, 8),
    ],
)
def test_get_hypercube_part_size(w: int, v: int, d: int, expected_size: int) -> None:
    """
    Tests `hypercube_part_size` with known values from the Rust tests.
    """
    assert hypercube_part_size(w, v, d) == expected_size


def test_find_layer_boundaries() -> None:
    """
    Tests `hypercube_find_layer` with specific boundary-crossing values.
    """
    w, v = 3, 2
    # Layer sizes for (w=3, v=2) are [1, 2, 3, 2, 1]
    # Prefix sums are [1, 3, 6, 8, 9]

    # x=0 is the 1st element, which is in layer 0. Remainder is 0.
    assert hypercube_find_layer(w, v, 0) == (0, 0)
    # x=1 is the 2nd element, which is the 1st element in layer 1.
    # Remainder is 0.
    assert hypercube_find_layer(w, v, 1) == (1, 0)
    # x=2 is the 3rd element, which is the 2nd element in layer 1.
    # Remainder is 1.
    assert hypercube_find_layer(w, v, 2) == (1, 1)
    # x=3 is the 4th element, which is the 1st element in layer 2.
    # Remainder is 0.
    assert hypercube_find_layer(w, v, 3) == (2, 0)
    # x=5 is the 6th element, which is the third (last) element in layer 3.
    # Remainder is 2.
    assert hypercube_find_layer(w, v, 5) == (2, 2)
    # x=6 is the 7th element, which is the first element in layer 3.
    # Remainder is 0.
    assert hypercube_find_layer(w, v, 6) == (3, 0)
    # x=8 is the 9th element, which is the 1st element in layer 4.
    # Remainder is 0.
    assert hypercube_find_layer(w, v, 8) == (4, 0)


def test_map_to_vertex_roundtrip() -> None:
    """
    Tests the map_to_vertex and map_to_integer roundtrip for a small case.
    This test is slow and only checks a limited range.
    """
    w, v, d = 4, 8, 20
    max_x = get_layer_size(w, v, d)

    # Iterate through every possible index in a specific layer
    # and check roundtrip
    for x in range(min(max_x, 100)):  # Capped at 100 iterations to keep test fast
        vertex = map_to_vertex(w, v, d, x)

        # Check that the vertex sum corresponds to the correct layer
        coord_sum = sum(vertex)
        assert (w - 1) * v - coord_sum == d

        # Check that mapping back gives the original index
        x_reconstructed = map_to_integer(w, v, d, vertex)
        assert x_reconstructed == x


def test_big_map() -> None:
    """
    Tests the full map_to_vertex -> map_to_integer roundtrip with a very
    large number, exactly replicating the Rust reference test.
    """
    w, v, d = 12, 40, 174
    x = 21790506781852242898091207809690042074412

    # Map the integer to a vertex.
    vertex_a = map_to_vertex(w, v, d, x)

    # Map the vertex back to an integer.
    x_reconstructed = map_to_integer(w, v, d, vertex_a)

    # Map the reconstructed integer back to a vertex again.
    vertex_b = map_to_vertex(w, v, d, x_reconstructed)

    # Assert that both steps of the roundtrip were successful.
    assert x == x_reconstructed
    assert vertex_a == vertex_b
