"""Tests for the hypercube mathematical operations."""

import itertools
import math
from functools import lru_cache
from typing import Any, Callable, List, Tuple

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

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


# ---------------------------
# Hypothesis property tests
# ---------------------------

DrawFn = Callable[[Any], Any]


# Strategy for small hypercubes where we can feasibly enumerate
@st.composite
def small_hypercube(draw: DrawFn) -> Tuple[int, int]:
    w = draw(st.integers(min_value=2, max_value=6))
    v = draw(st.integers(min_value=1, max_value=6))
    assume(w**v <= 6000)  # keep enumeration feasible
    return w, v


@st.composite
def small_hypercube_with_layer_and_index(draw: DrawFn) -> Tuple[int, int, int, int]:
    w = draw(st.integers(min_value=2, max_value=6))
    v = draw(st.integers(min_value=1, max_value=6))
    assume(w**v <= 6000)
    info = prepare_layer_info(w)[v]
    d = draw(st.integers(min_value=0, max_value=len(info.sizes) - 1))
    size = info.sizes[d]
    assume(size > 0)
    x = draw(st.integers(min_value=0, max_value=size - 1))
    return w, v, d, x


# Strategies for two distinct vertices in a layer
@st.composite
def two_distinct_index(draw: DrawFn) -> Tuple[int, int, int, int, int]:
    w = draw(st.integers(2, 6))
    v = draw(st.integers(1, 6))
    assume(w**v <= 6000)
    info = prepare_layer_info(w)[v]
    # pick layer with size >= 2
    candidates = [d for d, s in enumerate(info.sizes) if s >= 2]
    assume(candidates)
    d = draw(st.sampled_from(candidates))
    s = info.sizes[d]
    x1 = draw(st.integers(0, s - 1))
    x2 = draw(st.integers(0, s - 1))
    assume(x2 != x1)
    return w, v, d, x1, x2


@given(small_hypercube())
@settings(max_examples=120)
def test_property_layer_sizes_conservation_monotonicity(wv: Tuple[int, int]) -> None:
    """All vertices should be accounted for and prefix sums monotone."""
    w, v = wv
    info = prepare_layer_info(w)[v]
    # conservation
    assert info.prefix_sums[-1] == w**v
    assert sum(info.sizes) == w**v
    # non-negative sizes
    assert all(s >= 0 for s in info.sizes)
    # monotone prefix sums
    assert all(
        info.prefix_sums[i] <= info.prefix_sums[i + 1] for i in range(len(info.prefix_sums) - 1)
    )


@given(small_hypercube_with_layer_and_index())
@settings(max_examples=200)
def test_property_map_vertex_roundtrip(params: Tuple[int, int, int, int]) -> None:
    """Tests that map_to_vertex returns valid coords in layer d and
    map_to_integer inverts it correctly."""
    w, v, d, x = params
    vertex = map_to_vertex(w, v, d, x)
    assert isinstance(vertex, list) and len(vertex) == v
    assert all(0 <= ai < w for ai in vertex)
    # membership in layer
    coord_sum = sum(vertex)
    assert (w - 1) * v - coord_sum == d
    # roundtrip via existing map_to_integer
    x_reconstructed = map_to_integer(w, v, d, vertex)
    assert x_reconstructed == x


@given(small_hypercube())
@settings(max_examples=40, deadline=None)
def test_property_bijectivity_enum(wv: Tuple[int, int]) -> None:
    """For tiny hypercubes, map_to_vertex enumerates exactly
    w**v distinct vertices."""
    w, v = wv
    assume(w**v <= 2000)  # extra safety
    info = prepare_layer_info(w)[v]
    seen = set()
    for d, size in enumerate(info.sizes):
        for x in range(size):
            a = tuple(map_to_vertex(w, v, d, x))
            assert len(a) == v
            seen.add(a)
    assert len(seen) == w**v


@given(small_hypercube())
@settings(max_examples=80)
def test_property_map_oob(wv: Tuple[int, int]) -> None:
    """map_to_vertex should raise ValueError when x is equal
    to the layer size (out-of-range)."""
    w, v = wv
    info = prepare_layer_info(w)[v]
    for d, size in enumerate(info.sizes):
        if size > 0:
            with pytest.raises(ValueError):
                map_to_vertex(w, v, d, size)
            break


@given(small_hypercube())
@settings(max_examples=120, deadline=None)
def test_property_find_layer_prefix(wv: Tuple[int, int]) -> None:
    """hypercube_find_layer returns (d, r) consistent with
    prefix sums and global index."""
    w, v = wv
    info = prepare_layer_info(w)[v]
    total = w**v
    candidates = {0, 1, total - 1, total // 2}
    for x in candidates:
        if not (0 <= x < total):
            continue
        d, r = hypercube_find_layer(w, v, x)
        assert 0 <= d < len(info.sizes)
        assert 0 <= r < info.sizes[d]
        prev = info.prefix_sums[d - 1] if d > 0 else 0
        assert prev + r == x


@given(two_distinct_index())
@settings(max_examples=200)
def test_property_layer_injectivity(params: Tuple[int, int, int, int, int]) -> None:
    """Ensure injectivity inside a layer for map_to_vertex.
    This is a randomized test: we pick two distinct indices
    and assert their mapped vertices differ."""
    w, v, d, x1, x2 = params
    a1 = map_to_vertex(w, v, d, x1)
    a2 = map_to_vertex(w, v, d, x2)
    assert a1 != a2
