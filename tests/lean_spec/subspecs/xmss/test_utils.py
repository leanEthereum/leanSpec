"""Tests for the utility functions in the XMSS signature scheme."""

import secrets
from typing import List

import pytest

from lean_spec.subspecs.koalabear.field import Fp, P
from lean_spec.subspecs.xmss.constants import TEST_CONFIG
from lean_spec.subspecs.xmss.prf import TEST_PRF
from lean_spec.subspecs.xmss.rand import TEST_RAND
from lean_spec.subspecs.xmss.subtree import HashSubTree
from lean_spec.subspecs.xmss.tweak_hash import TEST_TWEAK_HASHER
from lean_spec.subspecs.xmss.types import Parameter
from lean_spec.subspecs.xmss.utils import (
    expand_activation_time,
    int_to_base_p,
)
from lean_spec.types import Uint64


@pytest.mark.parametrize(
    "value, num_limbs, expected_values",
    [
        (0, 4, [0, 0, 0, 0]),
        (123, 4, [123, 0, 0, 0]),
        (P, 4, [0, 1, 0, 0]),
        (P - 1, 4, [P - 1, 0, 0, 0]),
        (3 * (P**2) + 2 * P + 1, 4, [1, 2, 3, 0]),
        (P**3 - 1, 3, [P - 1, P - 1, P - 1]),
    ],
)
def test_int_to_base_p(value: int, num_limbs: int, expected_values: List[int]) -> None:
    """Validates the base-P decomposition of an integer with known-answer tests."""
    # Convert the list of expected integer values to a list of Fp objects for comparison.
    expected_limbs = [Fp(value=v) for v in expected_values]
    # Perform the decomposition.
    actual_limbs = int_to_base_p(value, num_limbs)
    # Assert that the result matches the expected output.
    assert actual_limbs == expected_limbs


def test_int_to_base_p_roundtrip() -> None:
    """Ensures that the base-P decomposition is perfectly reversible."""
    # Create a large, random multi-limb integer.
    num_limbs = 5
    original_limbs = [secrets.randbelow(P) for _ in range(num_limbs)]
    original_value = sum(val * (P**i) for i, val in enumerate(original_limbs))

    # Decompose the integer into base-P limbs using the function under test.
    decomposed_limbs_fp = int_to_base_p(original_value, num_limbs)
    decomposed_limbs = [fp.value for fp in decomposed_limbs_fp]

    # Reconstruct the integer from the decomposed limbs.
    reconstructed_value = sum(val * (P**i) for i, val in enumerate(decomposed_limbs))

    # Assert that the original and reconstructed values are identical.
    assert original_value == reconstructed_value
    # Also assert that the original and decomposed limbs match.
    assert original_limbs == decomposed_limbs


@pytest.mark.parametrize(
    "log_lifetime, desired_activation, desired_num, expected_start_tree, expected_end_tree",
    [
        # Test case 1: Request falls on boundary, minimum duration
        (8, 0, 16, 0, 2),  # C = 16, requested [0, 16), aligned [0, 32) = 2 trees
        # Test case 2: Request needs rounding
        (8, 10, 5, 0, 2),  # C = 16, requested [10, 15), aligned [0, 32) = 2 trees
        # Test case 3: Larger request
        (8, 0, 100, 0, 7),  # C = 16, requested [0, 100), aligned [0, 112) = 7 trees
        # Test case 4: Request that exceeds lifetime
        (4, 0, 300, 0, 4),  # C = 4, LIFETIME = 16, clamped to [0, 16) = 4 trees
        # Test case 5: Request in middle
        (8, 32, 16, 2, 4),  # C = 16, requested [32, 48), aligned [32, 48) = 2 trees
    ],
)
def test_expand_activation_time(
    log_lifetime: int,
    desired_activation: int,
    desired_num: int,
    expected_start_tree: int,
    expected_end_tree: int,
) -> None:
    """Tests that expand_activation_time correctly aligns and expands activation intervals."""
    start_tree, end_tree = expand_activation_time(log_lifetime, desired_activation, desired_num)
    assert start_tree == expected_start_tree
    assert end_tree == expected_end_tree

    # Verify minimum duration constraint (at least 2 bottom trees)
    assert end_tree - start_tree >= 2

    # Verify alignment
    c = 1 << (log_lifetime // 2)
    actual_start_epoch = start_tree * c
    actual_end_epoch = end_tree * c
    assert actual_start_epoch % c == 0
    assert actual_end_epoch % c == 0

    # Verify it covers the desired range (if the desired range fits within lifetime)
    lifetime = c * c
    desired_end_epoch = desired_activation + desired_num
    if desired_end_epoch <= lifetime:
        assert actual_start_epoch <= desired_activation
        assert actual_end_epoch >= desired_end_epoch
    else:
        # If desired range exceeds lifetime, verify it's clamped to lifetime bounds
        assert actual_start_epoch >= 0
        assert actual_end_epoch <= lifetime


def test_hash_subtree_from_prf_key() -> None:
    """Tests that HashSubTree.from_prf_key generates a valid bottom tree."""
    config = TEST_CONFIG

    # Generate a PRF key
    prf_key = TEST_PRF.key_gen()

    # Generate a random parameter
    parameter = Parameter(
        data=[Fp(value=secrets.randbelow(P)) for _ in range(config.PARAMETER_LEN)]
    )

    # Generate bottom tree 0
    bottom_tree = HashSubTree.from_prf_key(
        prf=TEST_PRF,
        hasher=TEST_TWEAK_HASHER,
        rand=TEST_RAND,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(0),
        parameter=parameter,
    )

    # Verify structure
    assert bottom_tree.depth == Uint64(config.LOG_LIFETIME)
    assert bottom_tree.lowest_layer == Uint64(0)
    assert len(bottom_tree.layers) > 0

    # Verify the root layer has exactly one node
    root_layer = bottom_tree.layers.data[-1]
    assert len(root_layer.nodes) == 1

    # Verify the leaf layer covers the right range
    leafs_per_bottom_tree = 1 << (config.LOG_LIFETIME // 2)
    leaf_layer = bottom_tree.layers.data[0]
    assert len(leaf_layer.nodes) == leafs_per_bottom_tree


def test_hash_subtree_from_prf_key_deterministic() -> None:
    """Tests that HashSubTree.from_prf_key is deterministic."""
    config = TEST_CONFIG
    prf_key = TEST_PRF.key_gen()
    parameter = Parameter(
        data=[Fp(value=secrets.randbelow(P)) for _ in range(config.PARAMETER_LEN)]
    )

    # Generate the same bottom tree twice
    tree1 = HashSubTree.from_prf_key(
        prf=TEST_PRF,
        hasher=TEST_TWEAK_HASHER,
        rand=TEST_RAND,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(0),
        parameter=parameter,
    )

    tree2 = HashSubTree.from_prf_key(
        prf=TEST_PRF,
        hasher=TEST_TWEAK_HASHER,
        rand=TEST_RAND,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(0),
        parameter=parameter,
    )

    # Verify the roots are identical
    assert tree1.layers.data[-1].nodes[0] == tree2.layers.data[-1].nodes[0]


def test_hash_subtree_from_prf_key_different_indices() -> None:
    """Tests that different bottom tree indices produce different trees."""
    config = TEST_CONFIG
    prf_key = TEST_PRF.key_gen()
    parameter = Parameter(
        data=[Fp(value=secrets.randbelow(P)) for _ in range(config.PARAMETER_LEN)]
    )

    # Generate two different bottom trees
    tree0 = HashSubTree.from_prf_key(
        prf=TEST_PRF,
        hasher=TEST_TWEAK_HASHER,
        rand=TEST_RAND,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(0),
        parameter=parameter,
    )

    tree1 = HashSubTree.from_prf_key(
        prf=TEST_PRF,
        hasher=TEST_TWEAK_HASHER,
        rand=TEST_RAND,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(1),
        parameter=parameter,
    )

    # Verify the roots are different
    assert tree0.layers.data[-1].nodes[0] != tree1.layers.data[-1].nodes[0]
