"""Unit tests for SSZ utility functions."""

import hashlib

import pytest

from lean_spec.subspecs.ssz.utils import get_power_of_two_ceil, hash_nodes
from lean_spec.types.byte_arrays import Bytes32


@pytest.mark.parametrize(
    "x, expected",
    [
        (0, 1),  # Edge case: 0 should result in 1
        (1, 1),  # A power of two
        (2, 2),  # A power of two
        (3, 4),  # A number between powers of two
        (4, 4),  # A power of two
        (5, 8),
        (7, 8),
        (8, 8),
        (9, 16),
        (1023, 1024),
        (1024, 1024),  # A larger power of two
    ],
)
def test_get_power_of_two_ceil(x: int, expected: int) -> None:
    """
    Tests that get_power_of_two_ceil correctly finds the next highest
    power of two for a range of inputs.
    """
    assert get_power_of_two_ceil(x) == expected


def test_hash_nodes() -> None:
    """
    Tests that hash_nodes correctly computes the SHA-256 hash of two concatenated nodes.
    """
    # Define two known 32-byte nodes.
    node_a = Bytes32((1).to_bytes(32, "little"))
    node_b = Bytes32((2).to_bytes(32, "little"))

    # Manually compute the expected hash using the standard library.
    expected_digest = hashlib.sha256(node_a + node_b).digest()
    expected_hash = Bytes32(expected_digest)

    # Call the function and assert that the result matches the expected hash.
    assert hash_nodes(node_a, node_b) == expected_hash


def test_hash_nodes_with_zero() -> None:
    """
    Tests hashing a node with a zero-hash node to ensure correctness.
    """
    # Define a node and a zero node.
    node_a = Bytes32((42).to_bytes(32, "little"))
    zero_node = Bytes32(b"\x00" * 32)

    # Manually compute the expected hash.
    expected_digest = hashlib.sha256(node_a + zero_node).digest()
    expected_hash = Bytes32(expected_digest)

    # Assert the function's output is correct.
    assert hash_nodes(node_a, zero_node) == expected_hash
