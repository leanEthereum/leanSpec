"""Generic helper functions for SSZ and Merkle proofs."""

import hashlib

from lean_spec.types.byte_arrays import Bytes32


def get_power_of_two_ceil(x: int) -> int:
    """
    Calculates the smallest power of two greater than or equal to x.

    Examples: 0->1, 1->1, 2->2, 3->4, 4->4, 5->8.
    """
    if x <= 1:
        return 1
    return 1 << (x - 1).bit_length()


def hash_nodes(node_a: Bytes32, node_b: Bytes32) -> Bytes32:
    """Hashes two 32-byte nodes together using SHA-256."""
    return Bytes32(hashlib.sha256(node_a + node_b).digest())
