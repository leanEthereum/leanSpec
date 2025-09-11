"""Tests for the GeneralizedIndex class."""

import pytest
from pydantic import ValidationError
from typing_extensions import Any

from lean_spec.subspecs.ssz.merkle_proof.gindex import GeneralizedIndex


def test_pydantic_validation_accepts_valid_int() -> None:
    """Tests that Pydantic validation correctly accepts a valid positive integer."""
    instance = GeneralizedIndex(value=10)
    assert isinstance(instance, GeneralizedIndex)
    assert instance.value == 10


@pytest.mark.parametrize("invalid_value", [0, -1, -100])
def test_pydantic_validation_rejects_non_positive_int(invalid_value: int) -> None:
    """Tests that Pydantic validation rejects zero and negative integers."""
    with pytest.raises(ValidationError):
        GeneralizedIndex(value=invalid_value)


@pytest.mark.parametrize(
    "invalid_type",
    [1.0, "1", True, False, b"1", None],
)
def test_pydantic_validation_rejects_invalid_types(invalid_type: Any) -> None:
    """Tests that Pydantic's strict integer validation rejects non-integer types."""
    with pytest.raises(ValidationError):
        GeneralizedIndex(value=invalid_type)


@pytest.mark.parametrize(
    "value, expected_depth",
    [
        (1, 0),
        (2, 1),
        (3, 1),
        (4, 2),
        (5, 2),
        (6, 2),
        (7, 2),
        (13, 3),
        (31, 4),
    ],
)
def test_depth_property(value: int, expected_depth: int) -> None:
    """Tests that the `depth` property is calculated correctly."""
    index = GeneralizedIndex(value=value)
    assert index.depth == expected_depth


@pytest.mark.parametrize(
    "index_value, bit_position, expected_bool",
    [
        (13, 0, True),  # 1101 -> bit 0 is 1
        (13, 1, False),  # 1101 -> bit 1 is 0
        (13, 2, True),  # 1101 -> bit 2 is 1
        (13, 3, True),  # 1101 -> bit 3 is 1
        (13, 4, False),  # Out of bounds
        (1, 0, True),
        (1, 1, False),
    ],
)
def test_get_bit_method(index_value: int, bit_position: int, expected_bool: bool) -> None:
    """Tests the `get_bit` method for various positions."""
    index = GeneralizedIndex(value=index_value)
    assert index.get_bit(bit_position) is expected_bool


@pytest.mark.parametrize(
    "value, expected_sibling_value",
    [
        (2, 3),  # Left node
        (3, 2),  # Right node
        (10, 11),  # Left node
        (11, 10),  # Right node
    ],
)
def test_sibling_property(value: int, expected_sibling_value: int) -> None:
    """Tests that the `sibling` property correctly flips the last bit."""
    index = GeneralizedIndex(value=value)
    sibling = index.sibling
    assert isinstance(sibling, GeneralizedIndex)
    assert sibling.value == expected_sibling_value


def test_sibling_of_root_is_invalid() -> None:
    """
    Tests that getting the sibling of the root (value=1) produces a GeneralizedIndex
    with value=0, which will fail Pydantic's validation upon creation.
    """
    with pytest.raises(ValidationError, match="Input should be greater than 0"):
        _ = GeneralizedIndex(value=1).sibling


@pytest.mark.parametrize(
    "value, expected_parent_value",
    [
        (2, 1),
        (3, 1),
        (10, 5),
        (11, 5),
        (15, 7),
    ],
)
def test_parent_property(value: int, expected_parent_value: int) -> None:
    """Tests that the `parent` property is calculated correctly."""
    index = GeneralizedIndex(value=value)
    parent = index.parent
    assert isinstance(parent, GeneralizedIndex)
    assert parent.value == expected_parent_value


def test_parent_of_root_raises_error() -> None:
    """Tests that getting the parent of the root node (value=1) raises a ValueError."""
    root = GeneralizedIndex(value=1)
    with pytest.raises(ValueError, match="Root node has no parent."):
        _ = root.parent


@pytest.mark.parametrize(
    "value, expected_indices_values",
    [
        (13, [12, 7, 2]),  # Path: 13 -> 6 -> 3 -> 1
        (8, [9, 5, 3]),  # Path: 8 -> 4 -> 2 -> 1
        (15, [14, 6, 2]),  # Path: 15 -> 7 -> 3 -> 1
        (2, [3]),
        (3, [2]),
        (1, []),  # Root node has no branch
    ],
)
def test_get_branch_indices(value: int, expected_indices_values: list[int]) -> None:
    """Tests the `get_branch_indices` method."""
    index = GeneralizedIndex(value=value)
    branch_indices = index.get_branch_indices()

    # Extract the integer values from the result for comparison
    result_values = [idx.value for idx in branch_indices]

    assert result_values == expected_indices_values


@pytest.mark.parametrize(
    "value, expected_indices_values",
    [
        (13, [13, 6, 3]),
        (8, [8, 4, 2]),
        (15, [15, 7, 3]),
        (2, [2]),
        (1, []),  # Root node has no path (excluding itself)
    ],
)
def test_get_path_indices(value: int, expected_indices_values: list[int]) -> None:
    """Tests the `get_path_indices` method."""
    index = GeneralizedIndex(value=value)
    path_indices = index.get_path_indices()

    # Extract the integer values from the result for comparison
    result_values = [idx.value for idx in path_indices]

    assert result_values == expected_indices_values


@pytest.mark.parametrize(
    "start_value, right_side, expected_child_value",
    [
        # Children of the root (node 1)
        (1, False, 2),
        (1, True, 3),
        # Children of a deeper left node (node 6)
        (6, False, 12),
        (6, True, 13),
        # Children of a deeper right node (node 7)
        (7, False, 14),
        (7, True, 15),
    ],
)
def test_child_method(start_value: int, right_side: bool, expected_child_value: int) -> None:
    """Tests the `child` method for both left and right children."""
    parent_index = GeneralizedIndex(value=start_value)
    child_index = parent_index.child(right_side=right_side)

    assert isinstance(child_index, GeneralizedIndex)
    assert child_index.value == expected_child_value
