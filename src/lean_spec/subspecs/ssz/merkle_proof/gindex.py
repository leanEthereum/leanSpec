"""Generalized Index implementation."""

from typing import List

from pydantic import Field

from lean_spec.types import StrictBaseModel


class GeneralizedIndex(StrictBaseModel):
    """
    Represents a Generalized Merkle Tree Index.

    Helper methods are provided for tree navigation.
    """

    value: int = Field(..., gt=0, description="The index value, must be a positive integer.")

    def __hash__(self) -> int:
        """Hashes the index value."""
        return hash(self.value)

    @property
    def depth(self) -> int:
        """The depth of the node in the tree."""
        return self.value.bit_length() - 1

    def get_bit(self, position: int) -> bool:
        """Returns the bit at a specific position (from the right)."""
        return (self.value >> position) & 1 == 1

    @property
    def sibling(self) -> "GeneralizedIndex":
        """Returns the index of the sibling node."""
        return type(self)(value=self.value ^ 1)

    @property
    def parent(self) -> "GeneralizedIndex":
        """Returns the index of the parent node."""
        if self.value <= 1:
            raise ValueError("Root node has no parent.")
        return type(self)(value=self.value // 2)

    def child(self, right_side: bool) -> "GeneralizedIndex":
        """
        Returns the index of a child node.

        - `right_side=False` for the left child (2k),
        - `right_side=True` for the right child (2k+1).
        """
        return type(self)(value=self.value * 2 + int(right_side))

    def get_branch_indices(self) -> List["GeneralizedIndex"]:
        """Gets the indices of the sibling nodes along the path to the root."""
        indices: List["GeneralizedIndex"] = []
        current_index = self.value
        while current_index > 1:
            # Sibling is the current index XOR 1
            sibling_index = current_index ^ 1
            indices.append(type(self)(value=sibling_index))
            # Move up to the parent
            current_index //= 2
        return indices

    def get_path_indices(self) -> List["GeneralizedIndex"]:
        """Gets the indices of the nodes along the path to the root."""
        indices: List["GeneralizedIndex"] = [self]
        while indices[-1].value > 1:
            indices.append(indices[-1].parent)
        return indices[:-1]
