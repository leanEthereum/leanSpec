"""Unit tests for Checkpoint ordering."""

from __future__ import annotations

import pytest

from lean_spec.forks.lstar.containers.checkpoint import Checkpoint
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.types import Bytes32

# Two distinct roots to verify ordering ignores root content.
ROOT_A = Bytes32(b"\xa0" * 32)
ROOT_B = Bytes32(b"\xb0" * 32)


def test_lt_returns_true_for_lower_slot() -> None:
    """Lower slot is less than higher slot."""
    low = Checkpoint(root=ROOT_A, slot=Slot(1))
    high = Checkpoint(root=ROOT_A, slot=Slot(2))
    assert (low < high) is True


def test_lt_returns_false_for_higher_slot() -> None:
    """Higher slot is not less than lower slot."""
    low = Checkpoint(root=ROOT_A, slot=Slot(1))
    high = Checkpoint(root=ROOT_A, slot=Slot(2))
    assert (high < low) is False


def test_lt_returns_false_for_equal_slots_with_different_roots() -> None:
    """Equal slots are incomparable regardless of root."""
    a = Checkpoint(root=ROOT_A, slot=Slot(7))
    b = Checkpoint(root=ROOT_B, slot=Slot(7))
    assert (a < b) is False
    assert (b < a) is False


def test_lt_returns_false_for_identical_checkpoint() -> None:
    """Checkpoint is never less than itself."""
    cp = Checkpoint(root=ROOT_A, slot=Slot(3))
    assert (cp < cp) is False


def test_lt_returns_not_implemented_for_non_checkpoint() -> None:
    """Direct dunder call returns NotImplemented for foreign types."""
    cp = Checkpoint(root=ROOT_A, slot=Slot(1))
    assert cp.__lt__(42) is NotImplemented  # type: ignore[arg-type]


def test_lt_raises_typeerror_when_compared_with_non_checkpoint() -> None:
    """Operator < raises TypeError after the reflected fallback fails."""
    cp = Checkpoint(root=ROOT_A, slot=Slot(1))
    with pytest.raises(TypeError):
        _ = cp < 42  # type: ignore[operator]


def test_max_returns_higher_slot_regardless_of_argument_order() -> None:
    """max selects the higher-slot checkpoint regardless of argument order."""
    low = Checkpoint(root=ROOT_A, slot=Slot(1))
    high = Checkpoint(root=ROOT_B, slot=Slot(2))
    assert max(low, high) == high
    assert max(high, low) == high


def test_max_keeps_first_argument_on_slot_tie() -> None:
    """max returns the first argument on slot ties."""
    a = Checkpoint(root=ROOT_A, slot=Slot(5))
    b = Checkpoint(root=ROOT_B, slot=Slot(5))
    assert max(a, b) == a
    assert max(b, a) == b
