"""Unit tests for Checkpoint ordering."""

from __future__ import annotations

import pytest

from lean_spec.types import Bytes32, Checkpoint, Slot

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


def test_advance_to_returns_candidate_on_higher_slot() -> None:
    """A candidate at a strictly higher slot replaces the receiver."""
    current = Checkpoint(root=ROOT_A, slot=Slot(3))
    candidate = Checkpoint(root=ROOT_B, slot=Slot(4))
    assert current.advance_to(candidate) == candidate


def test_advance_to_keeps_self_on_lower_slot() -> None:
    """A candidate at a lower slot is ignored."""
    current = Checkpoint(root=ROOT_A, slot=Slot(4))
    candidate = Checkpoint(root=ROOT_B, slot=Slot(3))
    assert current.advance_to(candidate) == current


def test_advance_to_keeps_self_on_slot_tie() -> None:
    """On a slot tie the receiver wins regardless of root."""
    current = Checkpoint(root=ROOT_A, slot=Slot(7))
    candidate = Checkpoint(root=ROOT_B, slot=Slot(7))
    assert current.advance_to(candidate) == current
    # Symmetric: the receiver of the call always wins on a tie.
    assert candidate.advance_to(current) == candidate


def test_advance_to_is_idempotent() -> None:
    """Calling against the same checkpoint returns the receiver unchanged."""
    cp = Checkpoint(root=ROOT_A, slot=Slot(2))
    assert cp.advance_to(cp) == cp
