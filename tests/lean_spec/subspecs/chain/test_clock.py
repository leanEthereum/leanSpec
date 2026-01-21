"""Tests for the SlotClock time-to-slot converter."""

import pytest

from lean_spec.subspecs.chain import Interval, SlotClock
from lean_spec.subspecs.chain.config import (
    INTERVALS_PER_SLOT,
    SECONDS_PER_INTERVAL,
    SECONDS_PER_SLOT,
)
from lean_spec.subspecs.containers import Slot
from lean_spec.types import Uint64


class TestCurrentSlot:
    """Tests for current_slot()."""

    def test_at_genesis(self) -> None:
        """Slot is 0 at exactly genesis time."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(genesis))
        assert clock.current_slot() == Slot(0)

    def test_before_genesis(self) -> None:
        """Slot is 0 before genesis."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(genesis - Uint64(100)))
        assert clock.current_slot() == Slot(0)

    def test_progression(self) -> None:
        """Slot increments every SECONDS_PER_SLOT seconds."""
        genesis = Uint64(1700000000)
        for expected_slot in range(5):
            time = genesis + Uint64(expected_slot) * SECONDS_PER_SLOT
            clock = SlotClock(genesis_time=genesis, _time_fn=lambda t=time: float(t))
            assert clock.current_slot() == Slot(expected_slot)

    def test_mid_slot(self) -> None:
        """Slot remains constant within a slot."""
        genesis = Uint64(1700000000)
        time = genesis + Uint64(3) * SECONDS_PER_SLOT + Uint64(2)
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(time))
        assert clock.current_slot() == Slot(3)

    def test_at_slot_boundary_minus_one(self) -> None:
        """Slot does not increment until boundary is reached."""
        genesis = Uint64(1700000000)
        time = genesis + SECONDS_PER_SLOT - Uint64(1)
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(time))
        assert clock.current_slot() == Slot(0)


class TestCurrentInterval:
    """Tests for current_interval()."""

    def test_at_slot_start(self) -> None:
        """Interval is 0 at slot start."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(genesis))
        assert clock.current_interval() == Interval(0)

    def test_progression(self) -> None:
        """Interval increments every SECONDS_PER_INTERVAL seconds."""
        genesis = Uint64(1700000000)
        for expected_interval in range(int(INTERVALS_PER_SLOT)):
            time = genesis + Uint64(expected_interval) * SECONDS_PER_INTERVAL
            clock = SlotClock(genesis_time=genesis, _time_fn=lambda t=time: float(t))
            assert clock.current_interval() == Interval(expected_interval)

    def test_wraps_at_slot_boundary(self) -> None:
        """Interval resets to 0 at next slot."""
        genesis = Uint64(1700000000)
        time = genesis + SECONDS_PER_SLOT
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(time))
        assert clock.current_interval() == Interval(0)

    def test_before_genesis(self) -> None:
        """Interval is 0 before genesis."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(genesis - Uint64(100)))
        assert clock.current_interval() == Interval(0)

    def test_last_interval_of_slot(self) -> None:
        """Last interval before slot boundary is INTERVALS_PER_SLOT - 1."""
        genesis = Uint64(1700000000)
        time = genesis + SECONDS_PER_SLOT - Uint64(1)
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(time))
        assert clock.current_interval() == Interval(int(INTERVALS_PER_SLOT) - 1)


class TestTotalIntervals:
    """Tests for total_intervals()."""

    def test_counts_all_intervals(self) -> None:
        """total_intervals counts all intervals since genesis."""
        genesis = Uint64(1700000000)
        intervals_per_slot = int(INTERVALS_PER_SLOT)
        # 3 slots + 2 intervals = 14 total intervals
        time = genesis + Uint64(3) * SECONDS_PER_SLOT + Uint64(2) * SECONDS_PER_INTERVAL
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(time))
        assert clock.total_intervals() == Interval(3 * intervals_per_slot + 2)

    def test_before_genesis(self) -> None:
        """total_intervals is 0 before genesis."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(genesis - Uint64(100)))
        assert clock.total_intervals() == Interval(0)


class TestSlotClockImmutability:
    """Tests for SlotClock immutability."""

    def test_is_frozen(self) -> None:
        """SlotClock is immutable."""
        clock = SlotClock(genesis_time=Uint64(1700000000))
        with pytest.raises(AttributeError):
            clock.genesis_time = Uint64(1700000001)  # type: ignore[misc]


class TestReturnTypes:
    """Tests for proper return types."""

    def test_types_are_correct(self) -> None:
        """All return types are domain-specific."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: float(genesis))

        assert isinstance(clock.current_slot(), Slot)
        assert isinstance(clock.current_interval(), Uint64)
        assert isinstance(clock.total_intervals(), Uint64)
