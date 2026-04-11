"""Tests for the SlotClock time-to-slot converter."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.chain import Interval, SlotClock
from lean_spec.subspecs.chain.config import (
    INTERVALS_PER_SLOT,
    MILLISECONDS_PER_INTERVAL,
    MILLISECONDS_PER_SLOT,
    SECONDS_PER_SLOT,
)
from lean_spec.subspecs.containers import Slot
from lean_spec.types import Uint64

GENESIS_TIME = Uint64(1_700_000_000)


class TestIntervalFromUnixTime:
    """Tests for Interval.from_unix_time()."""

    def test_at_genesis(self) -> None:
        """Returns interval 0 when unix_seconds equals genesis_time."""
        assert Interval.from_unix_time(GENESIS_TIME, GENESIS_TIME) == Interval(0)

    def test_one_second_after_genesis(self) -> None:
        """One second equals 1000ms, yielding 1000 // 800 = 1 interval."""
        result = Interval.from_unix_time(GENESIS_TIME + Uint64(1), GENESIS_TIME)
        assert result == Interval(1)

    def test_one_slot_after_genesis(self) -> None:
        """One full slot (4s = 4000ms) yields 4000 // 800 = 5 intervals."""
        result = Interval.from_unix_time(GENESIS_TIME + SECONDS_PER_SLOT, GENESIS_TIME)
        expected = Interval(int(MILLISECONDS_PER_SLOT // MILLISECONDS_PER_INTERVAL))
        assert result == expected

    def test_sub_interval_rounds_down(self) -> None:
        """Partial intervals are truncated by integer division.

        At 0 full seconds past genesis the delta_ms is 0, so the result is 0.
        The method only accepts whole-second Uint64 values, so sub-interval
        precision only surfaces when 1000ms is not a multiple of the interval.
        Here we verify the floor behaviour across the first few seconds.
        """
        # 0s -> 0ms -> 0 intervals
        assert Interval.from_unix_time(GENESIS_TIME, GENESIS_TIME) == Interval(0)
        # 1s -> 1000ms -> 1000 // 800 = 1 (remainder 200ms truncated)
        assert Interval.from_unix_time(GENESIS_TIME + Uint64(1), GENESIS_TIME) == Interval(1)
        # 2s -> 2000ms -> 2000 // 800 = 2 (remainder 400ms truncated)
        assert Interval.from_unix_time(GENESIS_TIME + Uint64(2), GENESIS_TIME) == Interval(2)
        # 3s -> 3000ms -> 3000 // 800 = 3 (remainder 600ms truncated)
        assert Interval.from_unix_time(GENESIS_TIME + Uint64(3), GENESIS_TIME) == Interval(3)

    def test_multiple_slots(self) -> None:
        """Ten slots (40s = 40000ms) yields 40000 // 800 = 50 intervals."""
        ten_slots = Uint64(10) * SECONDS_PER_SLOT
        result = Interval.from_unix_time(GENESIS_TIME + ten_slots, GENESIS_TIME)
        expected_intervals = (ten_slots * Uint64(1000)) // MILLISECONDS_PER_INTERVAL
        assert result == Interval(expected_intervals)

    def test_return_type_is_interval(self) -> None:
        """Return value is an Interval instance, not a plain Uint64."""
        result = Interval.from_unix_time(GENESIS_TIME + Uint64(5), GENESIS_TIME)
        assert isinstance(result, Interval)

    def test_large_time_delta(self) -> None:
        """Works correctly with a large time delta (one day = 86400s)."""
        one_day = Uint64(86400)
        result = Interval.from_unix_time(GENESIS_TIME + one_day, GENESIS_TIME)
        expected = Interval((one_day * Uint64(1000)) // MILLISECONDS_PER_INTERVAL)
        assert result == expected

    def test_genesis_time_zero(self) -> None:
        """Works when genesis_time is zero."""
        result = Interval.from_unix_time(Uint64(4), Uint64(0))
        # 4s = 4000ms -> 4000 // 800 = 5
        assert result == Interval(5)


class TestIntervalFromSlot:
    """Tests for Interval.from_slot()."""

    def test_slot_zero(self) -> None:
        """Slot 0 maps to interval 0."""
        assert Interval.from_slot(Uint64(0)) == Interval(0)

    def test_slot_one(self) -> None:
        """Slot 1 maps to interval equal to INTERVALS_PER_SLOT."""
        assert Interval.from_slot(Uint64(1)) == Interval(INTERVALS_PER_SLOT)

    def test_slot_three(self) -> None:
        """Slot 3 maps to interval 3 * INTERVALS_PER_SLOT."""
        assert Interval.from_slot(Uint64(3)) == Interval(Uint64(3) * INTERVALS_PER_SLOT)

    def test_multiple_slots(self) -> None:
        """Each slot N maps to interval N * INTERVALS_PER_SLOT."""
        for n in range(10):
            slot = Uint64(n)
            assert Interval.from_slot(slot) == Interval(slot * INTERVALS_PER_SLOT)

    def test_return_type_is_interval(self) -> None:
        """Return value is an Interval instance, not a plain Uint64."""
        result = Interval.from_slot(Uint64(2))
        assert isinstance(result, Interval)

    def test_consistent_with_from_unix_time(self) -> None:
        """from_slot(N) equals from_unix_time at genesis + N * SECONDS_PER_SLOT."""
        for n in range(5):
            slot = Uint64(n)
            from_slot_result = Interval.from_slot(slot)
            from_unix_result = Interval.from_unix_time(
                GENESIS_TIME + slot * SECONDS_PER_SLOT, GENESIS_TIME
            )
            assert from_slot_result == from_unix_result


class TestCurrentSlot:
    """Tests for current_slot()."""

    def test_at_genesis(self) -> None:
        """Slot is 0 at exactly genesis time."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: float(genesis))
        assert clock.current_slot() == Slot(0)

    def test_before_genesis(self) -> None:
        """Slot is 0 before genesis."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: float(genesis - Uint64(100)))
        assert clock.current_slot() == Slot(0)

    def test_progression(self) -> None:
        """Slot increments every 4 seconds (SECONDS_PER_SLOT)."""
        genesis = Uint64(1700000000)
        for expected_slot in range(5):
            slot_duration_seconds = Uint64(expected_slot) * SECONDS_PER_SLOT
            time = genesis + slot_duration_seconds
            clock = SlotClock(genesis_time=genesis, time_fn=lambda t=time: float(t))
            assert clock.current_slot() == Slot(expected_slot)

    def test_mid_slot(self) -> None:
        """Slot remains constant within a slot."""
        genesis = Uint64(1700000000)
        slot_3_seconds = Uint64(3) * SECONDS_PER_SLOT
        time = genesis + slot_3_seconds + Uint64(2)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: float(time))
        assert clock.current_slot() == Slot(3)

    def test_at_slot_boundary_minus_one(self) -> None:
        """Slot does not increment until boundary is reached."""
        genesis = Uint64(1700000000)
        slot_duration_seconds = SECONDS_PER_SLOT
        time = genesis + slot_duration_seconds - Uint64(1)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: float(time))
        assert clock.current_slot() == Slot(0)


class TestCurrentInterval:
    """Tests for current_interval()."""

    def test_at_slot_start(self) -> None:
        """Interval is 0 at slot start."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: float(genesis))
        assert clock.current_interval() == Interval(0)

    def test_progression(self) -> None:
        """Interval increments based on milliseconds since genesis.

        With MILLISECONDS_PER_INTERVAL = 800:
        - 0ms → interval 0
        - 800ms → interval 1
        - 1600ms → interval 2
        - 2400ms → interval 3
        - 3200ms → interval 4
        """
        genesis = Uint64(1700000000)
        # Test with sub-second precision
        expected_intervals = [
            (0.0, 0),  # 0ms -> interval 0
            (0.8, 1),  # 800ms -> interval 1 (exactly at boundary)
            (1.0, 1),  # 1000ms -> interval 1
            (1.6, 2),  # 1600ms -> interval 2
            (2.0, 2),  # 2000ms -> interval 2
            (2.4, 3),  # 2400ms -> interval 3
            (3.0, 3),  # 3000ms -> interval 3
            (3.2, 4),  # 3200ms -> interval 4 (previously unreachable)
            (3.9, 4),  # 3900ms -> interval 4
        ]
        for secs_after_genesis, expected_interval in expected_intervals:
            time = float(genesis) + secs_after_genesis
            clock = SlotClock(genesis_time=genesis, time_fn=lambda t=time: t)
            assert clock.current_interval() == Interval(expected_interval), (
                f"At {secs_after_genesis}s, expected interval {expected_interval}"
            )

    def test_wraps_at_slot_boundary(self) -> None:
        """Interval resets to 0 at next slot."""
        genesis = Uint64(1700000000)
        slot_duration_seconds = SECONDS_PER_SLOT
        time = genesis + slot_duration_seconds
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: float(time))
        assert clock.current_interval() == Interval(0)

    def test_before_genesis(self) -> None:
        """Interval is 0 before genesis."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: float(genesis - Uint64(100)))
        assert clock.current_interval() == Interval(0)

    def test_last_interval_of_slot(self) -> None:
        """Interval 4 at 3.2s (3200ms // 800 = 4)."""
        genesis = Uint64(1700000000)
        time = float(genesis) + 3.2
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: time)
        assert clock.current_interval() == Interval(4)

    def test_subsecond_precision(self) -> None:
        """Verifies sub-second timing affects interval calculation."""
        genesis = Uint64(1700000000)
        # 750ms into genesis should give interval 0 (not 1)
        clock_750ms = SlotClock(genesis_time=genesis, time_fn=lambda: float(genesis) + 0.75)
        assert clock_750ms.current_interval() == Interval(0)

        # 850ms into genesis should give interval 1
        clock_850ms = SlotClock(genesis_time=genesis, time_fn=lambda: float(genesis) + 0.85)
        assert clock_850ms.current_interval() == Interval(1)


class TestTotalIntervals:
    """Tests for total_intervals()."""

    def test_counts_all_intervals(self) -> None:
        """total_intervals counts all intervals since genesis with sub-second precision.

        With MILLISECONDS_PER_INTERVAL = 800:
        14.4 seconds = 14400ms = 18 intervals (14400 // 800)
        """
        genesis = Uint64(1700000000)
        # 14.4 seconds = 14400ms = 18 intervals (14400 // 800)
        time = float(genesis) + 14.4
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: time)
        assert clock.total_intervals() == Interval(18)

    def test_before_genesis(self) -> None:
        """total_intervals is 0 before genesis."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: float(genesis - Uint64(100)))
        assert clock.total_intervals() == Interval(0)


class TestSlotClockImmutability:
    """Tests for SlotClock immutability."""

    def test_is_frozen(self) -> None:
        """SlotClock is immutable."""
        clock = SlotClock(genesis_time=Uint64(1700000000))
        with pytest.raises(AttributeError):
            clock.genesis_time = Uint64(1700000001)  # type: ignore[misc]


class TestCurrentTime:
    """Tests for current_time()."""

    def test_returns_uint64(self) -> None:
        """current_time returns Uint64."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: 1700000005.5)
        result = clock.current_time()
        assert isinstance(result, Uint64)
        assert result == Uint64(1700000005)

    def test_truncates_to_integer(self) -> None:
        """current_time truncates float to integer seconds."""
        genesis = Uint64(0)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: 123.999)
        assert clock.current_time() == Uint64(123)

    def test_at_genesis(self) -> None:
        """current_time returns genesis time at genesis."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: float(genesis))
        assert clock.current_time() == genesis


class TestSecondsUntilNextInterval:
    """Tests for seconds_until_next_interval()."""

    def test_mid_interval(self) -> None:
        """Returns time until next boundary when mid-interval."""
        genesis = Uint64(1000)
        interval_seconds = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        # Half way into first interval.
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: 1000.0 + interval_seconds / 2)
        result = clock.seconds_until_next_interval()
        assert abs(result - interval_seconds / 2) < 0.01

    def test_at_interval_boundary(self) -> None:
        """Returns one full interval when exactly at boundary.

        With MILLISECONDS_PER_INTERVAL = 800:
        At 1s = 1000ms, time_into_interval = 1000 % 800 = 200ms
        At 800ms exactly (0.8s), time_into_interval = 0
        But using fractional seconds has FP precision issues.

        Instead test at 1s: should return 800 - 200 = 600ms = 0.6s
        """
        genesis = Uint64(1000)
        # At 1 second after genesis: 1000ms % 800 = 200ms into interval
        # Time until next = 800 - 200 = 600ms = 0.6s
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: 1001.0)
        result = clock.seconds_until_next_interval()
        assert abs(result - 0.6) < 0.01

    def test_before_genesis(self) -> None:
        """Returns time until genesis when before genesis."""
        genesis = Uint64(1000)
        # 100 seconds before genesis.
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: 900.0)
        result = clock.seconds_until_next_interval()
        assert abs(result - 100.0) < 0.001

    def test_at_genesis(self) -> None:
        """Returns one full interval at exactly genesis."""
        genesis = Uint64(1000)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: 1000.0)
        result = clock.seconds_until_next_interval()
        assert abs(result - (float(MILLISECONDS_PER_INTERVAL) / 1000.0)) < 0.001

    def test_fractional_precision(self) -> None:
        """Preserves fractional seconds in calculation."""
        genesis = Uint64(1000)
        # 0.123 seconds into interval.
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: 1000.123)
        result = clock.seconds_until_next_interval()
        expected = (float(MILLISECONDS_PER_INTERVAL) / 1000.0) - 0.123
        assert abs(result - expected) < 0.001


class TestReturnTypes:
    """Tests for proper return types."""

    def test_types_are_correct(self) -> None:
        """All return types are domain-specific."""
        genesis = Uint64(1700000000)
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: float(genesis))

        assert isinstance(clock.current_slot(), Slot)
        assert isinstance(clock.current_interval(), Uint64)
        assert isinstance(clock.total_intervals(), Uint64)
        assert isinstance(clock.current_time(), Uint64)
        assert isinstance(clock.seconds_until_next_interval(), float)
