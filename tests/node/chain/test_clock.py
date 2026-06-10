"""Tests for the SlotClock time-to-slot converter."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from lean_spec.node.chain import SlotClock
from lean_spec.spec.forks import Interval, Slot
from lean_spec.spec.forks.lstar.config import INTERVALS_PER_SLOT
from lean_spec.spec.ssz import Uint64


def clock_at(genesis_seconds: int, now_seconds: float) -> SlotClock:
    """Build a SlotClock frozen at the given genesis and current time, both in seconds."""
    return SlotClock(genesis_time=Uint64(genesis_seconds), time_fn=lambda: now_seconds)


class TestCurrentSlot:
    """Tests for current_slot()."""

    @pytest.mark.parametrize(
        ("genesis", "now", "expected_slot"),
        [
            # Exactly at genesis.
            (0, 0.0, 0),
            # Just before the slot 1 boundary: a slot is 4s = 4000ms.
            (0, 3.999, 0),
            # Slot 1 begins exactly at 4s.
            (0, 4.0, 1),
            # 10s -> 10000ms // 4000 = slot 2.
            (0, 10.0, 2),
            # Non-zero genesis: 6s elapsed lands in slot 1.
            (1000, 1006.0, 1),
            # One second before genesis clamps to slot 0.
            (1000, 999.0, 0),
            # Large elapsed time stays exact.
            (0, 4000.0, 1000),
        ],
    )
    def test_floors_elapsed_time_to_whole_slots(
        self, genesis: int, now: float, expected_slot: int
    ) -> None:
        """The slot number is elapsed milliseconds floored to whole slots."""
        assert clock_at(genesis, now).current_slot() == Slot(expected_slot)

    def test_constant_within_a_slot(self) -> None:
        """The slot does not change between its first and last interval."""
        assert clock_at(0, 8.0).current_slot() == Slot(2)
        assert clock_at(0, 11.999).current_slot() == Slot(2)


class TestCurrentInterval:
    """Tests for current_interval()."""

    @pytest.mark.parametrize(
        ("now", "expected_interval"),
        [
            # Each interval is 800ms; a slot holds 5 of them.
            (0.0, 0),  # 0ms -> interval 0
            (0.8, 1),  # 800ms exactly -> interval 1
            (1.0, 1),  # 1000ms // 800 -> interval 1
            (1.6, 2),  # 1600ms -> interval 2
            (2.4, 3),  # 2400ms -> interval 3
            (3.2, 4),  # 3200ms -> interval 4, the last interval of the slot
            (3.9, 4),  # 3900ms -> still interval 4
            (4.0, 0),  # next slot resets the interval to 0
            (4.8, 1),  # 800ms into slot 1 -> interval 1
        ],
    )
    def test_position_within_slot(self, now: float, expected_interval: int) -> None:
        """The interval is the sub-slot position floored to 800ms steps."""
        assert clock_at(0, now).current_interval() == Interval(expected_interval)

    @pytest.mark.parametrize(
        ("now", "expected_interval"),
        [
            # Sub-second precision decides the interval at the boundary.
            (0.75, 0),  # 750ms is still inside interval 0
            (0.85, 1),  # 850ms has crossed into interval 1
        ],
    )
    def test_sub_second_precision(self, now: float, expected_interval: int) -> None:
        """Milliseconds below one second still move the interval."""
        assert clock_at(0, now).current_interval() == Interval(expected_interval)

    def test_before_genesis_is_zero(self) -> None:
        """The interval is 0 for any time before genesis."""
        assert clock_at(1000, 900.0).current_interval() == Interval(0)


class TestTotalIntervals:
    """Tests for total_intervals()."""

    @pytest.mark.parametrize(
        ("genesis", "now", "expected_total"),
        [
            # Counts every 800ms interval since genesis.
            (0, 0.0, 0),  # 0ms
            (0, 0.8, 1),  # 800ms
            (0, 4.0, 5),  # one full slot is 5 intervals
            (0, 14.4, 18),  # 14400ms // 800
            (1000, 1004.0, 5),  # non-zero genesis, one slot elapsed
        ],
    )
    def test_counts_intervals_since_genesis(
        self, genesis: int, now: float, expected_total: int
    ) -> None:
        """The total is elapsed milliseconds floored to whole intervals."""
        assert clock_at(genesis, now).total_intervals() == Interval(expected_total)

    def test_before_genesis_is_zero(self) -> None:
        """The total is 0 for any time before genesis."""
        assert clock_at(1000, 900.0).total_intervals() == Interval(0)


class TestCurrentTime:
    """Tests for current_time()."""

    @pytest.mark.parametrize(
        ("now", "expected_seconds"),
        [
            # Whole seconds pass through unchanged.
            (1_700_000_000.0, 1_700_000_000),
            # Sub-second precision truncates toward zero.
            (123.999, 123),
            (0.0, 0),
        ],
    )
    def test_truncates_to_whole_seconds(self, now: float, expected_seconds: int) -> None:
        """The wall-clock reading floors to whole Unix seconds."""
        assert clock_at(0, now).current_time() == Uint64(expected_seconds)

    def test_default_time_source_is_wall_clock(self) -> None:
        """Without an injected source the clock reads real wall-clock time."""
        clock = SlotClock(genesis_time=Uint64(0))
        # Real Unix time is well past the test's reference epoch.
        assert int(clock.current_time()) > 1_700_000_000


class TestSecondsUntilNextInterval:
    """Tests for seconds_until_next_interval()."""

    @pytest.mark.parametrize(
        ("genesis", "now", "expected_seconds"),
        [
            # 250ms into an 800ms interval leaves 550ms.
            (1000, 1000.25, 0.55),
            # 500ms into the interval leaves 300ms.
            (1000, 1000.5, 0.3),
            # 1000ms past genesis sits 200ms into an interval, leaving 600ms.
            (1000, 1001.0, 0.6),
            # Exactly on a boundary returns a full interval, never zero.
            (1000, 1000.0, 0.8),
            # Before genesis returns the time remaining until genesis.
            (1000, 900.0, 100.0),
        ],
    )
    def test_time_until_boundary(self, genesis: int, now: float, expected_seconds: float) -> None:
        """Returns the seconds remaining until the next interval boundary."""
        seconds_until_next_interval = clock_at(genesis, now).seconds_until_next_interval()
        assert seconds_until_next_interval == pytest.approx(expected_seconds, abs=1e-3)


class TestSleepUntilNextInterval:
    """Tests for sleep_until_next_interval()."""

    @pytest.mark.parametrize(
        ("genesis", "now", "expected_sleep"),
        [
            # 500ms into an 800ms interval sleeps the remaining 300ms.
            (1000, 1000.5, 0.3),
            # Called before genesis sleeps until genesis arrives.
            (1000, 900.0, 100.0),
        ],
    )
    async def test_sleeps_until_next_boundary(
        self, genesis: int, now: float, expected_sleep: float
    ) -> None:
        """Awaits a sleep equal to the time until the next interval boundary."""
        captured: list[float] = []

        async def capture_sleep(duration: float) -> None:
            captured.append(duration)

        with patch("asyncio.sleep", new=capture_sleep):
            await clock_at(genesis, now).sleep_until_next_interval()

        assert captured == [pytest.approx(expected_sleep, abs=1e-3)]

    async def test_skips_sleep_when_no_time_remains(self) -> None:
        """The guard avoids a zero-length sleep when nothing is left to wait."""
        clock = clock_at(1000, 1000.0)
        slept = False

        async def record_sleep(duration: float) -> None:
            nonlocal slept
            slept = True

        # The boundary calculation never yields a non-positive wait on its own.
        # Force one to exercise the guard that skips the sleep.
        with (
            patch.object(SlotClock, "seconds_until_next_interval", return_value=0.0),
            patch("asyncio.sleep", new=record_sleep),
        ):
            await clock.sleep_until_next_interval()

        assert slept is False


class TestClockConsistency:
    """Cross-method invariants that must hold at every instant."""

    @pytest.mark.parametrize(
        "milliseconds_since_genesis",
        [
            # genesis
            0,
            # first millisecond
            1,
            # last millisecond of interval 0
            799,
            # first interval boundary
            800,
            # just past the boundary
            801,
            # interval 2 boundary
            1600,
            # interval 4 boundary
            3200,
            # last millisecond of slot 0
            3999,
            # slot 1 boundary
            4000,
            # just into slot 1
            4001,
            # slot 2 boundary
            8000,
            # arbitrary mid-slot offset
            12345,
            # far from genesis
            1_000_000,
        ],
    )
    def test_slot_and_interval_decompose_total_intervals(
        self, milliseconds_since_genesis: int
    ) -> None:
        """Slot and interval are the quotient and remainder of total intervals over a slot."""
        clock = clock_at(0, milliseconds_since_genesis / 1000.0)
        total = int(clock.total_intervals())

        # The slot is total intervals divided by the intervals in one slot.
        assert clock.current_slot() == Slot(total // int(INTERVALS_PER_SLOT))
        # The interval is the leftover position inside the current slot.
        assert clock.current_interval() == Interval(total % int(INTERVALS_PER_SLOT))
        # The interval index always stays within a single slot.
        assert 0 <= int(clock.current_interval()) < int(INTERVALS_PER_SLOT)


class TestSlotClockImmutability:
    """Tests for SlotClock immutability."""

    def test_is_frozen(self) -> None:
        """The clock is immutable, so reassigning a field raises."""
        clock = SlotClock(genesis_time=Uint64(1_700_000_000))
        with pytest.raises(AttributeError):
            clock.genesis_time = Uint64(1_700_000_001)  # type: ignore[misc]


class TestReturnTypes:
    """Tests for domain-specific return types."""

    def test_methods_return_domain_types(self) -> None:
        """Each accessor returns its narrow domain type, not a plain integer or float."""
        clock = clock_at(1_700_000_000, 1_700_000_005.5)
        assert isinstance(clock.current_slot(), Slot)
        assert isinstance(clock.current_interval(), Interval)
        assert isinstance(clock.total_intervals(), Interval)
        assert isinstance(clock.current_time(), Uint64)
        assert isinstance(clock.seconds_until_next_interval(), float)
