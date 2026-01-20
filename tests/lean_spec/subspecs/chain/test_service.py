"""Tests for the ChainService consensus clock driver."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import patch

from lean_spec.subspecs.chain import ChainService, SlotClock
from lean_spec.subspecs.chain.config import SECONDS_PER_INTERVAL
from lean_spec.types import Uint64


@dataclass
class MockStore:
    """Mock store that tracks on_tick calls."""

    time: Uint64 = field(default_factory=lambda: Uint64(0))
    tick_calls: list[tuple[Uint64, bool]] = field(default_factory=list)
    head: Any = field(default_factory=lambda: b"\x00" * 32)  # Mock head hash
    # Mock finalized checkpoint with slot attribute
    latest_finalized: Any = field(
        default_factory=lambda: type("obj", (object,), {"slot": Uint64(0)})()
    )

    def on_tick(self, time: Uint64, has_proposal: bool) -> "MockStore":
        """Record the tick call and return a new store."""
        new_store = MockStore(
            time=time,
            tick_calls=list(self.tick_calls),
            head=self.head,
            latest_finalized=self.latest_finalized,
        )
        new_store.tick_calls.append((time, has_proposal))
        return new_store


@dataclass
class MockSyncService:
    """Mock sync service for testing ChainService."""

    store: Any = field(default_factory=MockStore)


class TestChainServiceLifecycle:
    """Tests for ChainService start/stop lifecycle."""

    def test_starts_not_running(self) -> None:
        """Service is not running by default."""
        sync_service = MockSyncService()
        clock = SlotClock(genesis_time=Uint64(0), _time_fn=lambda: 0.0)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        assert chain_service.is_running is False

    def test_stop_sets_flag(self) -> None:
        """stop() sets the running flag to False."""
        sync_service = MockSyncService()
        clock = SlotClock(genesis_time=Uint64(0), _time_fn=lambda: 0.0)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        chain_service._running = True
        assert chain_service.is_running is True

        chain_service.stop()
        assert chain_service.is_running is False

    def test_run_sets_running_flag(self) -> None:
        """run() sets the running flag before loop starts."""
        sync_service = MockSyncService()
        clock = SlotClock(genesis_time=Uint64(0), _time_fn=lambda: 0.0)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        call_count = 0

        async def stop_on_second_call(_duration: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                chain_service.stop()

        async def run_briefly() -> None:
            with patch("asyncio.sleep", new=stop_on_second_call):
                await chain_service.run()

        asyncio.run(run_briefly())

        # After stopping, flag should be False
        assert chain_service.is_running is False


class TestIntervalTiming:
    """Tests for interval boundary timing."""

    def test_sleep_calculation_mid_interval(self) -> None:
        """Sleep duration is calculated correctly mid-interval."""
        genesis = Uint64(1000)
        current_time = 1000.5  # 0.5 seconds into first interval
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        captured_duration: float | None = None

        async def capture_sleep(duration: float) -> None:
            nonlocal captured_duration
            captured_duration = duration

        async def check_sleep() -> None:
            with patch("asyncio.sleep", new=capture_sleep):
                await chain_service._sleep_until_next_interval()

        asyncio.run(check_sleep())

        # Should sleep until next interval boundary (1.0 second mark)
        # With SECONDS_PER_INTERVAL = 1, next boundary is at 1001.0
        expected = 1001.0 - current_time  # 0.5 seconds
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001

    def test_sleep_at_interval_boundary(self) -> None:
        """Sleep duration is one full interval at exact boundary."""
        genesis = Uint64(1000)
        # Exactly at interval boundary
        current_time = float(genesis + SECONDS_PER_INTERVAL)
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        captured_duration: float | None = None

        async def capture_sleep(duration: float) -> None:
            nonlocal captured_duration
            captured_duration = duration

        async def check_sleep() -> None:
            with patch("asyncio.sleep", new=capture_sleep):
                await chain_service._sleep_until_next_interval()

        asyncio.run(check_sleep())

        # At boundary, should sleep until next boundary
        expected = float(SECONDS_PER_INTERVAL)
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001

    def test_sleep_before_genesis(self) -> None:
        """Sleeps until genesis when current time is before genesis."""
        genesis = Uint64(1000)
        current_time = 900.0  # 100 seconds before genesis
        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        captured_duration: float | None = None

        async def capture_sleep(duration: float) -> None:
            nonlocal captured_duration
            captured_duration = duration

        async def check_sleep() -> None:
            with patch("asyncio.sleep", new=capture_sleep):
                await chain_service._sleep_until_next_interval()

        asyncio.run(check_sleep())

        # Should sleep until genesis
        expected = float(genesis) - current_time  # 100 seconds
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001


class TestStoreTicking:
    """Tests for store tick integration."""

    def test_ticks_store_with_current_time(self) -> None:
        """Store is ticked with current wall-clock time."""
        genesis = Uint64(1000)
        current_time = 1005.0  # 5 seconds after genesis

        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        call_count = 0

        async def stop_on_second_call(_duration: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                chain_service.stop()

        async def run_limited() -> None:
            with patch("asyncio.sleep", new=stop_on_second_call):
                await chain_service.run()

        asyncio.run(run_limited())

        # Store should have been ticked
        assert len(sync_service.store.tick_calls) >= 1
        # First tick should be with current time
        first_call = sync_service.store.tick_calls[0]
        assert first_call[0] == Uint64(int(current_time))
        assert first_call[1] is False  # has_proposal always False

    def test_has_proposal_always_false(self) -> None:
        """has_proposal is always False (minimal version)."""
        genesis = Uint64(1000)
        current_time = 1005.0

        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        tick_count = 0

        async def stop_after_three(_duration: float) -> None:
            nonlocal tick_count
            tick_count += 1
            if tick_count >= 3:
                chain_service.stop()

        async def run_and_check() -> None:
            with patch("asyncio.sleep", new=stop_after_three):
                await chain_service.run()

        asyncio.run(run_and_check())

        # All ticks should have has_proposal=False
        for _time_val, has_proposal in sync_service.store.tick_calls:
            assert has_proposal is False

    def test_sync_service_store_updated(self) -> None:
        """SyncService.store is updated with new store after tick."""
        genesis = Uint64(1000)
        current_time = 1005.0

        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: current_time)
        initial_store = MockStore()
        sync_service = MockSyncService(store=initial_store)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def stop_immediately(_duration: float) -> None:
            chain_service.stop()

        async def run_once() -> None:
            with patch("asyncio.sleep", new=stop_immediately):
                await chain_service.run()

        asyncio.run(run_once())

        # Store should have been replaced
        assert sync_service.store is not initial_store
        # New store should have tick records (initial tick + main loop tick)
        assert len(sync_service.store.tick_calls) == 2


class TestMultipleIntervals:
    """Tests for running through multiple intervals."""

    def test_advances_through_intervals(self) -> None:
        """Service advances through multiple intervals correctly."""
        genesis = Uint64(1000)
        times = [1001.0, 1002.0, 1003.0, 1004.0]  # 4 intervals
        time_index = 0

        def advancing_time() -> float:
            nonlocal time_index
            if time_index < len(times):
                return times[time_index]
            return times[-1]

        clock = SlotClock(genesis_time=genesis, _time_fn=advancing_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def advance_and_stop(_duration: float) -> None:
            nonlocal time_index
            time_index += 1
            if time_index >= len(times):
                chain_service.stop()

        async def run_four_intervals() -> None:
            with patch("asyncio.sleep", new=advance_and_stop):
                await chain_service.run()

        asyncio.run(run_four_intervals())

        # Should have ticked for each interval
        assert len(sync_service.store.tick_calls) >= 3


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_genesis_time_zero(self) -> None:
        """Works with genesis_time of 0."""
        genesis = Uint64(0)
        current_time = 5.0

        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def stop_immediately(_duration: float) -> None:
            chain_service.stop()

        async def run_once() -> None:
            with patch("asyncio.sleep", new=stop_immediately):
                await chain_service.run()

        asyncio.run(run_once())

        # Initial tick + main loop tick
        assert len(sync_service.store.tick_calls) == 2
        assert sync_service.store.tick_calls[0][0] == Uint64(5)

    def test_large_genesis_time(self) -> None:
        """Works with realistic Unix timestamp genesis times."""
        genesis = Uint64(1700000000)  # Nov 2023
        current_time = float(genesis) + 100.5

        clock = SlotClock(genesis_time=genesis, _time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def stop_immediately(_duration: float) -> None:
            chain_service.stop()

        async def run_once() -> None:
            with patch("asyncio.sleep", new=stop_immediately):
                await chain_service.run()

        asyncio.run(run_once())

        # Initial tick + main loop tick
        assert len(sync_service.store.tick_calls) == 2
        assert sync_service.store.tick_calls[0][0] == Uint64(int(current_time))
