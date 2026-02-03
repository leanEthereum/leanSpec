"""Tests for the ChainService consensus clock driver."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from unittest.mock import patch

from lean_spec.subspecs.chain import SlotClock
from lean_spec.subspecs.chain.config import MILLISECONDS_PER_INTERVAL
from lean_spec.subspecs.chain.service import ChainService
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import ZERO_HASH, Bytes32, Uint64


@dataclass
class MockCheckpoint:
    """Mock checkpoint for the latest_finalized attribute."""

    slot: Slot = field(default_factory=lambda: Slot(0))


@dataclass
class MockStore:
    """Mock store that tracks on_tick calls."""

    time: Uint64 = field(default_factory=lambda: Uint64(0))
    tick_calls: list[tuple[Uint64, bool]] = field(default_factory=list)
    head: Bytes32 = field(default_factory=lambda: ZERO_HASH)
    latest_finalized: MockCheckpoint = field(default_factory=MockCheckpoint)

    def on_tick(self, time: Uint64, has_proposal: bool) -> MockStore:
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

    store: MockStore = field(default_factory=MockStore)


class TestChainServiceLifecycle:
    """Tests for ChainService start/stop lifecycle."""

    def test_starts_not_running(self) -> None:
        """
        Service initializes in stopped state.

        The running flag prevents accidental double-starts and enables graceful shutdown.
        """
        sync_service = MockSyncService()
        clock = SlotClock(genesis_time=Uint64(0), time_fn=lambda: 0.0)
        # MockSyncService satisfies SyncService interface for testing.
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        assert chain_service.is_running is False

    def test_stop_sets_flag(self) -> None:
        """
        stop() transitions running flag from True to False.

        This allows the run loop to exit gracefully at the next sleep boundary.
        """
        sync_service = MockSyncService()
        clock = SlotClock(genesis_time=Uint64(0), time_fn=lambda: 0.0)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        chain_service._running = True
        assert chain_service.is_running is True

        chain_service.stop()
        assert chain_service.is_running is False

    def test_run_sets_running_flag(self) -> None:
        """
        run() sets the running flag before entering the main loop.

        This ensures is_running reflects actual state during execution.
        """
        sync_service = MockSyncService()
        clock = SlotClock(genesis_time=Uint64(0), time_fn=lambda: 0.0)
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

        # After stopping, flag should be False.
        assert chain_service.is_running is False


class TestIntervalTiming:
    """Tests for interval boundary timing."""

    def test_sleep_calculation_mid_interval(self) -> None:
        """
        Mid-interval sleep calculation ensures wakeup at next boundary.

        Precise boundary alignment is critical for coordinated validator actions.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        # Halfway into first interval.
        current_time = float(genesis) + interval_secs / 2
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
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

        # Should sleep until next interval boundary.
        expected = float(genesis) + interval_secs - current_time
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.002  # floating-point tolerance

    def test_sleep_at_interval_boundary(self) -> None:
        """
        When clock reads exactly at interval boundary, sleep is one full interval.

        This tests the math of the sleep calculation, not real-world timing.
        """
        genesis = Uint64(1000)
        # Clock reads exactly at first interval boundary.
        current_time = float(genesis + (MILLISECONDS_PER_INTERVAL // Uint64(1000)))
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
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

        # At boundary, next boundary is one full interval away.
        expected = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001

    def test_sleep_before_genesis(self) -> None:
        """
        Before genesis, sleeps until genesis time.

        The network cannot produce valid blocks or attestations pre-genesis.
        """
        genesis = Uint64(1000)
        current_time = 900.0  # 100 seconds before genesis
        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
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

        # Should sleep until genesis.
        expected = float(genesis) - current_time
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001


class TestStoreTicking:
    """Tests for store tick integration."""

    def test_ticks_store_with_current_time(self) -> None:
        """
        Store receives current wall-clock time on tick.

        The Store internally converts this to intervals for its time field.
        """
        genesis = Uint64(1000)
        # Several intervals after genesis.
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        current_time = float(genesis) + 5 * interval_secs
        expected_time = Uint64(int(current_time))

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
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

        # Initial tick handles the interval, main loop recognizes it and waits.
        assert sync_service.store.tick_calls == [(expected_time, False)]

    def test_has_proposal_always_false(self) -> None:
        """
        has_proposal is always False for this minimal service.

        Block production requires validator keys, which this service does not handle.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        current_time = float(genesis) + 5 * interval_secs
        expected_time = Uint64(int(current_time))

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
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

        # All ticks have has_proposal=False.
        assert sync_service.store.tick_calls == [(expected_time, False)]

    def test_sync_service_store_updated(self) -> None:
        """
        SyncService.store is replaced with new store after each tick.

        The Store uses immutable updates, so each tick creates a new instance.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        current_time = float(genesis) + 5 * interval_secs
        expected_time = Uint64(int(current_time))

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        initial_store = MockStore()
        sync_service = MockSyncService(store=initial_store)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        # No ticks before our first run.
        assert sync_service.store.tick_calls == []

        async def stop_immediately(_duration: float) -> None:
            chain_service.stop()

        async def run_once() -> None:
            with patch("asyncio.sleep", new=stop_immediately):
                await chain_service.run()

        asyncio.run(run_once())

        # Store should have been replaced.
        assert sync_service.store is not initial_store

        # Initial tick handles the interval, main loop recognizes it and waits.
        assert sync_service.store.tick_calls == [(expected_time, False)]


class TestMultipleIntervals:
    """Tests for running through multiple intervals."""

    def test_advances_through_intervals(self) -> None:
        """
        Service advances through multiple intervals correctly.

        Each interval triggers a store tick with the current time.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        # 4 consecutive interval times.
        times = [
            float(genesis) + 1 * interval_secs,
            float(genesis) + 2 * interval_secs,
            float(genesis) + 3 * interval_secs,
            float(genesis) + 4 * interval_secs,
        ]
        time_index = 0

        def advancing_time() -> float:
            nonlocal time_index
            if time_index < len(times):
                return times[time_index]
            return times[-1]

        clock = SlotClock(genesis_time=genesis, time_fn=advancing_time)
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

        # Initial tick at time[0], then main loop ticks at time[1], time[2], time[3].
        # The initial tick handles time[0], so main loop skips it.
        assert sync_service.store.tick_calls == [
            (Uint64(int(times[0])), False),
            (Uint64(int(times[1])), False),
            (Uint64(int(times[2])), False),
            (Uint64(int(times[3])), False),
        ]


class TestInitialTick:
    """Tests for the initial tick behavior at startup."""

    def test_initial_tick_skipped_before_genesis(self) -> None:
        """
        Initial tick is a no-op when current time is before genesis.

        The store time should not advance before the network starts.
        This ensures the main loop correctly handles the genesis wait.
        """
        genesis = Uint64(1000)
        current_time = 900.0  # Before genesis

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        initial_store = MockStore()
        sync_service = MockSyncService(store=initial_store)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        # Run just the initial tick without the full run loop.
        async def run_initial_tick() -> None:
            await chain_service._initial_tick()

        asyncio.run(run_initial_tick())

        # Store should not have been ticked.
        assert sync_service.store is initial_store
        assert sync_service.store.tick_calls == []

    def test_initial_tick_executed_after_genesis(self) -> None:
        """
        Initial tick advances store time when past genesis.

        This ensures attestation validation works immediately on startup.
        """
        genesis = Uint64(1000)
        # Several intervals after genesis.
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        current_time = float(genesis) + 5 * interval_secs
        expected_time = Uint64(int(current_time))

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        initial_store = MockStore()
        sync_service = MockSyncService(store=initial_store)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def run_initial_tick() -> None:
            await chain_service._initial_tick()

        asyncio.run(run_initial_tick())

        # Store should have been replaced and ticked once.
        assert sync_service.store is not initial_store
        assert sync_service.store.tick_calls == [(expected_time, False)]

    def test_initial_tick_at_exact_genesis(self) -> None:
        """
        Initial tick is executed when current time equals genesis.

        At genesis, the network is active and the store should be initialized.
        """
        genesis = Uint64(1000)
        current_time = float(genesis)  # Exactly at genesis
        expected_time = Uint64(int(current_time))

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        initial_store = MockStore()
        sync_service = MockSyncService(store=initial_store)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def run_initial_tick() -> None:
            await chain_service._initial_tick()

        asyncio.run(run_initial_tick())

        # Store should have been replaced and ticked once.
        assert sync_service.store is not initial_store
        assert sync_service.store.tick_calls == [(expected_time, False)]


class TestIntervalTracking:
    """Tests for the last_handled_total_interval tracking logic."""

    def test_does_not_reprocess_same_interval(self) -> None:
        """
        Same interval is not processed twice when processing is fast.

        The last_handled_total_interval tracks which interval was last processed
        to prevent duplicate ticks if the service finishes before the next boundary.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        # Halfway into second interval (stays constant).
        current_time = float(genesis) + interval_secs + interval_secs / 2
        expected_time = Uint64(int(current_time))

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        sleep_call_count = 0

        async def count_sleeps_and_stop(_duration: float) -> None:
            nonlocal sleep_call_count
            sleep_call_count += 1
            # After several sleep calls, stop the service.
            # If deduplication works, we should see sleeps but not extra ticks.
            if sleep_call_count >= 3:
                chain_service.stop()

        async def run_test() -> None:
            with patch("asyncio.sleep", new=count_sleeps_and_stop):
                await chain_service.run()

        asyncio.run(run_test())

        # Only the initial tick happens.
        # The interval tracking prevents redundant ticks for the same interval.
        assert sync_service.store.tick_calls == [(expected_time, False)]


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_genesis_time_zero(self) -> None:
        """
        Works correctly with genesis_time of 0.

        This tests the boundary condition of Unix epoch as genesis.
        """
        genesis = Uint64(0)
        current_time = 5 * (float(MILLISECONDS_PER_INTERVAL) / 1000.0)
        expected_time = Uint64(int(current_time))

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def stop_immediately(_duration: float) -> None:
            chain_service.stop()

        async def run_once() -> None:
            with patch("asyncio.sleep", new=stop_immediately):
                await chain_service.run()

        asyncio.run(run_once())

        # Initial tick handles the interval, main loop recognizes it and waits.
        assert sync_service.store.tick_calls == [(expected_time, False)]

    def test_large_genesis_time(self) -> None:
        """
        Works with realistic Unix timestamp genesis times.

        Tests that large integer arithmetic works correctly.
        """
        genesis = Uint64(1700000000)  # Nov 2023
        current_time = float(genesis) + 100 * (float(MILLISECONDS_PER_INTERVAL) / 1000.0) + 0.5
        expected_time = Uint64(int(current_time))

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def stop_immediately(_duration: float) -> None:
            chain_service.stop()

        async def run_once() -> None:
            with patch("asyncio.sleep", new=stop_immediately):
                await chain_service.run()

        asyncio.run(run_once())

        # Initial tick handles the interval, main loop recognizes it and waits.
        assert sync_service.store.tick_calls == [(expected_time, False)]

    def test_stop_during_sleep(self) -> None:
        """
        Service exits cleanly when stopped during sleep.

        The running flag is checked after each sleep to enable graceful shutdown.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        current_time = float(genesis) + 5 * interval_secs
        expected_time = Uint64(int(current_time))

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def stop_during_sleep(_duration: float) -> None:
            # Simulate stop being called while sleeping.
            chain_service.stop()

        async def run_test() -> None:
            with patch("asyncio.sleep", new=stop_during_sleep):
                await chain_service.run()

        asyncio.run(run_test())

        # Service should have stopped cleanly.
        assert chain_service.is_running is False

        # Only initial tick happens before stop.
        assert sync_service.store.tick_calls == [(expected_time, False)]
