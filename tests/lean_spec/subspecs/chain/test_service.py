"""Tests for the ChainService consensus clock driver."""

from __future__ import annotations

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
    """Mock store that tracks tick_interval calls."""

    time: Uint64 = field(default_factory=lambda: Uint64(0))
    tick_calls: list[tuple[Uint64, bool]] = field(default_factory=list)
    head: Bytes32 = field(default_factory=lambda: ZERO_HASH)
    latest_finalized: MockCheckpoint = field(default_factory=MockCheckpoint)

    def tick_interval(
        self, has_proposal: bool, is_aggregator: bool = False
    ) -> tuple[MockStore, list]:
        """Record the tick call, advance time by one interval, and return a new store."""
        new_time = self.time + Uint64(1)
        new_store = MockStore(
            time=new_time,
            tick_calls=[*self.tick_calls, (new_time, has_proposal)],
            head=self.head,
            latest_finalized=self.latest_finalized,
        )
        return new_store, []

    def model_copy(self, *, update: dict) -> MockStore:
        """Return a copy with updated fields."""
        return MockStore(
            time=update.get("time", self.time),
            tick_calls=list(self.tick_calls),
            head=update.get("head", self.head),
            latest_finalized=update.get("latest_finalized", self.latest_finalized),
        )


@dataclass
class MockSyncService:
    """Mock sync service for testing ChainService."""

    store: MockStore = field(default_factory=MockStore)
    is_aggregator: bool = False
    published_aggregations: list = field(default_factory=list)

    async def publish_aggregated_attestation(self, agg: object) -> None:
        """Record published aggregations."""
        self.published_aggregations.append(agg)


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

    async def test_run_sets_running_flag(self) -> None:
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

        with patch("asyncio.sleep", new=stop_on_second_call):
            await chain_service.run()

        # After stopping, flag should be False.
        assert chain_service.is_running is False


class TestIntervalTiming:
    """Tests for interval boundary timing."""

    async def test_sleep_calculation_mid_interval(self) -> None:
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

        with patch("asyncio.sleep", new=capture_sleep):
            await chain_service._sleep_until_next_interval()

        # Should sleep until next interval boundary.
        expected = float(genesis) + interval_secs - current_time
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.002  # floating-point tolerance

    async def test_sleep_at_interval_boundary(self) -> None:
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

        with patch("asyncio.sleep", new=capture_sleep):
            await chain_service._sleep_until_next_interval()

        # At boundary, next boundary is one full interval away.
        expected = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001

    async def test_sleep_before_genesis(self) -> None:
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

        with patch("asyncio.sleep", new=capture_sleep):
            await chain_service._sleep_until_next_interval()

        # Should sleep until genesis.
        expected = float(genesis) - current_time
        assert captured_duration is not None
        assert abs(captured_duration - expected) < 0.001


class TestStoreTicking:
    """Tests for store tick integration."""

    async def test_ticks_store_with_current_interval(self) -> None:
        """
        Store receives the current interval count on tick.

        The chain service passes intervals (not seconds) so the store
        can advance time without lossy seconds→intervals conversion.
        """
        genesis = Uint64(1000)
        # 5 intervals after genesis = 5 * 800ms = 4.0 seconds.
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        current_time = float(genesis) + 5 * interval_secs

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        call_count = 0

        async def stop_on_second_call(_duration: float) -> None:
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                chain_service.stop()

        with patch("asyncio.sleep", new=stop_on_second_call):
            await chain_service.run()

        # Initial tick handles all 5 intervals (0→1, 1→2, ..., 4→5).
        # Main loop recognizes the interval was handled and waits.
        expected_ticks = [(Uint64(i), False) for i in range(1, 6)]
        assert sync_service.store.tick_calls == expected_ticks

    async def test_has_proposal_always_false(self) -> None:
        """
        has_proposal is always False for this minimal service.

        Block production requires validator keys, which this service does not handle.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        current_time = float(genesis) + 5 * interval_secs

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        tick_count = 0

        async def stop_after_three(_duration: float) -> None:
            nonlocal tick_count
            tick_count += 1
            if tick_count >= 3:
                chain_service.stop()

        with patch("asyncio.sleep", new=stop_after_three):
            await chain_service.run()

        # All ticks have has_proposal=False.
        assert all(proposal is False for _, proposal in sync_service.store.tick_calls)

    async def test_sync_service_store_updated(self) -> None:
        """
        SyncService.store is replaced with new store after each tick.

        The Store uses immutable updates, so each tick creates a new instance.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        current_time = float(genesis) + 5 * interval_secs

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        initial_store = MockStore()
        sync_service = MockSyncService(store=initial_store)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        # No ticks before our first run.
        assert sync_service.store.tick_calls == []

        async def stop_immediately(_duration: float) -> None:
            chain_service.stop()

        with patch("asyncio.sleep", new=stop_immediately):
            await chain_service.run()

        # Store should have been replaced.
        assert sync_service.store is not initial_store

        # Initial tick handles all 5 intervals.
        assert sync_service.store.time == Uint64(5)


class TestMultipleIntervals:
    """Tests for running through multiple intervals."""

    async def test_advances_through_intervals(self) -> None:
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

        with patch("asyncio.sleep", new=advance_and_stop):
            await chain_service.run()

        # Initial tick at interval 1, then main loop ticks at 2, 3, 4.
        # Each _tick_to call ticks exactly one interval (gap=1 each time).
        assert sync_service.store.tick_calls == [
            (Uint64(1), False),
            (Uint64(2), False),
            (Uint64(3), False),
            (Uint64(4), False),
        ]


class TestInitialTick:
    """Tests for the initial tick behavior at startup."""

    async def test_initial_tick_skipped_before_genesis(self) -> None:
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
        await chain_service._initial_tick()

        # Store should not have been ticked.
        assert sync_service.store is initial_store
        assert sync_service.store.tick_calls == []

    async def test_initial_tick_executed_after_genesis(self) -> None:
        """
        Initial tick advances store time when past genesis.

        This ensures attestation validation works immediately on startup.
        """
        genesis = Uint64(1000)
        # 5 intervals after genesis = 5 * 800ms = 4.0 seconds.
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        current_time = float(genesis) + 5 * interval_secs

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        initial_store = MockStore()
        sync_service = MockSyncService(store=initial_store)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        await chain_service._initial_tick()

        # Store should have been replaced and ticked through all 5 intervals.
        assert sync_service.store is not initial_store
        assert sync_service.store.time == Uint64(5)
        assert len(sync_service.store.tick_calls) == 5

    async def test_initial_tick_at_exact_genesis(self) -> None:
        """
        Initial tick is executed when current time equals genesis.

        At genesis, the network is active and the store should be initialized.
        """
        genesis = Uint64(1000)
        current_time = float(genesis)  # Exactly at genesis

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        initial_store = MockStore()
        sync_service = MockSyncService(store=initial_store)
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        await chain_service._initial_tick()

        # At interval 0, no ticks needed (store already at time=0).
        assert sync_service.store.time == Uint64(0)
        assert sync_service.store.tick_calls == []

    async def test_initial_tick_skips_stale_intervals(self) -> None:
        """
        Initial tick skips stale intervals when far behind genesis.

        When the gap exceeds one slot, only the last slot's worth of
        intervals is processed. This prevents event loop starvation.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        # 20 intervals after genesis (4 full slots).
        current_time = float(genesis) + 20 * interval_secs

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        await chain_service._initial_tick()

        # Gap=20 > INTERVALS_PER_SLOT(5), so skip to interval 15.
        # Only last 5 intervals are ticked (15→16, ..., 19→20).
        assert sync_service.store.time == Uint64(20)
        assert len(sync_service.store.tick_calls) == 5
        assert sync_service.store.tick_calls[0] == (Uint64(16), False)
        assert sync_service.store.tick_calls[-1] == (Uint64(20), False)


class TestIntervalTracking:
    """Tests for the last_handled_total_interval tracking logic."""

    async def test_does_not_reprocess_same_interval(self) -> None:
        """
        Same interval is not processed twice when processing is fast.

        The last_handled_total_interval tracks which interval was last processed
        to prevent duplicate ticks if the service finishes before the next boundary.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        # Halfway into second interval (stays constant).
        # 1.5 intervals * 800ms = 1200ms. total_intervals = 1200 // 800 = 1.
        current_time = float(genesis) + interval_secs + interval_secs / 2

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

        with patch("asyncio.sleep", new=count_sleeps_and_stop):
            await chain_service.run()

        # Only the initial tick happens (one interval: 0→1).
        # The interval tracking prevents redundant ticks for the same interval.
        assert sync_service.store.tick_calls == [(Uint64(1), False)]


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    async def test_genesis_time_zero(self) -> None:
        """
        Works correctly with genesis_time of 0.

        This tests the boundary condition of Unix epoch as genesis.
        """
        genesis = Uint64(0)
        current_time = 5 * (float(MILLISECONDS_PER_INTERVAL) / 1000.0)

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def stop_immediately(_duration: float) -> None:
            chain_service.stop()

        with patch("asyncio.sleep", new=stop_immediately):
            await chain_service.run()

        # Initial tick advances through 5 intervals.
        assert sync_service.store.time == Uint64(5)
        assert len(sync_service.store.tick_calls) == 5

    async def test_large_genesis_time(self) -> None:
        """
        Works with realistic Unix timestamp genesis times.

        Tests that large integer arithmetic works correctly.
        """
        genesis = Uint64(1700000000)  # Nov 2023
        # 100 intervals = 80s, plus 0.5s mid-interval offset.
        # total_intervals = int(80.5 * 1000) // 800 = 80500 // 800 = 100.
        current_time = float(genesis) + 100 * (float(MILLISECONDS_PER_INTERVAL) / 1000.0) + 0.5

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def stop_immediately(_duration: float) -> None:
            chain_service.stop()

        with patch("asyncio.sleep", new=stop_immediately):
            await chain_service.run()

        # Gap=100 > INTERVALS_PER_SLOT(5), so stale intervals are skipped.
        # Only the last 5 intervals are ticked (96→97, ..., 99→100).
        assert sync_service.store.time == Uint64(100)
        assert len(sync_service.store.tick_calls) == 5

    async def test_stop_during_sleep(self) -> None:
        """
        Service exits cleanly when stopped during sleep.

        The running flag is checked after each sleep to enable graceful shutdown.
        """
        genesis = Uint64(1000)
        interval_secs = float(MILLISECONDS_PER_INTERVAL) / 1000.0
        current_time = float(genesis) + 5 * interval_secs

        clock = SlotClock(genesis_time=genesis, time_fn=lambda: current_time)
        sync_service = MockSyncService()
        chain_service = ChainService(sync_service=sync_service, clock=clock)  # type: ignore[arg-type]

        async def stop_during_sleep(_duration: float) -> None:
            # Simulate stop being called while sleeping.
            chain_service.stop()

        with patch("asyncio.sleep", new=stop_during_sleep):
            await chain_service.run()

        # Service should have stopped cleanly.
        assert chain_service.is_running is False

        # Initial tick handles all 5 intervals even though stop is called
        # during the yield sleeps (stop only checked in main loop).
        assert sync_service.store.time == Uint64(5)
