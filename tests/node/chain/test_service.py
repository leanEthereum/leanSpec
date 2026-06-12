"""Tests for the ChainService consensus clock driver."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from unittest.mock import patch

import pytest

from consensus_testing import make_genesis_store
from lean_spec.node.chain import SlotClock
from lean_spec.node.chain.service import ChainService
from lean_spec.spec.forks import Checkpoint, Interval, LstarSpec, Slot
from lean_spec.spec.forks.lstar.config import INTERVALS_PER_SLOT, MILLISECONDS_PER_INTERVAL
from lean_spec.spec.forks.lstar.containers import (
    AggregationBits,
    AttestationData,
    SignedAggregatedAttestation,
    SingleMessageAggregate,
    Store,
)
from lean_spec.spec.ssz import Boolean, ByteList512KiB, Bytes32, Uint64

# One interval lasts this many wall-clock seconds.
#
# Tests express time as a multiple of it so the millisecond math stays readable.
INTERVAL_SECONDS = float(MILLISECONDS_PER_INTERVAL) / 1000.0


def make_aggregate(seed: int) -> SignedAggregatedAttestation:
    """Build a distinct aggregated attestation cheaply, without signing keys."""
    # The driver treats the aggregate as an opaque payload.
    # The seed only makes separate instances compare unequal.
    return SignedAggregatedAttestation(
        data=AttestationData(
            slot=Slot(2),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(2)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(2)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        ),
        proof=SingleMessageAggregate(
            participants=AggregationBits(data=[Boolean(True)]),
            proof=ByteList512KiB(data=bytes([seed])),
        ),
    )


class ProbeSpec(LstarSpec):
    """Real spec that records each tick so a test can see what the driver did."""

    def __init__(self, emit: list[SignedAggregatedAttestation] | None = None) -> None:
        """Begin with an empty tick log and remember the aggregates to emit, if any."""
        super().__init__()
        self.ticks: list[tuple[int, bool, bool]] = []
        self.emit = emit or []

    def tick_interval(
        self, store: Store, has_proposal: bool, is_aggregator: bool = False
    ) -> tuple[Store, list[SignedAggregatedAttestation]]:
        """Advance the real store, record the call, then emit at the aggregation interval."""
        # Delegate to the real spec so the store advances exactly as in production.
        # Discard its real aggregates; this stub substitutes its own below.
        store, _ = super().tick_interval(store, has_proposal, is_aggregator)

        # Record after the tick, so the logged time is the post-tick value.
        self.ticks.append((int(store.time), has_proposal, is_aggregator))

        # A real aggregator builds its proof at interval 2 of each slot.
        at_aggregation_interval = int(store.time) % int(INTERVALS_PER_SLOT) == 2

        # Emit the configured aggregates only there, and nothing on other intervals.
        return store, self.emit if at_aggregation_interval else []


class PublishRecorder:
    """Async publisher that records every aggregate the driver hands it."""

    def __init__(self) -> None:
        """Begin with an empty record of received aggregates."""
        self.received: list[SignedAggregatedAttestation] = []

    async def __call__(self, aggregate: SignedAggregatedAttestation) -> None:
        """Record one published aggregate."""
        self.received.append(aggregate)


@dataclass
class SyncServiceStub:
    """Minimal stand-in exposing only what the driver reads from the sync service."""

    store: Store
    """Forkchoice store the driver ticks forward."""

    is_aggregator: bool = False
    """Whether the node acts as an aggregator."""

    publish_aggregated_attestation: (
        Callable[[SignedAggregatedAttestation], Coroutine[None, None, None]] | None
    ) = None
    """Callback for produced aggregates, or nothing when no publisher is wired."""


def make_service(
    spec: ProbeSpec,
    *,
    genesis_seconds: int = 1000,
    time_fn: Callable[[], float] | None = None,
    is_aggregator: bool = False,
    publisher: Callable[[SignedAggregatedAttestation], Coroutine[None, None, None]] | None = None,
) -> ChainService:
    """
    Assemble a chain service over a real store with a controllable clock.

    The clock defaults to a fixed reading at genesis.
    That suits tests calling the catch-up helpers directly, which never advance time.

    Args:
        spec: Recording spec the driver ticks each interval.
        genesis_seconds: Genesis time in seconds, shared by the store and the clock.
        time_fn: Wall-clock source; defaults to a fixed reading at genesis.
        is_aggregator: Whether the node acts as an aggregator.
        publisher: Callback for produced aggregates, or nothing to drop them.

    Returns:
        A chain service wired to the stub sync service and the clock.
    """
    sync_service = SyncServiceStub(
        store=make_genesis_store(genesis_time=genesis_seconds),
        is_aggregator=is_aggregator,
        publish_aggregated_attestation=publisher,
    )
    clock = SlotClock(
        genesis_time=Uint64(genesis_seconds),
        time_fn=time_fn or (lambda: float(genesis_seconds)),
    )
    # The stub supplies the members the driver uses, but is not a nominal sync service.
    return ChainService(sync_service=sync_service, clock=clock, spec=spec)  # type: ignore[arg-type]


class TestCatchUp:
    """Tests for the catch-up helper that walks the store to a target interval."""

    @pytest.mark.parametrize(
        ("target", "expected_tick_times"),
        [
            # Already at the target: nothing to do.
            (0, []),
            # Within one slot: every interval ticks.
            (3, [1, 2, 3]),
            # Exactly one slot behind: still no skip.
            (5, [1, 2, 3, 4, 5]),
            # Just over one slot: the first interval is skipped.
            (6, [2, 3, 4, 5, 6]),
            # Four slots behind: whole stale slots are skipped, only the last slot ticks.
            (20, [16, 17, 18, 19, 20]),
            # Twenty slots behind: the skip math holds at scale, still one slot of ticks.
            (100, [96, 97, 98, 99, 100]),
        ],
    )
    async def test_advances_and_skips_stale_intervals(
        self, target: int, expected_tick_times: list[int]
    ) -> None:
        """Catch-up reaches the target, skipping stale intervals beyond one slot."""
        spec = ProbeSpec()
        service = make_service(spec)
        await service._tick_to(Interval(target))
        assert [time for time, _, _ in spec.ticks] == expected_tick_times
        assert int(service.sync_service.store.time) == target

    async def test_never_proposes_and_forwards_aggregator_flag(self) -> None:
        """Each tick reports no proposal and forwards the configured aggregator flag."""
        spec = ProbeSpec()
        service = make_service(spec, is_aggregator=True)
        await service._tick_to(Interval(3))
        assert spec.ticks == [(1, False, True), (2, False, True), (3, False, True)]

    async def test_clamps_a_backward_wall_clock_target_to_a_no_op(self) -> None:
        """A target before the store time ticks nothing and yields no aggregates."""
        spec = ProbeSpec()
        service = make_service(spec)
        # A backward wall clock can target an interval the store already passed.
        service.sync_service.store = service.sync_service.store.model_copy(
            update={"time": Interval(5)}
        )
        produced_aggregates = await service._tick_to(Interval(3))
        assert produced_aggregates == []
        assert spec.ticks == []
        assert int(service.sync_service.store.time) == 5

    async def test_clamps_a_target_equal_to_the_current_time_to_a_no_op(self) -> None:
        """A target equal to the store time ticks nothing and yields no aggregates."""
        spec = ProbeSpec()
        service = make_service(spec)
        service.sync_service.store = service.sync_service.store.model_copy(
            update={"time": Interval(5)}
        )
        produced_aggregates = await service._tick_to(Interval(5))
        assert produced_aggregates == []
        assert spec.ticks == []
        assert int(service.sync_service.store.time) == 5

    async def test_continues_on_a_store_swapped_in_during_the_yield(self) -> None:
        """A store replaced mid-catch-up is picked up on the next tick, not the stale one."""
        service = make_service(ProbeSpec())

        # Stand in for a gossip handler that processes a block during the yield.
        # It installs a fresh store object, which the driver must continue from.
        #
        # The swapped store carries a distinctive genesis time so the final store
        # can be traced back to it rather than to the stale original object.
        swapped = make_genesis_store(genesis_time=2000, time=Interval(1))
        swap = {"done": False}

        async def swap_store_once(duration: float) -> None:
            if not swap["done"]:
                swap["done"] = True
                service.sync_service.store = swapped

        with patch("asyncio.sleep", new=swap_store_once):
            await service._tick_to(Interval(3))

        # The final store descends from the swapped object, proving the post-yield
        # re-read: it carries the swapped genesis time and reaches the target time.
        final_store = service.sync_service.store
        assert final_store.config.genesis_time == Uint64(2000)
        assert int(final_store.time) == 3


class TestStartupTick:
    """Tests for the one-shot catch-up performed at startup."""

    @pytest.mark.parametrize(
        ("intervals_elapsed", "expected_interval", "expected_tick_times"),
        [
            # Before genesis: nothing ticks, the caller waits.
            (-0.5, None, []),
            # Exactly at genesis: the store already sits at the anchor.
            (0.0, Interval(0), []),
            # One slot in: five ticks, no skip.
            (5.0, Interval(5), [1, 2, 3, 4, 5]),
            # Four slots behind: stale intervals are skipped.
            (20.0, Interval(20), [16, 17, 18, 19, 20]),
        ],
    )
    async def test_catches_store_up_to_wall_clock(
        self,
        intervals_elapsed: float,
        expected_interval: Interval | None,
        expected_tick_times: list[int],
    ) -> None:
        """Startup ticks the store to the current interval, or reports waiting if pre-genesis."""
        spec = ProbeSpec()
        now = 1000 + intervals_elapsed * INTERVAL_SECONDS
        service = make_service(spec, time_fn=lambda: now)
        initial_tick_interval = await service._initial_tick()
        assert initial_tick_interval == expected_interval
        assert [time for time, _, _ in spec.ticks] == expected_tick_times

    async def test_discards_aggregates_produced_during_catch_up(self) -> None:
        """Aggregates emitted while catching up are dropped, not published."""
        recorder = PublishRecorder()
        service = make_service(
            ProbeSpec(emit=[make_aggregate(1)]),
            time_fn=lambda: 1000 + 5 * INTERVAL_SECONDS,
            is_aggregator=True,
            publisher=recorder,
        )
        await service._initial_tick()
        assert recorder.received == []


@dataclass
class IntervalClock:
    """Wall clock that advances one interval each time the loop waits."""

    genesis_seconds: int
    interval: int

    def __call__(self) -> float:
        # Land mid-interval so floating-point jitter never crosses a boundary.
        return self.genesis_seconds + (self.interval + 0.5) * INTERVAL_SECONDS

    def advance(self) -> None:
        """Move the clock forward by one interval."""
        self.interval += 1


async def run_for_waits(service: ChainService, *, waits: int = 1) -> None:
    """Run the loop with a frozen clock, stopping after the given number of boundary waits."""
    count = 0

    async def stop_after_waits(duration: float) -> None:
        nonlocal count
        # Zero-duration sleeps are the tick loop yielding, not interval boundaries.
        if duration <= 0:
            return
        count += 1
        if count >= waits:
            service.stop()

    with patch("asyncio.sleep", new=stop_after_waits):
        await service.run()


async def run_advancing(
    service: ChainService, clock: IntervalClock, *, stop_at_interval: int
) -> None:
    """Run the loop, advancing the clock one interval per wait, until the target interval."""

    async def advance_then_maybe_stop(duration: float) -> None:
        # Ignore the zero-duration yields inside the tick loop.
        if duration <= 0:
            return
        clock.advance()
        if clock.interval >= stop_at_interval:
            service.stop()

    with patch("asyncio.sleep", new=advance_then_maybe_stop):
        await service.run()


class TestRunLoop:
    """Tests for the run loop that drives catch-up at each interval boundary."""

    def test_starts_not_running(self) -> None:
        """A freshly built service reports that it is not running."""
        assert make_service(ProbeSpec()).is_running is False

    def test_stop_clears_running_flag(self) -> None:
        """Stopping a running service flips the flag back to not running."""
        service = make_service(ProbeSpec())
        service._running = True
        assert service.is_running is True
        service.stop()
        assert service.is_running is False

    async def test_run_then_stop_leaves_not_running(self) -> None:
        """The run loop clears the running flag once stopped."""
        service = make_service(ProbeSpec(), time_fn=lambda: 1000 + INTERVAL_SECONDS)
        await run_for_waits(service)
        assert service.is_running is False

    async def test_does_not_tick_before_genesis(self) -> None:
        """Before genesis the loop only waits, never ticking the store."""
        spec = ProbeSpec()
        service = make_service(spec, time_fn=lambda: 900.0)
        await run_for_waits(service)
        assert spec.ticks == []

    async def test_does_not_retick_an_already_handled_interval(self) -> None:
        """A frozen clock past startup yields repeated waits but no extra ticks."""
        spec = ProbeSpec()
        # 1.5 intervals in: the total interval count truncates to 1.
        service = make_service(spec, time_fn=lambda: 1000 + 1.5 * INTERVAL_SECONDS)
        await run_for_waits(service, waits=3)
        assert [time for time, _, _ in spec.ticks] == [1]

    async def test_waits_for_genesis_then_starts_ticking(self) -> None:
        """A service started before genesis ticks once the clock crosses genesis."""
        spec = ProbeSpec()
        # Interval -1 sits before genesis; each wait advances toward and past it.
        clock = IntervalClock(genesis_seconds=1000, interval=-1)
        service = make_service(spec, time_fn=clock)
        await run_advancing(service, clock, stop_at_interval=2)
        assert [time for time, _, _ in spec.ticks] == [1]

    async def test_publishes_aggregates_produced_in_the_loop(self) -> None:
        """Aggregates produced by a steady-state tick reach the publisher in order."""
        recorder = PublishRecorder()
        first, second = make_aggregate(1), make_aggregate(2)
        clock = IntervalClock(genesis_seconds=1000, interval=1)
        service = make_service(
            ProbeSpec(emit=[first, second]), time_fn=clock, is_aggregator=True, publisher=recorder
        )
        await run_advancing(service, clock, stop_at_interval=3)
        assert recorder.received == [first, second]

    async def test_tolerates_missing_publisher(self) -> None:
        """A produced aggregate with no publisher wired does not raise."""
        spec = ProbeSpec(emit=[make_aggregate(1)])
        clock = IntervalClock(genesis_seconds=1000, interval=1)
        service = make_service(spec, time_fn=clock, is_aggregator=True, publisher=None)
        await run_advancing(service, clock, stop_at_interval=3)
        assert [time for time, _, _ in spec.ticks] == [1, 2]
