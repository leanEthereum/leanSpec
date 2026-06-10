"""Chain service that drives consensus timing."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from lean_spec.node.chain.clock import SlotClock
from lean_spec.node.sync import SyncService
from lean_spec.spec.forks import Interval, LstarSpec, SignedAggregatedAttestation
from lean_spec.spec.forks.lstar.config import INTERVALS_PER_SLOT

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ChainService:
    """Drives the consensus clock by periodically ticking the fork choice store."""

    sync_service: SyncService
    """Sync service whose store we tick."""

    clock: SlotClock
    """Clock for time calculation."""

    spec: LstarSpec = field(default_factory=LstarSpec)
    """Fork spec driving consensus methods."""

    _running: bool = field(default=False, repr=False)
    """Whether the service is running."""

    async def run(self) -> None:
        """Tick the store forward at each interval boundary, until stopped."""
        self._running = True

        # Catch up store time to current wall clock.
        # - Before genesis this returns nothing; the loop handles the wait.
        # - After genesis this keeps attestation validation from rejecting valid votes.
        last_handled_total_interval = await self._initial_tick()

        while self._running:
            # Wait for genesis if we are before it.
            # The clock sleeps exactly until genesis when called before it.
            if self.clock.current_time() < self.clock.genesis_time:
                await self.clock.sleep_until_next_interval()
                continue

            total_interval = self.clock.total_intervals()

            # Already handled this interval: sleep to the next boundary.
            already_handled = (
                last_handled_total_interval is not None
                and total_interval <= last_handled_total_interval
            )
            if already_handled:
                await self.clock.sleep_until_next_interval()
                if not self._running:
                    break
                # Time may not have advanced during the sleep.
                # Skip this iteration to avoid ticking the same interval twice.
                total_interval = self.clock.total_intervals()
                if total_interval <= last_handled_total_interval:
                    continue

            # Advance the store to the current interval.
            # This service never proposes; block production needs validator keys.
            new_aggregated_attestations = await self._tick_to(total_interval)

            # No publisher is wired in tests or offline runs, so guard on its presence.
            publish = self.sync_service.publish_aggregated_attestation
            if new_aggregated_attestations and publish is not None:
                for aggregate in new_aggregated_attestations:
                    await publish(aggregate)

            logger.info(
                "Tick: slot=%d interval=%d head=%s finalized=slot%d",
                self.clock.current_slot(),
                total_interval,
                self.sync_service.store.head.hex(),
                self.sync_service.store.latest_finalized.slot,
            )

            last_handled_total_interval = total_interval

    async def _tick_to(self, target_interval: Interval) -> list[SignedAggregatedAttestation]:
        """
        Advance the store to the target interval, skipping stale work and yielding.

        When the node falls behind by more than one slot, stale intervals are skipped.
        Processing every missed interval synchronously blocks the event loop.
        That starves gossip and pushes the node further behind.

        Between remaining ticks, yield so gossip messages can be processed.
        Update the sync service store after each tick so gossip handlers see current time.

        Returns aggregated attestations produced during the ticks.
        """
        store = self.sync_service.store
        all_new_aggregates: list[SignedAggregatedAttestation] = []

        # The target comes from wall clock, so it never moves time backward.
        assert target_interval >= store.time

        # Skip stale intervals when falling behind.
        # Jump to the last full slot boundary before the target.
        # The final slot still runs normally.
        # That preserves aggregation, safe target, and attestation acceptance.
        #
        # Acceptance for the jumped slots waits for the final slot's tick.
        # That is safe: acceptance is a monotone pool merge, and the head recomputes from scratch.
        if target_interval - store.time > Interval(INTERVALS_PER_SLOT):
            store = store.model_copy(
                update={"time": target_interval - Interval(INTERVALS_PER_SLOT)}
            )

        # Tick remaining intervals one at a time.
        while store.time < target_interval:
            store, new_aggregates = self.spec.tick_interval(
                store,
                has_proposal=False,
                is_aggregator=self.sync_service.is_aggregator,
            )
            all_new_aggregates.extend(new_aggregates)
            self.sync_service.store = store

            # Yield to the event loop so gossip handlers can run.
            # Re-read the store: a handler may have added blocks or attestations.
            await asyncio.sleep(0)
            store = self.sync_service.store

        return all_new_aggregates

    async def _initial_tick(self) -> Interval | None:
        """Catch up store time to wall clock at startup."""
        current_time = self.clock.current_time()

        # Only tick once past genesis.
        if current_time >= self.clock.genesis_time:
            target_interval = self.clock.total_intervals()

            # Reuse the skip-and-yield path for catch-up.
            # Discard aggregated attestations from catch-up.
            # During initial sync we may be many slots behind.
            # Publishing stale aggregations would spam the network.
            await self._tick_to(target_interval)

            return target_interval

        return None

    def stop(self) -> None:
        """
        Stop the service.

        The loop exits after its current sleep cycle finishes.
        """
        self._running = False

    @property
    def is_running(self) -> bool:
        """Whether the service is currently running."""
        return self._running
