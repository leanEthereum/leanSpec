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
    """Source of wall-clock time and interval boundaries."""

    spec: LstarSpec = field(default_factory=LstarSpec)
    """Fork spec driving consensus methods."""

    _running: bool = field(default=False, repr=False)
    """Whether the service is running."""

    async def run(self) -> None:
        """Tick the store forward at each interval boundary, until stopped."""
        self._running = True

        # Catch the store time up to the wall clock before looping.
        # Otherwise stale store time makes attestation validation reject valid votes.
        last_handled_total_interval = await self._initial_tick()

        while self._running:
            total_interval = self.clock.total_intervals()

            # Wait when no new interval is due yet.
            # Before genesis the clock sleeps straight through to it.
            # A frozen clock past startup reports the same interval, so keep waiting.
            if (
                self.clock.current_time() < self.clock.genesis_time
                or total_interval <= last_handled_total_interval
            ):
                await self.clock.sleep_until_next_interval()
                continue

            # This service only follows the chain; proposing needs validator keys.
            new_aggregated_attestations = await self._tick_to(total_interval)

            # Offline runs and tests wire no publisher, so guard on its presence.
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
        Advance the store to the target interval, one interval at a time.

        Skip stale intervals when far behind so synchronous ticking never starves gossip.
        Returns the aggregated attestations produced along the way.
        """
        store = self.sync_service.store
        all_new_aggregates: list[SignedAggregatedAttestation] = []

        # The target comes from the wall clock, which can step backward.
        # NTP slew, a leap second, or a VM migration can move it before the store time.
        # A backward target would tick nothing, so return early.
        if target_interval <= store.time:
            return []

        # Skip stale intervals when falling behind.
        # Jump to the last full slot boundary before the target.
        # The final slot still runs normally.
        # That preserves aggregation, safe target, and attestation acceptance.
        #
        # Acceptance for the jumped slots waits for the final slot's tick.
        # That is safe: acceptance only merges into a monotone pool.
        # The head recomputes from scratch, so nothing is lost by waiting.
        if target_interval - store.time > Interval(INTERVALS_PER_SLOT):
            store = store.model_copy(
                update={"time": target_interval - Interval(INTERVALS_PER_SLOT)}
            )

        # Tick the remaining intervals one at a time.
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

    async def _initial_tick(self) -> Interval:
        """Catch up store time to the wall clock at startup."""
        if self.clock.current_time() < self.clock.genesis_time:
            return Interval(0)

        # Discard the aggregates: at startup we may be many slots behind.
        # Publishing those stale aggregations would spam the network.
        target_interval = self.clock.total_intervals()
        await self._tick_to(target_interval)
        return target_interval

    def stop(self) -> None:
        """Stop the service; the loop exits after its current sleep finishes."""
        self._running = False

    @property
    def is_running(self) -> bool:
        """Whether the service is currently running."""
        return self._running
