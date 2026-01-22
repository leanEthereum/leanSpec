"""
Chain service that drives consensus timing.

The Chain Problem
-----------------
Ethereum consensus runs on a clock. Every 4 seconds (1 slot), validators:
- Interval 0: Propose blocks
- Interval 1: Create attestations
- Interval 2: Update safe target
- Interval 3: Accept attestations into fork choice

The Store has all this logic built in. But nothing drives the clock.
ChainService is that driver - a simple timer loop.

How It Works
------------
1. Sleep until next interval boundary
2. Get current wall-clock time
3. Tick the store forward to current time
4. Update the sync service with the new store state
5. Repeat forever
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from lean_spec.subspecs.sync import SyncService

from .clock import Interval, SlotClock

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ChainService:
    """
    Drives the consensus clock by periodically ticking the forkchoice store.

    ChainService is the heartbeat of a consensus client. It ensures time
    advances in the Store, triggering interval-specific actions like
    attestation acceptance and safe target updates.

    The service is intentionally minimal:
    - Timer loop that wakes every interval
    - Ticks the store forward to current time
    - Updates the sync service's store reference
    """

    sync_service: SyncService
    """Sync service whose store we tick."""

    clock: SlotClock
    """Clock for time calculation."""

    _running: bool = field(default=False, repr=False)
    """Whether the service is running."""

    async def run(self) -> None:
        """
        Main loop - tick the store every interval.

        This is the core of the chain service. It runs forever, sleeping
        until each interval boundary and then advancing the store's time.

        The loop continues until the service is stopped.

        NOTE: We track the last handled interval to avoid skipping intervals.
        If processing takes time and we end up in a new interval, we
        handle it immediately instead of sleeping past it.
        """
        self._running = True

        # Catch up store time to current wall clock (post-genesis only).
        #
        # - Before genesis, returns None; the main loop handles the wait.
        # - After genesis, this ensures attestation validation accepts valid attestations
        # (the store's time would otherwise lag behind wall-clock).
        last_handled_total_interval = await self._initial_tick()

        while self._running:
            # Get current wall-clock time.
            current_time = self.clock.current_time()
            genesis_time = self.clock.genesis_time

            # Wait for genesis if we're before it.
            if current_time < genesis_time:
                sleep_duration = int(genesis_time) - int(current_time)
                await asyncio.sleep(sleep_duration)
                continue

            # Get current total interval count.
            total_interval = self.clock.total_intervals()

            # If we've already handled this interval, sleep until the next boundary.
            already_handled = (
                last_handled_total_interval is not None
                and total_interval <= last_handled_total_interval
            )
            if already_handled:
                await self._sleep_until_next_interval()
                # Check if stopped during sleep.
                if not self._running:
                    break
                # Re-fetch interval after sleep.
                #
                # If still the same (e.g., time didn't advance),
                # skip this iteration to avoid duplicate ticks.
                total_interval = self.clock.total_intervals()
                if total_interval <= last_handled_total_interval:
                    continue

            # Get current wall-clock time as Unix timestamp (may have changed after sleep).
            #
            # The store expects an absolute timestamp, not intervals.
            # It internally converts to intervals.
            current_time = self.clock.current_time()

            # Tick the store forward to current time.
            #
            # The store advances time interval by interval, performing
            # appropriate actions at each interval.
            #
            # This minimal service does not produce blocks.
            # Block production requires validator keys.
            new_store = self.sync_service.store.on_tick(
                time=current_time,
                has_proposal=False,
            )

            # Update sync service's store reference.
            #
            # SyncService owns the authoritative store. After ticking,
            # we update its reference so gossip block processing sees
            # the updated time.
            self.sync_service.store = new_store

            logger.info(
                "Tick: slot=%d interval=%d time=%d head=%s finalized=slot%d",
                self.clock.current_slot(),
                self.clock.total_intervals(),
                current_time,
                new_store.head.hex(),
                new_store.latest_finalized.slot,
            )

            # Mark this interval as handled.
            last_handled_total_interval = total_interval

    async def _initial_tick(self) -> Interval | None:
        """
        Perform initial tick to catch up store time to current wall clock.

        This is called once at startup to ensure the store's time reflects
        actual wall clock time, not just the genesis anchor time.

        Returns the interval that was handled, or None if before genesis.
        """
        current_time = self.clock.current_time()

        # Only tick if we're past genesis.
        if current_time >= self.clock.genesis_time:
            new_store = self.sync_service.store.on_tick(
                time=current_time,
                has_proposal=False,
            )
            self.sync_service.store = new_store
            return self.clock.total_intervals()

        return None

    async def _sleep_until_next_interval(self) -> None:
        """
        Sleep until the next interval boundary.

        Uses the clock to calculate precise sleep duration, ensuring tick
        timing is aligned with network consensus expectations.
        """
        sleep_time = self.clock.seconds_until_next_interval()
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)

    def stop(self) -> None:
        """
        Stop the service.

        Sets the running flag to False, causing the run() loop to exit
        after completing its current sleep cycle.
        """
        self._running = False

    @property
    def is_running(self) -> bool:
        """Check if the service is currently running."""
        return self._running
