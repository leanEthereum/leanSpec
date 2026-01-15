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
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lean_spec.types import Uint64

from .clock import SlotClock
from .config import SECONDS_PER_INTERVAL

if TYPE_CHECKING:
    from lean_spec.subspecs.sync import SyncService


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
        """
        self._running = True

        while self._running:
            # Sleep until next interval boundary for precise timing.
            #
            # Interval boundaries occur every SECONDS_PER_INTERVAL (1 second).
            # Sleeping to boundaries ensures consistent tick timing.
            await self._sleep_until_next_interval()

            # Get current wall-clock time as Unix timestamp.
            #
            # The store expects an absolute timestamp, not intervals.
            # It internally converts to intervals.
            current_time = Uint64(int(self.clock._time_fn()))

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

    async def _sleep_until_next_interval(self) -> None:
        """
        Sleep until the next interval boundary.

        Calculates the precise sleep duration to wake up at the start
        of the next interval. This ensures tick timing is aligned with
        network consensus expectations.
        """
        now = self.clock._time_fn()
        genesis = int(self.clock.genesis_time)

        # Time since genesis in seconds (float for precision).
        elapsed = now - genesis

        if elapsed < 0:
            # Before genesis - sleep until genesis.
            await asyncio.sleep(-elapsed)
            return

        # Current interval number (floored to integer).
        current_interval = int(elapsed // int(SECONDS_PER_INTERVAL))

        # Next interval boundary in absolute time.
        next_boundary = genesis + (current_interval + 1) * int(SECONDS_PER_INTERVAL)

        # Sleep duration (may be zero if we're exactly at boundary).
        sleep_time = max(0.0, next_boundary - now)
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
