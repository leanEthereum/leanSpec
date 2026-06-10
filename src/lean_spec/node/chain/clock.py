"""Slot clock."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from time import time as wall_time

from lean_spec.spec.forks import Interval, Slot
from lean_spec.spec.forks.lstar.config import (
    MILLISECONDS_PER_INTERVAL,
    MILLISECONDS_PER_SLOT,
)
from lean_spec.spec.ssz import Uint64


@dataclass(frozen=True, slots=True)
class SlotClock:
    """Converts wall-clock time to consensus slots and intervals."""

    genesis_time: Uint64
    """Unix timestamp (seconds) when slot 0 began."""

    time_fn: Callable[[], float] = wall_time
    """Time source function (injectable for testing)."""

    def _milliseconds_since_genesis(self) -> Uint64:
        """Milliseconds elapsed since genesis (0 if before genesis)."""
        now_ms = int(self.time_fn() * 1000)
        genesis_ms = int(self.genesis_time) * 1000
        if now_ms < genesis_ms:
            return Uint64(0)
        return Uint64(now_ms - genesis_ms)

    def current_slot(self) -> Slot:
        """Get the current slot number (0 if before genesis)."""
        return Slot(self._milliseconds_since_genesis() // MILLISECONDS_PER_SLOT)

    def current_interval(self) -> Interval:
        """Get the current interval within the slot (0-4)."""
        milliseconds_into_slot = self._milliseconds_since_genesis() % MILLISECONDS_PER_SLOT
        return Interval(milliseconds_into_slot // MILLISECONDS_PER_INTERVAL)

    def total_intervals(self) -> Interval:
        """Get total intervals elapsed since genesis."""
        return Interval(self._milliseconds_since_genesis() // MILLISECONDS_PER_INTERVAL)

    def current_time(self) -> Uint64:
        """Get current wall-clock time as Uint64 (Unix timestamp in seconds)."""
        return Uint64(int(self.time_fn()))

    def seconds_until_next_interval(self) -> float:
        """
        Calculate seconds until the next interval boundary.

        - Returns time until genesis if called before genesis.
        - Returns a full interval when exactly on a boundary, never zero.
        """
        now = self.time_fn()
        genesis = int(self.genesis_time)
        elapsed = now - genesis

        if elapsed < 0:
            return -elapsed

        # Position within the current interval, in milliseconds.
        elapsed_ms = int(elapsed * 1000)
        time_into_interval_ms = elapsed_ms % int(MILLISECONDS_PER_INTERVAL)

        # Remaining milliseconds until the boundary.
        #
        # A full interval when already exactly on a boundary.
        ms_until_next = int(MILLISECONDS_PER_INTERVAL) - time_into_interval_ms
        return ms_until_next / 1000.0

    async def sleep_until_next_interval(self) -> None:
        """Sleep until the next interval boundary."""
        sleep_time = self.seconds_until_next_interval()
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
