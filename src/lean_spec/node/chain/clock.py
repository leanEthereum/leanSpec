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
        now_milliseconds = int(self.time_fn() * 1000)
        genesis_milliseconds = int(self.genesis_time) * 1000

        # Before genesis, the next boundary is genesis itself.
        if now_milliseconds < genesis_milliseconds:
            return (genesis_milliseconds - now_milliseconds) / 1000.0

        # Position within the current interval, off the shared millisecond
        # time-base that every other accessor on this clock uses.
        milliseconds_into_interval = int(self._milliseconds_since_genesis()) % int(
            MILLISECONDS_PER_INTERVAL
        )

        # Remaining milliseconds until the boundary.
        #
        # A full interval when already exactly on a boundary.
        milliseconds_until_next_interval = (
            int(MILLISECONDS_PER_INTERVAL) - milliseconds_into_interval
        )
        return milliseconds_until_next_interval / 1000.0

    async def sleep_until_next_interval(self) -> None:
        """Sleep until the next interval boundary."""
        sleep_time = self.seconds_until_next_interval()
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
