"""
Slot Clock.

Time-to-slot conversion for Lean Consensus.

The slot clock bridges wall-clock time to the discrete slot-based time
model used by consensus. Every node must agree on slot boundaries to
coordinate block proposals and attestations.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from time import time as wall_time

from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.types import Uint64

from .config import (
    INTERVALS_PER_SLOT,
    MILLISECONDS_PER_INTERVAL,
    MILLISECONDS_PER_SLOT,
    SECONDS_PER_SLOT,
)


class Interval(Uint64):
    """Interval count since genesis (matches `Store.time`)."""

    @classmethod
    def from_unix_time(cls, unix_seconds: Uint64, genesis_time: Uint64) -> Interval:
        """
        Convert a Unix timestamp to a total interval count since genesis.

        Useful when external inputs provide absolute timestamps but the
        store tracks time as intervals (800 ms each, 5 per slot).

        Args:
            unix_seconds: Absolute Unix timestamp in seconds.
            genesis_time: Genesis Unix timestamp in seconds.

        Returns:
            Total intervals elapsed between genesis and the given time.
        """
        # Convert the elapsed seconds to milliseconds.
        #
        # The store measures time at sub-second granularity (800 ms intervals),
        # so second-precision input must be scaled up before dividing.
        delta_ms = (unix_seconds - genesis_time) * Uint64(1000)

        # Truncate to whole intervals.
        return cls(delta_ms // MILLISECONDS_PER_INTERVAL)

    @classmethod
    def from_slot(cls, slot: Uint64) -> Interval:
        """
        Convert a slot number to the interval at that slot's start.

        Each slot spans a fixed number of intervals.
        This gives the first interval of the given slot.

        Args:
            slot: Slot number since genesis.

        Returns:
            Interval count at the start of the given slot.
        """
        # Slot boundaries fall on exact multiples of the interval count.
        return cls(slot * INTERVALS_PER_SLOT)


@dataclass(frozen=True, slots=True)
class SlotClock:
    """
    Converts wall-clock time to consensus slots and intervals.

    All time values are in seconds (Unix timestamps).
    """

    genesis_time: Uint64
    """Unix timestamp (seconds) when slot 0 began."""

    time_fn: Callable[[], float] = wall_time
    """Time source function (injectable for testing)."""

    def _seconds_since_genesis(self) -> Uint64:
        """Seconds elapsed since genesis (0 if before genesis)."""
        now = self.current_time()
        if now < self.genesis_time:
            return Uint64(0)
        return now - self.genesis_time

    def _milliseconds_since_genesis(self) -> Uint64:
        """Milliseconds elapsed since genesis (0 if before genesis)."""
        now_ms = int(self.time_fn() * 1000)
        genesis_ms = int(self.genesis_time) * 1000
        if now_ms < genesis_ms:
            return Uint64(0)
        return Uint64(now_ms - genesis_ms)

    def current_slot(self) -> Slot:
        """Get the current slot number (0 if before genesis)."""
        return Slot(self._seconds_since_genesis() // SECONDS_PER_SLOT)

    def current_interval(self) -> Interval:
        """Get the current interval within the slot (0-4)."""
        milliseconds_into_slot = self._milliseconds_since_genesis() % MILLISECONDS_PER_SLOT
        return Interval(milliseconds_into_slot // MILLISECONDS_PER_INTERVAL)

    def total_intervals(self) -> Interval:
        """
        Get total intervals elapsed since genesis.

        This is the value expected by our store time type.
        """
        return Interval(self._milliseconds_since_genesis() // MILLISECONDS_PER_INTERVAL)

    def current_time(self) -> Uint64:
        """Get current wall-clock time as Uint64 (Unix timestamp in seconds)."""
        return Uint64(int(self.time_fn()))

    def seconds_until_next_interval(self) -> float:
        """
        Calculate seconds until the next interval boundary.

        Returns time until genesis if before genesis.
        Returns 0.0 if exactly at an interval boundary.
        """
        now = self.time_fn()
        genesis = int(self.genesis_time)
        elapsed = now - genesis

        if elapsed < 0:
            # Before genesis - return time until genesis.
            return -elapsed

        # Convert to milliseconds and find time into current interval.
        elapsed_ms = int(elapsed * 1000)
        time_into_interval_ms = elapsed_ms % int(MILLISECONDS_PER_INTERVAL)

        # Time until next boundary (may be 0 if exactly at boundary).
        ms_until_next = int(MILLISECONDS_PER_INTERVAL) - time_into_interval_ms
        return ms_until_next / 1000.0

    async def sleep_until_next_interval(self) -> None:
        """Sleep until the next interval boundary."""
        sleep_time = self.seconds_until_next_interval()
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
