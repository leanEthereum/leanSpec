"""Test vectors for slot clock timing computations.

Every consensus client must derive identical slot and interval numbers
from wall-clock timestamps. These vectors verify the conversion logic
for a 4-second slot with 5 intervals of 800 ms each.
"""

import pytest
from consensus_testing import SlotClockTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

GENESIS = 1700000000
"""Arbitrary genesis timestamp (seconds) used across most vectors."""


# --- Interval.from_unix_time ---


def test_from_unix_time_at_genesis(slot_clock: SlotClockTestFiller) -> None:
    """At genesis, zero seconds elapsed yields interval 0."""
    slot_clock(
        operation="from_unix_time",
        input={"unixSeconds": GENESIS, "genesisTime": GENESIS},
    )


def test_from_unix_time_one_second(slot_clock: SlotClockTestFiller) -> None:
    """One second = 1000 ms. floor(1000 / 800) = 1 interval."""
    slot_clock(
        operation="from_unix_time",
        input={"unixSeconds": GENESIS + 1, "genesisTime": GENESIS},
    )


def test_from_unix_time_one_slot(slot_clock: SlotClockTestFiller) -> None:
    """One slot = 4 seconds = 4000 ms. 4000 / 800 = 5 intervals."""
    slot_clock(
        operation="from_unix_time",
        input={"unixSeconds": GENESIS + 4, "genesisTime": GENESIS},
    )


def test_from_unix_time_two_seconds(slot_clock: SlotClockTestFiller) -> None:
    """Two seconds = 2000 ms. floor(2000 / 800) = 2 intervals."""
    slot_clock(
        operation="from_unix_time",
        input={"unixSeconds": GENESIS + 2, "genesisTime": GENESIS},
    )


def test_from_unix_time_three_seconds(slot_clock: SlotClockTestFiller) -> None:
    """Three seconds = 3000 ms. floor(3000 / 800) = 3 intervals."""
    slot_clock(
        operation="from_unix_time",
        input={"unixSeconds": GENESIS + 3, "genesisTime": GENESIS},
    )


def test_from_unix_time_ten_slots(slot_clock: SlotClockTestFiller) -> None:
    """Ten slots = 40 seconds = 50 intervals."""
    slot_clock(
        operation="from_unix_time",
        input={"unixSeconds": GENESIS + 40, "genesisTime": GENESIS},
    )


def test_from_unix_time_one_day(slot_clock: SlotClockTestFiller) -> None:
    """One day = 86400 seconds = 108000 intervals."""
    slot_clock(
        operation="from_unix_time",
        input={"unixSeconds": GENESIS + 86400, "genesisTime": GENESIS},
    )


def test_from_unix_time_genesis_zero(slot_clock: SlotClockTestFiller) -> None:
    """Genesis at Unix epoch 0. 100 seconds elapsed = 125 intervals."""
    slot_clock(
        operation="from_unix_time",
        input={"unixSeconds": 100, "genesisTime": 0},
    )


# --- Interval.from_slot ---


def test_from_slot_zero(slot_clock: SlotClockTestFiller) -> None:
    """Slot 0 starts at interval 0."""
    slot_clock(operation="from_slot", input={"slot": 0})


def test_from_slot_one(slot_clock: SlotClockTestFiller) -> None:
    """Slot 1 starts at interval 5."""
    slot_clock(operation="from_slot", input={"slot": 1})


def test_from_slot_ten(slot_clock: SlotClockTestFiller) -> None:
    """Slot 10 starts at interval 50."""
    slot_clock(operation="from_slot", input={"slot": 10})


def test_from_slot_hundred(slot_clock: SlotClockTestFiller) -> None:
    """Slot 100 starts at interval 500."""
    slot_clock(operation="from_slot", input={"slot": 100})


# --- SlotClock.current_slot ---


def test_current_slot_at_genesis(slot_clock: SlotClockTestFiller) -> None:
    """Exactly at genesis: slot 0."""
    slot_clock(
        operation="current_slot",
        input={"genesisTime": GENESIS, "currentTimeMs": GENESIS * 1000},
    )


def test_current_slot_before_genesis(slot_clock: SlotClockTestFiller) -> None:
    """Before genesis: clamped to slot 0."""
    slot_clock(
        operation="current_slot",
        input={"genesisTime": GENESIS, "currentTimeMs": (GENESIS - 10) * 1000},
    )


def test_current_slot_mid_slot(slot_clock: SlotClockTestFiller) -> None:
    """2 seconds into slot 0: still slot 0."""
    slot_clock(
        operation="current_slot",
        input={"genesisTime": GENESIS, "currentTimeMs": GENESIS * 1000 + 2000},
    )


def test_current_slot_at_boundary(slot_clock: SlotClockTestFiller) -> None:
    """Exactly at slot 1 boundary (4 seconds): slot 1."""
    slot_clock(
        operation="current_slot",
        input={"genesisTime": GENESIS, "currentTimeMs": GENESIS * 1000 + 4000},
    )


def test_current_slot_before_boundary(slot_clock: SlotClockTestFiller) -> None:
    """One ms before slot 1 boundary: still slot 0 (integer division floors)."""
    slot_clock(
        operation="current_slot",
        input={"genesisTime": GENESIS, "currentTimeMs": GENESIS * 1000 + 3999},
    )


# --- SlotClock.current_interval ---


def test_current_interval_at_slot_start(slot_clock: SlotClockTestFiller) -> None:
    """Exactly at slot start: interval 0."""
    slot_clock(
        operation="current_interval",
        input={"genesisTime": GENESIS, "currentTimeMs": GENESIS * 1000},
    )


def test_current_interval_800ms(slot_clock: SlotClockTestFiller) -> None:
    """800 ms into slot: interval 1."""
    slot_clock(
        operation="current_interval",
        input={"genesisTime": GENESIS, "currentTimeMs": GENESIS * 1000 + 800},
    )


def test_current_interval_1600ms(slot_clock: SlotClockTestFiller) -> None:
    """1600 ms into slot: interval 2."""
    slot_clock(
        operation="current_interval",
        input={"genesisTime": GENESIS, "currentTimeMs": GENESIS * 1000 + 1600},
    )


def test_current_interval_3200ms(slot_clock: SlotClockTestFiller) -> None:
    """3200 ms into slot: interval 4."""
    slot_clock(
        operation="current_interval",
        input={"genesisTime": GENESIS, "currentTimeMs": GENESIS * 1000 + 3200},
    )


def test_current_interval_wraps_at_next_slot(slot_clock: SlotClockTestFiller) -> None:
    """4000 ms = next slot start: interval wraps back to 0."""
    slot_clock(
        operation="current_interval",
        input={"genesisTime": GENESIS, "currentTimeMs": GENESIS * 1000 + 4000},
    )


def test_current_interval_before_genesis(slot_clock: SlotClockTestFiller) -> None:
    """Before genesis: interval 0."""
    slot_clock(
        operation="current_interval",
        input={"genesisTime": GENESIS, "currentTimeMs": (GENESIS - 5) * 1000},
    )


# --- SlotClock.total_intervals ---


def test_total_intervals_multi_slot(slot_clock: SlotClockTestFiller) -> None:
    """14.4 seconds = 18 intervals (14400 ms / 800 ms)."""
    slot_clock(
        operation="total_intervals",
        input={"genesisTime": GENESIS, "currentTimeMs": GENESIS * 1000 + 14400},
    )


def test_total_intervals_before_genesis(slot_clock: SlotClockTestFiller) -> None:
    """Before genesis: 0 intervals."""
    slot_clock(
        operation="total_intervals",
        input={"genesisTime": GENESIS, "currentTimeMs": (GENESIS - 1) * 1000},
    )
