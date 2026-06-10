"""Test vectors for slot clock timing computations (4-second slot, 5 intervals of 800 ms)."""

import pytest

from consensus_testing import (
    CurrentInterval,
    CurrentSlot,
    FromSlot,
    FromUnixTime,
    SlotClockTestFiller,
    TotalIntervals,
)

pytestmark = pytest.mark.valid_until("Lstar")

GENESIS = 1700000000
"""Arbitrary genesis timestamp (seconds) used across most vectors."""


def test_from_unix_time_at_genesis(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A timestamp at genesis maps to interval 0.

    Given
    -----
    - a timestamp equal to the genesis time.

    When
    ----
    - the interval for that timestamp is computed.

    Then
    ----
    - the interval is 0.
    """
    slot_clock_test(
        operation=FromUnixTime(unix_seconds=GENESIS, genesis_time=GENESIS),
    )


def test_from_unix_time_one_second(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A timestamp one second past genesis maps to interval 1.

    Given
    -----
    - a timestamp one second (1000 ms) past genesis.

    When
    ----
    - the interval for that timestamp is computed.

    Then
    ----
    - the interval is 1 (floor of 1000 over 800).
    """
    slot_clock_test(
        operation=FromUnixTime(unix_seconds=GENESIS + 1, genesis_time=GENESIS),
    )


def test_from_unix_time_one_slot(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A timestamp one slot past genesis maps to interval 5.

    Given
    -----
    - a timestamp one slot (4 seconds, 4000 ms) past genesis.

    When
    ----
    - the interval for that timestamp is computed.

    Then
    ----
    - the interval is 5 (4000 over 800).
    """
    slot_clock_test(
        operation=FromUnixTime(unix_seconds=GENESIS + 4, genesis_time=GENESIS),
    )


def test_from_unix_time_two_seconds(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A timestamp two seconds past genesis maps to interval 2.

    Given
    -----
    - a timestamp two seconds (2000 ms) past genesis.

    When
    ----
    - the interval for that timestamp is computed.

    Then
    ----
    - the interval is 2 (floor of 2000 over 800).
    """
    slot_clock_test(
        operation=FromUnixTime(unix_seconds=GENESIS + 2, genesis_time=GENESIS),
    )


def test_from_unix_time_three_seconds(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A timestamp three seconds past genesis maps to interval 3.

    Given
    -----
    - a timestamp three seconds (3000 ms) past genesis.

    When
    ----
    - the interval for that timestamp is computed.

    Then
    ----
    - the interval is 3 (floor of 3000 over 800).
    """
    slot_clock_test(
        operation=FromUnixTime(unix_seconds=GENESIS + 3, genesis_time=GENESIS),
    )


def test_from_unix_time_ten_slots(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A timestamp ten slots past genesis maps to interval 50.

    Given
    -----
    - a timestamp ten slots (40 seconds) past genesis.

    When
    ----
    - the interval for that timestamp is computed.

    Then
    ----
    - the interval is 50.
    """
    slot_clock_test(
        operation=FromUnixTime(unix_seconds=GENESIS + 40, genesis_time=GENESIS),
    )


def test_from_unix_time_one_day(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A timestamp one day past genesis maps to interval 108000.

    Given
    -----
    - a timestamp one day (86400 seconds) past genesis.

    When
    ----
    - the interval for that timestamp is computed.

    Then
    ----
    - the interval is 108000.
    """
    slot_clock_test(
        operation=FromUnixTime(unix_seconds=GENESIS + 86400, genesis_time=GENESIS),
    )


def test_from_unix_time_genesis_zero(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A timestamp 100 seconds past a zero genesis maps to interval 125.

    Given
    -----
    - a genesis time at Unix epoch 0.
    - a timestamp 100 seconds past genesis.

    When
    ----
    - the interval for that timestamp is computed.

    Then
    ----
    - the interval is 125.
    """
    slot_clock_test(
        operation=FromUnixTime(unix_seconds=100, genesis_time=0),
    )


def test_from_slot_zero(slot_clock_test: SlotClockTestFiller) -> None:
    """
    Slot 0 starts at interval 0.

    Given
    -----
    - slot 0.

    When
    ----
    - the starting interval of the slot is computed.

    Then
    ----
    - the interval is 0.
    """
    slot_clock_test(
        operation=FromSlot(slot=0),
    )


def test_from_slot_one(slot_clock_test: SlotClockTestFiller) -> None:
    """
    Slot 1 starts at interval 5.

    Given
    -----
    - slot 1.

    When
    ----
    - the starting interval of the slot is computed.

    Then
    ----
    - the interval is 5.
    """
    slot_clock_test(
        operation=FromSlot(slot=1),
    )


def test_from_slot_ten(slot_clock_test: SlotClockTestFiller) -> None:
    """
    Slot 10 starts at interval 50.

    Given
    -----
    - slot 10.

    When
    ----
    - the starting interval of the slot is computed.

    Then
    ----
    - the interval is 50.
    """
    slot_clock_test(
        operation=FromSlot(slot=10),
    )


def test_from_slot_hundred(slot_clock_test: SlotClockTestFiller) -> None:
    """
    Slot 100 starts at interval 500.

    Given
    -----
    - slot 100.

    When
    ----
    - the starting interval of the slot is computed.

    Then
    ----
    - the interval is 500.
    """
    slot_clock_test(
        operation=FromSlot(slot=100),
    )


def test_current_slot_at_genesis(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock exactly at genesis reports slot 0.

    Given
    -----
    - a wall-clock time equal to the genesis time.

    When
    ----
    - the current slot is computed.

    Then
    ----
    - the current slot is 0.
    """
    slot_clock_test(
        operation=CurrentSlot(genesis_time=GENESIS, current_time_milliseconds=GENESIS * 1000),
    )


def test_current_slot_before_genesis(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock before genesis clamps to slot 0.

    Given
    -----
    - a wall-clock time ten seconds before genesis.

    When
    ----
    - the current slot is computed.

    Then
    ----
    - the current slot is clamped to 0.
    """
    slot_clock_test(
        operation=CurrentSlot(
            genesis_time=GENESIS, current_time_milliseconds=(GENESIS - 10) * 1000
        ),
    )


def test_current_slot_mid_slot(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock partway through slot 0 still reports slot 0.

    Given
    -----
    - a wall-clock time two seconds past genesis.

    When
    ----
    - the current slot is computed.

    Then
    ----
    - the current slot is 0.
    """
    slot_clock_test(
        operation=CurrentSlot(
            genesis_time=GENESIS, current_time_milliseconds=GENESIS * 1000 + 2000
        ),
    )


def test_current_slot_at_boundary(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock exactly at the slot 1 boundary reports slot 1.

    Given
    -----
    - a wall-clock time four seconds past genesis.

    When
    ----
    - the current slot is computed.

    Then
    ----
    - the current slot is 1.
    """
    slot_clock_test(
        operation=CurrentSlot(
            genesis_time=GENESIS, current_time_milliseconds=GENESIS * 1000 + 4000
        ),
    )


def test_current_slot_before_boundary(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock one millisecond before the slot 1 boundary still reports slot 0.

    Given
    -----
    - a wall-clock time one millisecond before the slot 1 boundary.

    When
    ----
    - the current slot is computed.

    Then
    ----
    - the current slot is 0.
    - the floor of the division keeps the slot below 1.
    """
    slot_clock_test(
        operation=CurrentSlot(
            genesis_time=GENESIS, current_time_milliseconds=GENESIS * 1000 + 3999
        ),
    )


def test_current_interval_at_slot_start(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock exactly at a slot start reports interval 0.

    Given
    -----
    - a wall-clock time at the start of a slot.

    When
    ----
    - the interval within the slot is computed.

    Then
    ----
    - the interval is 0.
    """
    slot_clock_test(
        operation=CurrentInterval(genesis_time=GENESIS, current_time_milliseconds=GENESIS * 1000),
    )


def test_current_interval_800ms(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock 800 ms into a slot reports interval 1.

    Given
    -----
    - a wall-clock time 800 ms into a slot.

    When
    ----
    - the interval within the slot is computed.

    Then
    ----
    - the interval is 1.
    """
    slot_clock_test(
        operation=CurrentInterval(
            genesis_time=GENESIS, current_time_milliseconds=GENESIS * 1000 + 800
        ),
    )


def test_current_interval_1600ms(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock 1600 ms into a slot reports interval 2.

    Given
    -----
    - a wall-clock time 1600 ms into a slot.

    When
    ----
    - the interval within the slot is computed.

    Then
    ----
    - the interval is 2.
    """
    slot_clock_test(
        operation=CurrentInterval(
            genesis_time=GENESIS, current_time_milliseconds=GENESIS * 1000 + 1600
        ),
    )


def test_current_interval_3200ms(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock 3200 ms into a slot reports interval 4.

    Given
    -----
    - a wall-clock time 3200 ms into a slot.

    When
    ----
    - the interval within the slot is computed.

    Then
    ----
    - the interval is 4.
    """
    slot_clock_test(
        operation=CurrentInterval(
            genesis_time=GENESIS, current_time_milliseconds=GENESIS * 1000 + 3200
        ),
    )


def test_current_interval_wraps_at_next_slot(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock at the next slot start wraps the interval back to 0.

    Given
    -----
    - a wall-clock time 4000 ms past the slot start.
    - 4000 ms is the start of the next slot.

    When
    ----
    - the interval within the slot is computed.

    Then
    ----
    - the interval wraps back to 0.
    """
    slot_clock_test(
        operation=CurrentInterval(
            genesis_time=GENESIS, current_time_milliseconds=GENESIS * 1000 + 4000
        ),
    )


def test_current_interval_before_genesis(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock before genesis reports interval 0.

    Given
    -----
    - a wall-clock time five seconds before genesis.

    When
    ----
    - the interval within the slot is computed.

    Then
    ----
    - the interval is 0.
    """
    slot_clock_test(
        operation=CurrentInterval(
            genesis_time=GENESIS, current_time_milliseconds=(GENESIS - 5) * 1000
        ),
    )


def test_total_intervals_multi_slot(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock 14400 ms past genesis counts 18 total intervals.

    Given
    -----
    - a wall-clock time 14400 ms past genesis.

    When
    ----
    - the total intervals elapsed since genesis are computed.

    Then
    ----
    - the count is 18 (14400 over 800).
    """
    slot_clock_test(
        operation=TotalIntervals(
            genesis_time=GENESIS, current_time_milliseconds=GENESIS * 1000 + 14400
        ),
    )


def test_total_intervals_before_genesis(slot_clock_test: SlotClockTestFiller) -> None:
    """
    A clock before genesis counts 0 total intervals.

    Given
    -----
    - a wall-clock time one second before genesis.

    When
    ----
    - the total intervals elapsed since genesis are computed.

    Then
    ----
    - the count is 0.
    """
    slot_clock_test(
        operation=TotalIntervals(
            genesis_time=GENESIS, current_time_milliseconds=(GENESIS - 1) * 1000
        ),
    )
