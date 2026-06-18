"""Validator: sync-lag duty gate decision and hysteresis."""

import pytest

from consensus_testing import (
    DutyGateInitialState,
    DutyGateStep,
    ValidatorDutyGateTestFiller,
)

pytestmark = pytest.mark.valid_until("Lstar")


def test_threshold_and_hysteresis(
    validator_duty_gate_test: ValidatorDutyGateTestFiller,
) -> None:
    """
    The open-gate threshold, the hysteresis band, and clock-skew saturation.

    Given
    -----
    - the head starts at slot 10 with a fresh block at slot 20, so the network never looks stalled.

    When
    ----
    - lag 4 is allowed, the upper edge of the open threshold.
    - lag 5 closes the gate.
    - lag 3 stays closed, holding below the threshold and pinning the band to 2 rather than 1.
    - lag 2 reopens the gate.
    - the head moves ahead of the wall clock, saturating lag to 0.

    Then
    ----
    - the decisions are allow, skip, skip, allow, allow in order.
    """
    validator_duty_gate_test(
        initial_state=DutyGateInitialState(head_slot=10, max_seen_slot=20),
        steps=[
            DutyGateStep(wall_clock_slot=14, duty="block"),
            DutyGateStep(wall_clock_slot=15, duty="block"),
            DutyGateStep(wall_clock_slot=15, set_head_slot=12, duty="block"),
            DutyGateStep(wall_clock_slot=15, set_head_slot=13, duty="block"),
            DutyGateStep(wall_clock_slot=15, set_head_slot=20, duty="block"),
        ],
    )


def test_network_stall_escape(
    validator_duty_gate_test: ValidatorDutyGateTestFiller,
) -> None:
    """
    The network-stall escape, its strict boundary, and that it covers an open and a closed gate.

    Given
    -----
    - the head is at slot 10 and the freshest block at slot 12, so network lag tracks the clock.

    When
    ----
    - network lag 8 is not yet a stall, so the local lag closes the gate.
    - network lag 9 escapes the stall and reopens the closed gate.
    - network lag 10 keeps an already-open gate signing, here for an attestation duty.

    Then
    ----
    - the decisions are skip, allow, allow in order.
    """
    validator_duty_gate_test(
        initial_state=DutyGateInitialState(head_slot=10, max_seen_slot=12),
        steps=[
            DutyGateStep(wall_clock_slot=20, duty="block"),
            DutyGateStep(wall_clock_slot=21, duty="block"),
            DutyGateStep(wall_clock_slot=22, duty="attestation"),
        ],
    )
