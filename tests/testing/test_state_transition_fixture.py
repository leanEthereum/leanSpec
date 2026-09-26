"""The emitted state-transition fixture must be reproducible from its own contents."""

from __future__ import annotations

from consensus_testing import BlockSpec, ExpectedRejection, build_genesis_state
from consensus_testing.test_fixtures.state_transition import StateTransitionTest
from lean_spec.spec.forks import RejectionReason, Slot
from lean_spec.spec.forks.lstar.spec import LstarSpec


def test_an_ordinary_fixture_carries_no_slot_processing_instruction() -> None:
    """A test that advances slots normally emits nothing extra, as every runner does that."""
    fixture = StateTransitionTest(
        pre=build_genesis_state(),
        blocks=[BlockSpec(slot=Slot(1)), BlockSpec(slot=Slot(2))],
    ).generate()

    assert fixture.skip_slot_processing is None


def test_a_skipped_slot_processing_block_says_so_in_the_fixture() -> None:
    """
    A block the spec processes without advancing slots must say so.

    The rejection under test only happens while the state is behind the block's slot. A
    runner that calls the whole state transition advances the slot first, never reaches the
    mismatch, and reports the fixture as broken rather than reproducing it.
    """
    pre = LstarSpec().process_slots(build_genesis_state(), Slot(1))

    fixture = StateTransitionTest(
        pre=pre,
        blocks=[BlockSpec(slot=Slot(2), skip_slot_processing=True)],
        expected_rejection=ExpectedRejection(
            reason=RejectionReason.BLOCK_SLOT_MISMATCH,
            exact_message="Block slot mismatch",
        ),
    ).generate()

    assert fixture.skip_slot_processing == [True]


def test_the_instruction_is_per_block_and_in_order() -> None:
    """
    A run that mixes both kinds pins which block skips, not merely that one of them does.

    A single flag, or a list built in the wrong order, would pass a test where every block
    skips. This one would not.
    """
    pre = LstarSpec().process_slots(build_genesis_state(), Slot(1))

    fixture = StateTransitionTest(
        pre=pre,
        blocks=[
            # Processed against a state already at slot 1, so slots must not advance again.
            BlockSpec(slot=Slot(1), skip_slot_processing=True),
            # An ordinary block, which the runner advances to as usual.
            BlockSpec(slot=Slot(2)),
        ],
    ).generate()

    assert fixture.skip_slot_processing == [True, False]
