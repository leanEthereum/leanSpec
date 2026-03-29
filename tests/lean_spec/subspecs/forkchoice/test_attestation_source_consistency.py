"""
Tests for attestation source consistency between voting and block building.

Regression test for a bug where produce_attestation_data used store.latest_justified
as the attestation source, while build_block filtered attestations against
post_state.latest_justified. When store.latest_justified diverged from the head
state's latest_justified (caused by processing a non-head-chain block that crosses
the 2/3 supermajority threshold), all attestations would be filtered out during
block building, producing blocks with 0 attestations.

The fix aligns produce_attestation_data with the original 3sf-mini design: the
attestation source comes from the head block's post-state, not from the store-wide
max.

See: ethereum/research 3sf-mini/p2p.py — Staker.vote() uses
self.post_states[self.head].latest_justified_hash, not a store-wide value.
"""

from __future__ import annotations

from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32

from tests.lean_spec.helpers import (
    TEST_VALIDATOR_ID,
    make_bytes32,
    make_store,
)


class TestAttestationSourceUsesHeadState:
    """
    Verify that produce_attestation_data uses the head state's justified
    checkpoint rather than the store's (which may be higher).

    In 3sf-mini, the voting source is always head_state.latest_justified.
    leanSpec must match this behavior to avoid a source mismatch with
    build_block's post_state.latest_justified filter.
    """

    def test_attestation_source_equals_head_state_justified_at_genesis(self) -> None:
        """At genesis, store and head state justified are both slot 0 — trivially consistent."""
        store = make_store(num_validators=4)
        att_data = store.produce_attestation_data(Slot(1))

        head_state = store.states[store.head]

        assert att_data.source == head_state.latest_justified, (
            "Attestation source should equal head state's latest justified"
        )

    def test_attestation_source_ignores_diverged_store_justified(self) -> None:
        """
        When store.latest_justified is artificially higher than head_state.latest_justified,
        produce_attestation_data must still use head_state.latest_justified.

        This is the core regression test. Before the fix, produce_attestation_data
        returned source=store.latest_justified, which would cause build_block to
        filter out every attestation because post_state.latest_justified (starting
        from head_state for an empty candidate block) was lower.
        """
        store = make_store(num_validators=4)
        head_state = store.states[store.head]

        # Sanity: at genesis, latest_justified is at slot 0 with genesis root
        assert head_state.latest_justified.slot == Slot(0)

        # Simulate store.latest_justified advancing past head state
        # (as if a non-head-chain block's state transition justified slot 5)
        fake_justified = Checkpoint(root=make_bytes32(42), slot=Slot(5))
        diverged_store = store.model_copy(update={"latest_justified": fake_justified})

        # Precondition: store justified is now higher than head state's
        assert diverged_store.latest_justified.slot > head_state.latest_justified.slot

        att_data = diverged_store.produce_attestation_data(Slot(1))

        # The attestation source MUST match head_state's justified, not store's
        assert att_data.source == head_state.latest_justified, (
            f"Attestation source should be head_state.latest_justified "
            f"(slot={head_state.latest_justified.slot}), "
            f"not store.latest_justified (slot={diverged_store.latest_justified.slot})"
        )
        assert att_data.source != fake_justified, (
            "Attestation source must NOT use the diverged store justified"
        )

    def test_attestation_source_matches_build_block_filter(self) -> None:
        """
        The attestation source must always match what build_block uses as its
        initial filter (post_state.latest_justified for an empty candidate block,
        which equals head_state.latest_justified).

        This ensures the first iteration of build_block's fixed-point loop can
        include attestations created by produce_attestation_data.
        """
        store = make_store(num_validators=4)

        # Diverge store justified
        fake_justified = Checkpoint(root=make_bytes32(99), slot=Slot(10))
        diverged_store = store.model_copy(update={"latest_justified": fake_justified})

        att_data = diverged_store.produce_attestation_data(Slot(1))

        # Simulate what build_block does on first iteration:
        # process an empty block on head_state -> post_state.latest_justified
        # should equal head_state.latest_justified (empty block can't advance justified)
        head_state = diverged_store.states[diverged_store.head]
        build_block_initial_filter = head_state.latest_justified

        assert att_data.source == build_block_initial_filter, (
            "Attestation source must match build_block's initial filter "
            "(head_state.latest_justified) to avoid 0-attestation blocks"
        )
