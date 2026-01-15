"""Tests for sync service state machine."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.sync.states import SyncState


class TestSyncStateValues:
    """Tests for SyncState enum values and basic properties."""

    def test_all_states_exist(self) -> None:
        """All expected sync states are defined."""
        assert hasattr(SyncState, "IDLE")
        assert hasattr(SyncState, "SYNCING")
        assert hasattr(SyncState, "SYNCED")

    def test_state_count(self) -> None:
        """Exactly three sync states exist."""
        assert len(SyncState) == 3

    def test_states_are_unique(self) -> None:
        """Each state has a unique value."""
        values = [state.value for state in SyncState]
        assert len(values) == len(set(values))


class TestSyncStateTransitions:
    """Tests for state transition validation."""

    def test_idle_can_transition_to_syncing(self) -> None:
        """IDLE can transition to SYNCING."""
        assert SyncState.IDLE.can_transition_to(SyncState.SYNCING)

    def test_idle_cannot_transition_to_synced(self) -> None:
        """IDLE cannot transition directly to SYNCED."""
        assert not SyncState.IDLE.can_transition_to(SyncState.SYNCED)

    def test_idle_cannot_transition_to_itself(self) -> None:
        """IDLE cannot transition to IDLE."""
        assert not SyncState.IDLE.can_transition_to(SyncState.IDLE)

    def test_syncing_valid_transitions(self) -> None:
        """SYNCING can transition to SYNCED or IDLE."""
        assert SyncState.SYNCING.can_transition_to(SyncState.SYNCED)
        assert SyncState.SYNCING.can_transition_to(SyncState.IDLE)

    def test_syncing_cannot_transition_to_itself(self) -> None:
        """SYNCING cannot transition to itself."""
        assert not SyncState.SYNCING.can_transition_to(SyncState.SYNCING)

    def test_synced_valid_transitions(self) -> None:
        """SYNCED can transition to SYNCING or IDLE."""
        assert SyncState.SYNCED.can_transition_to(SyncState.SYNCING)
        assert SyncState.SYNCED.can_transition_to(SyncState.IDLE)

    def test_synced_cannot_transition_to_itself(self) -> None:
        """SYNCED cannot transition to itself."""
        assert not SyncState.SYNCED.can_transition_to(SyncState.SYNCED)

    def test_all_active_states_can_transition_to_idle(self) -> None:
        """SYNCING and SYNCED can transition to IDLE (loss of peers)."""
        assert SyncState.SYNCING.can_transition_to(SyncState.IDLE)
        assert SyncState.SYNCED.can_transition_to(SyncState.IDLE)


class TestSyncStateIsSyncing:
    """Tests for the is_syncing property."""

    def test_idle_is_not_syncing(self) -> None:
        """IDLE state is not actively syncing."""
        assert not SyncState.IDLE.is_syncing

    def test_syncing_is_syncing(self) -> None:
        """SYNCING state is actively syncing."""
        assert SyncState.SYNCING.is_syncing

    def test_synced_is_not_syncing(self) -> None:
        """SYNCED state is not actively syncing."""
        assert not SyncState.SYNCED.is_syncing

    def test_syncing_states_set(self) -> None:
        """Exactly one state is a syncing state."""
        syncing_states = [s for s in SyncState if s.is_syncing]
        assert len(syncing_states) == 1
        assert syncing_states[0] == SyncState.SYNCING


class TestSyncStateAcceptsGossip:
    """Tests for the accepts_gossip property."""

    def test_idle_does_not_accept_gossip(self) -> None:
        """IDLE state does not accept gossip blocks."""
        assert not SyncState.IDLE.accepts_gossip

    def test_syncing_accepts_gossip(self) -> None:
        """SYNCING state accepts gossip blocks."""
        assert SyncState.SYNCING.accepts_gossip

    def test_synced_accepts_gossip(self) -> None:
        """SYNCED state accepts gossip blocks."""
        assert SyncState.SYNCED.accepts_gossip

    def test_gossip_accepting_states_set(self) -> None:
        """Exactly two states accept gossip."""
        gossip_states = [s for s in SyncState if s.accepts_gossip]
        assert len(gossip_states) == 2
        assert set(gossip_states) == {SyncState.SYNCING, SyncState.SYNCED}


class TestSyncStateTransitionPaths:
    """Tests for valid complete transition paths through the state machine."""

    def test_happy_path_to_synced(self) -> None:
        """Test the happy path: IDLE -> SYNCING -> SYNCED."""
        current = SyncState.IDLE

        assert current.can_transition_to(SyncState.SYNCING)
        current = SyncState.SYNCING

        assert current.can_transition_to(SyncState.SYNCED)
        current = SyncState.SYNCED

        assert current == SyncState.SYNCED

    def test_synced_to_syncing_cycle(self) -> None:
        """Test SYNCED -> SYNCING for gap handling."""
        current = SyncState.SYNCED

        assert current.can_transition_to(SyncState.SYNCING)
        current = SyncState.SYNCING

        assert current.can_transition_to(SyncState.SYNCED)
        current = SyncState.SYNCED

        assert current == SyncState.SYNCED

    def test_any_active_state_to_idle_on_disconnect(self) -> None:
        """Test that any active state can return to IDLE on peer disconnect."""
        active_states = [SyncState.SYNCING, SyncState.SYNCED]

        for state in active_states:
            assert state.can_transition_to(SyncState.IDLE), (
                f"{state.name} should transition to IDLE"
            )


class TestSyncStateEdgeCases:
    """Tests for edge cases and invariants."""

    @pytest.mark.parametrize("state", list(SyncState))
    def test_no_self_transitions(self, state: SyncState) -> None:
        """No state can transition to itself."""
        assert not state.can_transition_to(state)

    def test_idle_only_has_one_outgoing_transition(self) -> None:
        """IDLE has exactly one valid outgoing transition."""
        valid_targets = [s for s in SyncState if SyncState.IDLE.can_transition_to(s)]
        assert len(valid_targets) == 1
        assert valid_targets[0] == SyncState.SYNCING
