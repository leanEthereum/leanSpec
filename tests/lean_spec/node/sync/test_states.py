"""Tests for sync service state machine."""

from __future__ import annotations

from lean_spec.node.sync.states import SyncState


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


class TestSyncStateAcceptsGossip:
    """Tests for the accepts_gossip property."""

    def test_idle_does_not_accept_gossip(self) -> None:
        """An idle service ignores incoming gossip blocks."""
        assert not SyncState.IDLE.accepts_gossip

    def test_syncing_accepts_gossip(self) -> None:
        """An actively syncing service processes incoming gossip blocks."""
        assert SyncState.SYNCING.accepts_gossip

    def test_synced_accepts_gossip(self) -> None:
        """A synced service keeps processing gossip blocks for live updates."""
        assert SyncState.SYNCED.accepts_gossip

    def test_gossip_accepting_states_set(self) -> None:
        """Exactly the two non-idle states accept gossip."""
        gossip_states = {s for s in SyncState if s.accepts_gossip}
        assert gossip_states == {SyncState.SYNCING, SyncState.SYNCED}
