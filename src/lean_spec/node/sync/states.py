"""Sync service state machine."""

from __future__ import annotations

from enum import Enum, auto


class SyncState(Enum):
    """
    Sync lifecycle and gossip eligibility.

    Peer status activates a service that starts idle.
    A finalized-slot gap resumes syncing after the service catches up.

    Peer disconnection preserves the current phase.
    Shutdown stops the service tasks while preserving the phase.
    """

    IDLE = auto()
    """Initial phase awaiting peer status when immediate gossip processing is disabled."""
    SYNCING = auto()
    """Active block processing and backfill driven by gossip."""
    SYNCED = auto()
    """Caught up to the network finalized slot."""

    @property
    def accepts_gossip(self) -> bool:
        """Whether incoming gossip blocks should be processed in this state."""
        return self in {SyncState.SYNCING, SyncState.SYNCED}
