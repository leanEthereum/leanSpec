"""Sync service state machine."""

from __future__ import annotations

from enum import Enum, auto


class SyncState(Enum):
    """Three-phase progression for the sync service.

    Lifecycle:

        IDLE -> SYNCING -> SYNCED
          ^         |         |
          +---------+---------+

    - IDLE: no peers connected, or shutdown requested.
    - SYNCING: active block processing and backfill driven by gossip.
    - SYNCED: caught up to the network finalized slot.

    Either active state may fall back to IDLE on disconnect.
    SYNCED falls back to SYNCING when a gap reappears.
    """

    IDLE = auto()
    """No peers connected, or shutdown requested."""
    SYNCING = auto()
    """Active block processing and backfill driven by gossip."""
    SYNCED = auto()
    """Caught up to the network finalized slot."""

    @property
    def accepts_gossip(self) -> bool:
        """Whether incoming gossip blocks should be processed in this state."""
        return self in {SyncState.SYNCING, SyncState.SYNCED}
