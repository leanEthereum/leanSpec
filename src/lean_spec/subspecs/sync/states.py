"""Sync service state machine."""

from __future__ import annotations

from enum import Enum, auto


class SyncState(Enum):
    """
    Sync service states representing the current synchronization phase.

    This is a simple three-state machine for reactive synchronization:

    State Machine Diagram
    ---------------------
    ::

        IDLE --> SYNCING --> SYNCED
          ^         |           |
          +---------+-----------+

    The Lifecycle
    -------------
    A newly started node follows this progression:

    1. **IDLE**: Node starts, no peers connected yet
    2. **SYNCING**: Peers report chain ahead of us; react to gossip blocks
    3. **SYNCED**: Local head reaches network finalized slot; fully synchronized

    How It Works
    ------------
    - Blocks arrive via gossip
    - If parent is known, process immediately
    - If parent is unknown, cache block and fetch parent (backfill)
    - Backfill happens naturally within SYNCING, not as a separate state

    Transitions
    -----------
    IDLE -> SYNCING
        - Triggered when: Peers connected and we need to sync
        - Action: Start processing gossip blocks

    SYNCING -> SYNCED
        - Triggered when: local_head >= network_finalized_slot and no orphans
        - Action: Transition to passive mode

    SYNCED -> SYNCING
        - Triggered when: Gap detected or fell behind
        - Action: Resume active sync

    Any -> IDLE
        - Triggered when: No connected peers or shutdown requested
        - Action: Pause all sync activity
    """

    IDLE = auto()
    """
    Inactive state: no synchronization in progress.

    The sync service enters IDLE when:

    - **Startup**: Before any peers connect
    - **No peers**: All peers disconnected or unreachable
    - **Shutdown**: Graceful termination requested

    While IDLE, the service waits passively. No requests are sent. The only
    way out is connecting to peers and receiving Status messages.
    """

    SYNCING = auto()
    """
    Active synchronization state: processing gossip and backfilling.

    SYNCING is the main working state. The node receives gossip blocks and
    processes them, backfilling missing parents as needed.

    In this state:

    - Gossip blocks are processed immediately if parent is known
    - Unknown parents trigger backfill requests
    - Cached blocks are processed when parents arrive
    """

    SYNCED = auto()
    """
    Fully synchronized state: at or past network finalized slot.

    SYNCED is the goal state. The node's head has reached or passed the
    network's finalized checkpoint. This means:

    - We have all finalized blocks
    - We are following the chain head in real-time
    - No active sync activity is needed

    In this state:

    - Gossip blocks are still processed
    - Falls back to SYNCING if gaps appear
    """

    def can_transition_to(self, target: "SyncState") -> bool:
        """
        Check if transition to target state is valid.

        State machines enforce invariants through transition rules. This method
        encodes those rules. Callers should check validity before transitioning
        to catch logic errors early.

        Args:
            target: The proposed target state.

        Returns:
            True if the transition is allowed by the state machine rules.
        """
        return target in _VALID_TRANSITIONS.get(self, set())

    @property
    def is_syncing(self) -> bool:
        """
        Check if this state represents active synchronization.

        Returns:
            True if the state involves active block processing.
        """
        return self == SyncState.SYNCING

    @property
    def accepts_gossip(self) -> bool:
        """
        Check if gossip blocks should be processed in this state.

        Returns:
            True if incoming gossip blocks should be processed.
        """
        return self in {SyncState.SYNCING, SyncState.SYNCED}


_VALID_TRANSITIONS: dict[SyncState, set[SyncState]] = {
    SyncState.IDLE: {SyncState.SYNCING},
    SyncState.SYNCING: {SyncState.SYNCED, SyncState.IDLE},
    SyncState.SYNCED: {SyncState.SYNCING, SyncState.IDLE},
}
"""Valid state transitions for the sync state machine."""
