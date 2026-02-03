"""
Sync service for the lean Ethereum consensus client.

What Is Sync?
-------------
When an Ethereum node starts, it needs to catch up with the network. The
chain may be millions of blocks ahead. Sync is the process of downloading
and validating those blocks until the node reaches the chain head.

The Challenge
-------------
Sync is harder than it sounds:

1. **Ordering**: Blocks reference parents; children arrive before parents
2. **Unreliable peers**: Some peers are slow, some are malicious
3. **Progress tracking**: Need to know when we are "done"

How It Works
------------
- Blocks arrive via gossip subscription
- If parent is known, process immediately
- If parent is unknown, cache block and fetch parent (backfill)
- When parents arrive, process waiting children
"""

from __future__ import annotations

__all__ = [
    # Main service
    "SyncService",
    "SyncProgress",
    # States
    "SyncState",
    # Block cache
    "BlockCache",
    "PendingBlock",
    # Peer management
    "PeerManager",
    "SyncPeer",
    # Backfill sync
    "BackfillSync",
    "NetworkRequester",
    # Head sync
    "HeadSync",
    "HeadSyncResult",
    # Checkpoint sync
    "CheckpointSyncError",
    "fetch_finalized_state",
    "verify_checkpoint_state",
    # Configuration constants
    "MAX_BLOCKS_PER_REQUEST",
    "MAX_CONCURRENT_REQUESTS",
    "REQUEST_TIMEOUT",
    "MAX_CACHED_BLOCKS",
    "MAX_BACKFILL_DEPTH",
]

from .backfill_sync import BackfillSync, NetworkRequester
from .block_cache import BlockCache, PendingBlock
from .checkpoint_sync import (
    CheckpointSyncError,
    fetch_finalized_state,
    verify_checkpoint_state,
)
from .config import (
    MAX_BACKFILL_DEPTH,
    MAX_BLOCKS_PER_REQUEST,
    MAX_CACHED_BLOCKS,
    MAX_CONCURRENT_REQUESTS,
    REQUEST_TIMEOUT,
)
from .head_sync import HeadSync, HeadSyncResult
from .peer_manager import PeerManager, SyncPeer
from .service import SyncProgress, SyncService
from .states import SyncState
