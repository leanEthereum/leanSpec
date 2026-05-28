"""
Sync service for the lean Ethereum consensus client.

What Is Sync?

When an Ethereum node starts, it needs to catch up with the network. The
chain may be millions of blocks ahead. Sync is the process of downloading
and validating those blocks until the node reaches the chain head.

The Challenge

Sync is harder than it sounds:

1. **Ordering**: Blocks reference parents; children arrive before parents
2. **Unreliable peers**: Some peers are slow, some are malicious
3. **Progress tracking**: Need to know when we are "done"

How It Works

- Blocks arrive via gossip subscription
- If parent is known, process immediately
- If parent is unknown, cache block and fetch parent (backfill)
- When parents arrive, process waiting children
"""

from __future__ import annotations

__all__ = [
    "SyncService",
    "BlockCache",
    "NetworkRequester",
    "PeerManager",
]

from .backfill_sync import NetworkRequester
from .block_cache import BlockCache
from .peer_manager import PeerManager
from .service import SyncService
