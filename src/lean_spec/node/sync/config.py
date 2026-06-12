"""
Sync service configuration constants.

Operational parameters for synchronization: batch sizes, timeouts, and limits.
"""

from __future__ import annotations

from typing import Final

MAX_CONCURRENT_REQUESTS: Final[int] = 2
"""Maximum concurrent requests to a single peer."""

MAX_CACHED_BLOCKS: Final[int] = 1024
"""Maximum blocks to hold in the pending cache."""

MAX_BACKFILL_DEPTH: Final[int] = 512
"""Maximum depth for backfill parent chain resolution."""

MAX_PENDING_ATTESTATIONS: Final[int] = 1024
"""Maximum buffered attestations awaiting block processing."""
