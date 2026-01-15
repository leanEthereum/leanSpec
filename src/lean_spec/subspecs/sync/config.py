"""
Sync service configuration constants.

Operational parameters for synchronization: batch sizes, timeouts, and limits.
"""

from __future__ import annotations

from typing import Final

MAX_BLOCKS_PER_REQUEST: Final[int] = 10
"""Maximum blocks to request in a single BlocksByRoot request."""

MAX_CONCURRENT_REQUESTS: Final[int] = 2
"""Maximum concurrent requests to a single peer."""

REQUEST_TIMEOUT: Final[float] = 10.0
"""Timeout for individual block requests in seconds."""

MAX_CACHED_BLOCKS: Final[int] = 1024
"""Maximum blocks to hold in the pending cache."""

MAX_BACKFILL_DEPTH: Final[int] = 512
"""Maximum depth for backfill parent chain resolution."""
