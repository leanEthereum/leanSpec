"""
Runtime controller for the node's aggregator role.

Exposes get/set operations over the shared is_aggregator flag so the admin
API can rotate aggregator duties across nodes without restarting.

Toggles are serialized under an asyncio lock so concurrent admin requests
cannot leave the sync and network services disagreeing on the current role.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from lean_spec.subspecs.networking import NetworkService
from lean_spec.subspecs.sync import SyncService

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AggregatorController:
    """
    Runtime control over the node's aggregator role.

    Operators toggle the flag to rotate aggregation duties across nodes when
    an active aggregator becomes unhealthy, without restarting the node.

    The spec-level semantics are unchanged: the sync service reads
    is_aggregator on each gossip event and each tick, so flipping the flag
    takes effect from the next event or tick onward.
    """

    sync_service: SyncService
    """Sync service whose flag drives gossip-side aggregator behavior."""

    network_service: NetworkService
    """Network service whose flag mirrors the sync service for consistency."""

    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    """Serializes concurrent toggles from API handlers."""

    def is_enabled(self) -> bool:
        """Return whether the node is currently acting as aggregator."""
        return self.sync_service.is_aggregator

    async def set_enabled(self, enabled: bool) -> bool:
        """
        Update the aggregator role and return the previous value.

        The sync and network services are updated together under a lock so
        both views remain consistent from any observer's perspective.

        Args:
            enabled: Desired aggregator state.

        Returns:
            Aggregator state prior to the update.
        """
        async with self._lock:
            previous = self.sync_service.is_aggregator
            self.sync_service.is_aggregator = enabled
            self.network_service.is_aggregator = enabled
            if previous != enabled:
                logger.info(
                    "Aggregator role %s via admin API",
                    "activated" if enabled else "deactivated",
                )
            return previous
