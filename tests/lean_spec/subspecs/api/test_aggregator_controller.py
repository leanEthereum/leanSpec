"""Tests for the aggregator runtime controller."""

from __future__ import annotations

import asyncio

from lean_spec.subspecs.api import AggregatorController
from lean_spec.subspecs.networking import NetworkService, PeerId
from lean_spec.subspecs.sync import SyncService
from tests.lean_spec.helpers import MockEventSource, create_mock_sync_service

FORK_DIGEST = "0x00000000"


def _make_controller(
    peer_id: PeerId,
    *,
    initial: bool = False,
) -> tuple[AggregatorController, SyncService, NetworkService]:
    """Build a controller wired to realistic sync/network services."""
    sync_service = create_mock_sync_service(peer_id)
    sync_service.is_aggregator = initial
    network_service = NetworkService(
        sync_service=sync_service,
        event_source=MockEventSource(events=[]),
        fork_digest=FORK_DIGEST,
        is_aggregator=initial,
    )
    controller = AggregatorController(
        sync_service=sync_service,
        network_service=network_service,
    )
    return controller, sync_service, network_service


class TestAggregatorControllerRead:
    """Tests for the read path."""

    def test_is_enabled_reflects_sync_service_flag(self, peer_id: PeerId) -> None:
        """is_enabled reads the sync service flag as the source of truth."""
        controller, sync_service, _ = _make_controller(peer_id, initial=False)
        assert controller.is_enabled() is False

        sync_service.is_aggregator = True
        assert controller.is_enabled() is True


class TestAggregatorControllerWrite:
    """Tests for the write path."""

    async def test_set_enabled_activates_role(self, peer_id: PeerId) -> None:
        """set_enabled(True) flips the flag on both services."""
        controller, sync_service, network_service = _make_controller(peer_id, initial=False)

        previous = await controller.set_enabled(True)

        assert previous is False
        assert controller.is_enabled() is True
        assert sync_service.is_aggregator is True
        assert network_service.is_aggregator is True

    async def test_set_enabled_deactivates_role(self, peer_id: PeerId) -> None:
        """set_enabled(False) flips the flag off on both services."""
        controller, sync_service, network_service = _make_controller(peer_id, initial=True)

        previous = await controller.set_enabled(False)

        assert previous is True
        assert controller.is_enabled() is False
        assert sync_service.is_aggregator is False
        assert network_service.is_aggregator is False

    async def test_set_enabled_idempotent(self, peer_id: PeerId) -> None:
        """Setting the same value returns the current value and leaves state intact."""
        controller, sync_service, network_service = _make_controller(peer_id, initial=True)

        previous = await controller.set_enabled(True)

        assert previous is True
        assert sync_service.is_aggregator is True
        assert network_service.is_aggregator is True

    async def test_sequential_toggles_converge(self, peer_id: PeerId) -> None:
        """Sequential toggles each see the prior state and converge to the last value."""
        controller, sync_service, network_service = _make_controller(peer_id, initial=False)

        results = await asyncio.gather(
            controller.set_enabled(True),
            controller.set_enabled(False),
            controller.set_enabled(True),
        )

        # asyncio.gather on a single-threaded event loop preserves order.
        # Each toggle sees the previous state correctly.
        assert results == [False, True, False]
        assert controller.is_enabled() is True
        assert sync_service.is_aggregator is True
        assert network_service.is_aggregator is True
