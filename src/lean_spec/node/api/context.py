"""Typed dependencies the HTTP API handlers receive."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from aiohttp import web

from lean_spec.spec.forks import LstarSpec, SignedBlock, Store
from lean_spec.spec.ssz import Bytes32


class AggregatorRoleControl(Protocol):
    """The slice of the sync service the admin endpoints read and write."""

    is_aggregator: bool


@dataclass(frozen=True, slots=True)
class ApiContext:
    """Dependencies shared across handlers, resolved once at startup."""

    spec: LstarSpec
    """Fork spec driving consensus computations such as fork-choice weights."""

    store_getter: Callable[[], Store | None] | None
    """Callable returning the live store, or None before the store exists."""

    aggregator_role_control: AggregatorRoleControl | None
    """Holder of the aggregator flag, or None when aggregator control is unwired."""

    signed_block_getter: Callable[[Bytes32], SignedBlock | None] | None
    """Callable returning the signed block for a block root, or None when unwired."""

    def require_store(self) -> Store:
        """
        Return the live store, or raise 503 when the node has no store yet.

        The store is a frozen snapshot, so all reads in one handler stay consistent.
        """
        store = self.store_getter() if self.store_getter else None
        if store is None:
            raise web.HTTPServiceUnavailable(reason="Store not initialized")
        return store

    def require_aggregator_role_control(self) -> AggregatorRoleControl:
        """Return the aggregator role control, or raise 503 when it is unwired."""
        if self.aggregator_role_control is None:
            raise web.HTTPServiceUnavailable(reason="Aggregator role control not available")
        return self.aggregator_role_control

    def require_signed_block_getter(self) -> Callable[[Bytes32], SignedBlock | None]:
        """Return the signed-block source, or raise 503 when it is unwired."""
        if self.signed_block_getter is None:
            raise web.HTTPServiceUnavailable(reason="Signed block source not configured")
        return self.signed_block_getter
