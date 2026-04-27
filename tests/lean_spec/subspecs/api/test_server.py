"""Tests for the API server implementation details.

API contract tests (status codes, content types, response structure) are in
tests/api/ and also run automatically with `uv run pytest`.

These tests cover leanSpec-specific implementation details:
- Configuration behavior
- Store integration
- Error handling when store not initialized
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

from lean_spec.forks.lstar import Store
from lean_spec.subspecs.api import AggregatorController, ApiServer, ApiServerConfig


@dataclass(slots=True)
class _AggregatorStub:
    """Minimal aggregator role holder for wiring AggregatorController in tests."""

    is_aggregator: bool = field(default=False)


def _make_test_controller(initial: bool = False) -> AggregatorController:
    """Build an AggregatorController backed by lightweight stubs.

    Avoids pulling in the full SyncService / NetworkService dependency graph
    for endpoint-level tests that only exercise the flag-toggle contract.
    """
    sync_stub = _AggregatorStub(is_aggregator=initial)
    network_stub = _AggregatorStub(is_aggregator=initial)
    return AggregatorController(
        sync_service=sync_stub,  # type: ignore[arg-type]
        network_service=network_stub,  # type: ignore[arg-type]
    )


class TestApiServerConfiguration:
    """Tests for API server configuration behavior."""

    def test_default_config_uses_standard_port(self) -> None:
        """Default configuration uses port 5052 and binds to all interfaces."""
        config = ApiServerConfig()

        assert config.host == "0.0.0.0"
        assert config.port == 5052
        assert config.enabled is True

    def test_custom_config_values_are_respected(self) -> None:
        """Custom configuration values override defaults."""
        config = ApiServerConfig(
            host="127.0.0.1",
            port=8080,
            enabled=False,
        )

        assert config.host == "127.0.0.1"
        assert config.port == 8080
        assert config.enabled is False


class TestApiServerStoreIntegration:
    """Tests for API server integration with the forkchoice store."""

    def test_server_created_without_store(self) -> None:
        """Server can be created before store is available."""
        config = ApiServerConfig()
        server = ApiServer(config=config)

        assert server.config == config
        assert server.store is None

    def test_store_getter_provides_access_to_store(self, base_store: Store) -> None:
        """Store getter callable provides access to the forkchoice store."""
        config = ApiServerConfig()
        server = ApiServer(config=config, store_getter=lambda: base_store)

        assert server.store is base_store


class TestFinalizedStateEndpoint:
    """Tests for the /lean/v0/states/finalized endpoint error handling."""

    async def test_returns_503_when_store_not_initialized(self) -> None:
        """Endpoint returns 503 Service Unavailable when store is not set."""
        config = ApiServerConfig(port=15054)
        server = ApiServer(config=config)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("http://127.0.0.1:15054/lean/v0/states/finalized")

                assert response.status_code == 503

        finally:
            await server.aclose()


class TestJustifiedCheckpointEndpoint:
    """Tests for the /lean/v0/checkpoints/justified endpoint error handling."""

    async def test_returns_503_when_store_not_initialized(self) -> None:
        """Endpoint returns 503 Service Unavailable when store is not set."""
        config = ApiServerConfig(port=15057)
        server = ApiServer(config=config)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("http://127.0.0.1:15057/lean/v0/checkpoints/justified")

                assert response.status_code == 503

        finally:
            await server.aclose()


class TestForkChoiceEndpoint:
    """Tests for the /lean/v0/fork_choice endpoint."""

    async def test_returns_503_when_store_not_initialized(self) -> None:
        """Endpoint returns 503 Service Unavailable when store is not set."""
        config = ApiServerConfig(port=15058)
        server = ApiServer(config=config)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("http://127.0.0.1:15058/lean/v0/fork_choice")

                assert response.status_code == 503

        finally:
            await server.aclose()

    async def test_returns_200_with_initialized_store(self, base_store: Store) -> None:
        """Endpoint returns 200 with fork choice tree when store is initialized."""
        config = ApiServerConfig(port=15059)
        server = ApiServer(config=config, store_getter=lambda: base_store)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("http://127.0.0.1:15059/lean/v0/fork_choice")

                assert response.status_code == 200
                assert response.headers["content-type"] == "application/json"

                data = response.json()

                assert set(data.keys()) == {
                    "nodes",
                    "head",
                    "justified",
                    "finalized",
                    "safe_target",
                    "validator_count",
                }

                head_root = "0x" + base_store.head.hex()

                assert data["head"] == head_root
                assert data["validator_count"] == 3
                assert data["justified"] == {
                    "slot": int(base_store.latest_justified.slot),
                    "root": "0x" + base_store.latest_justified.root.hex(),
                }
                assert data["finalized"] == {
                    "slot": int(base_store.latest_finalized.slot),
                    "root": "0x" + base_store.latest_finalized.root.hex(),
                }

                assert len(data["nodes"]) == 1
                node = data["nodes"][0]
                assert node["root"] == head_root
                assert node["slot"] == 0
                assert node["weight"] == 0

        finally:
            await server.aclose()


class TestAggregatorAdminEndpoint:
    """Tests for the /lean/v0/admin/aggregator endpoint."""

    async def test_status_returns_503_without_controller(self) -> None:
        """GET returns 503 when no controller is wired."""
        config = ApiServerConfig(port=15060)
        server = ApiServer(config=config)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("http://127.0.0.1:15060/lean/v0/admin/aggregator")

                assert response.status_code == 503

        finally:
            await server.aclose()

    async def test_status_returns_current_role(self) -> None:
        """GET returns the current aggregator role from the controller."""
        controller = _make_test_controller(initial=True)
        config = ApiServerConfig(port=15061)
        server = ApiServer(config=config, aggregator_controller=controller)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get("http://127.0.0.1:15061/lean/v0/admin/aggregator")

                assert response.status_code == 200
                assert response.headers["content-type"] == "application/json"
                assert response.json() == {"is_aggregator": True}

        finally:
            await server.aclose()

    async def test_toggle_activates_role(self) -> None:
        """POST with enabled=true activates the aggregator role."""
        controller = _make_test_controller(initial=False)
        config = ApiServerConfig(port=15062)
        server = ApiServer(config=config, aggregator_controller=controller)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://127.0.0.1:15062/lean/v0/admin/aggregator",
                    json={"enabled": True},
                )

                assert response.status_code == 200
                assert response.json() == {"is_aggregator": True, "previous": False}
                assert controller.is_enabled() is True

                # A follow-up GET sees the new value.
                follow_up = await client.get("http://127.0.0.1:15062/lean/v0/admin/aggregator")
                assert follow_up.json() == {"is_aggregator": True}

        finally:
            await server.aclose()

    async def test_toggle_deactivates_role(self) -> None:
        """POST with enabled=false deactivates the aggregator role."""
        controller = _make_test_controller(initial=True)
        config = ApiServerConfig(port=15063)
        server = ApiServer(config=config, aggregator_controller=controller)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://127.0.0.1:15063/lean/v0/admin/aggregator",
                    json={"enabled": False},
                )

                assert response.status_code == 200
                assert response.json() == {"is_aggregator": False, "previous": True}
                assert controller.is_enabled() is False

        finally:
            await server.aclose()

    async def test_toggle_rejects_missing_body(self) -> None:
        """POST with no body returns 400."""
        controller = _make_test_controller()
        config = ApiServerConfig(port=15064)
        server = ApiServer(config=config, aggregator_controller=controller)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://127.0.0.1:15064/lean/v0/admin/aggregator",
                    content=b"",
                    headers={"Content-Type": "application/json"},
                )

                assert response.status_code == 400

        finally:
            await server.aclose()

    async def test_toggle_rejects_missing_field(self) -> None:
        """POST without 'enabled' field returns 400."""
        controller = _make_test_controller()
        config = ApiServerConfig(port=15065)
        server = ApiServer(config=config, aggregator_controller=controller)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://127.0.0.1:15065/lean/v0/admin/aggregator",
                    json={},
                )

                assert response.status_code == 400

        finally:
            await server.aclose()

    async def test_toggle_rejects_non_boolean(self) -> None:
        """POST with non-boolean 'enabled' returns 400 and does not change state."""
        controller = _make_test_controller(initial=False)
        config = ApiServerConfig(port=15066)
        server = ApiServer(config=config, aggregator_controller=controller)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://127.0.0.1:15066/lean/v0/admin/aggregator",
                    json={"enabled": "yes"},
                )

                assert response.status_code == 400
                assert controller.is_enabled() is False

        finally:
            await server.aclose()

    async def test_sequential_posts_converge(self) -> None:
        """Multiple POSTs converge to the last-writer value."""
        controller = _make_test_controller(initial=False)
        config = ApiServerConfig(port=15067)
        server = ApiServer(config=config, aggregator_controller=controller)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                url = "http://127.0.0.1:15067/lean/v0/admin/aggregator"
                responses = await asyncio.gather(
                    client.post(url, json={"enabled": True}),
                    client.post(url, json={"enabled": False}),
                    client.post(url, json={"enabled": True}),
                )

                assert all(r.status_code == 200 for r in responses)
                assert controller.is_enabled() is True

        finally:
            await server.aclose()

    async def test_toggle_rejects_null_body(self) -> None:
        """POST with JSON null body returns 400."""
        controller = _make_test_controller()
        config = ApiServerConfig(port=15068)
        server = ApiServer(config=config, aggregator_controller=controller)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://127.0.0.1:15068/lean/v0/admin/aggregator",
                    content=b"null",
                    headers={"Content-Type": "application/json"},
                )

                assert response.status_code == 400

        finally:
            await server.aclose()

    async def test_toggle_rejects_array_body(self) -> None:
        """POST with JSON array body returns 400."""
        controller = _make_test_controller()
        config = ApiServerConfig(port=15069)
        server = ApiServer(config=config, aggregator_controller=controller)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://127.0.0.1:15069/lean/v0/admin/aggregator",
                    json=[True],
                )

                assert response.status_code == 400

        finally:
            await server.aclose()

    async def test_toggle_rejects_integer_enabled(self) -> None:
        """POST with integer 1 as enabled returns 400 (must be boolean)."""
        controller = _make_test_controller(initial=False)
        config = ApiServerConfig(port=15070)
        server = ApiServer(config=config, aggregator_controller=controller)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "http://127.0.0.1:15070/lean/v0/admin/aggregator",
                    json={"enabled": 1},
                )

                assert response.status_code == 400
                assert controller.is_enabled() is False

        finally:
            await server.aclose()
