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

import httpx

from lean_spec.subspecs.api import ApiServer, ApiServerConfig
from lean_spec.subspecs.forkchoice import Store


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
            server.stop()
            await asyncio.sleep(0.1)


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
            server.stop()
            await asyncio.sleep(0.1)
