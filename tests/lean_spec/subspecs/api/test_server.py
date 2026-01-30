"""Tests for the API server implementation details.

API contract tests (status codes, content types, response structure) are in
tests/api/ and also run automatically with `uv run pytest`.

These tests cover leanSpec-specific implementation details:
- Configuration behavior
- Store integration
- Error handling when store not initialized
- Client helper functions
"""

from __future__ import annotations

import asyncio

from lean_spec.subspecs.api import (
    ApiServer,
    ApiServerConfig,
    fetch_finalized_state,
    verify_checkpoint_state,
)
from lean_spec.subspecs.containers import State
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
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

    def test_returns_503_when_store_not_initialized(self) -> None:
        """Endpoint returns 503 Service Unavailable when store is not set."""
        import httpx

        async def run_test() -> None:
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

        asyncio.run(run_test())


class TestJustifiedCheckpointEndpoint:
    """Tests for the /lean/v0/checkpoints/justified endpoint error handling."""

    def test_returns_503_when_store_not_initialized(self) -> None:
        """Endpoint returns 503 Service Unavailable when store is not set."""
        import httpx

        async def run_test() -> None:
            config = ApiServerConfig(port=15057)
            server = ApiServer(config=config)

            await server.start()

            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        "http://127.0.0.1:15057/lean/v0/checkpoints/justified"
                    )

                    assert response.status_code == 503

            finally:
                server.stop()
                await asyncio.sleep(0.1)

        asyncio.run(run_test())


class TestStateVerification:
    """Tests for checkpoint state verification logic."""

    def test_valid_state_passes_verification(self, genesis_state: State) -> None:
        """Valid state with validators passes verification checks."""

        async def run_test() -> None:
            result = await verify_checkpoint_state(genesis_state)
            assert result is True

        asyncio.run(run_test())

    def test_state_without_validators_fails_verification(self, genesis_state: State) -> None:
        """State with no validators fails verification."""

        async def run_test() -> None:
            empty_state = State(
                config=genesis_state.config,
                slot=genesis_state.slot,
                latest_block_header=genesis_state.latest_block_header,
                latest_justified=genesis_state.latest_justified,
                latest_finalized=genesis_state.latest_finalized,
                historical_block_hashes=genesis_state.historical_block_hashes,
                justified_slots=genesis_state.justified_slots,
                validators=Validators(data=[]),
                justifications_roots=genesis_state.justifications_roots,
                justifications_validators=genesis_state.justifications_validators,
            )

            result = await verify_checkpoint_state(empty_state)
            assert result is False

        asyncio.run(run_test())


class TestCheckpointSyncClientServerIntegration:
    """Integration tests for checkpoint sync client fetching from server."""

    def test_client_fetches_and_deserializes_state(self, base_store: Store) -> None:
        """Client successfully fetches and deserializes state from server."""

        async def run_test() -> None:
            config = ApiServerConfig(port=15058)
            server = ApiServer(config=config, store_getter=lambda: base_store)

            await server.start()

            try:
                state = await fetch_finalized_state("http://127.0.0.1:15058", State)

                assert state is not None
                assert state.slot == Slot(0)

                is_valid = await verify_checkpoint_state(state)
                assert is_valid is True

            finally:
                server.stop()
                await asyncio.sleep(0.1)

        asyncio.run(run_test())
