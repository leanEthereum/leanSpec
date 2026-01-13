"""Tests for the API server checkpoint sync functionality."""

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

    def test_store_getter_provides_access_to_store(self, store: Store) -> None:
        """Store getter callable provides access to the forkchoice store."""
        config = ApiServerConfig()
        server = ApiServer(config=config)

        server.set_store_getter(lambda: store)

        assert server.store is store


class TestHealthEndpoint:
    """Tests for the /health endpoint behavior."""

    def test_returns_healthy_status_json(self) -> None:
        """Health endpoint returns JSON with healthy status."""

        async def run_test() -> None:
            config = ApiServerConfig(port=15052)
            server = ApiServer(config=config)

            await server.start()

            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", 15052)

                request = (
                    "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                writer.write(request.encode())
                await writer.drain()

                response = await reader.read()
                writer.close()
                await writer.wait_closed()

                response_str = response.decode("utf-8")

                assert "200 OK" in response_str
                assert "healthy" in response_str
                assert "lean-spec-api" in response_str

            finally:
                server.stop()

        asyncio.run(run_test())


class TestFinalizedStateEndpoint:
    """Tests for the /lean/states/finalized endpoint behavior."""

    def test_returns_503_when_store_not_initialized(self) -> None:
        """Endpoint returns 503 Service Unavailable when store is not set."""

        async def run_test() -> None:
            config = ApiServerConfig(port=15054)
            server = ApiServer(config=config)

            await server.start()

            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", 15054)

                request = (
                    "GET /lean/states/finalized HTTP/1.1\r\n"
                    "Host: localhost\r\nConnection: close\r\n\r\n"
                )
                writer.write(request.encode())
                await writer.drain()

                response = await reader.read()
                writer.close()
                await writer.wait_closed()

                response_str = response.decode("utf-8")

                assert "503" in response_str or "Service Unavailable" in response_str

            finally:
                server.stop()

        asyncio.run(run_test())

    def test_returns_ssz_state_when_store_available(self, store: Store) -> None:
        """Endpoint returns SSZ-encoded state as octet-stream."""

        async def run_test() -> None:
            config = ApiServerConfig(port=15056)
            server = ApiServer(config=config)
            server.set_store_getter(lambda: store)

            await server.start()

            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", 15056)

                request = (
                    "GET /lean/states/finalized HTTP/1.1\r\n"
                    "Host: localhost\r\nConnection: close\r\n\r\n"
                )
                writer.write(request.encode())
                await writer.drain()

                # Read headers
                headers = b""
                while True:
                    line = await reader.readline()
                    headers += line
                    if line == b"\r\n":
                        break

                header_str = headers.decode("utf-8")
                assert "200 OK" in header_str
                assert "application/octet-stream" in header_str

                # Read body (SSZ binary)
                body = await reader.read()
                writer.close()
                await writer.wait_closed()

                # Verify SSZ data can be deserialized
                assert len(body) > 0
                state = State.decode_bytes(body)
                assert state.slot == Slot(0)

            finally:
                server.stop()

        asyncio.run(run_test())


class TestUnknownEndpoints:
    """Tests for unknown endpoint handling."""

    def test_returns_404_for_unknown_path(self) -> None:
        """Unknown paths return 404 Not Found."""

        async def run_test() -> None:
            config = ApiServerConfig(port=15053)
            server = ApiServer(config=config)

            await server.start()

            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", 15053)

                request = (
                    "GET /unknown HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                writer.write(request.encode())
                await writer.drain()

                response = await reader.read()
                writer.close()
                await writer.wait_closed()

                response_str = response.decode("utf-8")

                assert "404" in response_str

            finally:
                server.stop()

        asyncio.run(run_test())


class TestStateVerification:
    """Tests for checkpoint state verification logic."""

    def test_valid_state_passes_verification(self, genesis_state: State) -> None:
        """Valid state with validators passes verification checks."""

        async def run_test() -> None:
            result = await verify_checkpoint_state(genesis_state)
            assert result is True

        asyncio.run(run_test())

    def test_state_without_validators_fails_verification(
        self, genesis_state: State
    ) -> None:
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

    def test_client_fetches_and_deserializes_state(self, store: Store) -> None:
        """Client successfully fetches and deserializes state from server."""

        async def run_test() -> None:
            config = ApiServerConfig(port=15058)
            server = ApiServer(config=config)
            server.set_store_getter(lambda: store)

            await server.start()

            try:
                state = await fetch_finalized_state("http://127.0.0.1:15058", State)

                assert state is not None
                assert state.slot == Slot(0)

                is_valid = await verify_checkpoint_state(state)
                assert is_valid is True

            finally:
                server.stop()

        asyncio.run(run_test())
