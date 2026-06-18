"""Tests for the API server implementation: configuration, store wiring, and admin endpoints."""

from __future__ import annotations

import httpx

from consensus_testing import store_backed_signed_block_getter
from lean_spec.node.api import ApiServer, ApiServerConfig
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import SignedBlock
from lean_spec.spec.forks.lstar import Store
from tests.node.api.conftest import AggregatorRoleStub


class TestApiServerConfiguration:
    """Tests for API server configuration behavior."""

    def test_default_config_uses_standard_port(self) -> None:
        """Default configuration uses port 5052 and binds to all interfaces."""
        config = ApiServerConfig()

        assert config.host == "0.0.0.0"
        assert config.port == 5052

    def test_custom_config_values_are_respected(self) -> None:
        """Custom configuration values override defaults."""
        config = ApiServerConfig(
            host="127.0.0.1",
            port=8080,
        )

        assert config.host == "127.0.0.1"
        assert config.port == 8080


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
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/states/finalized"
                )

                assert response.status_code == 503
                assert response.reason_phrase == "Store not initialized"

        finally:
            await server.aclose()

    async def test_returns_404_when_finalized_state_missing(self, base_store: Store) -> None:
        """Endpoint returns 404 when the finalized state is absent from the store."""
        store_without_states = base_store.model_copy(update={"states": {}})
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, store_getter=lambda: store_without_states)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/states/finalized"
                )

                assert response.status_code == 404
                assert response.reason_phrase == "Finalized state not available"

        finally:
            await server.aclose()


class TestFinalizedBlockEndpoint:
    """Tests for the /lean/v0/blocks/finalized endpoint."""

    async def test_returns_503_when_store_not_initialized(self) -> None:
        """Endpoint returns 503 Service Unavailable when store is not set."""
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/blocks/finalized"
                )

                assert response.status_code == 503

        finally:
            await server.aclose()

    async def test_returns_503_without_signed_block_source(self, base_store: Store) -> None:
        """Endpoint returns 503 when no signed-block source is configured."""
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, store_getter=lambda: base_store)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/blocks/finalized"
                )

                assert response.status_code == 503

        finally:
            await server.aclose()

    async def test_returns_404_when_block_unavailable(self, base_store: Store) -> None:
        """Endpoint returns 404 when the source has no block for the finalized root."""
        config = ApiServerConfig(port=0)
        server = ApiServer(
            config=config,
            store_getter=lambda: base_store,
            signed_block_getter=lambda root: None,
        )

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/blocks/finalized"
                )

                assert response.status_code == 404

        finally:
            await server.aclose()

    async def test_returns_finalized_anchor_block(self, base_store: Store) -> None:
        """Endpoint serves the signed block matching the finalized checkpoint root."""
        config = ApiServerConfig(port=0)
        server = ApiServer(
            config=config,
            store_getter=lambda: base_store,
            signed_block_getter=store_backed_signed_block_getter(base_store),
        )

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/blocks/finalized"
                )

                assert response.status_code == 200
                assert "application/octet-stream" in response.headers["content-type"]

                signed_block = SignedBlock.decode_bytes(response.content)

                assert hash_tree_root(signed_block.block) == base_store.latest_finalized.root

        finally:
            await server.aclose()


class TestJustifiedCheckpointEndpoint:
    """Tests for the /lean/v0/checkpoints/justified endpoint error handling."""

    async def test_returns_503_when_store_not_initialized(self) -> None:
        """Endpoint returns 503 Service Unavailable when store is not set."""
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/checkpoints/justified"
                )

                assert response.status_code == 503
                assert response.reason_phrase == "Store not initialized"

        finally:
            await server.aclose()


class TestForkChoiceEndpoint:
    """Tests for the /lean/v0/fork_choice endpoint."""

    async def test_returns_503_when_store_not_initialized(self) -> None:
        """Endpoint returns 503 Service Unavailable when store is not set."""
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/fork_choice"
                )

                assert response.status_code == 503
                assert response.reason_phrase == "Store not initialized"

        finally:
            await server.aclose()

    async def test_returns_200_with_initialized_store(self, base_store: Store) -> None:
        """Endpoint returns 200 with fork choice tree when store is initialized."""
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, store_getter=lambda: base_store)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/fork_choice"
                )

                assert response.status_code == 200
                assert response.headers["content-type"] == "application/json"

                response_body = response.json()

                assert set(response_body.keys()) == {
                    "nodes",
                    "head",
                    "justified",
                    "finalized",
                    "safe_target",
                    "validator_count",
                }

                head_root = "0x" + base_store.head.hex()

                assert response_body["head"] == head_root
                assert response_body["validator_count"] == 3
                assert response_body["justified"] == {
                    "slot": int(base_store.latest_justified.slot),
                    "root": "0x" + base_store.latest_justified.root.hex(),
                }
                assert response_body["finalized"] == {
                    "slot": int(base_store.latest_finalized.slot),
                    "root": "0x" + base_store.latest_finalized.root.hex(),
                }

                assert len(response_body["nodes"]) == 1
                node = response_body["nodes"][0]
                assert node["root"] == head_root
                assert node["slot"] == 0
                assert node["weight"] == 0

        finally:
            await server.aclose()

    async def test_validator_count_is_null_when_head_state_missing(self, base_store: Store) -> None:
        """Fork choice reports a null validator count when the head post-state is absent."""
        store_without_states = base_store.model_copy(update={"states": {}})
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, store_getter=lambda: store_without_states)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/fork_choice"
                )

                assert response.status_code == 200
                assert response.json()["validator_count"] is None

        finally:
            await server.aclose()


class TestAggregatorAdminEndpoint:
    """Tests for the /lean/v0/admin/aggregator endpoint."""

    async def test_status_returns_503_without_aggregator_control(self) -> None:
        """GET returns 503 when no aggregator role control is wired."""
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator"
                )

                assert response.status_code == 503
                assert response.reason_phrase == "Aggregator role control not available"

        finally:
            await server.aclose()

    async def test_status_returns_current_role(self) -> None:
        """GET returns the current aggregator role from the sync service flag."""
        aggregator_role_stub = AggregatorRoleStub(is_aggregator=True)
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, aggregator_role_control=aggregator_role_stub)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator"
                )

                assert response.status_code == 200
                assert response.headers["content-type"] == "application/json"
                assert response.json() == {"is_aggregator": True}

        finally:
            await server.aclose()

    async def test_toggle_activates_role(self) -> None:
        """POST with enabled=true activates the aggregator role."""
        aggregator_role_stub = AggregatorRoleStub(is_aggregator=False)
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, aggregator_role_control=aggregator_role_stub)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator",
                    json={"enabled": True},
                )

                assert response.status_code == 200
                assert response.json() == {"is_aggregator": True, "previous": False}
                assert aggregator_role_stub.is_aggregator is True

                # A follow-up GET sees the new value.
                follow_up = await client.get(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator"
                )
                assert follow_up.json() == {"is_aggregator": True}

        finally:
            await server.aclose()

    async def test_toggle_deactivates_role(self) -> None:
        """POST with enabled=false deactivates the aggregator role."""
        aggregator_role_stub = AggregatorRoleStub(is_aggregator=True)
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, aggregator_role_control=aggregator_role_stub)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator",
                    json={"enabled": False},
                )

                assert response.status_code == 200
                assert response.json() == {"is_aggregator": False, "previous": True}
                assert aggregator_role_stub.is_aggregator is False

        finally:
            await server.aclose()

    async def test_toggle_rejects_missing_body(self) -> None:
        """POST with no body returns 400."""
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, aggregator_role_control=AggregatorRoleStub())

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator",
                    content=b"",
                    headers={"Content-Type": "application/json"},
                )

                assert response.status_code == 400
                assert response.reason_phrase == "Invalid JSON body"

        finally:
            await server.aclose()

    async def test_toggle_rejects_missing_field(self) -> None:
        """POST without 'enabled' field returns 400."""
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, aggregator_role_control=AggregatorRoleStub())

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator",
                    json={},
                )

                assert response.status_code == 400
                assert response.reason_phrase == "Missing 'enabled' field in body"

        finally:
            await server.aclose()

    async def test_toggle_rejects_non_boolean(self) -> None:
        """POST with non-boolean 'enabled' returns 400 and does not change state."""
        aggregator_role_stub = AggregatorRoleStub(is_aggregator=False)
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, aggregator_role_control=aggregator_role_stub)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator",
                    json={"enabled": "yes"},
                )

                assert response.status_code == 400
                assert response.reason_phrase == "'enabled' must be a boolean"
                assert aggregator_role_stub.is_aggregator is False

        finally:
            await server.aclose()

    async def test_sequential_posts_converge(self) -> None:
        """
        Multiple sequential POSTs converge to the last-writer value.

        Posts must be issued one at a time, never concurrently.
        Concurrent requests arrive in a racy order.
        The last-writer-wins assertion then goes flaky on slower runners.
        Observed on Python 3.14 macOS.
        """
        aggregator_role_stub = AggregatorRoleStub(is_aggregator=False)
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, aggregator_role_control=aggregator_role_stub)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                url = f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator"
                responses = [
                    await client.post(url, json={"enabled": True}),
                    await client.post(url, json={"enabled": False}),
                    await client.post(url, json={"enabled": True}),
                ]

                assert all(r.status_code == 200 for r in responses)
                assert aggregator_role_stub.is_aggregator is True

        finally:
            await server.aclose()

    async def test_toggle_rejects_null_body(self) -> None:
        """POST with JSON null body returns 400."""
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, aggregator_role_control=AggregatorRoleStub())

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator",
                    content=b"null",
                    headers={"Content-Type": "application/json"},
                )

                assert response.status_code == 400
                assert response.reason_phrase == "Missing 'enabled' field in body"

        finally:
            await server.aclose()

    async def test_toggle_rejects_array_body(self) -> None:
        """POST with JSON array body returns 400."""
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, aggregator_role_control=AggregatorRoleStub())

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator",
                    json=[True],
                )

                assert response.status_code == 400
                assert response.reason_phrase == "Missing 'enabled' field in body"

        finally:
            await server.aclose()

    async def test_toggle_rejects_integer_enabled(self) -> None:
        """POST with integer 1 as enabled returns 400 (must be boolean)."""
        aggregator_role_stub = AggregatorRoleStub(is_aggregator=False)
        config = ApiServerConfig(port=0)
        server = ApiServer(config=config, aggregator_role_control=aggregator_role_stub)

        await server.start()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{server.bound_port}/lean/v0/admin/aggregator",
                    json={"enabled": 1},
                )

                assert response.status_code == 400
                assert response.reason_phrase == "'enabled' must be a boolean"
                assert aggregator_role_stub.is_aggregator is False

        finally:
            await server.aclose()
