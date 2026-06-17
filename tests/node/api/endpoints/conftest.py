"""Pytest configuration for API conformance tests."""

import asyncio
import threading
import time
from typing import Generator

import httpx
import pytest

from consensus_testing import make_genesis_store, store_backed_signed_block_getter
from lean_spec.node.api import ApiServer, ApiServerConfig
from tests.node.api.conftest import AggregatorRoleStub


class _ServerThread(threading.Thread):
    """Thread that runs the API server in its own event loop."""

    def __init__(self, port: int):
        super().__init__(daemon=True)
        self.port = port
        self.server: ApiServer | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.ready = threading.Event()
        self.error: Exception | None = None

    def run(self) -> None:
        """Run the server in a new event loop."""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            self.server = self._create_server()
            self.loop.run_until_complete(self.server.start())
            self.ready.set()

            self.loop.run_forever()

        except Exception as exception:
            self.error = exception
            self.ready.set()
        finally:
            if self.loop:
                self.loop.close()

    def _create_server(self) -> ApiServer:
        """Create the API server with a test store and aggregator flag holder."""
        store = make_genesis_store(num_validators=3, observer=True, genesis_time=int(time.time()))

        config = ApiServerConfig(host="127.0.0.1", port=self.port)
        return ApiServer(
            config=config,
            store_getter=lambda: store,
            signed_block_getter=store_backed_signed_block_getter(store),
            aggregator_role_control=AggregatorRoleStub(),
        )

    def stop(self) -> None:
        """Stop the server and event loop, awaiting the graceful shutdown coroutine."""
        if self.server and self.loop:

            async def shutdown() -> None:
                if self.server:
                    await self.server.aclose()
                if self.loop and self.loop.is_running():
                    self.loop.stop()

            future = asyncio.run_coroutine_threadsafe(shutdown(), self.loop)
            try:
                future.result(timeout=5.0)
            except TimeoutError:
                if self.loop and self.loop.is_running():
                    self.loop.call_soon_threadsafe(self.loop.stop)


def _wait_for_server(url: str, timeout: float = 5.0) -> bool:
    """Wait for server to be ready by polling the health endpoint."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            response = httpx.get(f"{url}/lean/v0/health", timeout=1.0)
            if response.status_code == 200:
                return True
        except (httpx.ConnectError, httpx.ReadTimeout):
            pass
        time.sleep(0.1)
    return False


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add --server-url option for testing against external servers."""
    parser.addoption(
        "--server-url",
        action="store",
        default=None,
        help="External server URL. If not provided, starts a local server.",
    )


@pytest.fixture(scope="session")
def server_url(request: pytest.FixtureRequest) -> Generator[str, None, None]:
    """
    Provide the server URL for API tests.

    If --server-url is provided, uses that external server.
    Otherwise, starts a local leanSpec server for the test session.
    """
    external_url = request.config.getoption("--server-url")

    if external_url:
        yield external_url
    else:
        # Bind to port 0 so the OS assigns a free port.
        # This avoids collisions with other tests under parallel runs.
        server_thread = _ServerThread(0)
        server_thread.start()
        server_thread.ready.wait(timeout=10.0)

        if server_thread.error or server_thread.server is None:
            pytest.fail(f"Failed to start local server: {server_thread.error}")

        started_server = server_thread.server
        assert started_server is not None
        url = f"http://127.0.0.1:{started_server.bound_port}"

        if not _wait_for_server(url):
            server_thread.stop()
            pytest.fail("Local server failed to become ready")

        yield url

        server_thread.stop()
