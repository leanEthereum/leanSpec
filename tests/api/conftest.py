"""Pytest configuration for API conformance tests."""

import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Generator

import httpx
import pytest

from lean_spec.subspecs.api import AggregatorController, ApiServer, ApiServerConfig
from tests.lean_spec.helpers import make_store

# Default port for auto-started local server
DEFAULT_PORT = 15099


@dataclass(slots=True)
class _AggregatorStub:
    """Minimal stub exposing only the is_aggregator flag."""

    is_aggregator: bool = field(default=False)


def _make_conformance_controller(initial: bool = False) -> AggregatorController:
    """Build an AggregatorController backed by lightweight stubs."""
    sync_stub = _AggregatorStub(is_aggregator=initial)
    network_stub = _AggregatorStub(is_aggregator=initial)
    return AggregatorController(
        sync_service=sync_stub,  # type: ignore[arg-type]
        network_service=network_stub,  # type: ignore[arg-type]
    )


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

        except Exception as e:
            self.error = e
            self.ready.set()
        finally:
            if self.loop:
                self.loop.close()

    def _create_server(self) -> ApiServer:
        """Create the API server with a test store and aggregator controller."""
        store = make_store(num_validators=3, validator_id=None, genesis_time=int(time.time()))

        controller = _make_conformance_controller(initial=False)
        config = ApiServerConfig(host="127.0.0.1", port=self.port)
        return ApiServer(
            config=config,
            store_getter=lambda: store,
            aggregator_controller=controller,
        )

    def stop(self) -> None:
        """Stop the server and event loop, awaiting cleanup so _async_stop is run."""
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
        # Use external server
        yield external_url
    else:
        # Start local server
        server_thread = _ServerThread(DEFAULT_PORT)
        server_thread.start()
        server_thread.ready.wait(timeout=10.0)

        if server_thread.error:
            pytest.fail(f"Failed to start local server: {server_thread.error}")

        url = f"http://127.0.0.1:{DEFAULT_PORT}"

        if not _wait_for_server(url):
            server_thread.stop()
            pytest.fail("Local server failed to become ready")

        yield url

        server_thread.stop()
