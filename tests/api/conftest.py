"""Pytest configuration for API conformance tests."""

import asyncio
import threading
import time
from typing import TYPE_CHECKING, Generator

import httpx
import pytest

if TYPE_CHECKING:
    from lean_spec.subspecs.api import ApiServer

# Default port for auto-started local server
DEFAULT_PORT = 15099


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

    def _create_server(self) -> "ApiServer":
        """Create the API server with a test store."""
        from lean_spec.subspecs.api import ApiServer, ApiServerConfig
        from lean_spec.subspecs.containers import Block, BlockBody, State, Validator
        from lean_spec.subspecs.containers.block.types import AggregatedAttestations
        from lean_spec.subspecs.containers.slot import Slot
        from lean_spec.subspecs.containers.state import Validators
        from lean_spec.subspecs.containers.validator import ValidatorIndex
        from lean_spec.subspecs.forkchoice import Store
        from lean_spec.subspecs.ssz.hash import hash_tree_root
        from lean_spec.types import Bytes32, Bytes52, Uint64

        validators = Validators(
            data=[
                Validator(pubkey=Bytes52(b"\x00" * 52), index=ValidatorIndex(i)) for i in range(3)
            ]
        )

        genesis_state = State.generate_genesis(
            genesis_time=Uint64(int(time.time())),
            validators=validators,
        )

        genesis_block = Block(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=hash_tree_root(genesis_state),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )

        store = Store.get_forkchoice_store(genesis_state, genesis_block, None)

        config = ApiServerConfig(host="127.0.0.1", port=self.port)
        return ApiServer(config=config, store_getter=lambda: store)

    def stop(self) -> None:
        """Stop the server and event loop."""
        if self.server and self.loop:
            self.loop.call_soon_threadsafe(self.server.stop)
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
