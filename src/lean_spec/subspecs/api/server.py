"""
API server for checkpoint sync and node status endpoints.

Provides HTTP endpoints for:
- /lean/states/finalized - Serve finalized checkpoint state as SSZ
- /health - Health check endpoint

This matches the checkpoint sync API implemented in zeam.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lean_spec.subspecs.forkchoice import Store

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ApiServerConfig:
    """Configuration for the API server."""

    host: str = "0.0.0.0"
    """Host address to bind to."""

    port: int = 5052
    """Port to listen on."""

    enabled: bool = True
    """Whether the API server is enabled."""


@dataclass(slots=True)
class ApiServer:
    """
    HTTP API server for checkpoint sync and node status.

    Provides endpoints for:
    - Checkpoint sync: Download finalized state for fast sync
    - Health checks: Verify node is running
    - Status: Get current chain status

    The server runs in the background and serves requests asynchronously.
    """

    config: ApiServerConfig
    """Server configuration."""

    _store_getter: callable = field(default=lambda: None)
    """Callable that returns the current Store instance."""

    _server: asyncio.Server | None = field(default=None)
    """The asyncio server instance."""

    _shutdown: asyncio.Event = field(default_factory=asyncio.Event)
    """Event signaling shutdown request."""

    def set_store_getter(self, getter: callable) -> None:
        """
        Set the store getter function.

        Args:
            getter: Callable that returns the current Store instance.
        """
        self._store_getter = getter

    @property
    def store(self) -> Store | None:
        """Get the current Store instance."""
        return self._store_getter()

    async def start(self) -> None:
        """
        Start the API server.

        Binds to the configured host and port and begins accepting connections.
        """
        if not self.config.enabled:
            logger.info("API server is disabled")
            return

        self._server = await asyncio.start_server(
            self._handle_connection,
            self.config.host,
            self.config.port,
        )

        addrs = ", ".join(str(sock.getsockname()) for sock in self._server.sockets)
        logger.info(f"API server listening on {addrs}")

    async def run(self) -> None:
        """
        Run the API server until shutdown.

        This method blocks until stop() is called.
        """
        if self._server is None:
            await self.start()

        if self._server is None:
            return

        async with self._server:
            await self._server.serve_forever()

    def stop(self) -> None:
        """
        Request graceful shutdown.

        Signals the server to stop accepting new connections.
        """
        if self._server is not None:
            self._server.close()
        self._shutdown.set()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle an incoming HTTP connection.

        Parses the request and routes to the appropriate handler.
        """
        try:
            # Read the HTTP request line and headers
            request_line = await reader.readline()
            if not request_line:
                return

            # Parse request line (e.g., "GET /health HTTP/1.1")
            request_str = request_line.decode("utf-8").strip()
            parts = request_str.split(" ")
            if len(parts) < 2:
                await self._send_error(writer, HTTPStatus.BAD_REQUEST, "Invalid request")
                return

            method, path = parts[0], parts[1]

            # Read headers (we don't need them for now, but must consume them)
            while True:
                header_line = await reader.readline()
                if header_line == b"\r\n" or header_line == b"\n" or not header_line:
                    break

            # Route the request
            await self._route_request(method, path, writer)

        except Exception as e:
            logger.warning(f"Error handling request: {e}")
            try:
                await self._send_error(writer, HTTPStatus.INTERNAL_SERVER_ERROR, str(e))
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _route_request(
        self,
        method: str,
        path: str,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Route the request to the appropriate handler.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            writer: Stream writer for sending response
        """
        if method != "GET":
            await self._send_error(writer, HTTPStatus.METHOD_NOT_ALLOWED, "Method not allowed")
            return

        # Route to handlers
        if path == "/health":
            await self._handle_health(writer)
        elif path == "/lean/states/finalized":
            await self._handle_finalized_state(writer)
        else:
            await self._send_error(writer, HTTPStatus.NOT_FOUND, "Not found")

    async def _handle_health(self, writer: asyncio.StreamWriter) -> None:
        """
        Handle health check endpoint.

        Returns a simple JSON response indicating the server is healthy.
        """
        response = {"status": "healthy", "service": "lean-spec-api"}
        await self._send_json(writer, response)

    async def _handle_finalized_state(self, writer: asyncio.StreamWriter) -> None:
        """
        Handle finalized checkpoint state endpoint.

        Serves the finalized state as SSZ binary at /lean/states/finalized.
        This endpoint is used for checkpoint sync - clients can download
        the finalized state to bootstrap quickly instead of syncing from genesis.
        """
        store = self.store
        if store is None:
            await self._send_error(
                writer,
                HTTPStatus.SERVICE_UNAVAILABLE,
                "Store not initialized",
            )
            return

        # Get the finalized checkpoint
        finalized = store.latest_finalized

        # Get the state at the finalized checkpoint
        # The state is stored in store.states keyed by block root
        if finalized.root not in store.states:
            await self._send_error(
                writer,
                HTTPStatus.NOT_FOUND,
                "Finalized state not available",
            )
            return

        state = store.states[finalized.root]

        # Serialize to SSZ
        ssz_bytes = state.encode_bytes()

        # Send response
        await self._send_binary(writer, ssz_bytes, "application/octet-stream")

    async def _send_json(
        self,
        writer: asyncio.StreamWriter,
        data: dict,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        """Send a JSON response."""
        body = json.dumps(data).encode("utf-8")
        headers = [
            f"HTTP/1.1 {status.value} {status.phrase}",
            "Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(body)}",
            "Connection: close",
            "",
            "",
        ]
        response = "\r\n".join(headers).encode("utf-8") + body
        writer.write(response)
        await writer.drain()

    async def _send_binary(
        self,
        writer: asyncio.StreamWriter,
        data: bytes,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        """Send a binary response."""
        headers = [
            f"HTTP/1.1 {status.value} {status.phrase}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(data)}",
            "Connection: close",
            "",
            "",
        ]
        response = "\r\n".join(headers).encode("utf-8") + data
        writer.write(response)
        await writer.drain()

    async def _send_error(
        self,
        writer: asyncio.StreamWriter,
        status: HTTPStatus,
        message: str,
    ) -> None:
        """Send an error response."""
        await self._send_json(writer, {"error": message}, status)
