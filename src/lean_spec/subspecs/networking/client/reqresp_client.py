"""
Request/Response client implementing NetworkRequester.

This module provides a concrete implementation of the NetworkRequester protocol
used by the sync service. It uses the existing ConnectionManager and reqresp
codec to send requests and receive responses.

Wire Format
-----------
All req/resp messages use the same format:

Request::

    [varint: uncompressed_length][snappy_framed_ssz_payload]

Response::

    [response_code: 1 byte][varint: uncompressed_length][snappy_framed_ssz_payload]

Protocol Flow
-------------
1. Open a new yamux stream
2. Negotiate the protocol via multistream-select
3. Send SSZ-encoded, Snappy-compressed request
4. Read SSZ-encoded, Snappy-compressed response
5. Close the stream
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.networking.reqresp.codec import (
    CodecError,
    ResponseCode,
    encode_request,
)
from lean_spec.subspecs.networking.reqresp.message import (
    BLOCKS_BY_ROOT_PROTOCOL_V1,
    STATUS_PROTOCOL_V1,
    BlocksByRootRequest,
    BlocksByRootRequestRoots,
    Status,
)
from lean_spec.subspecs.networking.transport import PeerId
from lean_spec.subspecs.networking.transport.connection.manager import (
    ConnectionManager,
    YamuxConnection,
)
from lean_spec.subspecs.networking.transport.quic.connection import QuicConnection
from lean_spec.types import Bytes32

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS: float = 10.0
"""Default timeout for req/resp requests."""


@dataclass(slots=True)
class ReqRespClient:
    """
    Implements NetworkRequester using ConnectionManager.

    Provides methods for sending BlocksByRoot and Status requests to peers.
    Uses the existing transport stack (yamux + noise) and codec (SSZ + Snappy).

    Thread Safety
    -------------
    This class is designed for single-threaded async operation.
    Multiple concurrent requests to different peers are safe.
    """

    connection_manager: ConnectionManager
    """Connection manager providing transport."""

    _connections: dict[PeerId, YamuxConnection | QuicConnection] = field(default_factory=dict)
    """Active connections by peer ID."""

    timeout: float = REQUEST_TIMEOUT_SECONDS
    """Request timeout in seconds."""

    def register_connection(self, peer_id: PeerId, conn: YamuxConnection | QuicConnection) -> None:
        """
        Register a connection for req/resp use.

        Args:
            peer_id: Peer identifier.
            conn: Established yamux or QUIC connection.
        """
        self._connections[peer_id] = conn

    def unregister_connection(self, peer_id: PeerId) -> None:
        """
        Unregister a connection.

        Args:
            peer_id: Peer identifier to remove.
        """
        self._connections.pop(peer_id, None)

    async def request_blocks_by_root(
        self,
        peer_id: PeerId,
        roots: list[Bytes32],
    ) -> list[SignedBlockWithAttestation]:
        """
        Request blocks by root from a peer.

        Implements the NetworkRequester protocol method.

        Args:
            peer_id: Peer to request from.
            roots: Block roots to request.

        Returns:
            List of blocks received. May be fewer than requested if peer
            doesn't have all blocks. Empty on error.
        """
        if not roots:
            return []

        conn = self._connections.get(peer_id)
        if conn is None:
            logger.debug("No connection to peer %s for blocks_by_root", peer_id)
            return []

        try:
            return await asyncio.wait_for(
                self._do_blocks_by_root_request(conn, roots),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("Timeout requesting blocks from %s", peer_id)
            return []
        except Exception as e:
            logger.warning("Error requesting blocks from %s: %s", peer_id, e)
            return []

    async def _do_blocks_by_root_request(
        self,
        conn: YamuxConnection | QuicConnection,
        roots: list[Bytes32],
    ) -> list[SignedBlockWithAttestation]:
        """
        Execute a BlocksByRoot request.

        Opens a stream, negotiates the protocol, sends the request,
        and reads all response chunks.

        Args:
            conn: Connection to use.
            roots: Block roots to request.

        Returns:
            List of blocks received.
        """
        # Open a new stream and negotiate the protocol.
        stream = await conn.open_stream(BLOCKS_BY_ROOT_PROTOCOL_V1)

        try:
            # Build and send the request.
            request = BlocksByRootRequest(roots=BlocksByRootRequestRoots(data=roots))
            request_bytes = encode_request(request.encode_bytes())
            await stream.write(request_bytes)

            # Half-close to signal we're done sending.
            finish_write = getattr(stream, "finish_write", None)
            if finish_write is not None:
                await finish_write()

            # Read response chunks.
            #
            # Each block is sent as a separate response chunk.
            # We read until the stream closes or we get all blocks.
            blocks: list[SignedBlockWithAttestation] = []

            for _ in range(len(roots)):
                try:
                    response_data = await stream.read()
                    if not response_data:
                        # Stream closed, no more blocks.
                        break

                    code, ssz_bytes = ResponseCode.decode(response_data)

                    if code == ResponseCode.SUCCESS:
                        block = SignedBlockWithAttestation.decode_bytes(ssz_bytes)
                        blocks.append(block)
                    elif code == ResponseCode.RESOURCE_UNAVAILABLE:
                        # Peer doesn't have this block, continue.
                        continue
                    else:
                        # Other error, stop reading.
                        logger.debug("BlocksByRoot error response: %s", code)
                        break

                except CodecError as e:
                    logger.debug("BlocksByRoot decode error: %s", e)
                    break

            return blocks

        finally:
            await stream.close()

    async def send_status(
        self,
        peer_id: PeerId,
        status: Status,
    ) -> Status | None:
        """
        Send Status request and receive response.

        Args:
            peer_id: Peer to exchange status with.
            status: Our status to send.

        Returns:
            Peer's status, or None on error.
        """
        conn = self._connections.get(peer_id)
        if conn is None:
            logger.debug("No connection to peer %s for status", peer_id)
            return None

        try:
            return await asyncio.wait_for(
                self._do_status_request(conn, status),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("Timeout exchanging status with %s", peer_id)
            return None
        except Exception as e:
            logger.warning("Error exchanging status with %s: %s", peer_id, e)
            return None

    async def _do_status_request(
        self,
        conn: YamuxConnection | QuicConnection,
        status: Status,
        retry_count: int = 0,
    ) -> Status | None:
        """
        Execute a Status request.

        Args:
            conn: Connection to use.
            status: Our status to send.
            retry_count: Number of retries attempted (internal).

        Returns:
            Peer's status response.
        """
        stream = None
        try:
            # Open stream and negotiate protocol.
            #
            # This may fail if the QUIC stream is in a bad state right after
            # the handshake. The error "cannot call write() after FIN" can
            # happen during multistream negotiation writes.
            stream = await conn.open_stream(STATUS_PROTOCOL_V1)

            # Yield to allow aioquic to complete any pending state transitions.
            #
            # After multistream negotiation, aioquic may still be processing
            # internal events (epoch discards, stream state updates). A small
            # yield allows the event loop to process these before we write.
            await asyncio.sleep(0)

            # Send our status.
            request_bytes = encode_request(status.encode_bytes())
            await stream.write(request_bytes)

            # Half-close to signal we're done sending.
            finish_write = getattr(stream, "finish_write", None)
            if finish_write is not None:
                await finish_write()

            # Read peer's status response.
            response_data = await stream.read()
            if not response_data:
                return None

            code, ssz_bytes = ResponseCode.decode(response_data)

            if code == ResponseCode.SUCCESS:
                return Status.decode_bytes(ssz_bytes)
            else:
                logger.debug("Status error response: %s", code)
                return None

        except Exception as e:
            # Retry once with a new stream if the first attempt fails.
            #
            # QUIC stream 0 can sometimes be in a bad state right after
            # the handshake completes. Retrying with a new stream (stream 4)
            # often succeeds.
            if retry_count < 1:
                logger.debug(
                    "Status request failed (attempt %d), retrying: %s",
                    retry_count + 1,
                    e,
                )
                if stream is not None:
                    try:
                        await stream.close()
                    except Exception:
                        pass
                await asyncio.sleep(0.01)  # Small delay before retry
                return await self._do_status_request(conn, status, retry_count + 1)
            raise

        finally:
            if stream is not None:
                try:
                    await stream.close()
                except Exception:
                    pass
