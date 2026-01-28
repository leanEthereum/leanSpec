"""
Inbound ReqResp protocol handlers.

This module handles incoming peer requests in the Ethereum consensus protocol.
A peer opens a stream, sends a request, and expects one or more response chunks.


WHY INBOUND AND OUTBOUND ARE SEPARATE
-------------------------------------
Ethereum's req/resp protocol is asymmetric:

- Outbound: We initiate. We choose what to ask.
- Inbound: Peer initiates. We must respond correctly.

The flows mirror each other but have different responsibilities:

    Outbound: open_stream -> encode_request -> write -> read -> decode_response
    Inbound:  accept_stream -> decode_request -> handle -> encode_response -> write

Keeping them separate makes each flow easier to understand and test.


WHY HANDLERS USE ResponseStream ABSTRACTION
-------------------------------------------
Handlers receive a ResponseStream instead of a raw transport stream.
This design provides three benefits:

1. Testability: Unit tests provide mock streams without network I/O.
2. Flexibility: Different transports (yamux, memory, etc.) work with the same handlers.
3. Clarity: Handlers focus on protocol logic, not wire format encoding.

The ResponseStream translates high-level operations (send success, send error) into the
wire format defined in codec.py.


WIRE FORMAT
-----------
All responses use the same wire format from codec.py:

    [response_code: 1 byte][varint: uncompressed_length][snappy_framed_payload]

Response codes:

- 0 (SUCCESS): Payload contains SSZ-encoded response data
- 1 (INVALID_REQUEST): Peer sent malformed or invalid request
- 2 (SERVER_ERROR): Internal error during processing
- 3 (RESOURCE_UNAVAILABLE): Requested data not found

Error payloads contain UTF-8 encoded human-readable messages.


PROTOCOL IDENTIFIERS
--------------------
Each request type has a unique protocol ID negotiated via multistream-select:

- Status: "/leanconsensus/req/status/1/ssz_snappy"
- BlocksByRoot: "/leanconsensus/req/blocks_by_root/1/ssz_snappy"

The protocol ID determines:

- Which SSZ type to deserialize the request into
- Which handler processes the request
- What response type(s) the peer expects


References:
    Ethereum P2P spec:
        https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md
    Wire format details:
        See codec.py in this package
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol

from lean_spec.snappy import frame_decompress
from lean_spec.subspecs.containers import SignedBlockWithAttestation
from lean_spec.subspecs.networking.transport.connection.types import Stream
from lean_spec.subspecs.networking.varint import decode_varint
from lean_spec.types import Bytes32

from .codec import ResponseCode
from .message import (
    BLOCKS_BY_ROOT_PROTOCOL_V1,
    STATUS_PROTOCOL_V1,
    BlocksByRootRequest,
    Status,
)

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS: float = 10.0
"""Default timeout for processing inbound requests."""


class ResponseStream(Protocol):
    """
    Protocol for sending chunked responses to peers.

    Abstracts the underlying stream transport, allowing handlers to send
    responses without knowing the wire format details.

    Response Types
    --------------
    - Success: Contains SSZ-encoded response data.
    - Error: Contains UTF-8 error message.

    Both types are encoded using the same wire format from codec.py.
    """

    async def send_success(self, ssz_data: bytes) -> None:
        """
        Send a SUCCESS response chunk.

        Args:
            ssz_data: SSZ-encoded response payload.
        """
        ...

    async def send_error(self, code: ResponseCode, message: str) -> None:
        """
        Send an error response and close the stream.

        Args:
            code: Error code (INVALID_REQUEST, SERVER_ERROR, RESOURCE_UNAVAILABLE).
            message: Human-readable error description.
        """
        ...

    async def finish(self) -> None:
        """
        Signal end of response stream.

        Called after all response chunks have been sent.
        Closes the stream gracefully.
        """
        ...


@dataclass(slots=True)
class YamuxResponseStream:
    """
    ResponseStream implementation wrapping a yamux stream.

    Encodes responses using the wire format from codec.py and writes
    them to the underlying stream.
    """

    _stream: Stream
    """Underlying yamux stream."""

    async def send_success(self, ssz_data: bytes) -> None:
        """
        Send a SUCCESS response chunk.

        Args:
            ssz_data: SSZ-encoded response payload.
        """
        # Encode the response using the protocol wire format.
        #
        # ResponseCode.SUCCESS (0x00) tells the peer this chunk contains valid data.
        # The encode method handles:
        #
        # 1. Prepending the response code byte
        # 2. Adding the varint length prefix
        # 3. Compressing with Snappy framing
        encoded = ResponseCode.SUCCESS.encode(ssz_data)

        # Write using sync write + async drain for compatibility with both
        # raw QUIC streams (async write) and wrapper streams (sync write + drain).
        write_result = self._stream.write(encoded)
        if hasattr(write_result, "__await__"):
            await write_result
        drain = getattr(self._stream, "drain", None)
        if drain is not None:
            await drain()

    async def send_error(self, code: ResponseCode, message: str) -> None:
        """
        Send an error response.

        Args:
            code: Error code.
            message: Human-readable error description.
        """
        # Error messages must be UTF-8 encoded per the Ethereum P2P spec.
        #
        # The spec mandates UTF-8 for interoperability across clients.
        # Common error codes:
        #
        # - INVALID_REQUEST (1): Malformed request, bad SSZ, protocol violation
        # - SERVER_ERROR (2): Internal failure, handler exception
        # - RESOURCE_UNAVAILABLE (3): Block/blob not found
        encoded = code.encode(message.encode("utf-8"))

        # Write using sync write + async drain for compatibility.
        write_result = self._stream.write(encoded)
        if hasattr(write_result, "__await__"):
            await write_result
        drain = getattr(self._stream, "drain", None)
        if drain is not None:
            await drain()

    async def finish(self) -> None:
        """Close the stream gracefully."""
        await self._stream.close()


class RequestHandler(ABC):
    """
    Abstract base for request handlers.

    Implementations provide the logic for responding to specific request types.
    The sync service or network layer implements this to provide chain data.


    HANDLER CONTRACT
    ----------------
    Handlers MUST:

    - Send at least one response (success or error) via ResponseStream.
    - Not raise exceptions (errors should be sent as error responses).
    - Be idempotent (same request may arrive multiple times).


    CONCURRENCY
    -----------
    Handlers may be called concurrently for different requests.
    Implementations should be thread-safe if accessing shared state.
    """

    @abstractmethod
    async def handle_status(self, request: Status, response: ResponseStream) -> None:
        """
        Handle incoming Status request.

        The handler should respond with our current chain status.

        Args:
            request: Peer's status message.
            response: Stream for sending our status response.
        """
        ...

    @abstractmethod
    async def handle_blocks_by_root(
        self,
        request: BlocksByRootRequest,
        response: ResponseStream,
    ) -> None:
        """
        Handle incoming BlocksByRoot request.

        The handler should send each requested block as a separate response chunk.
        Blocks we do not have should be skipped (or RESOURCE_UNAVAILABLE sent).

        Args:
            request: List of block roots being requested.
            response: Stream for sending block responses.
        """
        ...


BlockLookup = Callable[[Bytes32], Awaitable[SignedBlockWithAttestation | None]]
"""Type alias for block lookup function.

Takes a block root and returns the block if available, None otherwise.
"""


@dataclass(slots=True)
class DefaultRequestHandler(RequestHandler):
    """
    Default request handler implementation.

    Uses callbacks to retrieve chain data.
    Suitable for use with NetworkEventSource.


    STATUS HANDLING
    ---------------
    Returns our current status, which must be set via our_status field.
    If no status is set, responds with SERVER_ERROR.


    BLOCKS BY ROOT HANDLING
    -----------------------
    Looks up each requested block via the block_lookup callback.
    Available blocks are sent as SUCCESS chunks.
    Unavailable blocks are silently skipped (per Ethereum P2P spec).
    """

    our_status: Status | None = None
    """Our current chain status for Status responses."""

    block_lookup: BlockLookup | None = None
    """Callback to look up blocks by root."""

    async def handle_status(self, request: Status, response: ResponseStream) -> None:
        """
        Handle incoming Status request.

        Responds with our current chain status.

        Args:
            request: Peer's status (logged but not used for response).
            response: Stream for sending our status.
        """
        # Guard: Ensure we have a status configured.
        #
        # This can happen during node startup before sync completes.
        if self.our_status is None:
            logger.warning("Status request received but no status configured")
            await response.send_error(ResponseCode.SERVER_ERROR, "Status not available")
            return

        # Respond with OUR status, not the peer's.
        #
        # The Status exchange is symmetric: each side sends its own chain state.
        # The peer's status (in `request`) is useful for:
        #
        # - Logging for debugging
        # - Peer scoring (handled elsewhere)
        # - Fork detection (handled by sync layer)
        #
        # But it does NOT affect what we respond with.
        # We always send our current head and finalized checkpoint.
        await response.send_success(self.our_status.encode_bytes())

    async def handle_blocks_by_root(
        self,
        request: BlocksByRootRequest,
        response: ResponseStream,
    ) -> None:
        """
        Handle incoming BlocksByRoot request.

        Looks up and sends each requested block.

        Args:
            request: Block roots to look up.
            response: Stream for sending blocks.
        """
        # Guard: Ensure we have a block lookup configured.
        if self.block_lookup is None:
            logger.warning("BlocksByRoot request received but no block_lookup configured")
            await response.send_error(ResponseCode.SERVER_ERROR, "Block lookup not available")
            return

        # Process each requested block root.
        #
        # Key design decisions per Ethereum P2P spec:
        #
        # 1. Missing blocks are SKIPPED, not errors.
        #    Peers expect partial responses. They track which roots they received.
        #
        # 2. Lookup errors are LOGGED and SKIPPED.
        #    One failed lookup should not prevent returning other blocks.
        #
        # 3. Order is preserved.
        #    Blocks are sent in the same order as requested.
        for root in request.roots.data:
            try:
                block = await self.block_lookup(root)
                if block is not None:
                    await response.send_success(block.encode_bytes())

                # Missing block: Skip silently.
                #
                # The spec allows partial responses.
                # Peers handle missing blocks by requesting from other peers.
                # Sending RESOURCE_UNAVAILABLE for each missing block would be noisy.
            except Exception as e:
                # Lookup error: Log and continue.
                #
                # Database errors, timeouts, etc. should not abort the response.
                # The peer can retry or ask another peer for this specific block.
                logger.warning("Error looking up block %s: %s", root.hex()[:8], e)


REQRESP_PROTOCOL_IDS: frozenset[str] = frozenset(
    {
        STATUS_PROTOCOL_V1,
        BLOCKS_BY_ROOT_PROTOCOL_V1,
    }
)
"""Protocol IDs handled by ReqRespServer."""


@dataclass(slots=True)
class ReqRespServer:
    """
    Server for handling inbound ReqResp streams.

    Routes incoming requests to the appropriate handler based on protocol ID.
    Handles decoding, dispatching, and error handling.


    STREAM LIFECYCLE
    ----------------
    For each incoming stream:

    1. Read all request data from stream.
    2. Decode the request (remove length prefix, decompress Snappy).
    3. Deserialize SSZ bytes to the appropriate type.
    4. Dispatch to handler.
    5. Handler sends response(s) via ResponseStream.
    6. Close stream.


    ERROR HANDLING
    --------------
    Errors at any stage result in an error response:

    - Malformed request: INVALID_REQUEST
    - Decode failure: INVALID_REQUEST
    - Handler error: SERVER_ERROR
    """

    handler: RequestHandler
    """Handler for processing requests."""

    _pending_data: dict[int, bytearray] = field(default_factory=dict)
    """Buffer for accumulating request data by stream ID.

    Request data may arrive in multiple chunks. We accumulate until
    the stream closes, then process the complete request.
    """

    async def handle_stream(self, stream: Stream, protocol_id: str) -> None:
        """
        Handle an incoming ReqResp stream.

        Reads the request, decodes it, and dispatches to the appropriate handler.

        Args:
            stream: Incoming yamux stream.
            protocol_id: Negotiated protocol ID.
        """
        response = YamuxResponseStream(_stream=stream)

        try:
            # Step 1: Read and decode the request.
            #
            # _read_request handles the wire format:
            # - Reads varint length prefix
            # - Reads and decompresses Snappy framed payload
            # - Returns raw SSZ bytes
            #
            # This does NOT wait for stream close - it reads exactly
            # the amount of data specified by the length prefix.
            ssz_bytes = await self._read_request(stream)
            if not ssz_bytes:
                await response.send_error(ResponseCode.INVALID_REQUEST, "Empty request")
                return

            # Step 2: Dispatch based on protocol ID.
            #
            # The protocol ID was negotiated via multistream-select before
            # this stream was created. It tells us:
            #
            # - What SSZ type to deserialize into
            # - Which handler processes the request
            await self._dispatch(protocol_id, ssz_bytes, response)

        except Exception as e:
            # Catch-all for unexpected errors.
            #
            # Any exception reaching here indicates a bug or system failure.
            # Send SERVER_ERROR so the peer knows we had an internal problem.
            # The peer may retry or try another node.
            logger.warning("Unexpected error handling request: %s", e)
            try:
                await response.send_error(ResponseCode.SERVER_ERROR, "Internal error")
            except Exception:
                # Write failed. Nothing more we can do.
                pass

        finally:
            # Always close the stream.
            #
            # This runs regardless of success or failure.
            # Closing signals to the peer that the response is complete.
            try:
                await response.finish()
            except Exception:
                # Close failed. Log is unnecessary - peer will timeout.
                pass

    async def _read_request(self, stream: Stream) -> bytes:
        """
        Read length-prefixed request data from a stream.

        The wire format is: [varint_length][snappy_framed_payload]

        Reads the varint length first, then reads until we have enough
        data to decompress successfully. Does NOT wait for stream close.

        Args:
            stream: Stream to read from.

        Returns:
            Complete SSZ request data (decompressed).
        """
        buffer = bytearray()

        # Read until we have the varint length prefix
        declared_length = None
        varint_size = 0

        while declared_length is None:
            chunk = await stream.read()
            if not chunk:
                # Stream closed before we got the length
                return bytes(buffer)
            buffer.extend(chunk)

            # Try to decode the varint
            try:
                declared_length, varint_size = decode_varint(bytes(buffer))
            except Exception:
                # Need more data for varint
                continue

        # Now read until we can successfully decompress
        compressed_data = buffer[varint_size:]

        while True:
            try:
                decompressed = frame_decompress(bytes(compressed_data))
                if len(decompressed) == declared_length:
                    return decompressed
                # Length mismatch - need more data
            except Exception:
                # Decompression failed - need more data
                pass

            chunk = await stream.read()
            if not chunk:
                # Stream closed, try one more decompress
                try:
                    return frame_decompress(bytes(compressed_data))
                except Exception:
                    return bytes(buffer)
            compressed_data.extend(chunk)

    async def _dispatch(
        self,
        protocol_id: str,
        ssz_bytes: bytes,
        response: ResponseStream,
    ) -> None:
        """
        Dispatch a request to the appropriate handler.

        Args:
            protocol_id: Protocol ID identifying the request type.
            ssz_bytes: SSZ-encoded request payload.
            response: Stream for sending responses.
        """
        # Dispatch pattern: Protocol ID determines handler.
        #
        # Each protocol ID maps to:
        #
        # 1. An SSZ type for deserialization
        # 2. A handler method to process the request
        #
        # Adding a new request type requires:
        #
        # - Define the SSZ types in message.py
        # - Add the protocol ID constant
        # - Add a handler method to RequestHandler
        # - Add a branch here

        if protocol_id == STATUS_PROTOCOL_V1:
            # Status request: Peer wants our chain state.
            #
            # SSZ decoding validates:
            #
            # - Correct size (80 bytes for Status)
            # - Valid field offsets
            try:
                request = Status.decode_bytes(ssz_bytes)
            except Exception as e:
                # SSZ decode failure: wrong size, malformed offsets, etc.
                #
                # This is INVALID_REQUEST - the peer sent bad SSZ.
                logger.debug("Status decode error: %s", e)
                await response.send_error(ResponseCode.INVALID_REQUEST, "Invalid Status message")
                return
            await self.handler.handle_status(request, response)

        elif protocol_id == BLOCKS_BY_ROOT_PROTOCOL_V1:
            # BlocksByRoot request: Peer wants specific blocks by hash.
            #
            # The request is an SSZ list of 32-byte roots.
            # Length must be a multiple of 32 bytes.
            try:
                request = BlocksByRootRequest.decode_bytes(ssz_bytes)
            except Exception as e:
                # SSZ decode failure: wrong size, not multiple of 32, etc.
                logger.debug("BlocksByRootRequest decode error: %s", e)
                await response.send_error(
                    ResponseCode.INVALID_REQUEST, "Invalid BlocksByRootRequest message"
                )
                return
            await self.handler.handle_blocks_by_root(request, response)

        else:
            # Unknown protocol ID.
            #
            # This should not happen in normal operation.
            # The transport layer filters streams by REQRESP_PROTOCOL_IDS.
            #
            # If we reach here, it indicates a bug in stream routing.
            # Use SERVER_ERROR because this is our fault, not the peer's.
            logger.warning("Unknown protocol: %s", protocol_id)
            await response.send_error(ResponseCode.SERVER_ERROR, "Unknown protocol")
