r"""
multistream-select 1.0 protocol negotiation implementation.

This module implements both client and server sides of the
multistream-select protocol negotiation.

Wire format:
    Message = [varint length][payload + '\n']
    - Length is encoded as unsigned LEB128 varint
    - Length INCLUDES the trailing newline
    - Maximum message size: 1024 bytes (arbitrary but reasonable)

Protocol flow:
    1. Both sides send the multistream header: /multistream/1.0.0
    2. Client proposes a protocol
    3. Server either echoes (accept) or sends "na" (reject)
    4. If rejected, client can propose another protocol
    5. On acceptance, negotiation is complete

Example:
    Client                      Server
    ------                      ------
    /multistream/1.0.0   ->
                         <-     /multistream/1.0.0
    /noise               ->
                         <-     /noise           (accepted!)
    [Noise handshake begins]

References:
    - https://github.com/multiformats/multistream-select
"""

from __future__ import annotations

import asyncio
from typing import Final

from lean_spec.subspecs.networking.varint import decode_varint, encode_varint

from ..protocols import StreamReaderProtocol, StreamWriterProtocol

MULTISTREAM_PROTOCOL_ID: Final[str] = "/multistream/1.0.0"
"""Protocol identifier for multistream-select 1.0."""

NA: Final[str] = "na"
"""Rejection response sent when protocol is not supported."""

MAX_MESSAGE_SIZE: Final[int] = 1024
"""Maximum message size (arbitrary but reasonable)."""

MAX_NEGOTIATION_ATTEMPTS: Final[int] = 10
"""Maximum protocol proposals before giving up."""

DEFAULT_TIMEOUT: Final[float] = 30.0
"""Default timeout for negotiation (seconds)."""


class NegotiationError(Exception):
    """Raised when protocol negotiation fails."""


async def negotiate_client(
    reader: StreamReaderProtocol,
    writer: StreamWriterProtocol,
    protocols: list[str],
) -> str:
    """
    Client-side protocol negotiation.

    Proposes protocols in order until one is accepted.

    Args:
        reader: Stream to read responses from
        writer: Stream to write proposals to
        protocols: List of protocols to propose, in preference order

    Returns:
        The accepted protocol ID

    Raises:
        NegotiationError: If no protocol is accepted or protocol error

    Usage:
        protocol = await negotiate_client(reader, writer, ["/noise"])
        # Now switch to the negotiated protocol
    """
    if not protocols:
        raise NegotiationError("No protocols to negotiate")

    # Exchange multistream headers
    await _write_message(writer, MULTISTREAM_PROTOCOL_ID)
    header = await _read_message(reader)

    if header != MULTISTREAM_PROTOCOL_ID:
        raise NegotiationError(f"Invalid multistream header: {header!r}")

    # Try each protocol in order
    for protocol in protocols:
        await _write_message(writer, protocol)
        response = await _read_message(reader)

        if response == protocol:
            # Accepted!
            return protocol
        elif response == NA:
            # Rejected, try next
            continue
        else:
            # Unexpected response
            raise NegotiationError(f"Unexpected response: {response!r}")

    # All protocols rejected
    raise NegotiationError(f"No protocols accepted from: {protocols}")


async def negotiate_server(
    reader: StreamReaderProtocol,
    writer: StreamWriterProtocol,
    supported: set[str],
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """
    Server-side protocol negotiation.

    Waits for client to propose protocols, accepts first supported one.

    Args:
        reader: Stream to read proposals from.
        writer: Stream to write responses to.
        supported: Set of protocol IDs this server supports.
        timeout: Maximum time to wait for negotiation (default 30s).

    Returns:
        The negotiated protocol ID.

    Raises:
        NegotiationError: If client proposes no supported protocols,
            too many attempts, or timeout reached.

    The server limits negotiation attempts to prevent DoS attacks
    where a malicious client sends endless unsupported protocols.

    Usage:
        protocol = await negotiate_server(reader, writer, {"/noise", "/plaintext"})
        # Now switch to the negotiated protocol
    """
    if not supported:
        raise NegotiationError("No supported protocols")

    async def _do_negotiation() -> str:
        # Exchange multistream headers
        header = await _read_message(reader)

        if header != MULTISTREAM_PROTOCOL_ID:
            raise NegotiationError(f"Invalid multistream header: {header!r}")

        await _write_message(writer, MULTISTREAM_PROTOCOL_ID)

        # Wait for client proposals with attempt limit
        for _ in range(MAX_NEGOTIATION_ATTEMPTS):
            proposal = await _read_message(reader)

            if proposal in supported:
                # Accept by echoing
                await _write_message(writer, proposal)
                return proposal
            else:
                # Reject and continue
                await _write_message(writer, NA)

        raise NegotiationError(f"Too many negotiation attempts (>{MAX_NEGOTIATION_ATTEMPTS})")

    # Apply timeout to entire negotiation
    try:
        return await asyncio.wait_for(_do_negotiation(), timeout=timeout)
    except asyncio.TimeoutError:
        raise NegotiationError(f"Negotiation timed out after {timeout}s") from None


async def negotiate_lazy_client(
    reader: StreamReaderProtocol,
    writer: StreamWriterProtocol,
    protocol: str,
) -> str:
    """
    Lazy client-side negotiation for single protocol.

    Sends both the multistream header and protocol proposal together,
    then waits for server to accept. This is an optimization that
    reduces round trips when we only want one specific protocol.

    Args:
        reader: Stream to read from
        writer: Stream to write to
        protocol: The protocol to propose

    Returns:
        The accepted protocol (same as input if successful)

    Raises:
        NegotiationError: If protocol not accepted
    """
    # Send header and protocol in one write
    await _write_message(writer, MULTISTREAM_PROTOCOL_ID)
    await _write_message(writer, protocol)

    # Read header
    header = await _read_message(reader)
    if header != MULTISTREAM_PROTOCOL_ID:
        raise NegotiationError(f"Invalid multistream header: {header!r}")

    # Read response to protocol proposal
    response = await _read_message(reader)
    if response == protocol:
        return protocol
    elif response == NA:
        raise NegotiationError(f"Protocol rejected: {protocol}")
    else:
        raise NegotiationError(f"Unexpected response: {response!r}")


async def _write_message(writer: StreamWriterProtocol, message: str) -> None:
    r"""
    Write a multistream message.

    Format: [varint length][message + '\n']

    Args:
        writer: Stream to write to
        message: Message content (without newline)
    """
    payload = message.encode("utf-8") + b"\n"
    length_prefix = encode_varint(len(payload))
    writer.write(length_prefix + payload)
    await writer.drain()


async def _read_message(reader: StreamReaderProtocol) -> str:
    """
    Read a multistream message.

    Args:
        reader: Stream to read from

    Returns:
        Message content (without newline)

    Raises:
        NegotiationError: If message is malformed
    """
    # Read length varint byte by byte
    length_bytes = bytearray()
    while True:
        byte = await reader.read(1)
        if not byte:
            raise NegotiationError("Connection closed while reading length")

        length_bytes.append(byte[0])

        # Check if this is the last byte of the varint (MSB not set)
        if byte[0] & 0x80 == 0:
            break

        if len(length_bytes) > 5:
            raise NegotiationError("Varint too long")

    try:
        length, _ = decode_varint(bytes(length_bytes))
    except Exception as e:
        raise NegotiationError(f"Invalid varint: {e}") from e

    if length > MAX_MESSAGE_SIZE:
        raise NegotiationError(f"Message too large: {length}")

    if length == 0:
        raise NegotiationError("Empty message")

    # Read payload
    payload = await reader.readexactly(length)

    # Strip trailing newline
    if not payload.endswith(b"\n"):
        raise NegotiationError("Message must end with newline")

    return payload[:-1].decode("utf-8")
