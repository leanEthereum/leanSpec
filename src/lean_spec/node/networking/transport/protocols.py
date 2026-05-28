"""Shared protocol definitions for transport layer.

InboundStreamProtocol
    Used by ReqResp handler and gossip message processing. Matches
    QuicStreamAdapter's buffered I/O interface.
"""

from __future__ import annotations

from typing import Protocol


class InboundStreamProtocol(Protocol):
    """Buffered stream for inbound request and gossip handling.

    Matches QuicStreamAdapter and test mocks.

    - `read()` takes no arguments (returns next available chunk).
    - `close()` is async (QUIC streams need async FIN).
    """

    async def read(self) -> bytes:
        """Read available data."""
        ...

    def write(self, data: bytes) -> None:
        """Buffer data for writing."""
        ...

    async def drain(self) -> None:
        """Flush buffered data."""
        ...

    async def close(self) -> None:
        """Close the stream."""
        ...
