r"""
multistream-select 1.0 protocol negotiation.

multistream-select is a simple text-based protocol for negotiating
which protocol to use on a connection or stream. It's used three times
per libp2p connection:

    1. Connection level: negotiate encryption (e.g., /noise)
    2. After encryption: negotiate multiplexer (e.g., /yamux/1.0.0)
    3. Per stream: negotiate application protocol (e.g., /leanconsensus/req/status/1/ssz_snappy)

Wire format:
    Each message is: [varint length][payload][newline]
    The length includes the trailing newline.

Example handshake:
    -> /multistream/1.0.0\n
    <- /multistream/1.0.0\n
    -> /noise\n
    <- /noise\n
    [Noise handshake begins]

Rejection:
    -> /some-protocol\n
    <- na\n

The protocol is intentionally simple - all complexity is in the
state machine, not the wire format.

References:
    - https://github.com/multiformats/multistream-select
"""

from .negotiation import (
    MULTISTREAM_PROTOCOL_ID,
    NA,
    NegotiationError,
    negotiate_client,
    negotiate_lazy_client,
    negotiate_server,
)

__all__ = [
    "MULTISTREAM_PROTOCOL_ID",
    "NA",
    "NegotiationError",
    "negotiate_client",
    "negotiate_lazy_client",
    "negotiate_server",
]
