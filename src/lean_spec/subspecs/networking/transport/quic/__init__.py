"""
QUIC transport with libp2p-tls for peer authentication.

QUIC provides encryption (TLS 1.3) and multiplexing natively,
with libp2p-tls for peer ID authentication.

Architecture:
    QUIC Transport -> libp2p-tls (peer ID auth) -> Native QUIC streams

References:
    - libp2p QUIC spec: https://github.com/libp2p/specs/tree/master/quic
    - libp2p TLS spec: https://github.com/libp2p/specs/blob/master/tls/tls.md
"""

from .connection import (
    QuicConnection,
    QuicConnectionManager,
    QuicStream,
    QuicTransportError,
    is_quic_multiaddr,
)
from .tls import generate_libp2p_certificate

__all__ = [
    "QuicConnection",
    "QuicConnectionManager",
    "QuicStream",
    "QuicTransportError",
    "is_quic_multiaddr",
    "generate_libp2p_certificate",
]
