"""
Shared pytest fixtures for subspecs tests.

Provides peer ID and connection state fixtures used by both networking and sync tests.
"""

from __future__ import annotations

import pytest

from lean_spec.node.networking import PeerId
from lean_spec.node.networking.peer import PeerInfo
from lean_spec.node.networking.types import ConnectionState, Multiaddr


@pytest.fixture
def peer_id() -> PeerId:
    """Primary test peer ID."""
    return PeerId.from_base58("16Uiu2HAmTestPeer123")


@pytest.fixture
def peer_id_2() -> PeerId:
    """Secondary test peer ID."""
    return PeerId.from_base58("16Uiu2HAmTestPeer456")


@pytest.fixture
def peer_id_3() -> PeerId:
    """Tertiary test peer ID."""
    return PeerId.from_base58("16Uiu2HAmTestPeer789")


@pytest.fixture
def connected_peer_info(peer_id: PeerId) -> PeerInfo:
    """Peer info in connected state."""
    return PeerInfo(
        peer_id=peer_id,
        state=ConnectionState.CONNECTED,
        address=Multiaddr("/ip4/192.168.1.1/udp/9000/quic-v1"),
    )


@pytest.fixture
def disconnected_peer_info(peer_id: PeerId) -> PeerInfo:
    """Peer info in disconnected state."""
    return PeerInfo(
        peer_id=peer_id,
        state=ConnectionState.DISCONNECTED,
        address=Multiaddr("/ip4/192.168.1.2/udp/9000/quic-v1"),
    )
