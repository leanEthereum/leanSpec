"""
Shared pytest fixtures for networking tests.

Provides peer ID and connection state fixtures.
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.peer.info import PeerInfo
from lean_spec.subspecs.networking.types import ConnectionState

# -----------------------------------------------------------------------------
# Peer ID Fixtures
# -----------------------------------------------------------------------------


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


# -----------------------------------------------------------------------------
# Peer Info Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture
def connected_peer_info(peer_id: PeerId) -> PeerInfo:
    """Peer info in connected state."""
    return PeerInfo(
        peer_id=peer_id,
        state=ConnectionState.CONNECTED,
        address="/ip4/192.168.1.1/tcp/9000",
    )


@pytest.fixture
def disconnected_peer_info(peer_id: PeerId) -> PeerInfo:
    """Peer info in disconnected state."""
    return PeerInfo(
        peer_id=peer_id,
        state=ConnectionState.DISCONNECTED,
        address="/ip4/192.168.1.2/tcp/9000",
    )
