"""
Shared pytest fixtures for sync service tests.

Provides sync-specific fixtures.
Core fixtures inherited from parent conftest files.
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.containers import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.peer.info import PeerInfo
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.types import ConnectionState
from lean_spec.types import Bytes32

# -----------------------------------------------------------------------------
# Peer Fixtures
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


# -----------------------------------------------------------------------------
# Sync-Specific Fixtures
# -----------------------------------------------------------------------------


@pytest.fixture
def sample_checkpoint() -> Checkpoint:
    """Sample checkpoint for sync tests."""
    return Checkpoint(root=Bytes32.zero(), slot=Slot(100))


@pytest.fixture
def sample_status(sample_checkpoint: Checkpoint) -> Status:
    """Sample Status message for sync tests."""
    return Status(
        finalized=sample_checkpoint,
        head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
    )
