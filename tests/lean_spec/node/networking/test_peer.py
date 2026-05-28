"""Tests for minimal peer module."""

from lean_spec.node.networking import PeerId
from lean_spec.node.networking.peer import PeerInfo
from lean_spec.node.networking.reqresp import Status
from lean_spec.node.networking.types import ConnectionState, Direction, Multiaddr
from lean_spec.spec.forks import Checkpoint, Slot
from lean_spec.spec.ssz import Bytes32


def peer(name: str) -> PeerId:
    """Create a PeerId from a test name."""
    return PeerId.from_base58(name)


class TestConnectionState:
    """Tests for ConnectionState enum."""

    def test_state_values(self) -> None:
        """ConnectionState has the 4 expected states."""
        assert ConnectionState.DISCONNECTED == 1
        assert ConnectionState.CONNECTING == 2
        assert ConnectionState.CONNECTED == 3
        assert ConnectionState.DISCONNECTING == 4


class TestDirection:
    """Tests for Direction enum."""

    def test_direction_values(self) -> None:
        """Direction has inbound and outbound."""
        assert Direction.INBOUND == 1
        assert Direction.OUTBOUND == 2


class TestPeerInfo:
    """Tests for PeerInfo dataclass."""

    def test_create_peer_info(self) -> None:
        """PeerInfo can be created with peer ID."""
        test_peer = peer("16Uiu2HAk")
        info = PeerInfo(peer_id=test_peer)
        assert info.peer_id == test_peer
        assert info.state == ConnectionState.DISCONNECTED
        assert info.direction == Direction.OUTBOUND
        assert info.address is None

    def test_create_with_all_fields(self) -> None:
        """PeerInfo can be created with all fields."""
        info = PeerInfo(
            peer_id=peer("16Uiu2HAk"),
            state=ConnectionState.CONNECTED,
            direction=Direction.INBOUND,
            address=Multiaddr("/ip4/192.168.1.1/udp/9000/quic-v1"),
        )
        assert info.state == ConnectionState.CONNECTED
        assert info.direction == Direction.INBOUND
        assert info.address == "/ip4/192.168.1.1/udp/9000/quic-v1"

    def test_is_connected(self) -> None:
        """is_connected() returns True only when connected."""
        info = PeerInfo(peer_id=peer("test"))

        info.state = ConnectionState.DISCONNECTED
        assert not info.is_connected()

        info.state = ConnectionState.CONNECTING
        assert not info.is_connected()

        info.state = ConnectionState.CONNECTED
        assert info.is_connected()

        info.state = ConnectionState.DISCONNECTING
        assert not info.is_connected()

    def test_enr_and_status_fields(self) -> None:
        """Test that enr and status fields exist and default to None."""
        info = PeerInfo(peer_id=peer("test"))
        assert info.enr is None
        assert info.status is None

    def test_status_can_be_set(self) -> None:
        """Test that status can be set and read back."""
        info = PeerInfo(peer_id=peer("test"))

        # Create a test status
        test_checkpoint = Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(100))
        test_status = Status(
            finalized=test_checkpoint,
            head=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(200)),
        )

        # Set status
        info.status = test_status
        assert info.status is not None
        assert info.status.finalized.slot == Slot(100)
        assert info.status.head.slot == Slot(200)
