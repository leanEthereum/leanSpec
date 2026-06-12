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


class TestPeerInfo:
    """Tests for PeerInfo dataclass."""

    def test_create_peer_info(self) -> None:
        """PeerInfo can be created with peer ID."""
        test_peer = peer("16Uiu2HAk")
        peer_info = PeerInfo(peer_id=test_peer)
        assert peer_info.peer_id == test_peer
        assert peer_info.state == ConnectionState.DISCONNECTED
        assert peer_info.direction == Direction.OUTBOUND
        assert peer_info.address is None

    def test_create_with_all_fields(self) -> None:
        """PeerInfo can be created with all fields."""
        peer_info = PeerInfo(
            peer_id=peer("16Uiu2HAk"),
            state=ConnectionState.CONNECTED,
            direction=Direction.INBOUND,
            address=Multiaddr("/ip4/192.168.1.1/udp/9000/quic-v1"),
        )
        assert peer_info.state == ConnectionState.CONNECTED
        assert peer_info.direction == Direction.INBOUND
        assert peer_info.address == "/ip4/192.168.1.1/udp/9000/quic-v1"

    def test_is_connected(self) -> None:
        """is_connected() returns True only when connected."""
        peer_info = PeerInfo(peer_id=peer("test"))

        peer_info.state = ConnectionState.DISCONNECTED
        assert not peer_info.is_connected()

        peer_info.state = ConnectionState.CONNECTING
        assert not peer_info.is_connected()

        peer_info.state = ConnectionState.CONNECTED
        assert peer_info.is_connected()

        peer_info.state = ConnectionState.DISCONNECTING
        assert not peer_info.is_connected()

    def test_enr_and_status_fields(self) -> None:
        """Test that enr and status fields exist and default to None."""
        peer_info = PeerInfo(peer_id=peer("test"))
        assert peer_info.enr is None
        assert peer_info.status is None

    def test_status_can_be_set(self) -> None:
        """Test that status can be set and read back."""
        peer_info = PeerInfo(peer_id=peer("test"))

        # Create a test status
        test_checkpoint = Checkpoint(root=Bytes32(b"\x00" * 32), slot=Slot(100))
        test_status = Status(
            finalized=test_checkpoint,
            head=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(200)),
        )

        # Set status
        peer_info.status = test_status
        assert peer_info.status is not None
        assert peer_info.status.finalized.slot == Slot(100)
        assert peer_info.status.head.slot == Slot(200)
