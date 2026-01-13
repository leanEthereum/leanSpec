"""Tests for minimal peer module."""

from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.peer import Direction, PeerInfo
from lean_spec.subspecs.networking.types import ConnectionState, GoodbyeReason


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


class TestGoodbyeReason:
    """Tests for GoodbyeReason codes."""

    def test_official_codes(self) -> None:
        """Official spec codes have correct values."""
        assert GoodbyeReason.CLIENT_SHUTDOWN == 1
        assert GoodbyeReason.IRRELEVANT_NETWORK == 2
        assert GoodbyeReason.FAULT_OR_ERROR == 3


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
            address="/ip4/192.168.1.1/tcp/9000",
        )
        assert info.state == ConnectionState.CONNECTED
        assert info.direction == Direction.INBOUND
        assert info.address == "/ip4/192.168.1.1/tcp/9000"

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

    def test_update_last_seen(self) -> None:
        """update_last_seen() updates timestamp."""
        info = PeerInfo(peer_id=peer("test"))
        original_time = info.last_seen

        # Small delay to ensure time difference
        import time

        time.sleep(0.01)

        info.update_last_seen()
        assert info.last_seen > original_time
