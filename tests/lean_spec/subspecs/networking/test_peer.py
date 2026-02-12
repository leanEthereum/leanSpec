"""Tests for minimal peer module."""

import time

from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.enr import ENR
from lean_spec.subspecs.networking.enr.eth2 import FAR_FUTURE_EPOCH
from lean_spec.subspecs.networking.peer import Direction, PeerInfo
from lean_spec.subspecs.networking.reqresp import Status
from lean_spec.subspecs.networking.types import ConnectionState, GoodbyeReason
from lean_spec.types import Bytes32, Bytes64, Uint64


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
            address="/ip4/192.168.1.1/udp/9000/quic-v1",
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

    def test_update_last_seen(self) -> None:
        """update_last_seen() updates timestamp."""
        info = PeerInfo(peer_id=peer("test"))
        original_time = info.last_seen

        # Small delay to ensure time difference
        time.sleep(0.01)

        info.update_last_seen()
        assert info.last_seen > original_time


class TestPeerInfoForkDigest:
    """Tests for PeerInfo fork_digest property."""

    def _make_enr_with_eth2(self, fork_digest_bytes: bytes) -> ENR:
        """Create a minimal ENR with eth2 data for testing."""
        # Create eth2 bytes: fork_digest(4) + next_fork_version(4) + next_fork_epoch(8)
        eth2_bytes = (
            fork_digest_bytes + fork_digest_bytes + int(FAR_FUTURE_EPOCH).to_bytes(8, "little")
        )
        return ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={"eth2": eth2_bytes, "id": b"v4"},
        )

    def test_fork_digest_none_without_enr(self) -> None:
        """fork_digest returns None when no ENR is set."""
        info = PeerInfo(peer_id=peer("test"))
        assert info.fork_digest is None

    def test_fork_digest_none_without_eth2(self) -> None:
        """fork_digest returns None when ENR has no eth2 data."""
        # ENR without eth2 key
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=Uint64(1),
            pairs={"id": b"v4"},
        )
        info = PeerInfo(peer_id=peer("test"), enr=enr)
        assert info.fork_digest is None

    def test_fork_digest_returns_bytes(self) -> None:
        """fork_digest returns 4-byte fork_digest from ENR eth2 data."""
        fork_bytes = b"\x12\x34\x56\x78"
        enr = self._make_enr_with_eth2(fork_bytes)
        info = PeerInfo(peer_id=peer("test"), enr=enr)

        assert info.fork_digest == fork_bytes

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

    def test_update_last_seen_updates_timestamp(self) -> None:
        """Test that update_last_seen updates the last_seen timestamp."""
        info = PeerInfo(peer_id=peer("test"))
        original_time = info.last_seen

        # Brief delay
        time.sleep(0.01)

        info.update_last_seen()
        assert info.last_seen > original_time
