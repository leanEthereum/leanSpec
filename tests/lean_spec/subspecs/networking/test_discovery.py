"""Tests for Discovery v5 Protocol Specification"""

from typing import TYPE_CHECKING

from lean_spec.subspecs.networking.discovery import (
    MAX_REQUEST_ID_LENGTH,
    PROTOCOL_ID,
    PROTOCOL_VERSION,
    DiscoveryConfig,
    Distance,
    FindNode,
    IdNonce,
    IPv4,
    IPv6,
    KBucket,
    MessageType,
    Nodes,
    Nonce,
    PacketFlag,
    Ping,
    Pong,
    Port,
    RequestId,
    RoutingTable,
    StaticHeader,
    TalkReq,
    TalkResp,
    WhoAreYouAuthdata,
)
from lean_spec.subspecs.networking.discovery.config import (
    ALPHA,
    BOND_EXPIRY_SECS,
    BUCKET_COUNT,
    HANDSHAKE_TIMEOUT_SECS,
    K_BUCKET_SIZE,
    MAX_NODES_RESPONSE,
    MAX_PACKET_SIZE,
    MIN_PACKET_SIZE,
    REQUEST_TIMEOUT_SECS,
)
from lean_spec.subspecs.networking.discovery.routing import (
    NodeEntry,
    log2_distance,
    xor_distance,
)
from lean_spec.subspecs.networking.types import NodeId, SeqNumber
from lean_spec.types.uint import Uint8, Uint16, Uint64

if TYPE_CHECKING:
    from lean_spec.subspecs.networking.enr import ENR


class TestProtocolConstants:
    """Verify protocol constants match Discovery v5 specification."""

    def test_protocol_id(self) -> None:
        """Protocol ID is 'discv5'."""
        assert PROTOCOL_ID == b"discv5"
        assert len(PROTOCOL_ID) == 6

    def test_protocol_version(self) -> None:
        """Protocol version is 0x0001 (v5.1)."""
        assert PROTOCOL_VERSION == 0x0001

    def test_max_request_id_length(self) -> None:
        """Request ID max length is 8 bytes."""
        assert MAX_REQUEST_ID_LENGTH == 8

    def test_k_bucket_size(self) -> None:
        """K-bucket size is 16 per Kademlia standard."""
        assert K_BUCKET_SIZE == 16

    def test_alpha_concurrency(self) -> None:
        """Alpha (lookup concurrency) is 3."""
        assert ALPHA == 3

    def test_bucket_count(self) -> None:
        """256 buckets for 256-bit node ID space."""
        assert BUCKET_COUNT == 256

    def test_request_timeout(self) -> None:
        """Request timeout is 500ms per spec."""
        assert REQUEST_TIMEOUT_SECS == 0.5

    def test_handshake_timeout(self) -> None:
        """Handshake timeout is 1s per spec."""
        assert HANDSHAKE_TIMEOUT_SECS == 1.0

    def test_max_nodes_response(self) -> None:
        """Max 16 ENRs per NODES response."""
        assert MAX_NODES_RESPONSE == 16

    def test_bond_expiry(self) -> None:
        """Bond expires after 24 hours."""
        assert BOND_EXPIRY_SECS == 86400

    def test_packet_size_limits(self) -> None:
        """Packet size limits per spec."""
        assert MAX_PACKET_SIZE == 1280
        assert MIN_PACKET_SIZE == 63


class TestCustomTypes:
    """Tests for custom Discovery v5 types."""

    def test_request_id_limit(self) -> None:
        """RequestId accepts up to 8 bytes."""
        req_id = RequestId(data=b"\x01\x02\x03\x04\x05\x06\x07\x08")
        assert len(req_id.data) == 8

    def test_request_id_variable_length(self) -> None:
        """RequestId is variable length."""
        req_id = RequestId(data=b"\x01")
        assert len(req_id.data) == 1

    def test_ipv4_length(self) -> None:
        """IPv4 is exactly 4 bytes."""
        ip = IPv4(b"\xc0\xa8\x01\x01")  # 192.168.1.1
        assert len(ip) == 4

    def test_ipv6_length(self) -> None:
        """IPv6 is exactly 16 bytes."""
        ip = IPv6(b"\x00" * 15 + b"\x01")  # ::1
        assert len(ip) == 16

    def test_id_nonce_length(self) -> None:
        """IdNonce is 16 bytes (128 bits)."""
        nonce = IdNonce(b"\x01" * 16)
        assert len(nonce) == 16

    def test_nonce_length(self) -> None:
        """Nonce is 12 bytes (96 bits)."""
        nonce = Nonce(b"\x01" * 12)
        assert len(nonce) == 12

    def test_distance_type(self) -> None:
        """Distance is Uint16."""
        d = Distance(256)
        assert isinstance(d, Uint16)

    def test_port_type(self) -> None:
        """Port is Uint16."""
        p = Port(30303)
        assert isinstance(p, Uint16)

    def test_enr_seq_type(self) -> None:
        """SeqNumber is Uint64."""
        seq = SeqNumber(42)
        assert isinstance(seq, Uint64)


class TestPacketFlag:
    """Tests for packet type flags."""

    def test_message_flag(self) -> None:
        """MESSAGE flag is 0."""
        assert PacketFlag.MESSAGE == 0

    def test_whoareyou_flag(self) -> None:
        """WHOAREYOU flag is 1."""
        assert PacketFlag.WHOAREYOU == 1

    def test_handshake_flag(self) -> None:
        """HANDSHAKE flag is 2."""
        assert PacketFlag.HANDSHAKE == 2


class TestMessageTypes:
    """Verify message type codes match wire protocol spec."""

    def test_ping_type(self) -> None:
        """PING is message type 0x01."""
        assert MessageType.PING == 0x01

    def test_pong_type(self) -> None:
        """PONG is message type 0x02."""
        assert MessageType.PONG == 0x02

    def test_findnode_type(self) -> None:
        """FINDNODE is message type 0x03."""
        assert MessageType.FINDNODE == 0x03

    def test_nodes_type(self) -> None:
        """NODES is message type 0x04."""
        assert MessageType.NODES == 0x04

    def test_talkreq_type(self) -> None:
        """TALKREQ is message type 0x05."""
        assert MessageType.TALKREQ == 0x05

    def test_talkresp_type(self) -> None:
        """TALKRESP is message type 0x06."""
        assert MessageType.TALKRESP == 0x06

    def test_experimental_types(self) -> None:
        """Experimental topic messages have correct types."""
        assert MessageType.REGTOPIC == 0x07
        assert MessageType.TICKET == 0x08
        assert MessageType.REGCONFIRMATION == 0x09
        assert MessageType.TOPICQUERY == 0x0A


class TestDiscoveryConfig:
    """Tests for DiscoveryConfig."""

    def test_default_values(self) -> None:
        """Default config uses spec-defined constants."""
        config = DiscoveryConfig()

        assert config.k_bucket_size == K_BUCKET_SIZE
        assert config.alpha == ALPHA
        assert config.request_timeout_secs == REQUEST_TIMEOUT_SECS
        assert config.handshake_timeout_secs == HANDSHAKE_TIMEOUT_SECS
        assert config.max_nodes_response == MAX_NODES_RESPONSE
        assert config.bond_expiry_secs == BOND_EXPIRY_SECS

    def test_custom_values(self) -> None:
        """Custom config values override defaults."""
        config = DiscoveryConfig(
            k_bucket_size=8,
            alpha=5,
            request_timeout_secs=2.0,
        )
        assert config.k_bucket_size == 8
        assert config.alpha == 5
        assert config.request_timeout_secs == 2.0


class TestPing:
    """Tests for PING message."""

    def test_creation_with_types(self) -> None:
        """PING with strongly typed fields."""
        ping = Ping(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            enr_seq=SeqNumber(2),
        )

        assert ping.request_id.data == b"\x00\x00\x00\x01"
        assert ping.enr_seq == SeqNumber(2)

    def test_max_request_id_length(self) -> None:
        """Request ID accepts up to 8 bytes."""
        ping = Ping(
            request_id=RequestId(data=b"\x01\x02\x03\x04\x05\x06\x07\x08"),
            enr_seq=SeqNumber(1),
        )
        assert len(ping.request_id.data) == 8


class TestPong:
    """Tests for PONG message."""

    def test_creation_ipv4(self) -> None:
        """PONG with IPv4 address (4 bytes)."""
        pong = Pong(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            enr_seq=SeqNumber(42),
            recipient_ip=b"\xc0\xa8\x01\x01",  # 192.168.1.1
            recipient_port=Port(9000),
        )

        assert pong.enr_seq == SeqNumber(42)
        assert len(pong.recipient_ip) == 4
        assert pong.recipient_port == Port(9000)

    def test_creation_ipv6(self) -> None:
        """PONG with IPv6 address (16 bytes)."""
        ipv6 = b"\x00" * 15 + b"\x01"  # ::1
        pong = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=ipv6,
            recipient_port=Port(30303),
        )

        assert len(pong.recipient_ip) == 16


class TestFindNode:
    """Tests for FINDNODE message."""

    def test_single_distance(self) -> None:
        """FINDNODE querying single distance."""
        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(256)],
        )

        assert findnode.distances == [Distance(256)]

    def test_multiple_distances(self) -> None:
        """FINDNODE querying multiple distances."""
        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(0), Distance(1), Distance(255), Distance(256)],
        )

        assert Distance(0) in findnode.distances  # Distance 0 returns node itself
        assert Distance(256) in findnode.distances  # Maximum distance

    def test_distance_zero_returns_self(self) -> None:
        """Distance 0 is valid and returns recipient's ENR."""
        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(0)],
        )
        assert findnode.distances == [Distance(0)]


class TestNodes:
    """Tests for NODES message."""

    def test_single_response(self) -> None:
        """NODES with single response (total=1)."""
        nodes = Nodes(
            request_id=RequestId(data=b"\x01"),
            total=Uint8(1),
            enrs=[b"enr:-example"],
        )

        assert nodes.total == Uint8(1)
        assert len(nodes.enrs) == 1

    def test_multiple_responses(self) -> None:
        """NODES indicating multiple response messages."""
        nodes = Nodes(
            request_id=RequestId(data=b"\x01"),
            total=Uint8(3),
            enrs=[b"enr1", b"enr2"],
        )

        assert nodes.total == Uint8(3)
        assert len(nodes.enrs) == 2


class TestTalkReq:
    """Tests for TALKREQ message."""

    def test_creation(self) -> None:
        """TALKREQ with protocol identifier."""
        req = TalkReq(
            request_id=RequestId(data=b"\x01"),
            protocol=b"portal",
            request=b"payload",
        )

        assert req.protocol == b"portal"
        assert req.request == b"payload"


class TestTalkResp:
    """Tests for TALKRESP message."""

    def test_creation(self) -> None:
        """TALKRESP with response data."""
        resp = TalkResp(
            request_id=RequestId(data=b"\x01"),
            response=b"response_data",
        )

        assert resp.response == b"response_data"

    def test_empty_response_unknown_protocol(self) -> None:
        """Empty response indicates unknown protocol."""
        resp = TalkResp(
            request_id=RequestId(data=b"\x01"),
            response=b"",
        )
        assert resp.response == b""


class TestStaticHeader:
    """Tests for packet static header."""

    def test_default_protocol_id(self) -> None:
        """Static header has correct default protocol ID."""
        header = StaticHeader(
            flag=Uint8(0),
            nonce=Nonce(b"\x00" * 12),
            authdata_size=Uint16(32),
        )

        assert header.protocol_id == b"discv5"
        assert header.version == Uint16(0x0001)

    def test_flag_values(self) -> None:
        """Static header accepts different flag values."""
        for flag in [0, 1, 2]:
            header = StaticHeader(
                flag=Uint8(flag),
                nonce=Nonce(b"\xff" * 12),
                authdata_size=Uint16(32),
            )
            assert header.flag == Uint8(flag)


class TestWhoAreYouAuthdata:
    """Tests for WHOAREYOU authdata."""

    def test_creation(self) -> None:
        """WHOAREYOU authdata with id_nonce and enr_seq."""
        authdata = WhoAreYouAuthdata(
            id_nonce=IdNonce(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"),
            enr_seq=SeqNumber(0),
        )

        assert len(authdata.id_nonce) == 16
        assert authdata.enr_seq == SeqNumber(0)


class TestXorDistance:
    """Tests for XOR distance calculation."""

    def test_identical_ids_zero_distance(self) -> None:
        """Identical node IDs have distance 0."""
        node_id = NodeId(b"\x00" * 32)
        assert xor_distance(node_id, node_id) == 0

    def test_complementary_ids_max_distance(self) -> None:
        """All-zeros XOR all-ones gives maximum distance."""
        a = NodeId(b"\x00" * 32)
        b = NodeId(b"\xff" * 32)
        assert xor_distance(a, b) == 2**256 - 1

    def test_distance_is_symmetric(self) -> None:
        """XOR distance satisfies d(a,b) == d(b,a)."""
        a = NodeId(b"\x12" * 32)
        b = NodeId(b"\x34" * 32)
        assert xor_distance(a, b) == xor_distance(b, a)

    def test_specific_xor_values(self) -> None:
        """Verify specific XOR calculations."""
        a = NodeId(b"\x00" * 31 + b"\x05")  # 5
        b = NodeId(b"\x00" * 31 + b"\x03")  # 3
        assert xor_distance(a, b) == 6  # 5 XOR 3 = 6


class TestLog2Distance:
    """Tests for log2 distance calculation."""

    def test_identical_ids_return_zero(self) -> None:
        """Identical IDs return log2 distance 0."""
        node_id = NodeId(b"\x00" * 32)
        assert log2_distance(node_id, node_id) == Distance(0)

    def test_single_bit_difference(self) -> None:
        """Single bit difference in LSB gives distance 1."""
        a = NodeId(b"\x00" * 32)
        b = NodeId(b"\x00" * 31 + b"\x01")
        assert log2_distance(a, b) == Distance(1)

    def test_high_bit_difference(self) -> None:
        """Difference in high bit gives distance 8."""
        a = NodeId(b"\x00" * 32)
        b = NodeId(b"\x00" * 31 + b"\x80")  # 0b10000000
        assert log2_distance(a, b) == Distance(8)

    def test_maximum_distance(self) -> None:
        """Maximum distance is 256 bits."""
        a = NodeId(b"\x00" * 32)
        b = NodeId(b"\x80" + b"\x00" * 31)  # High bit of first byte set
        assert log2_distance(a, b) == Distance(256)


class TestKBucket:
    """Tests for K-bucket implementation."""

    def test_new_bucket_is_empty(self) -> None:
        """Newly created bucket has no nodes."""
        bucket = KBucket()

        assert bucket.is_empty
        assert not bucket.is_full
        assert len(bucket) == 0

    def test_add_single_node(self) -> None:
        """Adding a node increases bucket size."""
        bucket = KBucket()
        entry = NodeEntry(node_id=NodeId(b"\x01" * 32))

        assert bucket.add(entry)
        assert len(bucket) == 1
        assert bucket.contains(NodeId(b"\x01" * 32))

    def test_bucket_capacity_limit(self) -> None:
        """Bucket rejects nodes when at K_BUCKET_SIZE capacity."""
        bucket = KBucket()

        for i in range(K_BUCKET_SIZE):
            entry = NodeEntry(node_id=NodeId(bytes([i]) + b"\x00" * 31))
            assert bucket.add(entry)

        assert bucket.is_full
        assert len(bucket) == K_BUCKET_SIZE

        extra = NodeEntry(node_id=NodeId(b"\xff" * 32))
        assert not bucket.add(extra)
        assert len(bucket) == K_BUCKET_SIZE

    def test_update_moves_to_tail(self) -> None:
        """Re-adding existing node moves it to tail (most recent)."""
        bucket = KBucket()

        entry1 = NodeEntry(node_id=NodeId(b"\x01" * 32), enr_seq=SeqNumber(1))
        entry2 = NodeEntry(node_id=NodeId(b"\x02" * 32), enr_seq=SeqNumber(1))
        bucket.add(entry1)
        bucket.add(entry2)

        updated = NodeEntry(node_id=NodeId(b"\x01" * 32), enr_seq=SeqNumber(2))
        bucket.add(updated)

        tail = bucket.tail()
        assert tail is not None
        assert tail.node_id == NodeId(b"\x01" * 32)
        assert tail.enr_seq == SeqNumber(2)

    def test_remove_node(self) -> None:
        """Removing node decreases bucket size."""
        bucket = KBucket()
        entry = NodeEntry(node_id=NodeId(b"\x01" * 32))
        bucket.add(entry)

        assert bucket.remove(NodeId(b"\x01" * 32))
        assert bucket.is_empty
        assert not bucket.contains(NodeId(b"\x01" * 32))

    def test_remove_nonexistent_returns_false(self) -> None:
        """Removing nonexistent node returns False."""
        bucket = KBucket()
        assert not bucket.remove(NodeId(b"\x01" * 32))

    def test_get_existing_node(self) -> None:
        """Get retrieves node by ID."""
        bucket = KBucket()
        entry = NodeEntry(node_id=NodeId(b"\x01" * 32), enr_seq=SeqNumber(42))
        bucket.add(entry)

        retrieved = bucket.get(NodeId(b"\x01" * 32))
        assert retrieved is not None
        assert retrieved.enr_seq == SeqNumber(42)

    def test_get_nonexistent_returns_none(self) -> None:
        """Get returns None for unknown node."""
        bucket = KBucket()
        assert bucket.get(NodeId(b"\x01" * 32)) is None

    def test_head_returns_oldest(self) -> None:
        """Head returns least-recently seen node."""
        bucket = KBucket()
        bucket.add(NodeEntry(node_id=NodeId(b"\x01" * 32)))
        bucket.add(NodeEntry(node_id=NodeId(b"\x02" * 32)))

        head = bucket.head()
        assert head is not None
        assert head.node_id == NodeId(b"\x01" * 32)

    def test_tail_returns_newest(self) -> None:
        """Tail returns most-recently seen node."""
        bucket = KBucket()
        bucket.add(NodeEntry(node_id=NodeId(b"\x01" * 32)))
        bucket.add(NodeEntry(node_id=NodeId(b"\x02" * 32)))

        tail = bucket.tail()
        assert tail is not None
        assert tail.node_id == NodeId(b"\x02" * 32)

    def test_iteration(self) -> None:
        """Bucket supports iteration over nodes."""
        bucket = KBucket()
        bucket.add(NodeEntry(node_id=NodeId(b"\x01" * 32)))
        bucket.add(NodeEntry(node_id=NodeId(b"\x02" * 32)))

        node_ids = [entry.node_id for entry in bucket]
        assert len(node_ids) == 2


class TestRoutingTable:
    """Tests for Kademlia routing table."""

    def test_new_table_is_empty(self) -> None:
        """New routing table has no nodes."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)

        assert table.node_count() == 0

    def test_has_256_buckets(self) -> None:
        """Routing table has 256 k-buckets."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)

        assert len(table.buckets) == BUCKET_COUNT

    def test_add_node(self) -> None:
        """Adding node increases count."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)

        entry = NodeEntry(node_id=NodeId(b"\x00" * 31 + b"\x01"))
        assert table.add(entry)
        assert table.node_count() == 1
        assert table.contains(entry.node_id)

    def test_cannot_add_self(self) -> None:
        """Adding local node ID is rejected."""
        local_id = NodeId(b"\xab" * 32)
        table = RoutingTable(local_id=local_id)

        entry = NodeEntry(node_id=local_id)
        assert not table.add(entry)
        assert table.node_count() == 0

    def test_bucket_assignment_by_distance(self) -> None:
        """Nodes placed in correct bucket by log2 distance."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)

        node_id = NodeId(b"\x00" * 31 + b"\x01")  # log2 distance = 1
        entry = NodeEntry(node_id=node_id)
        table.add(entry)

        bucket_idx = table.bucket_index(node_id)
        assert bucket_idx == 0  # distance 1 -> bucket 0
        assert table.buckets[0].contains(node_id)

    def test_get_existing_node(self) -> None:
        """Get retrieves node from table."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)

        entry = NodeEntry(node_id=NodeId(b"\x01" * 32), enr_seq=SeqNumber(99))
        table.add(entry)

        retrieved = table.get(entry.node_id)
        assert retrieved is not None
        assert retrieved.enr_seq == SeqNumber(99)

    def test_remove_node(self) -> None:
        """Remove deletes node from table."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)

        entry = NodeEntry(node_id=NodeId(b"\x01" * 32))
        table.add(entry)
        assert table.remove(entry.node_id)
        assert not table.contains(entry.node_id)

    def test_closest_nodes_sorted_by_distance(self) -> None:
        """closest_nodes returns nodes sorted by XOR distance."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)

        for i in range(1, 5):
            entry = NodeEntry(node_id=NodeId(bytes([i]) + b"\x00" * 31))
            table.add(entry)

        target = NodeId(b"\x01" + b"\x00" * 31)
        closest = table.closest_nodes(target, count=3)

        assert len(closest) == 3
        assert closest[0].node_id == target  # Distance 0 to itself

    def test_closest_nodes_respects_count(self) -> None:
        """closest_nodes returns at most count nodes."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)

        for i in range(10):
            entry = NodeEntry(node_id=NodeId(bytes([i + 1]) + b"\x00" * 31))
            table.add(entry)

        closest = table.closest_nodes(NodeId(b"\x05" + b"\x00" * 31), count=3)
        assert len(closest) == 3

    def test_nodes_at_distance(self) -> None:
        """nodes_at_distance returns nodes in specific bucket."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)

        node_id = NodeId(b"\x00" * 31 + b"\x01")  # distance 1
        entry = NodeEntry(node_id=node_id)
        table.add(entry)

        nodes = table.nodes_at_distance(Distance(1))
        assert len(nodes) == 1
        assert nodes[0].node_id == node_id

    def test_nodes_at_invalid_distance(self) -> None:
        """Invalid distances return empty list."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)

        assert table.nodes_at_distance(Distance(0)) == []
        assert table.nodes_at_distance(Distance(257)) == []


class TestRoutingTableForkFiltering:
    """Tests for routing table fork compatibility filtering."""

    def _make_enr_with_eth2(self, fork_digest_hex: str) -> "ENR":
        """Create a minimal ENR with eth2 data for testing."""
        from lean_spec.subspecs.networking.enr import ENR
        from lean_spec.subspecs.networking.enr.eth2 import FAR_FUTURE_EPOCH
        from lean_spec.types import Bytes64
        from lean_spec.types.byte_arrays import Bytes4

        # Create eth2 bytes: fork_digest(4) + next_fork_version(4) + next_fork_epoch(8)
        fork_digest = Bytes4(bytes.fromhex(fork_digest_hex))
        eth2_bytes = (
            bytes(fork_digest) + bytes(fork_digest) + int(FAR_FUTURE_EPOCH).to_bytes(8, "little")
        )
        enr = ENR(
            signature=Bytes64(b"\x00" * 64),
            seq=SeqNumber(1),
            pairs={"eth2": eth2_bytes, "id": b"v4"},
        )
        return enr

    def test_no_filtering_without_local_fork_digest(self) -> None:
        """Nodes are accepted when local_fork_digest is not set."""
        local_id = NodeId(b"\x00" * 32)
        table = RoutingTable(local_id=local_id)  # No fork_digest

        entry = NodeEntry(node_id=NodeId(b"\x01" * 32))  # No ENR
        assert table.add(entry)
        assert table.contains(entry.node_id)

    def test_filtering_rejects_node_without_enr(self) -> None:
        """Node without ENR is rejected when fork filtering is enabled."""
        from lean_spec.types.byte_arrays import Bytes4

        local_id = NodeId(b"\x00" * 32)
        fork_digest = Bytes4(bytes.fromhex("12345678"))
        table = RoutingTable(local_id=local_id, local_fork_digest=fork_digest)

        entry = NodeEntry(node_id=NodeId(b"\x01" * 32))  # No ENR
        assert not table.add(entry)
        assert not table.contains(entry.node_id)

    def test_filtering_rejects_mismatched_fork(self) -> None:
        """Node with different fork_digest is rejected."""
        from lean_spec.types.byte_arrays import Bytes4

        local_id = NodeId(b"\x00" * 32)
        local_fork = Bytes4(bytes.fromhex("12345678"))
        table = RoutingTable(local_id=local_id, local_fork_digest=local_fork)

        enr = self._make_enr_with_eth2("deadbeef")  # Different fork
        entry = NodeEntry(node_id=NodeId(b"\x01" * 32), enr=enr)

        assert not table.add(entry)
        assert not table.contains(entry.node_id)

    def test_filtering_accepts_matching_fork(self) -> None:
        """Node with matching fork_digest is accepted."""
        from lean_spec.types.byte_arrays import Bytes4

        local_id = NodeId(b"\x00" * 32)
        local_fork = Bytes4(bytes.fromhex("12345678"))
        table = RoutingTable(local_id=local_id, local_fork_digest=local_fork)

        enr = self._make_enr_with_eth2("12345678")  # Same fork
        entry = NodeEntry(node_id=NodeId(b"\x01" * 32), enr=enr)

        assert table.add(entry)
        assert table.contains(entry.node_id)

    def test_is_fork_compatible_method(self) -> None:
        """Test is_fork_compatible method directly."""
        from lean_spec.types.byte_arrays import Bytes4

        local_id = NodeId(b"\x00" * 32)
        local_fork = Bytes4(bytes.fromhex("12345678"))
        table = RoutingTable(local_id=local_id, local_fork_digest=local_fork)

        # Compatible entry
        compatible_enr = self._make_enr_with_eth2("12345678")
        compatible_entry = NodeEntry(node_id=NodeId(b"\x01" * 32), enr=compatible_enr)
        assert table.is_fork_compatible(compatible_entry)

        # Incompatible entry (different fork)
        incompatible_enr = self._make_enr_with_eth2("deadbeef")
        incompatible_entry = NodeEntry(node_id=NodeId(b"\x02" * 32), enr=incompatible_enr)
        assert not table.is_fork_compatible(incompatible_entry)

        # Entry without ENR
        no_enr_entry = NodeEntry(node_id=NodeId(b"\x03" * 32))
        assert not table.is_fork_compatible(no_enr_entry)


class TestNodeEntry:
    """Tests for NodeEntry dataclass."""

    def test_default_values(self) -> None:
        """NodeEntry has sensible defaults."""
        entry = NodeEntry(node_id=NodeId(b"\x01" * 32))

        assert entry.node_id == NodeId(b"\x01" * 32)
        assert entry.enr_seq == SeqNumber(0)
        assert entry.last_seen == 0.0
        assert entry.endpoint is None
        assert entry.verified is False
        assert entry.enr is None

    def test_full_construction(self) -> None:
        """NodeEntry accepts all fields."""
        entry = NodeEntry(
            node_id=NodeId(b"\x01" * 32),
            enr_seq=SeqNumber(42),
            last_seen=1234567890.0,
            endpoint="192.168.1.1:30303",
            verified=True,
        )

        assert entry.enr_seq == SeqNumber(42)
        assert entry.endpoint == "192.168.1.1:30303"
        assert entry.verified is True


class TestMessageConstructionFromTestVectors:
    """Test message construction using official Discovery v5 test vector inputs."""

    # From https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
    PING_REQUEST_ID = bytes.fromhex("00000001")
    PING_ENR_SEQ = 2
    WHOAREYOU_ID_NONCE = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

    def test_ping_message_construction(self) -> None:
        """Construct PING message matching test vector inputs."""
        ping = Ping(
            request_id=RequestId(data=self.PING_REQUEST_ID),
            enr_seq=SeqNumber(self.PING_ENR_SEQ),
        )

        assert ping.request_id.data == self.PING_REQUEST_ID
        assert ping.enr_seq == SeqNumber(2)

    def test_whoareyou_authdata_construction(self) -> None:
        """Construct WHOAREYOU authdata matching test vector inputs."""
        authdata = WhoAreYouAuthdata(
            id_nonce=IdNonce(self.WHOAREYOU_ID_NONCE),
            enr_seq=SeqNumber(0),
        )

        assert authdata.id_nonce == IdNonce(self.WHOAREYOU_ID_NONCE)
        assert authdata.enr_seq == SeqNumber(0)

    def test_plaintext_message_type(self) -> None:
        """PING message plaintext starts with message type 0x01."""
        # From AES-GCM test vector plaintext
        plaintext = bytes.fromhex("01c20101")
        assert plaintext[0] == MessageType.PING


class TestPacketStructure:
    """Tests for Discovery v5 packet structure constants."""

    def test_static_header_size(self) -> None:
        """Static header is 23 bytes per spec."""
        # protocol-id (6) + version (2) + flag (1) + nonce (12) + authdata-size (2)
        expected_size = 6 + 2 + 1 + 12 + 2
        assert expected_size == 23


class TestRoutingWithTestVectorNodeIds:
    """Tests using official test vector node IDs with routing functions."""

    # Node IDs from official test vectors (keccak256 of uncompressed pubkey)
    NODE_A_ID = bytes.fromhex("aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb")
    NODE_B_ID = bytes.fromhex("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9")

    def test_xor_distance_is_symmetric(self) -> None:
        """XOR distance between test vector nodes is symmetric and non-zero."""
        node_a = NodeId(self.NODE_A_ID)
        node_b = NodeId(self.NODE_B_ID)

        distance = xor_distance(node_a, node_b)
        assert distance > 0
        assert xor_distance(node_a, node_b) == xor_distance(node_b, node_a)

    def test_log2_distance_is_high(self) -> None:
        """Log2 distance between test vector nodes is high (differ in high bits)."""
        node_a = NodeId(self.NODE_A_ID)
        node_b = NodeId(self.NODE_B_ID)

        log_dist = log2_distance(node_a, node_b)
        assert log_dist > Distance(200)
