"""
Tests for Discovery v5 routing table.

Tests the RoutingTable and KBucket classes.
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.networking.discovery.config import BUCKET_COUNT, K_BUCKET_SIZE
from lean_spec.subspecs.networking.discovery.messages import Distance
from lean_spec.subspecs.networking.discovery.routing import (
    KBucket,
    NodeEntry,
    RoutingTable,
    log2_distance,
    xor_distance,
)
from lean_spec.subspecs.networking.enr import ENR
from lean_spec.subspecs.networking.enr.eth2 import FAR_FUTURE_EPOCH
from lean_spec.subspecs.networking.types import NodeId, SeqNumber
from lean_spec.types import Bytes64, Uint64
from lean_spec.types.byte_arrays import Bytes4


class TestXorDistance:
    """Tests for XOR distance calculation."""

    def test_distance_to_self_is_zero(self):
        """XOR distance between same IDs is 0."""
        node_id = NodeId(bytes(32))
        assert xor_distance(node_id, node_id) == 0

    def test_distance_is_symmetric(self, local_node_id, remote_node_id):
        """XOR distance is symmetric: d(a,b) == d(b,a)."""
        d1 = xor_distance(local_node_id, remote_node_id)
        d2 = xor_distance(remote_node_id, local_node_id)
        assert d1 == d2

    def test_distance_is_positive(self, local_node_id, remote_node_id):
        """XOR distance between different IDs is positive."""
        d = xor_distance(local_node_id, remote_node_id)
        assert d > 0

    def test_distance_max_for_inverted_ids(self):
        """Max distance occurs when IDs are bitwise inverted."""
        zeros = NodeId(bytes(32))
        ones = NodeId(bytes([0xFF] * 32))
        d = xor_distance(zeros, ones)
        assert d == 2**256 - 1


class TestLog2Distance:
    """Tests for log2 distance calculation."""

    def test_log2_distance_self_is_zero(self):
        """Log2 distance to self is 0."""
        node_id = NodeId(bytes(32))
        assert int(log2_distance(node_id, node_id)) == 0

    def test_log2_distance_low_byte_diff(self):
        """
        Difference in first byte (big-endian).

        bytes([1]) + bytes(31) differs in byte 0 bit 0 (LSB of first byte).
        XOR = 0x0100...00 = 2^248
        log2(2^248) = 248, but bit_length() returns 249.
        """
        a = NodeId(bytes(32))
        b = NodeId(bytes([1]) + bytes(31))
        # The XOR has the high bit at position 248, so bit_length is 249.
        assert int(log2_distance(a, b)) == 249

    def test_log2_distance_high_bit_first_byte(self):
        """
        High bit of first byte differs.

        bytes([0x80]) + bytes(31) = 0x80000...00
        XOR distance = 2^255, bit_length = 256.
        """
        a = NodeId(bytes(32))
        b = NodeId(bytes([0x80]) + bytes(31))
        assert int(log2_distance(a, b)) == 256

    def test_log2_distance_max(self):
        """Max distance for completely different IDs."""
        zeros = NodeId(bytes(32))
        ones = NodeId(bytes([0xFF] * 32))
        d = log2_distance(zeros, ones)
        assert int(d) == 256


class TestNodeEntry:
    """Tests for NodeEntry dataclass."""

    def test_create_minimal_entry(self):
        """NodeEntry with minimum required fields."""
        node_id = NodeId(bytes(32))
        entry = NodeEntry(node_id=node_id)

        assert entry.node_id == node_id
        assert int(entry.enr_seq) == 0
        assert entry.last_seen == 0.0
        assert entry.endpoint is None
        assert entry.verified is False
        assert entry.enr is None

    def test_create_full_entry(self):
        """NodeEntry with all fields."""
        node_id = NodeId(bytes(32))
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"id": b"v4"},
        )

        entry = NodeEntry(
            node_id=node_id,
            enr_seq=SeqNumber(42),
            last_seen=123.456,
            endpoint="192.168.1.1:30303",
            verified=True,
            enr=enr,
        )

        assert int(entry.enr_seq) == 42
        assert entry.last_seen == 123.456
        assert entry.endpoint == "192.168.1.1:30303"
        assert entry.verified is True
        assert entry.enr is enr


class TestKBucket:
    """Tests for KBucket class."""

    def test_empty_bucket(self):
        """New bucket is empty."""
        bucket = KBucket()

        assert bucket.is_empty
        assert not bucket.is_full
        assert len(bucket) == 0

    def test_add_to_bucket(self):
        """Adding entry to bucket increases count."""
        bucket = KBucket()
        entry = NodeEntry(node_id=NodeId(bytes(32)))

        result = bucket.add(entry)

        assert result is True
        assert len(bucket) == 1
        assert not bucket.is_empty

    def test_add_multiple_entries(self):
        """Multiple entries can be added."""
        bucket = KBucket()

        for i in range(5):
            node_id = NodeId(bytes([i]) + bytes(31))
            entry = NodeEntry(node_id=node_id)
            bucket.add(entry)

        assert len(bucket) == 5

    def test_bucket_full(self):
        """Bucket becomes full at K_BUCKET_SIZE."""
        bucket = KBucket()

        for i in range(K_BUCKET_SIZE):
            node_id = NodeId(bytes([i]) + bytes(31))
            entry = NodeEntry(node_id=node_id)
            bucket.add(entry)

        assert bucket.is_full
        assert len(bucket) == K_BUCKET_SIZE

    def test_add_to_full_bucket_returns_false(self):
        """Adding to full bucket returns False."""
        bucket = KBucket()

        for i in range(K_BUCKET_SIZE):
            node_id = NodeId(bytes([i]) + bytes(31))
            entry = NodeEntry(node_id=node_id)
            bucket.add(entry)

        # Try to add one more.
        new_entry = NodeEntry(node_id=NodeId(bytes([0xFF]) + bytes(31)))
        result = bucket.add(new_entry)

        assert result is False
        assert len(bucket) == K_BUCKET_SIZE

    def test_update_existing_moves_to_tail(self):
        """Updating existing entry moves it to tail."""
        bucket = KBucket()

        # Add three entries.
        for i in range(3):
            node_id = NodeId(bytes([i]) + bytes(31))
            entry = NodeEntry(node_id=node_id)
            bucket.add(entry)

        # Update the first entry.
        first_id = NodeId(bytes([0]) + bytes(31))
        updated_entry = NodeEntry(node_id=first_id, enr_seq=SeqNumber(999))
        result = bucket.add(updated_entry)

        assert result is True
        assert len(bucket) == 3
        # Entry should be at tail (most recent).
        tail = bucket.tail()
        assert tail is not None
        assert tail.node_id == first_id

    def test_contains(self):
        """Check if bucket contains a node ID."""
        bucket = KBucket()
        node_id = NodeId(bytes(32))
        entry = NodeEntry(node_id=node_id)
        bucket.add(entry)

        assert bucket.contains(node_id)
        assert not bucket.contains(NodeId(bytes([1]) + bytes(31)))

    def test_get_entry(self):
        """Retrieve entry by node ID."""
        bucket = KBucket()
        node_id = NodeId(bytes(32))
        entry = NodeEntry(node_id=node_id, enr_seq=SeqNumber(42))
        bucket.add(entry)

        retrieved = bucket.get(node_id)
        assert retrieved is not None
        assert int(retrieved.enr_seq) == 42

    def test_get_missing_returns_none(self):
        """Getting missing node returns None."""
        bucket = KBucket()
        result = bucket.get(NodeId(bytes(32)))
        assert result is None

    def test_remove_entry(self):
        """Remove entry from bucket."""
        bucket = KBucket()
        node_id = NodeId(bytes(32))
        entry = NodeEntry(node_id=node_id)
        bucket.add(entry)

        result = bucket.remove(node_id)

        assert result is True
        assert len(bucket) == 0
        assert not bucket.contains(node_id)

    def test_remove_missing_returns_false(self):
        """Removing missing node returns False."""
        bucket = KBucket()
        result = bucket.remove(NodeId(bytes(32)))
        assert result is False

    def test_head_and_tail(self):
        """Head is oldest, tail is newest."""
        bucket = KBucket()

        for i in range(3):
            node_id = NodeId(bytes([i]) + bytes(31))
            entry = NodeEntry(node_id=node_id)
            bucket.add(entry)

        head = bucket.head()
        tail = bucket.tail()
        assert head is not None
        assert tail is not None
        assert head.node_id == NodeId(bytes([0]) + bytes(31))
        assert tail.node_id == NodeId(bytes([2]) + bytes(31))

    def test_head_of_empty_is_none(self):
        """Head of empty bucket is None."""
        bucket = KBucket()
        assert bucket.head() is None

    def test_tail_of_empty_is_none(self):
        """Tail of empty bucket is None."""
        bucket = KBucket()
        assert bucket.tail() is None

    def test_iteration(self):
        """Bucket is iterable."""
        bucket = KBucket()

        for i in range(3):
            node_id = NodeId(bytes([i]) + bytes(31))
            entry = NodeEntry(node_id=node_id)
            bucket.add(entry)

        entries = list(bucket)
        assert len(entries) == 3


class TestRoutingTable:
    """Tests for RoutingTable class."""

    def test_create_table(self, local_node_id):
        """Create routing table with local ID."""
        table = RoutingTable(local_id=local_node_id)

        assert table.local_id == local_node_id
        assert len(table.buckets) == BUCKET_COUNT
        assert table.node_count() == 0

    def test_add_node(self, local_node_id, remote_node_id):
        """Add node to routing table."""
        table = RoutingTable(local_id=local_node_id)
        entry = NodeEntry(node_id=remote_node_id)

        result = table.add(entry)

        assert result is True
        assert table.node_count() == 1

    def test_add_self_returns_false(self, local_node_id):
        """Cannot add self to routing table."""
        table = RoutingTable(local_id=local_node_id)
        entry = NodeEntry(node_id=local_node_id)

        result = table.add(entry)

        assert result is False
        assert table.node_count() == 0

    def test_get_node(self, local_node_id, remote_node_id):
        """Retrieve node from routing table."""
        table = RoutingTable(local_id=local_node_id)
        entry = NodeEntry(node_id=remote_node_id, enr_seq=SeqNumber(42))
        table.add(entry)

        retrieved = table.get(remote_node_id)
        assert retrieved is not None
        assert int(retrieved.enr_seq) == 42

    def test_get_missing_returns_none(self, local_node_id, remote_node_id):
        """Getting missing node returns None."""
        table = RoutingTable(local_id=local_node_id)
        result = table.get(remote_node_id)
        assert result is None

    def test_contains(self, local_node_id, remote_node_id):
        """Check if node exists in table."""
        table = RoutingTable(local_id=local_node_id)
        entry = NodeEntry(node_id=remote_node_id)
        table.add(entry)

        assert table.contains(remote_node_id)
        assert not table.contains(local_node_id)

    def test_remove_node(self, local_node_id, remote_node_id):
        """Remove node from routing table."""
        table = RoutingTable(local_id=local_node_id)
        entry = NodeEntry(node_id=remote_node_id)
        table.add(entry)

        result = table.remove(remote_node_id)

        assert result is True
        assert table.node_count() == 0

    def test_bucket_index(self, local_node_id, remote_node_id):
        """Bucket index is based on log2 distance."""
        table = RoutingTable(local_id=local_node_id)

        idx = table.bucket_index(remote_node_id)

        # Bucket index should be in valid range.
        assert 0 <= idx < BUCKET_COUNT

    def test_get_bucket(self, local_node_id, remote_node_id):
        """Get bucket for a node ID."""
        table = RoutingTable(local_id=local_node_id)

        bucket = table.get_bucket(remote_node_id)

        assert isinstance(bucket, KBucket)

    def test_closest_nodes_empty_table(self, local_node_id, remote_node_id):
        """Closest nodes on empty table returns empty list."""
        table = RoutingTable(local_id=local_node_id)

        closest = table.closest_nodes(remote_node_id, 16)

        assert closest == []

    def test_closest_nodes_returns_sorted(self, local_node_id):
        """Closest nodes are sorted by distance."""
        table = RoutingTable(local_id=local_node_id)

        # Add some nodes.
        for i in range(10):
            node_id = NodeId(bytes([i * 10]) + bytes(31))
            entry = NodeEntry(node_id=node_id)
            table.add(entry)

        target = NodeId(bytes(32))
        closest = table.closest_nodes(target, 5)

        assert len(closest) == 5

        # Verify sorted by distance.
        for i in range(len(closest) - 1):
            d1 = xor_distance(closest[i].node_id, target)
            d2 = xor_distance(closest[i + 1].node_id, target)
            assert d1 <= d2

    def test_nodes_at_distance(self, local_node_id):
        """Get nodes at specific distance."""
        table = RoutingTable(local_id=local_node_id)

        nodes = table.nodes_at_distance(Distance(128))

        assert isinstance(nodes, list)

    def test_nodes_at_invalid_distance(self, local_node_id):
        """Invalid distances return empty list."""
        table = RoutingTable(local_id=local_node_id)

        # Distance 0 returns own ENR, but routing table doesn't store self.
        nodes = table.nodes_at_distance(Distance(0))
        assert nodes == []

        # Distance > 256 is invalid.
        nodes = table.nodes_at_distance(Distance(300))
        assert nodes == []


class TestForkCompatibility:
    """Tests for fork filtering in routing table."""

    def test_no_fork_filter_accepts_all(self, local_node_id, remote_node_id):
        """Without fork filter, all nodes are accepted."""
        table = RoutingTable(local_id=local_node_id, local_fork_digest=None)
        entry = NodeEntry(node_id=remote_node_id)

        assert table.is_fork_compatible(entry)

    def test_fork_filter_rejects_without_enr(self, local_node_id, remote_node_id):
        """With fork filter, nodes without ENR are rejected."""
        table = RoutingTable(
            local_id=local_node_id,
            local_fork_digest=Bytes4(bytes(4)),
        )
        entry = NodeEntry(node_id=remote_node_id, enr=None)

        assert not table.is_fork_compatible(entry)

    def test_fork_filter_rejects_without_eth2_data(self, local_node_id, remote_node_id):
        """Nodes without eth2 data are rejected when filtering."""
        table = RoutingTable(
            local_id=local_node_id,
            local_fork_digest=Bytes4(bytes(4)),
        )

        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"id": b"v4"},
        )
        entry = NodeEntry(node_id=remote_node_id, enr=enr)

        assert not table.is_fork_compatible(entry)

    def test_fork_filter_rejects_mismatched_fork(self, local_node_id, remote_node_id):
        """Node with different fork_digest is rejected."""

        local_fork = Bytes4(bytes.fromhex("12345678"))
        table = RoutingTable(local_id=local_node_id, local_fork_digest=local_fork)

        # Build eth2 bytes with a different fork digest.
        remote_digest = bytes.fromhex("deadbeef")
        eth2_bytes = remote_digest + remote_digest + int(FAR_FUTURE_EPOCH).to_bytes(8, "little")
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"eth2": eth2_bytes, "id": b"v4"},
        )
        entry = NodeEntry(node_id=remote_node_id, enr=enr)

        assert not table.add(entry)
        assert not table.contains(remote_node_id)

    def test_fork_filter_accepts_matching_fork(self, local_node_id, remote_node_id):
        """Node with matching fork_digest is accepted."""

        local_fork = Bytes4(bytes.fromhex("12345678"))
        table = RoutingTable(local_id=local_node_id, local_fork_digest=local_fork)

        # Build eth2 bytes with the same fork digest.
        eth2_bytes = (
            bytes.fromhex("12345678")
            + bytes.fromhex("12345678")
            + int(FAR_FUTURE_EPOCH).to_bytes(8, "little")
        )
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"eth2": eth2_bytes, "id": b"v4"},
        )
        entry = NodeEntry(node_id=remote_node_id, enr=enr)

        assert table.add(entry)
        assert table.contains(remote_node_id)

    def test_is_fork_compatible_method(self, local_node_id):
        """Verify is_fork_compatible for compatible, incompatible, and no-ENR entries."""

        local_fork = Bytes4(bytes.fromhex("12345678"))
        table = RoutingTable(local_id=local_node_id, local_fork_digest=local_fork)

        # Compatible entry.
        eth2_match = (
            bytes.fromhex("12345678")
            + bytes.fromhex("12345678")
            + int(FAR_FUTURE_EPOCH).to_bytes(8, "little")
        )
        compatible_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"eth2": eth2_match, "id": b"v4"},
        )
        compatible_entry = NodeEntry(node_id=NodeId(b"\x01" * 32), enr=compatible_enr)
        assert table.is_fork_compatible(compatible_entry)

        # Incompatible entry (different fork).
        eth2_mismatch = (
            bytes.fromhex("deadbeef")
            + bytes.fromhex("deadbeef")
            + int(FAR_FUTURE_EPOCH).to_bytes(8, "little")
        )
        incompatible_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"eth2": eth2_mismatch, "id": b"v4"},
        )
        incompatible_entry = NodeEntry(node_id=NodeId(b"\x02" * 32), enr=incompatible_enr)
        assert not table.is_fork_compatible(incompatible_entry)

        # Entry without ENR.
        no_enr_entry = NodeEntry(node_id=NodeId(b"\x03" * 32))
        assert not table.is_fork_compatible(no_enr_entry)


class TestIPDensityTracking:
    """Tests for tracking IP address density.

    Anti-eclipse protection limits nodes per IP subnet.
    This prevents attackers from filling the table with nodes
    all controlled from the same network.
    """

    @pytest.fixture
    def local_node_id(self):
        """Create local node ID."""
        return NodeId(bytes(32))

    def test_node_entry_with_endpoint(self, local_node_id):
        """NodeEntry can store endpoint information."""
        remote_id = NodeId(bytes([0x80]) + bytes(31))

        entry = NodeEntry(
            node_id=remote_id,
            endpoint="192.168.1.1:9000",
        )

        assert entry.endpoint == "192.168.1.1:9000"
        assert entry.node_id == remote_id

    def test_node_entry_without_endpoint(self, local_node_id):
        """NodeEntry works without endpoint."""
        remote_id = NodeId(bytes([0x80]) + bytes(31))

        entry = NodeEntry(
            node_id=remote_id,
        )

        assert entry.endpoint is None

    def test_nodes_from_same_subnet_distinct(self, local_node_id):
        """Nodes from same /24 subnet are distinct but related."""
        table = RoutingTable(local_id=local_node_id)

        # Create nodes from same /24 subnet.
        entries = []
        for i in range(5):
            # All in 192.168.1.x/24
            node_id = NodeId(bytes([0x80 + i]) + bytes(31))
            entry = NodeEntry(
                node_id=node_id,
                endpoint=f"192.168.1.{i + 1}:9000",
            )
            entries.append(entry)
            table.add(entry)

        # All should be in the table (assuming bucket has space).
        count = table.node_count()
        assert count == 5

    def test_nodes_from_different_subnets_independent(self, local_node_id):
        """Nodes from different /24 subnets are independent."""
        table = RoutingTable(local_id=local_node_id)

        subnets = [
            "192.168.1.1:9000",
            "192.168.2.1:9000",
            "10.0.0.1:9000",
            "172.16.0.1:9000",
        ]

        for i, subnet in enumerate(subnets):
            node_id = NodeId(bytes([0x80 + i]) + bytes(31))
            entry = NodeEntry(
                node_id=node_id,
                endpoint=subnet,
            )
            table.add(entry)

        # All should be added.
        assert table.node_count() == 4

    def test_ipv6_subnet_tracking(self, local_node_id):
        """IPv6 addresses can be tracked."""
        table = RoutingTable(local_id=local_node_id)

        # IPv6 addresses.
        ipv6_addresses = [
            "[::1]:9000",
            "[fe80::1]:9000",
            "[2001:db8::1]:9000",
        ]

        for i, addr in enumerate(ipv6_addresses):
            node_id = NodeId(bytes([0x80 + i]) + bytes(31))
            entry = NodeEntry(
                node_id=node_id,
                endpoint=addr,
            )
            table.add(entry)

        # All should be tracked.
        assert table.node_count() == 3


class TestRoutingTableNodeDiversity:
    """Tests for ensuring node diversity in routing table."""

    @pytest.fixture
    def local_node_id(self):
        """Create local node ID."""
        return NodeId(bytes(32))

    def test_bucket_accepts_diverse_nodes(self, local_node_id):
        """Buckets accept nodes from different networks."""
        table = RoutingTable(local_id=local_node_id)

        # Add nodes at same distance but different IPs.
        for i in range(5):
            node_id = NodeId(bytes([0x80, i]) + bytes(30))
            entry = NodeEntry(
                node_id=node_id,
                endpoint=f"10.{i}.0.1:9000",
            )
            table.add(entry)

        # All should be added to table.
        assert table.node_count() == 5

    def test_table_tracks_all_subnets(self, local_node_id):
        """Table tracks nodes across all subnets."""
        table = RoutingTable(local_id=local_node_id)

        # Add nodes to different buckets and subnets.
        for bucket_prefix in range(3):
            for subnet in range(3):
                node_id = NodeId(bytes([1 << (7 - bucket_prefix), subnet]) + bytes(30))
                entry = NodeEntry(
                    node_id=node_id,
                    endpoint=f"192.168.{bucket_prefix}.{subnet + 1}:9000",
                )
                table.add(entry)

        # All 9 nodes should be added.
        assert table.node_count() == 9
