"""Tests for Discovery v5 session management."""

import time

import pytest

from lean_spec.subspecs.networking.discovery.session import (
    BondCache,
    Session,
    SessionCache,
)
from lean_spec.subspecs.networking.types import NodeId


class TestSession:
    """Tests for Session dataclass."""

    def test_create_session(self):
        """Test session creation."""
        session = Session(
            node_id=NodeId(bytes(32)),
            send_key=bytes(16),
            recv_key=bytes(16),
            created_at=time.time(),
            last_seen=time.time(),
            is_initiator=True,
        )

        assert len(session.node_id) == 32
        assert len(session.send_key) == 16
        assert len(session.recv_key) == 16

    def test_is_expired_false_for_new_session(self):
        """Test that new session is not expired."""
        session = Session(
            node_id=NodeId(bytes(32)),
            send_key=bytes(16),
            recv_key=bytes(16),
            created_at=time.time(),
            last_seen=time.time(),
            is_initiator=True,
        )

        assert not session.is_expired(timeout_secs=3600)

    def test_is_expired_true_for_old_session(self):
        """Test that old session is expired."""
        session = Session(
            node_id=NodeId(bytes(32)),
            send_key=bytes(16),
            recv_key=bytes(16),
            created_at=time.time() - 7200,  # 2 hours ago
            last_seen=time.time() - 7200,
            is_initiator=True,
        )

        assert session.is_expired(timeout_secs=3600)

    def test_touch_updates_last_seen(self):
        """Test that touch updates last_seen timestamp."""
        session = Session(
            node_id=NodeId(bytes(32)),
            send_key=bytes(16),
            recv_key=bytes(16),
            created_at=time.time() - 100,
            last_seen=time.time() - 100,
            is_initiator=True,
        )

        old_last_seen = session.last_seen
        session.touch()

        assert session.last_seen > old_last_seen


class TestSessionCache:
    """Tests for SessionCache."""

    def test_create_and_get_session(self):
        """Test creating and retrieving a session."""
        cache = SessionCache()
        node_id = NodeId(bytes.fromhex("aa" * 32))
        send_key = bytes(16)
        recv_key = bytes(16)

        session = cache.create(node_id, send_key, recv_key, is_initiator=True)

        retrieved = cache.get(node_id)
        assert retrieved is session

    def test_get_nonexistent_returns_none(self):
        """Test that getting nonexistent session returns None."""
        cache = SessionCache()
        node_id = NodeId(bytes(32))

        assert cache.get(node_id) is None

    def test_get_expired_returns_none(self):
        """Test that getting expired session returns None and removes it."""
        cache = SessionCache(timeout_secs=0.001)
        node_id = NodeId(bytes(32))

        cache.create(node_id, bytes(16), bytes(16), is_initiator=True)
        time.sleep(0.01)

        assert cache.get(node_id) is None
        assert cache.count() == 0

    def test_remove_session(self):
        """Test removing a session."""
        cache = SessionCache()
        node_id = NodeId(bytes(32))

        cache.create(node_id, bytes(16), bytes(16), is_initiator=True)
        assert cache.remove(node_id)
        assert cache.get(node_id) is None

    def test_remove_nonexistent_returns_false(self):
        """Test that removing nonexistent session returns False."""
        cache = SessionCache()
        assert not cache.remove(NodeId(bytes(32)))

    def test_touch_updates_session(self):
        """Test that touch updates session timestamp."""
        cache = SessionCache()
        node_id = NodeId(bytes(32))

        cache.create(node_id, bytes(16), bytes(16), is_initiator=True)
        assert cache.touch(node_id)

    def test_touch_nonexistent_returns_false(self):
        """Test that touching nonexistent session returns False."""
        cache = SessionCache()
        assert not cache.touch(NodeId(bytes(32)))

    def test_count(self):
        """Test session count."""
        cache = SessionCache()

        assert cache.count() == 0

        cache.create(NodeId(bytes.fromhex("aa" * 32)), bytes(16), bytes(16), is_initiator=True)
        assert cache.count() == 1

        cache.create(NodeId(bytes.fromhex("bb" * 32)), bytes(16), bytes(16), is_initiator=True)
        assert cache.count() == 2

    def test_cleanup_expired(self):
        """Test expired session cleanup."""
        cache = SessionCache(timeout_secs=0.001)

        cache.create(NodeId(bytes.fromhex("aa" * 32)), bytes(16), bytes(16), is_initiator=True)
        cache.create(NodeId(bytes.fromhex("bb" * 32)), bytes(16), bytes(16), is_initiator=True)
        time.sleep(0.01)

        removed = cache.cleanup_expired()
        assert removed == 2
        assert cache.count() == 0

    def test_eviction_when_full(self):
        """Test that oldest session is evicted when cache is full."""
        cache = SessionCache(max_sessions=2)

        node1 = NodeId(bytes.fromhex("01" + "00" * 31))
        node2 = NodeId(bytes.fromhex("02" + "00" * 31))
        node3 = NodeId(bytes.fromhex("03" + "00" * 31))

        cache.create(node1, bytes(16), bytes(16), is_initiator=True)
        time.sleep(0.01)  # Ensure different timestamps
        cache.create(node2, bytes(16), bytes(16), is_initiator=True)

        assert cache.count() == 2

        # Adding third should evict first
        cache.create(node3, bytes(16), bytes(16), is_initiator=True)

        assert cache.count() == 2
        assert cache.get(node1) is None  # Oldest should be evicted
        assert cache.get(node2) is not None
        assert cache.get(node3) is not None

    def test_invalid_node_id_length_raises(self):
        """Test that invalid node ID length raises ValueError."""
        cache = SessionCache()
        with pytest.raises(ValueError, match="Node ID must be 32 bytes"):
            cache.create(bytes(31), bytes(16), bytes(16), is_initiator=True)  # type: ignore[arg-type]

    def test_invalid_key_length_raises(self):
        """Test that invalid key lengths raise ValueError."""
        cache = SessionCache()

        with pytest.raises(ValueError, match="Send key must be 16 bytes"):
            cache.create(NodeId(bytes(32)), bytes(15), bytes(16), is_initiator=True)

        with pytest.raises(ValueError, match="Recv key must be 16 bytes"):
            cache.create(NodeId(bytes(32)), bytes(16), bytes(15), is_initiator=True)

    def test_endpoint_keying_separates_sessions(self):
        """Same node_id at different ip:port has separate sessions.

        Per spec, sessions are tied to a specific UDP endpoint.
        This prevents session confusion if a node changes IP or port.
        """
        cache = SessionCache()
        node_id = NodeId(bytes.fromhex("aa" * 32))
        send_key_1 = bytes([0x01] * 16)
        send_key_2 = bytes([0x02] * 16)

        # Create sessions for same node at different endpoints.
        cache.create(node_id, send_key_1, bytes(16), is_initiator=True, ip="10.0.0.1", port=9000)
        cache.create(node_id, send_key_2, bytes(16), is_initiator=True, ip="10.0.0.2", port=9000)

        # Each endpoint retrieves its own session.
        session_1 = cache.get(node_id, "10.0.0.1", 9000)
        session_2 = cache.get(node_id, "10.0.0.2", 9000)

        assert session_1 is not None
        assert session_2 is not None
        assert session_1.send_key == send_key_1
        assert session_2.send_key == send_key_2

        # Different port for same IP is also separate.
        assert cache.get(node_id, "10.0.0.1", 9001) is None


class TestBondCache:
    """Tests for BondCache."""

    def test_add_and_check_bond(self):
        """Test adding and checking bond."""
        cache = BondCache()
        node_id = NodeId(bytes(32))

        assert not cache.is_bonded(node_id)

        cache.add_bond(node_id)
        assert cache.is_bonded(node_id)

    def test_expired_bond(self):
        """Test that expired bond returns False."""
        cache = BondCache(expiry_secs=0.001)
        node_id = NodeId(bytes(32))

        cache.add_bond(node_id)
        time.sleep(0.01)

        assert not cache.is_bonded(node_id)

    def test_remove_bond(self):
        """Test removing a bond."""
        cache = BondCache()
        node_id = NodeId(bytes(32))

        cache.add_bond(node_id)
        assert cache.remove_bond(node_id)
        assert not cache.is_bonded(node_id)

    def test_remove_nonexistent_returns_false(self):
        """Test that removing nonexistent bond returns False."""
        cache = BondCache()
        assert not cache.remove_bond(NodeId(bytes(32)))

    def test_cleanup_expired(self):
        """Test expired bond cleanup."""
        cache = BondCache(expiry_secs=0.001)

        cache.add_bond(NodeId(bytes.fromhex("aa" * 32)))
        cache.add_bond(NodeId(bytes.fromhex("bb" * 32)))
        time.sleep(0.01)

        removed = cache.cleanup_expired()
        assert removed == 2
