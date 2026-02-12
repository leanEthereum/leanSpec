"""
Session management for Discovery v5.

A session represents an established cryptographic channel with a peer.
Sessions are created after successful WHOAREYOU/HANDSHAKE exchange.

Session Lifecycle:
1. Initiator sends encrypted MESSAGE to recipient
2. Recipient can't decrypt (no session), sends WHOAREYOU
3. Initiator responds with HANDSHAKE containing ECDH ephemeral key
4. Both parties derive shared keys, session is established
5. Subsequent messages use session keys

Sessions expire after a timeout and must be re-established.
The spec recommends 24 hours, but implementations often use shorter durations.

References:
- https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md#session-cache
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock

from lean_spec.subspecs.networking.types import NodeId

from .config import BOND_EXPIRY_SECS

DEFAULT_SESSION_TIMEOUT_SECS = 86400
"""Default session timeout (24 hours)."""

MAX_SESSIONS = 1000
"""Maximum number of cached sessions to prevent memory exhaustion."""


@dataclass(slots=True)
class Session:
    """
    Active session with a peer.

    Stores the symmetric keys derived during handshake.
    Keys are directional: we use different keys for send vs receive.
    """

    node_id: NodeId
    """Peer's 32-byte node ID."""

    send_key: bytes
    """16-byte key for encrypting messages to this peer."""

    recv_key: bytes
    """16-byte key for decrypting messages from this peer."""

    created_at: float
    """Unix timestamp when session was established."""

    last_seen: float
    """Unix timestamp of last successful message exchange."""

    is_initiator: bool
    """True if we initiated the handshake."""

    def is_expired(self, timeout_secs: float = DEFAULT_SESSION_TIMEOUT_SECS) -> bool:
        """Check if session has expired."""
        return time.time() - self.created_at > timeout_secs

    def touch(self) -> None:
        """Update last_seen timestamp."""
        self.last_seen = time.time()


type SessionKey = tuple[NodeId, str, int]
"""Session cache key: (node_id, ip, port).

Per spec, sessions are tied to a specific UDP endpoint.
This prevents session confusion if a node changes IP or port.
"""


@dataclass
class SessionCache:
    """
    Cache of active sessions with peers.

    Thread-safe session storage with automatic expiration cleanup.
    Sessions are keyed by (node_id, ip, port) per spec requirement
    that sessions are tied to a specific UDP endpoint.
    """

    sessions: dict[SessionKey, Session] = field(default_factory=dict)
    """(node_id, ip, port) -> Session mapping."""

    timeout_secs: float = DEFAULT_SESSION_TIMEOUT_SECS
    """Session expiration timeout."""

    max_sessions: int = MAX_SESSIONS
    """Maximum cached sessions."""

    _lock: Lock = field(default_factory=Lock)
    """Thread safety lock."""

    def get(self, node_id: NodeId, ip: str = "", port: int = 0) -> Session | None:
        """
        Get an active session for a node at a specific endpoint.

        Returns None if no session exists or if it has expired.

        Args:
            node_id: 32-byte peer node ID.
            ip: Peer IP address.
            port: Peer UDP port.

        Returns:
            Active session or None.
        """
        key: SessionKey = (node_id, ip, port)
        with self._lock:
            session = self.sessions.get(key)
            if session is None:
                return None

            if session.is_expired(self.timeout_secs):
                del self.sessions[key]
                return None

            return session

    def create(
        self,
        node_id: NodeId,
        send_key: bytes,
        recv_key: bytes,
        is_initiator: bool,
        ip: str = "",
        port: int = 0,
    ) -> Session:
        """
        Create and store a new session.

        If a session already exists for this endpoint, it is replaced.
        If the cache is full, the oldest session is evicted.

        Args:
            node_id: 32-byte peer node ID.
            send_key: 16-byte encryption key for outgoing messages.
            recv_key: 16-byte decryption key for incoming messages.
            is_initiator: True if we initiated the handshake.
            ip: Peer IP address.
            port: Peer UDP port.

        Returns:
            The newly created session.
        """
        if len(node_id) != 32:
            raise ValueError(f"Node ID must be 32 bytes, got {len(node_id)}")
        if len(send_key) != 16:
            raise ValueError(f"Send key must be 16 bytes, got {len(send_key)}")
        if len(recv_key) != 16:
            raise ValueError(f"Recv key must be 16 bytes, got {len(recv_key)}")

        key: SessionKey = (node_id, ip, port)
        now = time.time()
        session = Session(
            node_id=node_id,
            send_key=send_key,
            recv_key=recv_key,
            created_at=now,
            last_seen=now,
            is_initiator=is_initiator,
        )

        with self._lock:
            # Evict oldest if at capacity.
            if len(self.sessions) >= self.max_sessions and key not in self.sessions:
                self._evict_oldest()

            self.sessions[key] = session

        return session

    def remove(self, node_id: NodeId, ip: str = "", port: int = 0) -> bool:
        """
        Remove a session.

        Args:
            node_id: 32-byte peer node ID.
            ip: Peer IP address.
            port: Peer UDP port.

        Returns:
            True if session was removed, False if not found.
        """
        key: SessionKey = (node_id, ip, port)
        with self._lock:
            if key in self.sessions:
                del self.sessions[key]
                return True
            return False

    def touch(self, node_id: NodeId, ip: str = "", port: int = 0) -> bool:
        """
        Update the last_seen timestamp for a session.

        Holds the lock across lookup and mutation to prevent a concurrent
        thread from evicting the session between the two operations.

        Args:
            node_id: 32-byte peer node ID.
            ip: Peer IP address.
            port: Peer UDP port.

        Returns:
            True if session was updated, False if not found.
        """
        key: SessionKey = (node_id, ip, port)
        with self._lock:
            session = self.sessions.get(key)
            if session is not None and not session.is_expired(self.timeout_secs):
                session.touch()
                return True
            return False

    def cleanup_expired(self) -> int:
        """
        Remove all expired sessions.

        Returns:
            Number of sessions removed.
        """
        with self._lock:
            expired = [
                key
                for key, session in self.sessions.items()
                if session.is_expired(self.timeout_secs)
            ]
            for key in expired:
                del self.sessions[key]
            return len(expired)

    def count(self) -> int:
        """Return number of active sessions."""
        with self._lock:
            return len(self.sessions)

    def _evict_oldest(self) -> None:
        """Evict the least recently used session. Must be called with lock held."""
        if not self.sessions:
            return

        oldest_key = min(self.sessions, key=lambda k: self.sessions[k].last_seen)
        del self.sessions[oldest_key]


@dataclass
class BondCache:
    """
    Cache tracking which nodes we have successfully bonded with.

    A node is considered "bonded" after a successful PING/PONG exchange.
    Bonded nodes can be included in FINDNODE responses.

    This is separate from sessions because a bond can persist
    even if the session expires.
    """

    bonds: dict[NodeId, float] = field(default_factory=dict)
    """Node ID -> timestamp of last successful PONG."""

    expiry_secs: float = BOND_EXPIRY_SECS
    """Bond expiration timeout (default 24 hours)."""

    _lock: Lock = field(default_factory=Lock)
    """Thread safety lock."""

    def is_bonded(self, node_id: NodeId) -> bool:
        """Check if we have a valid bond with a node."""
        with self._lock:
            timestamp = self.bonds.get(node_id)
            if timestamp is None:
                return False
            if time.time() - timestamp > self.expiry_secs:
                del self.bonds[node_id]
                return False
            return True

    def add_bond(self, node_id: NodeId) -> None:
        """Record a successful bond with a node."""
        with self._lock:
            self.bonds[node_id] = time.time()

    def remove_bond(self, node_id: NodeId) -> bool:
        """Remove a bond."""
        with self._lock:
            if node_id in self.bonds:
                del self.bonds[node_id]
                return True
            return False

    def cleanup_expired(self) -> int:
        """Remove expired bonds."""
        now = time.time()
        with self._lock:
            expired = [
                node_id
                for node_id, timestamp in self.bonds.items()
                if now - timestamp > self.expiry_secs
            ]
            for node_id in expired:
                del self.bonds[node_id]
            return len(expired)
