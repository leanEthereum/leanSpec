"""
Gossipsub Message Cache
=======================

Caches recent messages for gossip dissemination and IWANT responses.

Overview
--------

The message cache enables the lazy pull protocol by storing messages
that can be requested via IWANT after receiving IHAVE advertisements.

::

    Peer A                        Peer B (non-mesh)
       |                              |
       |--- IHAVE [msg1, msg2] ------>|
       |                              |
       |<----- IWANT [msg2] ----------|
       |                              |
       |--- MESSAGE [msg2] ---------->|  <- Retrieved from cache

Sliding Window Design
---------------------

The cache is organized as a sliding window of history buckets::

    +----------+----------+----------+----------+
    | Window 0 | Window 1 | Window 2 | Window 3 | ...
    | (newest) |          |          | (oldest) |
    +----------+----------+----------+----------+
         ^
         |
    New messages go here

Each heartbeat:

1. Oldest window is evicted (messages cleaned up)
2. New empty window is prepended
3. Windows shift: 0 -> 1 -> 2 -> ...

Key Parameters
--------------

- **mcache_len** (6): Total windows retained
- **mcache_gossip** (3): Recent windows included in IHAVE

Only the first `mcache_gossip` windows are advertised via IHAVE.
Older messages can still be retrieved via IWANT but won't be
actively gossiped.

Seen Cache
----------

A separate `SeenCache` tracks message IDs for deduplication
without storing full messages. Uses TTL-based expiry.

References:
----------
- Gossipsub v1.0: https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .message import GossipsubMessage
from .types import MessageId, Timestamp, TopicId


@dataclass(slots=True)
class CacheEntry:
    """A single entry in the message cache.

    Stores the message along with its topic for efficient retrieval
    during IWANT responses and topic-filtered IHAVE gossip.
    """

    message: GossipsubMessage
    """The cached gossipsub message."""

    topic: TopicId
    """Topic this message was published to.

    Used to filter messages when generating IHAVE gossip for a specific topic.
    """


@dataclass(slots=True)
class MessageCache:
    """Sliding window cache for gossipsub messages.

    Maintains recent messages for:

    - **IWANT responses**: Retrieve full messages by ID
    - **IHAVE gossip**: Get message IDs for advertisement
    """

    mcache_len: int = 6
    """Number of history windows to retain.

    Messages are evicted after this many heartbeat intervals.

    Higher values increase memory usage but improve message
    availability for late IWANT requests.
    """

    mcache_gossip: int = 3
    """Number of recent windows to include in IHAVE gossip.

    Only messages from the most recent windows are advertised.
    Should be less than or equal to mcache_len.
    """

    _windows: deque[set[MessageId]] = field(init=False, repr=False)
    """Sliding window of message ID sets.

    Index 0 is the newest window. Each heartbeat, windows shift
    right and a new empty window is prepended.
    """

    _by_id: dict[MessageId, CacheEntry] = field(init=False, default_factory=dict, repr=False)
    """Message lookup index keyed by ID.

    Provides O(1) retrieval for IWANT responses.
    """

    def __post_init__(self) -> None:
        """Initialize the sliding window structure."""
        self._windows = deque(maxlen=self.mcache_len)
        self._windows.append(set())

    def put(self, topic: TopicId, message: GossipsubMessage) -> bool:
        """Add a message to the cache.

        Messages are added to the newest window (index 0) and
        indexed for fast retrieval. Duplicates are ignored.

        Args:
            topic: Topic this message belongs to.
            message: Message to cache.

        Returns:
            True if added (not a duplicate).
        """
        msg_id = message.id

        if msg_id in self._by_id:
            return False

        self._windows[0].add(msg_id)
        self._by_id[msg_id] = CacheEntry(message=message, topic=topic)
        return True

    def get(self, msg_id: MessageId) -> GossipsubMessage | None:
        """Retrieve a message by ID.

        Used to respond to IWANT requests from peers.

        Args:
            msg_id: Message ID to look up.

        Returns:
            The cached message, or None if not found/evicted.
        """
        entry = self._by_id.get(msg_id)
        return entry.message if entry else None

    def has(self, msg_id: MessageId) -> bool:
        """Check if a message is cached.

        Args:
            msg_id: Message ID to check.

        Returns:
            True if the message is in the cache.
        """
        return msg_id in self._by_id

    def get_gossip_ids(self, topic: TopicId) -> list[MessageId]:
        """Get message IDs for IHAVE gossip.

        Returns IDs from the most recent `mcache_gossip` windows
        that belong to the specified topic.

        Args:
            topic: Topic to filter messages by.

        Returns:
            List of message IDs for IHAVE advertisement.
        """
        result: list[MessageId] = []

        windows_to_check = min(self.mcache_gossip, len(self._windows))

        for i in range(windows_to_check):
            for msg_id in self._windows[i]:
                entry = self._by_id.get(msg_id)
                if entry and entry.topic == topic:
                    result.append(msg_id)

        return result

    def shift(self) -> int:
        """Shift the cache window, evicting the oldest.

        Called at each heartbeat to age the cache:

        1. If at capacity, remove oldest window and its messages
        2. Prepend new empty window

        Returns:
            Number of messages evicted.
        """
        evicted = 0

        if len(self._windows) >= self.mcache_len:
            oldest = self._windows.pop()
            for msg_id in oldest:
                if msg_id in self._by_id:
                    del self._by_id[msg_id]
                    evicted += 1

        self._windows.appendleft(set())

        return evicted

    def clear(self) -> None:
        """Clear all cached messages."""
        self._windows.clear()
        self._windows.append(set())
        self._by_id.clear()

    def __len__(self) -> int:
        """Return the total number of cached messages."""
        return len(self._by_id)

    def __contains__(self, msg_id: MessageId) -> bool:
        """Check if a message ID is in the cache."""
        return msg_id in self._by_id


@dataclass(slots=True)
class SeenCache:
    """TTL-based cache for deduplicating messages.

    Tracks message IDs that have been seen to prevent reprocessing
    duplicates. Unlike `MessageCache`, this only stores IDs (not
    full messages) with time-based expiry.

    Use Cases
    ---------

    - Skip processing of already-seen messages
    - Avoid forwarding duplicates to mesh peers
    - Bound memory with automatic TTL cleanup
    """

    ttl_seconds: int = 120
    """Time-to-live for entries in seconds.

    Entries older than this are removed during cleanup.

    Should be:
        - long enough to cover network propagation,
        - short enough to bound memory usage.
    """

    _seen: set[MessageId] = field(default_factory=set, repr=False)
    """Set of message IDs that have been seen.

    Provides O(1) membership testing.
    """

    _timestamps: dict[MessageId, Timestamp] = field(default_factory=dict, repr=False)
    """Timestamp when each message was first seen.

    Used to determine expiry during cleanup.
    """

    def add(self, msg_id: MessageId, timestamp: Timestamp) -> bool:
        """Mark a message as seen.

        Args:
            msg_id: Message ID to mark as seen.
            timestamp: Current Unix timestamp.

        Returns:
            True if newly seen (not a duplicate).
        """
        if msg_id in self._seen:
            return False

        self._seen.add(msg_id)
        self._timestamps[msg_id] = timestamp
        return True

    def has(self, msg_id: MessageId) -> bool:
        """Check if a message has been seen.

        Args:
            msg_id: Message ID to check.

        Returns:
            True if the message has been seen.
        """
        return msg_id in self._seen

    def cleanup(self, current_time: float) -> int:
        """Remove expired entries.

        Should be called periodically (e.g., each heartbeat)
        to prevent unbounded memory growth.

        Args:
            current_time: Current Unix timestamp.

        Returns:
            Number of entries removed.
        """
        cutoff = current_time - self.ttl_seconds
        expired = [msg_id for msg_id, ts in self._timestamps.items() if ts < cutoff]

        for msg_id in expired:
            self._seen.discard(msg_id)
            del self._timestamps[msg_id]

        return len(expired)

    def clear(self) -> None:
        """Clear all seen entries."""
        self._seen.clear()
        self._timestamps.clear()

    def __len__(self) -> int:
        """Return the number of seen message IDs."""
        return len(self._seen)

    def __contains__(self, msg_id: MessageId) -> bool:
        """Check if a message ID has been seen."""
        return msg_id in self._seen
