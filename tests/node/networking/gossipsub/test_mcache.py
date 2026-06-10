"""Tests for the gossipsub message cache and seen cache."""

from __future__ import annotations

import time

from lean_spec.node.networking.gossipsub.mcache import MessageCache, SeenCache
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.types import MessageId, Timestamp, TopicId


class TestMessageCacheShift:
    """Tests for MessageCache.shift() edge cases."""

    def test_shift_when_not_full(self) -> None:
        """shift() does not evict when fewer windows than mcache_length."""
        cache = MessageCache(mcache_length=6, mcache_gossip=3)
        message = GossipsubMessage(topic=b"t", raw_data=b"data1")
        cache.put(TopicId("t"), message)

        # Only 1 window used out of 6; shift should evict nothing.
        evicted = cache.shift()
        assert evicted == 0
        assert cache.has(message.id)

    def test_shift_evicts_oldest_window(self) -> None:
        """shift() evicts messages from the oldest window at capacity."""
        cache = MessageCache(mcache_length=3, mcache_gossip=2)

        message = GossipsubMessage(topic=b"t", raw_data=b"old")
        cache.put(TopicId("t"), message)

        # Fill to capacity (3 windows total: initial + 2 shifts).
        cache.shift()
        cache.shift()

        # Next shift should evict the original window.
        evicted = cache.shift()
        assert evicted == 1
        assert not cache.has(message.id)

    def test_shift_returns_correct_eviction_count(self) -> None:
        """shift() returns the number of messages evicted."""
        cache = MessageCache(mcache_length=2, mcache_gossip=1)

        # Put 3 messages in the first window.
        messages = [GossipsubMessage(topic=b"t", raw_data=f"d{i}".encode()) for i in range(3)]
        for message in messages:
            cache.put(TopicId("t"), message)

        # One shift: still within capacity (2 windows).
        evicted = cache.shift()
        assert evicted == 0
        assert all(cache.has(message.id) for message in messages)

        # Second shift: oldest window (with 3 messages) is evicted.
        evicted = cache.shift()
        assert evicted == 3
        assert not any(cache.has(message.id) for message in messages)


class TestMessageCacheGetGossipIds:
    """Tests for get_gossip_ids() with window aging."""

    def test_returns_only_recent_windows(self) -> None:
        """get_gossip_ids() only returns IDs from mcache_gossip windows."""
        cache = MessageCache(mcache_length=4, mcache_gossip=2)

        # Window 0: put message_old.
        message_old = GossipsubMessage(topic=b"t", raw_data=b"old")
        cache.put(TopicId("t"), message_old)

        # Shift twice: message_old is now in window 2 (outside gossip=2).
        cache.shift()
        cache.shift()

        # Window 0 (current): put message_new.
        message_new = GossipsubMessage(topic=b"t", raw_data=b"new")
        cache.put(TopicId("t"), message_new)

        ids = cache.get_gossip_ids(TopicId("t"))
        assert message_new.id in ids
        assert message_old.id not in ids

    def test_filters_by_topic(self) -> None:
        """get_gossip_ids() only returns IDs for the requested topic."""
        cache = MessageCache(mcache_length=6, mcache_gossip=3)

        msg1 = GossipsubMessage(topic=b"topic1", raw_data=b"data1")
        msg2 = GossipsubMessage(topic=b"topic2", raw_data=b"data2")
        msg3 = GossipsubMessage(topic=b"topic1", raw_data=b"data3")

        cache.put(TopicId("topic1"), msg1)
        cache.put(TopicId("topic2"), msg2)
        cache.put(TopicId("topic1"), msg3)

        gossip_ids = cache.get_gossip_ids(TopicId("topic1"))
        assert msg1.id in gossip_ids
        assert msg3.id in gossip_ids
        assert msg2.id not in gossip_ids

        assert cache.get_gossip_ids(TopicId("topicUnknown")) == []

    def test_iwant_after_gossip_window(self) -> None:
        """Messages outside gossip window are still retrievable via get()."""
        cache = MessageCache(mcache_length=4, mcache_gossip=1)

        message = GossipsubMessage(topic=b"t", raw_data=b"data")
        cache.put(TopicId("t"), message)

        # Shift past the gossip window but still within cache.
        cache.shift()
        cache.shift()

        # Not in gossip IDs anymore.
        assert message.id not in cache.get_gossip_ids(TopicId("t"))
        # But still retrievable via IWANT.
        assert cache.get(message.id) is not None


class TestMessageCachePutAndGet:
    """Tests for put, get, and duplicate detection."""

    def test_get_retrieves_cached_message(self) -> None:
        """get() retrieves a message by ID after put()."""
        cache = MessageCache()
        message = GossipsubMessage(topic=b"t", raw_data=b"data")
        cache.put(TopicId("t"), message)
        assert cache.get(message.id) == message

    def test_get_returns_none_for_unknown(self) -> None:
        """get() returns None for an unknown message ID."""
        cache = MessageCache()
        assert cache.get(MessageId(b"\x00" * 20)) is None

    def test_put_duplicate_returns_false(self) -> None:
        """Putting the same message twice returns False on second call."""
        cache = MessageCache()
        message = GossipsubMessage(topic=b"t", raw_data=b"data")

        assert cache.put(TopicId("t"), message) is True
        assert cache.put(TopicId("t"), message) is False
        assert cache.has(message.id)

    def test_has_method(self) -> None:
        """The has() method works for message IDs."""
        cache = MessageCache()
        message = GossipsubMessage(topic=b"t", raw_data=b"data")
        cache.put(TopicId("t"), message)

        assert cache.has(message.id)
        assert not cache.has(MessageId(b"\x00" * 20))


class TestSeenCache:
    """Tests for SeenCache TTL behavior."""

    def test_add_returns_true_for_new(self) -> None:
        """add() returns True for a new message ID."""
        seen = SeenCache(ttl_seconds=120)
        message_id = MessageId(b"12345678901234567890")
        assert seen.add(message_id, Timestamp(time.time())) is True

    def test_add_returns_false_for_duplicate(self) -> None:
        """add() returns False for an already-seen message ID."""
        seen = SeenCache(ttl_seconds=120)
        message_id = MessageId(b"12345678901234567890")
        seen.add(message_id, Timestamp(time.time()))
        assert seen.add(message_id, Timestamp(time.time())) is False

    def test_cleanup_removes_expired(self) -> None:
        """cleanup() removes entries past TTL."""
        seen = SeenCache(ttl_seconds=10)
        now = time.time()

        old_id = MessageId(b"aaaaaaaaaaaaaaaaaaaa")
        fresh_id = MessageId(b"bbbbbbbbbbbbbbbbbbbb")
        seen.add(old_id, Timestamp(now - 20))
        seen.add(fresh_id, Timestamp(now))

        removed = seen.cleanup(now)
        assert removed == 1
        assert not seen.has(old_id)
        assert seen.has(fresh_id)

    def test_cleanup_no_expired(self) -> None:
        """cleanup() with no expired entries removes nothing."""
        seen = SeenCache(ttl_seconds=120)
        now = time.time()
        message_id = MessageId(b"12345678901234567890")
        seen.add(message_id, Timestamp(now))

        removed = seen.cleanup(now)
        assert removed == 0
        assert seen.has(message_id)

    def test_has_method(self) -> None:
        """The has() method works for seen message IDs."""
        seen = SeenCache()
        message_id = MessageId(b"12345678901234567890")
        seen.add(message_id, Timestamp(time.time()))

        assert seen.has(message_id)
        assert not seen.has(MessageId(b"\x00" * 20))
