"""Tests for gossipsub cache edge cases and GossipsubMessage."""

from __future__ import annotations

import time

from lean_spec.subspecs.networking.gossipsub.mcache import MessageCache, SeenCache
from lean_spec.subspecs.networking.gossipsub.message import GossipsubMessage
from lean_spec.types import Bytes20


class TestMessageCacheShift:
    """Tests for MessageCache.shift() edge cases."""

    def test_shift_when_not_full(self) -> None:
        """shift() does not evict when fewer windows than mcache_len."""
        cache = MessageCache(mcache_len=6, mcache_gossip=3)
        msg = GossipsubMessage(topic=b"t", raw_data=b"data1")
        cache.put("t", msg)

        # Only 1 window used out of 6; shift should evict nothing.
        evicted = cache.shift()
        assert evicted == 0
        assert len(cache) == 1
        assert cache.has(msg.id)

    def test_shift_evicts_oldest_window(self) -> None:
        """shift() evicts messages from the oldest window at capacity."""
        cache = MessageCache(mcache_len=3, mcache_gossip=2)

        msg = GossipsubMessage(topic=b"t", raw_data=b"old")
        cache.put("t", msg)

        # Fill to capacity (3 windows total: initial + 2 shifts).
        cache.shift()
        cache.shift()

        # Next shift should evict the original window.
        evicted = cache.shift()
        assert evicted == 1
        assert not cache.has(msg.id)

    def test_shift_returns_correct_eviction_count(self) -> None:
        """shift() returns the number of messages evicted."""
        cache = MessageCache(mcache_len=2, mcache_gossip=1)

        # Put 3 messages in the first window.
        msgs = [GossipsubMessage(topic=b"t", raw_data=f"d{i}".encode()) for i in range(3)]
        for m in msgs:
            cache.put("t", m)

        # One shift: still within capacity (2 windows).
        evicted = cache.shift()
        assert evicted == 0
        assert len(cache) == 3

        # Second shift: oldest window (with 3 msgs) is evicted.
        evicted = cache.shift()
        assert evicted == 3
        assert len(cache) == 0


class TestMessageCacheClear:
    """Tests for MessageCache.clear()."""

    def test_clear_empties_all(self) -> None:
        """clear() removes all messages and resets windows."""
        cache = MessageCache()
        for i in range(5):
            msg = GossipsubMessage(topic=b"t", raw_data=f"d{i}".encode())
            cache.put("t", msg)

        assert len(cache) == 5
        cache.clear()
        assert len(cache) == 0

    def test_clear_allows_reuse(self) -> None:
        """After clear(), new messages can be added normally."""
        cache = MessageCache()
        old_msg = GossipsubMessage(topic=b"t", raw_data=b"old")
        cache.put("t", old_msg)
        cache.clear()

        new_msg = GossipsubMessage(topic=b"t", raw_data=b"new")
        assert cache.put("t", new_msg) is True
        assert len(cache) == 1


class TestMessageCacheGetGossipIds:
    """Tests for get_gossip_ids() with window aging."""

    def test_returns_only_recent_windows(self) -> None:
        """get_gossip_ids() only returns IDs from mcache_gossip windows."""
        cache = MessageCache(mcache_len=4, mcache_gossip=2)

        # Window 0: put msg_old.
        msg_old = GossipsubMessage(topic=b"t", raw_data=b"old")
        cache.put("t", msg_old)

        # Shift twice: msg_old is now in window 2 (outside gossip=2).
        cache.shift()
        cache.shift()

        # Window 0 (current): put msg_new.
        msg_new = GossipsubMessage(topic=b"t", raw_data=b"new")
        cache.put("t", msg_new)

        ids = cache.get_gossip_ids("t")
        assert msg_new.id in ids
        assert msg_old.id not in ids

    def test_returns_empty_for_unrelated_topic(self) -> None:
        """get_gossip_ids() returns empty for topics with no messages."""
        cache = MessageCache()
        msg = GossipsubMessage(topic=b"topicA", raw_data=b"data")
        cache.put("topicA", msg)

        assert cache.get_gossip_ids("topicB") == []

    def test_iwant_after_gossip_window(self) -> None:
        """Messages outside gossip window are still retrievable via get()."""
        cache = MessageCache(mcache_len=4, mcache_gossip=1)

        msg = GossipsubMessage(topic=b"t", raw_data=b"data")
        cache.put("t", msg)

        # Shift past the gossip window but still within cache.
        cache.shift()
        cache.shift()

        # Not in gossip IDs anymore.
        assert msg.id not in cache.get_gossip_ids("t")
        # But still retrievable via IWANT.
        assert cache.get(msg.id) is not None


class TestMessageCacheDuplicate:
    """Tests for duplicate detection."""

    def test_put_duplicate_returns_false(self) -> None:
        """Putting the same message twice returns False on second call."""
        cache = MessageCache()
        msg = GossipsubMessage(topic=b"t", raw_data=b"data")

        assert cache.put("t", msg) is True
        assert cache.put("t", msg) is False
        assert len(cache) == 1

    def test_contains_operator(self) -> None:
        """The __contains__ operator works for message IDs."""
        cache = MessageCache()
        msg = GossipsubMessage(topic=b"t", raw_data=b"data")
        cache.put("t", msg)

        assert msg.id in cache
        assert Bytes20(b"\x00" * 20) not in cache


class TestSeenCache:
    """Tests for SeenCache TTL behavior."""

    def test_add_returns_true_for_new(self) -> None:
        """add() returns True for a new message ID."""
        seen = SeenCache(ttl_seconds=120)
        msg_id = Bytes20(b"12345678901234567890")
        assert seen.add(msg_id, time.time()) is True

    def test_add_returns_false_for_duplicate(self) -> None:
        """add() returns False for an already-seen message ID."""
        seen = SeenCache(ttl_seconds=120)
        msg_id = Bytes20(b"12345678901234567890")
        seen.add(msg_id, time.time())
        assert seen.add(msg_id, time.time()) is False

    def test_cleanup_removes_expired(self) -> None:
        """cleanup() removes entries past TTL."""
        seen = SeenCache(ttl_seconds=10)
        now = time.time()

        old_id = Bytes20(b"aaaaaaaaaaaaaaaaaaaa")
        fresh_id = Bytes20(b"bbbbbbbbbbbbbbbbbbbb")
        seen.add(old_id, now - 20)
        seen.add(fresh_id, now)

        removed = seen.cleanup(now)
        assert removed == 1
        assert not seen.has(old_id)
        assert seen.has(fresh_id)

    def test_cleanup_no_expired(self) -> None:
        """cleanup() with no expired entries removes nothing."""
        seen = SeenCache(ttl_seconds=120)
        now = time.time()
        seen.add(Bytes20(b"12345678901234567890"), now)

        removed = seen.cleanup(now)
        assert removed == 0
        assert len(seen) == 1

    def test_clear_empties_all(self) -> None:
        """clear() removes all entries."""
        seen = SeenCache()
        for i in range(5):
            seen.add(Bytes20(f"x{i:019d}".encode()), time.time())

        assert len(seen) == 5
        seen.clear()
        assert len(seen) == 0

    def test_contains_operator(self) -> None:
        """The __contains__ operator works for seen message IDs."""
        seen = SeenCache()
        msg_id = Bytes20(b"12345678901234567890")
        seen.add(msg_id, time.time())

        assert msg_id in seen
        assert Bytes20(b"\x00" * 20) not in seen


class TestGossipsubMessageId:
    """Tests for GossipsubMessage ID computation."""

    def test_id_is_deterministic(self) -> None:
        """Same topic + data produce the same ID."""
        msg1 = GossipsubMessage(topic=b"topic", raw_data=b"data")
        msg2 = GossipsubMessage(topic=b"topic", raw_data=b"data")
        assert msg1.id == msg2.id

    def test_id_differs_with_different_data(self) -> None:
        """Different data produces a different ID."""
        msg1 = GossipsubMessage(topic=b"topic", raw_data=b"data1")
        msg2 = GossipsubMessage(topic=b"topic", raw_data=b"data2")
        assert msg1.id != msg2.id

    def test_id_differs_with_different_topic(self) -> None:
        """Different topic produces a different ID."""
        msg1 = GossipsubMessage(topic=b"topicA", raw_data=b"data")
        msg2 = GossipsubMessage(topic=b"topicB", raw_data=b"data")
        assert msg1.id != msg2.id

    def test_id_is_20_bytes(self) -> None:
        """Message ID is exactly 20 bytes (Bytes20)."""
        msg = GossipsubMessage(topic=b"t", raw_data=b"d")
        assert len(msg.id) == 20
        assert isinstance(msg.id, Bytes20)

    def test_id_is_cached(self) -> None:
        """The ID is computed once and cached."""
        msg = GossipsubMessage(topic=b"t", raw_data=b"d")
        id1 = msg.id
        id2 = msg.id
        assert id1 is id2

    def test_compute_id_with_snappy(self) -> None:
        """compute_id uses decompressed data when snappy succeeds."""
        raw = b"compressed"
        decompressed = b"decompressed"

        id_with_snappy = GossipsubMessage.compute_id(
            b"t", raw, snappy_decompress=lambda _: decompressed
        )
        id_without = GossipsubMessage.compute_id(b"t", raw)

        # Different domain bytes and data -> different IDs.
        assert id_with_snappy != id_without

    def test_compute_id_with_failed_snappy(self) -> None:
        """compute_id falls back to raw data when snappy fails."""

        def bad_decompress(_: bytes) -> bytes:
            raise RuntimeError("bad snappy")

        id_failed = GossipsubMessage.compute_id(b"t", b"data", snappy_decompress=bad_decompress)
        id_none = GossipsubMessage.compute_id(b"t", b"data", snappy_decompress=None)

        # Both use INVALID_SNAPPY domain + raw data -> same ID.
        assert id_failed == id_none


class TestGossipsubMessageTopicStr:
    """Tests for GossipsubMessage.topic_str property."""

    def test_topic_str_decodes_utf8(self) -> None:
        """topic_str decodes bytes to UTF-8 string."""
        msg = GossipsubMessage(topic=b"/eth2/topic", raw_data=b"data")
        assert msg.topic_str == "/eth2/topic"

    def test_topic_str_empty(self) -> None:
        """topic_str handles empty topic bytes."""
        msg = GossipsubMessage(topic=b"", raw_data=b"data")
        assert msg.topic_str == ""


class TestGossipsubMessageHash:
    """Tests for GossipsubMessage.__hash__."""

    def test_same_message_same_hash(self) -> None:
        """Messages with same content have the same hash."""
        msg1 = GossipsubMessage(topic=b"t", raw_data=b"d")
        msg2 = GossipsubMessage(topic=b"t", raw_data=b"d")
        assert hash(msg1) == hash(msg2)

    def test_usable_in_set(self) -> None:
        """Messages can be stored in a set, deduplicated by content."""
        msg1 = GossipsubMessage(topic=b"t", raw_data=b"d")
        msg2 = GossipsubMessage(topic=b"t", raw_data=b"d")
        msg3 = GossipsubMessage(topic=b"t", raw_data=b"other")

        s = {msg1, msg2, msg3}
        assert len(s) == 2
