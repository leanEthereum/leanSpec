"""Test vectors for gossipsub handler protocol decisions."""

import pytest
from consensus_testing import GossipsubHandlerTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

TOPIC = "test_topic"
PARAMS = {"d": 4, "dLow": 3, "dHigh": 6, "dLazy": 3}
MSG_ID = "0x8dc6bba09a9550cdccb1b1b432bb04919901ce1e"
"""Message ID for topic=b'test_topic', data=0xdeadbeef, invalid-snappy domain."""

MSG_ID_2 = "0xb51451075fcc3e8f0baa9041d8256c647ceaeaac"
"""Message ID for topic=b'test_topic', data=0xcafebabe, invalid-snappy domain."""


# --- GRAFT handler ---


def test_graft_accept(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """Accept GRAFT when subscribed and mesh has capacity."""
    gossipsub_handler(
        handler_name="graft",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {TOPIC: ["peerAx"]},
            "peers": {
                "peerAx": {"subscriptions": [TOPIC]},
                "peerBx": {"subscriptions": [TOPIC]},
            },
        },
        event={"fromPeer": "peerBx", "graft": [{"topicId": TOPIC}]},
    )


def test_graft_reject_capacity(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """Reject GRAFT with PRUNE when mesh is at d_high."""
    gossipsub_handler(
        handler_name="graft",
        params={"d": 4, "dLow": 3, "dHigh": 3, "dLazy": 3},
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {TOPIC: ["peerAx", "peerBx", "peerCx"]},
            "peers": {
                "peerAx": {"subscriptions": [TOPIC]},
                "peerBx": {"subscriptions": [TOPIC]},
                "peerCx": {"subscriptions": [TOPIC]},
                "peerDx": {"subscriptions": [TOPIC]},
            },
        },
        event={"fromPeer": "peerDx", "graft": [{"topicId": TOPIC}]},
    )


def test_graft_reject_backoff(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """Reject GRAFT with PRUNE when peer is in backoff period."""
    gossipsub_handler(
        handler_name="graft",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {TOPIC: ["peerAx"]},
            "peers": {
                "peerAx": {"subscriptions": [TOPIC]},
                "peerBx": {"subscriptions": [TOPIC], "backoff": {TOPIC: 1060.0}},
            },
        },
        event={"fromPeer": "peerBx", "graft": [{"topicId": TOPIC}]},
        now=1000.0,
    )


def test_graft_ignore_unsubscribed(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """Silently ignore GRAFT for a topic we are not subscribed to."""
    gossipsub_handler(
        handler_name="graft",
        params=PARAMS,
        initial_state={
            "subscriptions": [],
            "meshes": {},
            "peers": {
                "peerAx": {"subscriptions": [TOPIC]},
            },
        },
        event={"fromPeer": "peerAx", "graft": [{"topicId": TOPIC}]},
    )


def test_graft_idempotent(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """GRAFT for a peer already in mesh is harmless."""
    gossipsub_handler(
        handler_name="graft",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {TOPIC: ["peerAx"]},
            "peers": {
                "peerAx": {"subscriptions": [TOPIC]},
            },
        },
        event={"fromPeer": "peerAx", "graft": [{"topicId": TOPIC}]},
    )


# --- PRUNE handler ---


def test_prune_with_backoff(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """PRUNE removes peer from mesh and sets backoff timer."""
    gossipsub_handler(
        handler_name="prune",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {TOPIC: ["peerAx", "peerBx"]},
            "peers": {
                "peerAx": {"subscriptions": [TOPIC]},
                "peerBx": {"subscriptions": [TOPIC]},
            },
        },
        event={"fromPeer": "peerAx", "prune": [{"topicId": TOPIC, "backoff": 60}]},
    )


def test_prune_zero_backoff(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """PRUNE with backoff=0 removes from mesh but does not set backoff timer."""
    gossipsub_handler(
        handler_name="prune",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {TOPIC: ["peerAx"]},
            "peers": {
                "peerAx": {"subscriptions": [TOPIC]},
            },
        },
        event={"fromPeer": "peerAx", "prune": [{"topicId": TOPIC, "backoff": 0}]},
    )


# --- IHAVE handler ---


def test_ihave_unseen_triggers_iwant(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """IHAVE for an unseen message triggers an IWANT response."""
    gossipsub_handler(
        handler_name="ihave",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {},
            "peers": {"peerAx": {"subscriptions": [TOPIC]}},
            "seenMessageIds": [],
            "cachedMessages": [],
        },
        event={
            "fromPeer": "peerAx",
            "ihave": [{"topicId": TOPIC, "messageIds": [MSG_ID]}],
        },
    )


def test_ihave_seen_no_iwant(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """IHAVE for an already-seen message produces no IWANT."""
    gossipsub_handler(
        handler_name="ihave",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {},
            "peers": {"peerAx": {"subscriptions": [TOPIC]}},
            "seenMessageIds": [MSG_ID],
            "cachedMessages": [],
        },
        event={
            "fromPeer": "peerAx",
            "ihave": [{"topicId": TOPIC, "messageIds": [MSG_ID]}],
        },
    )


def test_ihave_mixed(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """IHAVE with seen and unseen IDs. IWANT only for the unseen one."""
    gossipsub_handler(
        handler_name="ihave",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {},
            "peers": {"peerAx": {"subscriptions": [TOPIC]}},
            "seenMessageIds": [MSG_ID],
            "cachedMessages": [],
        },
        event={
            "fromPeer": "peerAx",
            "ihave": [{"topicId": TOPIC, "messageIds": [MSG_ID, MSG_ID_2]}],
        },
    )


# --- IWANT handler ---


def test_iwant_cached_responds(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """IWANT for a cached message responds with the full message."""
    gossipsub_handler(
        handler_name="iwant",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {},
            "peers": {"peerAx": {"subscriptions": [TOPIC]}},
            "seenMessageIds": [],
            "cachedMessages": [
                {"topic": TOPIC, "data": "0xdeadbeef", "messageId": MSG_ID},
            ],
        },
        event={
            "fromPeer": "peerAx",
            "iwant": [{"messageIds": [MSG_ID]}],
        },
    )


# --- Message handler ---


def test_message_forward_to_mesh(gossipsub_handler: GossipsubHandlerTestFiller) -> None:
    """New message forwarded to mesh peers except the sender."""
    gossipsub_handler(
        handler_name="message",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {TOPIC: ["senderX", "peerAx", "peerBx"]},
            "peers": {
                "senderX": {"subscriptions": [TOPIC]},
                "peerAx": {"subscriptions": [TOPIC]},
                "peerBx": {"subscriptions": [TOPIC]},
            },
        },
        event={
            "fromPeer": "senderX",
            "publish": [{"topic": TOPIC, "data": "0xdeadbeef"}],
        },
    )


def test_message_duplicate_not_forwarded(
    gossipsub_handler: GossipsubHandlerTestFiller,
) -> None:
    """Duplicate message (already in seen cache) is not forwarded."""
    gossipsub_handler(
        handler_name="message",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {TOPIC: ["senderX", "peerAx"]},
            "peers": {
                "senderX": {"subscriptions": [TOPIC]},
                "peerAx": {"subscriptions": [TOPIC]},
            },
            "seenMessageIds": [MSG_ID],
        },
        event={
            "fromPeer": "senderX",
            "publish": [{"topic": TOPIC, "data": "0xdeadbeef"}],
        },
    )


def test_message_idontwant_skips_peer(
    gossipsub_handler: GossipsubHandlerTestFiller,
) -> None:
    """Peer that sent IDONTWANT for this message ID is skipped during forwarding."""
    gossipsub_handler(
        handler_name="message",
        params=PARAMS,
        initial_state={
            "subscriptions": [TOPIC],
            "meshes": {TOPIC: ["senderX", "peerAx", "peerBx"]},
            "peers": {
                "senderX": {"subscriptions": [TOPIC]},
                "peerAx": {"subscriptions": [TOPIC], "dontWantIds": [MSG_ID]},
                "peerBx": {"subscriptions": [TOPIC]},
            },
        },
        event={
            "fromPeer": "senderX",
            "publish": [{"topic": TOPIC, "data": "0xdeadbeef"}],
        },
    )
