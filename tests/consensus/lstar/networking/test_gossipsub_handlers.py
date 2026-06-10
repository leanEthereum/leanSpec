"""Test vectors for gossipsub handler protocol decisions."""

import pytest

from consensus_testing import (
    CachedMessage,
    GossipsubEvent,
    GossipsubHandlerTestFiller,
    GossipsubInitialState,
    GossipsubMeshParameters,
    IncomingGraft,
    IncomingIHave,
    IncomingIWant,
    IncomingPrune,
    IncomingPublish,
    PeerConfiguration,
)

pytestmark = [pytest.mark.valid_until("Lstar"), pytest.mark.order_sensitive]

TOPIC = "test_topic"
PARAMS = GossipsubMeshParameters(d=4, d_low=3, d_high=6, d_lazy=3)
MESSAGE_ID = "0x8dc6bba09a9550cdccb1b1b432bb04919901ce1e"
"""Message ID for topic=b'test_topic', data=0xdeadbeef, invalid-snappy domain."""

MESSAGE_ID_2 = "0xb51451075fcc3e8f0baa9041d8256c647ceaeaac"
"""Message ID for topic=b'test_topic', data=0xcafebabe, invalid-snappy domain."""


def test_graft_accept(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    A GRAFT is accepted when subscribed with mesh capacity.

    Given
    -----
    - the node is subscribed to the topic.
    - the mesh holds peerAx, below capacity.
    - peerBx is subscribed and not yet in the mesh.

    When
    ----
    - peerBx sends a GRAFT for the topic.

    Then
    ----
    - peerBx is added to the mesh.
    """
    gossipsub_handler_test(
        handler_name="graft",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={TOPIC: ["peerAx"]},
            peers={
                "peerAx": PeerConfiguration(subscriptions=[TOPIC]),
                "peerBx": PeerConfiguration(subscriptions=[TOPIC]),
            },
        ),
        event=GossipsubEvent(from_peer="peerBx", graft=[IncomingGraft(topic_id=TOPIC)]),
    )


def test_graft_reject_capacity(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    A GRAFT is rejected with a PRUNE when the mesh is full.

    Given
    -----
    - the node is subscribed to the topic.
    - the mesh holds three peers, at its upper bound.
    - peerDx is subscribed and not in the mesh.

    When
    ----
    - peerDx sends a GRAFT for the topic.

    Then
    ----
    - the node replies with a PRUNE.
    - peerDx is not added to the mesh.
    """
    gossipsub_handler_test(
        handler_name="graft",
        params=GossipsubMeshParameters(d=4, d_low=3, d_high=3, d_lazy=3),
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={TOPIC: ["peerAx", "peerBx", "peerCx"]},
            peers={
                "peerAx": PeerConfiguration(subscriptions=[TOPIC]),
                "peerBx": PeerConfiguration(subscriptions=[TOPIC]),
                "peerCx": PeerConfiguration(subscriptions=[TOPIC]),
                "peerDx": PeerConfiguration(subscriptions=[TOPIC]),
            },
        ),
        event=GossipsubEvent(from_peer="peerDx", graft=[IncomingGraft(topic_id=TOPIC)]),
    )


def test_graft_reject_backoff(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    A GRAFT is rejected with a PRUNE while the peer is in backoff.

    Given
    -----
    - the node is subscribed to the topic.
    - the mesh holds peerAx.
    - peerBx has a backoff that expires at 1060, later than now=1000.

    When
    ----
    - peerBx sends a GRAFT for the topic.

    Then
    ----
    - the node replies with a PRUNE.
    - peerBx is not added to the mesh.
    """
    gossipsub_handler_test(
        handler_name="graft",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={TOPIC: ["peerAx"]},
            peers={
                "peerAx": PeerConfiguration(subscriptions=[TOPIC]),
                "peerBx": PeerConfiguration(subscriptions=[TOPIC], backoff={TOPIC: 1060.0}),
            },
        ),
        event=GossipsubEvent(from_peer="peerBx", graft=[IncomingGraft(topic_id=TOPIC)]),
        now=1000.0,
    )


def test_graft_ignore_unsubscribed(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    A GRAFT for an unsubscribed topic is ignored.

    Given
    -----
    - the node has no subscriptions and no meshes.
    - peerAx is subscribed to the topic.

    When
    ----
    - peerAx sends a GRAFT for the topic.

    Then
    ----
    - the node sends no reply.
    - no mesh is created.
    """
    gossipsub_handler_test(
        handler_name="graft",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[], meshes={}, peers={"peerAx": PeerConfiguration(subscriptions=[TOPIC])}
        ),
        event=GossipsubEvent(from_peer="peerAx", graft=[IncomingGraft(topic_id=TOPIC)]),
    )


def test_graft_idempotent(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    A GRAFT from a peer already in the mesh is harmless.

    Given
    -----
    - the node is subscribed to the topic.
    - the mesh already holds peerAx.

    When
    ----
    - peerAx sends a GRAFT for the topic.

    Then
    ----
    - the mesh still holds peerAx exactly once.
    """
    gossipsub_handler_test(
        handler_name="graft",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={TOPIC: ["peerAx"]},
            peers={"peerAx": PeerConfiguration(subscriptions=[TOPIC])},
        ),
        event=GossipsubEvent(from_peer="peerAx", graft=[IncomingGraft(topic_id=TOPIC)]),
    )


def test_prune_with_backoff(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    A PRUNE removes the peer from the mesh and arms a backoff.

    Given
    -----
    - the node is subscribed to the topic.
    - the mesh holds peerAx and peerBx.

    When
    ----
    - peerAx sends a PRUNE for the topic with a 60-second backoff.

    Then
    ----
    - peerAx is removed from the mesh.
    - a backoff timer is set for peerAx.
    """
    gossipsub_handler_test(
        handler_name="prune",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={TOPIC: ["peerAx", "peerBx"]},
            peers={
                "peerAx": PeerConfiguration(subscriptions=[TOPIC]),
                "peerBx": PeerConfiguration(subscriptions=[TOPIC]),
            },
        ),
        event=GossipsubEvent(from_peer="peerAx", prune=[IncomingPrune(topic_id=TOPIC, backoff=60)]),
    )


def test_prune_zero_backoff(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    A PRUNE with zero backoff removes the peer without arming a backoff.

    Given
    -----
    - the node is subscribed to the topic.
    - the mesh holds peerAx.

    When
    ----
    - peerAx sends a PRUNE for the topic with a zero backoff.

    Then
    ----
    - peerAx is removed from the mesh.
    - no backoff timer is set.
    """
    gossipsub_handler_test(
        handler_name="prune",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={TOPIC: ["peerAx"]},
            peers={"peerAx": PeerConfiguration(subscriptions=[TOPIC])},
        ),
        event=GossipsubEvent(from_peer="peerAx", prune=[IncomingPrune(topic_id=TOPIC, backoff=0)]),
    )


def test_ihave_unseen_triggers_iwant(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    An IHAVE for an unseen message triggers an IWANT.

    Given
    -----
    - the node is subscribed to the topic.
    - the seen cache is empty.
    - peerAx is subscribed.

    When
    ----
    - peerAx sends an IHAVE advertising one unseen message id.

    Then
    ----
    - the node replies with an IWANT for that message id.
    """
    gossipsub_handler_test(
        handler_name="ihave",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={},
            peers={"peerAx": PeerConfiguration(subscriptions=[TOPIC])},
            seen_message_ids=[],
            cached_messages=[],
        ),
        event=GossipsubEvent(
            from_peer="peerAx", ihave=[IncomingIHave(topic_id=TOPIC, message_ids=[MESSAGE_ID])]
        ),
    )


def test_ihave_seen_no_iwant(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    An IHAVE for an already-seen message produces no IWANT.

    Given
    -----
    - the node is subscribed to the topic.
    - the seen cache already holds the advertised message id.
    - peerAx is subscribed.

    When
    ----
    - peerAx sends an IHAVE advertising that seen message id.

    Then
    ----
    - the node sends no IWANT.
    """
    gossipsub_handler_test(
        handler_name="ihave",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={},
            peers={"peerAx": PeerConfiguration(subscriptions=[TOPIC])},
            seen_message_ids=[MESSAGE_ID],
            cached_messages=[],
        ),
        event=GossipsubEvent(
            from_peer="peerAx", ihave=[IncomingIHave(topic_id=TOPIC, message_ids=[MESSAGE_ID])]
        ),
    )


def test_ihave_mixed(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    An IHAVE mixing seen and unseen ids triggers an IWANT for the unseen one only.

    Given
    -----
    - the node is subscribed to the topic.
    - the seen cache holds the first message id.
    - peerAx is subscribed.

    When
    ----
    - peerAx sends an IHAVE advertising the seen id and an unseen id.

    Then
    ----
    - the node replies with an IWANT for the unseen id only.
    """
    gossipsub_handler_test(
        handler_name="ihave",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={},
            peers={"peerAx": PeerConfiguration(subscriptions=[TOPIC])},
            seen_message_ids=[MESSAGE_ID],
            cached_messages=[],
        ),
        event=GossipsubEvent(
            from_peer="peerAx",
            ihave=[IncomingIHave(topic_id=TOPIC, message_ids=[MESSAGE_ID, MESSAGE_ID_2])],
        ),
    )


def test_iwant_cached_responds(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    An IWANT for a cached message returns the full message.

    Given
    -----
    - the node is subscribed to the topic.
    - the message cache holds a message under the requested id.
    - peerAx is subscribed.

    When
    ----
    - peerAx sends an IWANT for that message id.

    Then
    ----
    - the node replies with the full cached message.
    """
    gossipsub_handler_test(
        handler_name="iwant",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={},
            peers={"peerAx": PeerConfiguration(subscriptions=[TOPIC])},
            seen_message_ids=[],
            cached_messages=[CachedMessage(topic=TOPIC, data="0xdeadbeef", message_id=MESSAGE_ID)],
        ),
        event=GossipsubEvent(from_peer="peerAx", iwant=[IncomingIWant(message_ids=[MESSAGE_ID])]),
    )


def test_message_forward_to_mesh(gossipsub_handler_test: GossipsubHandlerTestFiller) -> None:
    """
    A new message is forwarded to mesh peers except the sender.

    Given
    -----
    - the node is subscribed to the topic.
    - the mesh holds senderX, peerAx, and peerBx.

    When
    ----
    - senderX publishes a new message on the topic.

    Then
    ----
    - the message is forwarded to peerAx and peerBx.
    - the message is not forwarded back to senderX.
    """
    gossipsub_handler_test(
        handler_name="message",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={TOPIC: ["senderX", "peerAx", "peerBx"]},
            peers={
                "senderX": PeerConfiguration(subscriptions=[TOPIC]),
                "peerAx": PeerConfiguration(subscriptions=[TOPIC]),
                "peerBx": PeerConfiguration(subscriptions=[TOPIC]),
            },
        ),
        event=GossipsubEvent(
            from_peer="senderX", publish=[IncomingPublish(topic=TOPIC, data="0xdeadbeef")]
        ),
    )


def test_message_duplicate_not_forwarded(
    gossipsub_handler_test: GossipsubHandlerTestFiller,
) -> None:
    """
    A duplicate message is not forwarded.

    Given
    -----
    - the node is subscribed to the topic.
    - the mesh holds senderX and peerAx.
    - the seen cache already holds the message id.

    When
    ----
    - senderX publishes that already-seen message on the topic.

    Then
    ----
    - the message is not forwarded to any peer.
    """
    gossipsub_handler_test(
        handler_name="message",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={TOPIC: ["senderX", "peerAx"]},
            peers={
                "senderX": PeerConfiguration(subscriptions=[TOPIC]),
                "peerAx": PeerConfiguration(subscriptions=[TOPIC]),
            },
            seen_message_ids=[MESSAGE_ID],
        ),
        event=GossipsubEvent(
            from_peer="senderX", publish=[IncomingPublish(topic=TOPIC, data="0xdeadbeef")]
        ),
    )


def test_message_idontwant_skips_peer(
    gossipsub_handler_test: GossipsubHandlerTestFiller,
) -> None:
    """
    A peer that declined the message id is skipped during forwarding.

    Given
    -----
    - the node is subscribed to the topic.
    - the mesh holds senderX, peerAx, and peerBx.
    - peerAx has sent an IDONTWANT for this message id.

    When
    ----
    - senderX publishes the message on the topic.

    Then
    ----
    - the message is forwarded to peerBx.
    - the message is not forwarded to peerAx.
    - the message is not forwarded back to senderX.
    """
    gossipsub_handler_test(
        handler_name="message",
        params=PARAMS,
        initial_state=GossipsubInitialState(
            subscriptions=[TOPIC],
            meshes={TOPIC: ["senderX", "peerAx", "peerBx"]},
            peers={
                "senderX": PeerConfiguration(subscriptions=[TOPIC]),
                "peerAx": PeerConfiguration(subscriptions=[TOPIC], dont_want_ids=[MESSAGE_ID]),
                "peerBx": PeerConfiguration(subscriptions=[TOPIC]),
            },
        ),
        event=GossipsubEvent(
            from_peer="senderX", publish=[IncomingPublish(topic=TOPIC, data="0xdeadbeef")]
        ),
    )
