"""Gossipsub handler test fixture for protocol behavior conformance."""

import asyncio
from dataclasses import dataclass, field
from typing import Any, ClassVar
from unittest.mock import patch

from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from consensus_testing.test_fixtures.hex_codec import from_hex, to_hex
from lean_spec.base import StrictBaseModel
from lean_spec.node.networking import PeerId
from lean_spec.node.networking.gossipsub.behavior import GossipsubBehavior, PeerState
from lean_spec.node.networking.gossipsub.message import GossipsubMessage
from lean_spec.node.networking.gossipsub.parameters import GossipsubParameters
from lean_spec.node.networking.gossipsub.rpc import (
    RPC,
    ControlGraft,
    ControlIDontWant,
    ControlIHave,
    ControlIWant,
    ControlMessage,
    ControlPrune,
    Message,
)
from lean_spec.node.networking.gossipsub.types import MessageId, Timestamp, TopicId

# Sentinel that satisfies `outbound_stream is not None` checks.
# The patched _send_rpc never touches the stream, so any non-None value works.
_FAKE_STREAM: Any = object()


@dataclass
class _SendCapture:
    """Records each outbound RPC as a (peer, rpc) pair."""

    sent: list[tuple[PeerId, RPC]] = field(default_factory=list)

    async def __call__(self, peer_id: PeerId, rpc: RPC) -> None:
        self.sent.append((peer_id, rpc))


def _peer_id(name: str) -> PeerId:
    """Convert a short test name to a PeerId."""
    return PeerId.from_base58(name)


class GossipsubMeshParameters(StrictBaseModel):
    """Mesh degree parameters the handler runs under."""

    d: int = 8
    """Target mesh degree."""

    d_low: int = 6
    """Lower mesh degree bound."""

    d_high: int = 12
    """Upper mesh degree bound."""

    d_lazy: int = 6
    """Gossip emission degree."""


class PeerConfiguration(StrictBaseModel):
    """Initial protocol state for one registered peer."""

    subscriptions: list[str] = []
    """Topics the peer is subscribed to."""

    with_stream: bool = True
    """Whether the peer has an open outbound stream."""

    backoff: dict[str, float] = {}
    """Backoff expiry per topic, blocking re-GRAFT until then."""

    dont_want_ids: list[str] = []
    """Hex message identifiers the peer asked not to receive."""


class CachedMessage(StrictBaseModel):
    """One message preloaded into the message cache."""

    topic: str
    """Topic the cached message belongs to."""

    data: str
    """Hex message payload."""

    message_id: str
    """Hex identifier the cache stores the message under."""


class GossipsubInitialState(StrictBaseModel):
    """Behavior state seeded before the incoming event is dispatched."""

    subscriptions: list[str] = []
    """Topics the local node participates in."""

    peers: dict[str, PeerConfiguration] = {}
    """Registered peers keyed by short test name."""

    meshes: dict[str, list[str]] = {}
    """Mesh members per topic, by short peer name."""

    seen_message_ids: list[str] = []
    """Hex identifiers of previously received messages."""

    cached_messages: list[CachedMessage] = []
    """Messages preloaded into the cache for IWANT responses."""


class IncomingGraft(StrictBaseModel):
    """One GRAFT in the incoming RPC."""

    topic_id: str
    """Topic the sender wants to graft."""


class IncomingPrune(StrictBaseModel):
    """One PRUNE in the incoming RPC."""

    topic_id: str
    """Topic the sender prunes."""

    backoff: int = 0
    """Backoff seconds the sender requests."""


class IncomingIHave(StrictBaseModel):
    """One IHAVE in the incoming RPC."""

    topic_id: str
    """Topic the advertised messages belong to."""

    message_ids: list[str] = []
    """Hex identifiers of the advertised messages."""


class IncomingIWant(StrictBaseModel):
    """One IWANT in the incoming RPC."""

    message_ids: list[str] = []
    """Hex identifiers of the requested messages."""


class IncomingIDontWant(StrictBaseModel):
    """One IDONTWANT in the incoming RPC."""

    message_ids: list[str] = []
    """Hex identifiers of the unwanted messages."""


class IncomingPublish(StrictBaseModel):
    """One published message in the incoming RPC."""

    topic: str = ""
    """Topic the message belongs to."""

    data: str | None = None
    """Hex message payload."""


class GossipsubEvent(StrictBaseModel):
    """One incoming RPC from a peer."""

    from_peer: str
    """Short name of the sending peer."""

    graft: list[IncomingGraft] = []
    """GRAFT requests carried by the RPC."""

    prune: list[IncomingPrune] = []
    """PRUNE notices carried by the RPC."""

    ihave: list[IncomingIHave] = []
    """IHAVE advertisements carried by the RPC."""

    iwant: list[IncomingIWant] = []
    """IWANT requests carried by the RPC."""

    idontwant: list[IncomingIDontWant] = []
    """IDONTWANT notices carried by the RPC."""

    publish: list[IncomingPublish] = []
    """Messages carried by the RPC."""

    def build_rpc(self) -> RPC:
        """Convert to the wire-format RPC the handler receives."""
        control_components: dict[str, list[Any]] = {}

        if self.graft:
            control_components["graft"] = [
                ControlGraft(topic_id=TopicId(graft.topic_id)) for graft in self.graft
            ]
        if self.prune:
            control_components["prune"] = [
                ControlPrune(topic_id=TopicId(prune.topic_id), backoff=prune.backoff)
                for prune in self.prune
            ]
        if self.ihave:
            control_components["ihave"] = [
                ControlIHave(
                    topic_id=TopicId(ihave.topic_id),
                    message_ids=[from_hex(message_id) for message_id in ihave.message_ids],
                )
                for ihave in self.ihave
            ]
        if self.iwant:
            control_components["iwant"] = [
                ControlIWant(message_ids=[from_hex(message_id) for message_id in iwant.message_ids])
                for iwant in self.iwant
            ]
        if self.idontwant:
            control_components["idontwant"] = [
                ControlIDontWant(
                    message_ids=[from_hex(message_id) for message_id in idontwant.message_ids]
                )
                for idontwant in self.idontwant
            ]

        return RPC(
            publish=[
                Message(
                    topic=TopicId(message.topic),
                    data=from_hex(message.data) if message.data else b"",
                )
                for message in self.publish
            ],
            control=ControlMessage(**control_components) if control_components else None,
        )


class SentSubscription(StrictBaseModel):
    """One subscription change in an outbound RPC."""

    subscribe: bool
    """True to subscribe, False to unsubscribe."""

    topic_id: str
    """Topic the change applies to."""


class SentPublish(StrictBaseModel):
    """One forwarded message in an outbound RPC."""

    topic: str
    """Topic the message belongs to."""

    data: str
    """Hex message payload."""


class SentGraft(StrictBaseModel):
    """One GRAFT in an outbound RPC."""

    topic_id: str
    """Topic grafted."""


class SentPrune(StrictBaseModel):
    """One PRUNE in an outbound RPC."""

    topic_id: str
    """Topic pruned."""

    backoff: int
    """Backoff seconds requested."""


class SentMessageIdentifiers(StrictBaseModel):
    """One IWANT or IDONTWANT entry in an outbound RPC."""

    message_ids: list[str]
    """Hex identifiers carried by the entry."""


class SentControl(StrictBaseModel):
    """Control sub-messages in an outbound RPC; absent groups stay None."""

    graft: list[SentGraft] | None = None
    """GRAFT requests, when any."""

    prune: list[SentPrune] | None = None
    """PRUNE notices, when any."""

    iwant: list[SentMessageIdentifiers] | None = None
    """IWANT requests, when any."""

    idontwant: list[SentMessageIdentifiers] | None = None
    """IDONTWANT notices, when any."""


class SentRpc(StrictBaseModel):
    """One outbound RPC the handler must emit."""

    to_peer: str
    """Short name of the receiving peer."""

    subscriptions: list[SentSubscription] | None = None
    """Subscription changes, when any."""

    publish: list[SentPublish] | None = None
    """Forwarded messages, when any."""

    control: SentControl | None = None
    """Control sub-messages, when any."""


class GossipsubExpectation(StrictBaseModel):
    """Outbound RPCs and final mesh topology the client must reproduce."""

    sent_rpcs: list[SentRpc]
    """Outbound RPCs in send order."""

    mesh_after: dict[str, list[str]]
    """Mesh members per topic after the event, sorted by peer name."""


class GossipsubHandlerFixture(BaseConsensusFixture):
    """
    Emitted vector for gossipsub handler behavior conformance.

    JSON output: handlerName, params, initialState, event, now, expected.
    """

    handler_name: str
    """Handler under test."""

    params: GossipsubMeshParameters
    """Mesh degree parameters."""

    initial_state: GossipsubInitialState
    """Behavior state seeded before the event."""

    event: GossipsubEvent
    """Incoming RPC dispatched to the handler."""

    now: float
    """Current timestamp for backoff checks."""

    expected: GossipsubExpectation
    """Expected outbound RPCs and final mesh state."""


class GossipsubHandlerTest(BaseTestSpec):
    """
    Spec for gossipsub handler behavior conformance.

    Tests protocol decisions: given initial state + incoming event,
    what RPCs are sent and how does the mesh change?
    """

    format_name: ClassVar[str] = "gossipsub_handler_test"
    description: ClassVar[str] = "Tests gossipsub handler protocol decisions"

    handler_name: str
    """Handler being tested: graft, prune, ihave, iwant, message."""

    params: GossipsubMeshParameters = GossipsubMeshParameters()
    """Mesh degree parameters."""

    initial_state: GossipsubInitialState
    """Behavior state to seed before the event: subscriptions, meshes, peers, caches."""

    event: GossipsubEvent
    """Incoming event: sending peer plus RPC content."""

    now: float = 1000.0
    """Current timestamp for backoff checks."""

    def generate(self) -> GossipsubHandlerFixture:
        """Produce the emitted vector with expected outputs filled in."""
        return GossipsubHandlerFixture(
            handler_name=self.handler_name,
            params=self.params,
            initial_state=self.initial_state,
            event=self.event,
            now=self.now,
            expected=asyncio.run(self._execute()),
        )

    async def _execute(self) -> GossipsubExpectation:
        """
        Run the handler against a fully-configured behavior instance.

        Builds the gossipsub behavior from fixture inputs, dispatches the
        incoming RPC, and returns the outbound RPCs and final mesh state.
        """
        behavior = GossipsubBehavior(
            params=GossipsubParameters(
                d=self.params.d,
                d_low=self.params.d_low,
                d_high=self.params.d_high,
                d_lazy=self.params.d_lazy,
            )
        )

        # Intercept outbound RPCs instead of sending them over the network.
        capture = _SendCapture()
        behavior._send_rpc = capture  # type: ignore[assignment]

        # Map between human-readable test names and opaque peer identifiers.
        peer_names: dict[PeerId, str] = {}

        # Subscriptions define which topics the local node participates in.
        #
        # Handlers ignore messages for topics we are not subscribed to.
        for topic in self.initial_state.subscriptions:
            behavior.mesh.subscribe(TopicId(topic))

        # Register each peer with its subscriptions and protocol state.
        #
        # Peer properties like backoff timers and IDONTWANT sets directly
        # influence handler decisions (e.g., reject GRAFTs, skip forwarding).
        for peer_name, peer_configuration in self.initial_state.peers.items():
            peer_id = _peer_id(peer_name)
            peer_names[peer_id] = peer_name
            peer_state = PeerState(
                peer_id=peer_id,
                subscriptions={
                    TopicId(topic_string) for topic_string in peer_configuration.subscriptions
                },
                outbound_stream=_FAKE_STREAM if peer_configuration.with_stream else None,
            )

            # Backoff prevents re-GRAFTing a recently-pruned peer.
            for topic_string, expiry in peer_configuration.backoff.items():
                peer_state.backoff[TopicId(topic_string)] = expiry

            # IDONTWANT suppresses forwarding to peers that already have the message.
            for message_id_hex in peer_configuration.dont_want_ids:
                peer_state.dont_want_ids.add(MessageId(from_hex(message_id_hex)))
            behavior._peers[peer_id] = peer_state

        # Mesh topology determines who receives forwarded messages.
        #
        # Handlers check mesh membership for GRAFT acceptance, PRUNE removal,
        # and message forwarding decisions.
        for topic_string, mesh_peer_names in self.initial_state.meshes.items():
            topic = TopicId(topic_string)
            for peer_name in mesh_peer_names:
                behavior.mesh.add_to_mesh(topic, _peer_id(peer_name))

        # Seen cache tracks previously-received message IDs.
        #
        # Duplicate messages are silently dropped; IHAVE for seen IDs
        # does not trigger an IWANT response.
        for message_id_hex in self.initial_state.seen_message_ids:
            behavior.seen_cache.add(MessageId(from_hex(message_id_hex)), Timestamp(self.now))

        # Message cache holds full message payloads for IWANT responses.
        #
        # When a peer requests a message via IWANT, the handler looks it up
        # here and sends the payload back.
        for cached_message in self.initial_state.cached_messages:
            message = GossipsubMessage(
                topic=cached_message.topic.encode("utf-8"),
                raw_data=from_hex(cached_message.data),
            )
            message._cached_id = MessageId(from_hex(cached_message.message_id))
            behavior.message_cache.put(TopicId(cached_message.topic), message)

        # Build the incoming RPC from the event.
        from_peer = _peer_id(self.event.from_peer)
        peer_names.setdefault(from_peer, self.event.from_peer)

        # Fix the clock so backoff and TTL checks are deterministic.
        with patch("time.time", return_value=self.now):
            await behavior._handle_rpc(from_peer, self.event.build_rpc())

        # Convert captured outbound RPCs to typed expectation entries.
        #
        # Each entry represents one RPC sent to a peer.
        # The structure mirrors the gossipsub RPC wire format.
        # Fixture consumers use this to assert exact outbound behavior.
        # Emit outbound RPCs in canonical recipient order.
        # The send order to mesh peers is set-driven.
        # It is not consensus-relevant.
        # Sorting by recipient keeps the emitted vector reproducible across runs.
        sent_rpcs = []
        for recipient_peer_id, rpc in sorted(
            capture.sent, key=lambda entry: peer_names.get(entry[0], str(entry[0]))
        ):
            subscriptions = (
                [
                    SentSubscription(
                        subscribe=subscription.subscribe, topic_id=str(subscription.topic_id)
                    )
                    for subscription in rpc.subscriptions
                ]
                if rpc.subscriptions
                else None
            )

            publish = (
                [
                    SentPublish(topic=str(message.topic), data=to_hex(message.data))
                    for message in rpc.publish
                ]
                if rpc.publish
                else None
            )

            # Only include control fields that carry sub-messages.
            control = None
            if rpc.control and not rpc.control.is_empty():
                control = SentControl(
                    graft=(
                        [SentGraft(topic_id=str(graft.topic_id)) for graft in rpc.control.graft]
                        if rpc.control.graft
                        else None
                    ),
                    prune=(
                        [
                            SentPrune(topic_id=str(prune.topic_id), backoff=prune.backoff)
                            for prune in rpc.control.prune
                        ]
                        if rpc.control.prune
                        else None
                    ),
                    iwant=(
                        [
                            SentMessageIdentifiers(
                                message_ids=[to_hex(message_id) for message_id in iwant.message_ids]
                            )
                            for iwant in rpc.control.iwant
                        ]
                        if rpc.control.iwant
                        else None
                    ),
                    idontwant=(
                        [
                            SentMessageIdentifiers(
                                message_ids=[
                                    to_hex(message_id) for message_id in idontwant.message_ids
                                ]
                            )
                            for idontwant in rpc.control.idontwant
                        ]
                        if rpc.control.idontwant
                        else None
                    ),
                )

            sent_rpcs.append(
                SentRpc(
                    to_peer=peer_names.get(recipient_peer_id, str(recipient_peer_id)),
                    subscriptions=subscriptions,
                    publish=publish,
                    control=control,
                )
            )

        # Snapshot the mesh topology after handler execution.
        # Sorting ensures deterministic output for fixture comparison.
        mesh_after = {
            str(topic): sorted(
                peer_names.get(peer_id, str(peer_id))
                for peer_id in behavior.mesh.get_mesh_peers(topic)
            )
            for topic in behavior.mesh.subscriptions
        }

        return GossipsubExpectation(sent_rpcs=sent_rpcs, mesh_after=mesh_after)
