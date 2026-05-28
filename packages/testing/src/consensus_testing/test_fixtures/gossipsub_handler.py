"""
Gossipsub handler test fixture for protocol behavior conformance.

Generates JSON test vectors that assert gossipsub protocol decisions.
Each vector captures an initial peer/mesh/cache state, an incoming RPC event,
and the expected outbound RPCs plus resulting mesh topology.

The fixture tests protocol logic only, not wire encoding or I/O.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, ClassVar
from unittest.mock import patch

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

from .base import BaseConsensusFixture

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


def _unhex(hex_str: str) -> bytes:
    """Decode a 0x-prefixed hex string to bytes."""
    return bytes.fromhex(hex_str.removeprefix("0x"))


def _serialize_rpcs(
    sent: list[tuple[PeerId, RPC]], peer_names: dict[PeerId, str]
) -> list[dict[str, Any]]:
    """
    Convert captured outbound RPCs to JSON-friendly dicts.

    Each entry in the output list represents one RPC sent to a peer.
    The structure mirrors the gossipsub RPC wire format:

    - toPeer: human-readable peer name
    - subscriptions: topic subscribe/unsubscribe changes (if any)
    - publish: forwarded messages with hex-encoded data (if any)
    - control: GRAFT, PRUNE, IWANT, IDONTWANT sub-messages (if any)

    Fixture consumers use this to assert exact outbound behavior.
    """
    result = []
    for pid, rpc in sent:
        name = peer_names.get(pid, str(pid))
        entry: dict[str, Any] = {"toPeer": name}

        if rpc.subscriptions:
            entry["subscriptions"] = [
                {"subscribe": s.subscribe, "topicId": str(s.topic_id)} for s in rpc.subscriptions
            ]

        if rpc.publish:
            entry["publish"] = [
                {"topic": str(m.topic), "data": "0x" + m.data.hex()} for m in rpc.publish
            ]

        # Only include control fields that carry sub-messages.
        if rpc.control and not rpc.control.is_empty():
            ctrl: dict[str, Any] = {}
            if rpc.control.graft:
                ctrl["graft"] = [{"topicId": str(g.topic_id)} for g in rpc.control.graft]
            if rpc.control.prune:
                ctrl["prune"] = [
                    {"topicId": str(p.topic_id), "backoff": p.backoff} for p in rpc.control.prune
                ]
            if rpc.control.iwant:
                ctrl["iwant"] = [
                    {"messageIds": ["0x" + mid.hex() for mid in w.message_ids]}
                    for w in rpc.control.iwant
                ]
            if rpc.control.idontwant:
                ctrl["idontwant"] = [
                    {"messageIds": ["0x" + mid.hex() for mid in d.message_ids]}
                    for d in rpc.control.idontwant
                ]
            entry["control"] = ctrl

        result.append(entry)
    return result


def _serialize_meshes(
    behavior: GossipsubBehavior, peer_names: dict[PeerId, str]
) -> dict[str, list[str]]:
    """
    Snapshot the mesh topology after handler execution.

    Returns a dict mapping each topic to a sorted list of peer names.
    Sorting ensures deterministic output for fixture comparison.
    """
    return {
        str(topic): sorted(peer_names.get(p, str(p)) for p in behavior.mesh.get_mesh_peers(topic))
        for topic in behavior.mesh.subscriptions
    }


class GossipsubHandlerTest(BaseConsensusFixture):
    """Fixture for gossipsub handler behavior conformance.

    Tests protocol decisions: given initial state + incoming event,
    what RPCs are sent and how does the mesh change?

    JSON output: params, initialState, event, now, expected.
    """

    format_name: ClassVar[str] = "gossipsub_handler"
    description: ClassVar[str] = "Tests gossipsub handler protocol decisions"

    handler_name: str
    """Handler being tested: graft, prune, ihave, iwant, message."""

    params: dict[str, int]
    """Gossipsub parameters: d, dLow, dHigh, dLazy."""

    initial_state: dict[str, Any]
    """Initial behavior state: subscriptions, meshes, peers, caches."""

    event: dict[str, Any]
    """Incoming event: fromPeer + RPC content."""

    now: float = 1000.0
    """Current timestamp for backoff checks."""

    expected: dict[str, Any] = {}
    """Expected output. Filled by make_fixture."""

    def make_fixture(self) -> "GossipsubHandlerTest":
        """Produce the completed fixture with expected outputs filled in."""
        self.expected = asyncio.run(self._execute())
        return self

    async def _execute(self) -> dict[str, Any]:
        """
        Run the handler against a fully-configured behavior instance.

        Builds the gossipsub behavior from fixture inputs, dispatches the
        incoming RPC, and returns the outbound RPCs and final mesh state.
        """
        gs_params = GossipsubParameters(
            d=self.params.get("d", 8),
            d_low=self.params.get("dLow", 6),
            d_high=self.params.get("dHigh", 12),
            d_lazy=self.params.get("dLazy", 6),
        )
        behavior = GossipsubBehavior(params=gs_params)

        # Intercept outbound RPCs instead of sending them over the network.
        capture = _SendCapture()
        behavior._send_rpc = capture  # type: ignore[assignment]

        # Map between human-readable test names and opaque peer identifiers.
        peer_names: dict[PeerId, str] = {}

        # Subscriptions define which topics the local node participates in.
        #
        # Handlers ignore messages for topics we are not subscribed to.
        for topic in self.initial_state.get("subscriptions", []):
            behavior.mesh.subscribe(TopicId(topic))

        # Register each peer with its subscriptions and protocol state.
        #
        # Peer properties like backoff timers and IDONTWANT sets directly
        # influence handler decisions (e.g., reject GRAFTs, skip forwarding).
        for name, info in self.initial_state.get("peers", {}).items():
            pid = _peer_id(name)
            peer_names[pid] = name
            state = PeerState(
                peer_id=pid,
                subscriptions={TopicId(t) for t in info.get("subscriptions", [])},
                outbound_stream=_FAKE_STREAM if info.get("withStream", True) else None,
            )

            # Backoff prevents re-GRAFTing a recently-pruned peer.
            for topic_str, expiry in info.get("backoff", {}).items():
                state.backoff[TopicId(topic_str)] = expiry

            # IDONTWANT suppresses forwarding to peers that already have the message.
            for mid_hex in info.get("dontWantIds", []):
                state.dont_want_ids.add(MessageId(_unhex(mid_hex)))
            behavior._peers[pid] = state

        # Mesh topology determines who receives forwarded messages.
        #
        # Handlers check mesh membership for GRAFT acceptance, PRUNE removal,
        # and message forwarding decisions.
        for topic_str, peer_list in self.initial_state.get("meshes", {}).items():
            topic = TopicId(topic_str)
            for name in peer_list:
                behavior.mesh.add_to_mesh(topic, _peer_id(name))

        # Seen cache tracks previously-received message IDs.
        #
        # Duplicate messages are silently dropped; IHAVE for seen IDs
        # does not trigger an IWANT response.
        for mid_hex in self.initial_state.get("seenMessageIds", []):
            behavior.seen_cache.add(MessageId(_unhex(mid_hex)), Timestamp(self.now))

        # Message cache holds full message payloads for IWANT responses.
        #
        # When a peer requests a message via IWANT, the handler looks it up
        # here and sends the payload back.
        for entry in self.initial_state.get("cachedMessages", []):
            msg = GossipsubMessage(
                topic=entry["topic"].encode("utf-8"),
                raw_data=_unhex(entry["data"]),
            )
            msg._cached_id = MessageId(_unhex(entry["messageId"]))
            behavior.message_cache.put(TopicId(entry["topic"]), msg)

        # Build the incoming RPC from the event.
        from_peer = _peer_id(self.event["fromPeer"])
        peer_names.setdefault(from_peer, self.event["fromPeer"])

        # Fix the clock so backoff and TTL checks are deterministic.
        with patch("time.time", return_value=self.now):
            await behavior._handle_rpc(from_peer, _build_event_rpc(self.event))

        return {
            "sentRpcs": _serialize_rpcs(capture.sent, peer_names),
            "meshAfter": _serialize_meshes(behavior, peer_names),
        }


def _build_event_rpc(event: dict[str, Any]) -> RPC:
    """
    Construct an RPC from the event dict supplied by the test fixture.

    The event dict describes one incoming message from a peer.
    Required key:

    - fromPeer: short name of the sending peer

    Optional keys (include one or more to build the RPC):

    - graft: list of dicts with topicId
    - prune: list of dicts with topicId and optional backoff
    - ihave: list of dicts with topicId and hex messageIds
    - iwant: list of dicts with hex messageIds
    - idontwant: list of dicts with hex messageIds
    - publish: list of dicts with topic and hex data
    """
    control_parts: dict[str, list[Any]] = {}

    if "graft" in event:
        control_parts["graft"] = [
            ControlGraft(topic_id=TopicId(g["topicId"])) for g in event["graft"]
        ]
    if "prune" in event:
        control_parts["prune"] = [
            ControlPrune(topic_id=TopicId(p["topicId"]), backoff=p.get("backoff", 0))
            for p in event["prune"]
        ]
    if "ihave" in event:
        control_parts["ihave"] = [
            ControlIHave(
                topic_id=TopicId(ih["topicId"]),
                message_ids=[_unhex(m) for m in ih.get("messageIds", [])],
            )
            for ih in event["ihave"]
        ]
    if "iwant" in event:
        control_parts["iwant"] = [
            ControlIWant(message_ids=[_unhex(m) for m in iw.get("messageIds", [])])
            for iw in event["iwant"]
        ]
    if "idontwant" in event:
        control_parts["idontwant"] = [
            ControlIDontWant(message_ids=[_unhex(m) for m in idw.get("messageIds", [])])
            for idw in event["idontwant"]
        ]

    return RPC(
        publish=[
            Message(
                topic=TopicId(m.get("topic", "")),
                data=_unhex(m["data"]) if m.get("data") else b"",
            )
            for m in event.get("publish", [])
        ],
        control=ControlMessage(**control_parts) if control_parts else None,
    )
