"""Test network orchestrator for multi-node gossipsub integration tests.

Manages node lifecycle and provides common topologies (full mesh, star,
chain, ring) so individual tests focus on protocol behavior, not setup.
"""

from __future__ import annotations

import asyncio

from lean_spec.node.networking.gossipsub.parameters import GossipsubParameters
from lean_spec.node.networking.gossipsub.types import TopicId

from .node import GossipsubTestNode

# PeerId uses Base58 encoding, which excludes 0, O, I, and l to prevent
# visual ambiguity. These names use only characters in the Base58 alphabet.
PEER_NAMES = [
    "peerA",
    "peerB",
    "peerC",
    "peerD",
    "peerE",
    "peerF",
    "peerG",
    "peerH",
    "peerJ",
    "peerK",
    "peerM",
    "peerN",
    "peerQ",
    "peerR",
    "peerS",
    "peerT",
    "peerU",
    "peerV",
    "peerW",
    "peerX",
    "peerY",
    "peerZ",
    "peer1",
    "peer2",
    "peer3",
    "peer4",
    "peer5",
    "peer6",
    "peer7",
    "peer8",
]
"""Base58-valid peer names (avoids 0, O, I, l)."""


class GossipsubTestNetwork:
    """Manages a network of gossipsub test nodes.

    Provides topology creation helpers (full mesh, star, chain, ring)
    and lifecycle management for all nodes.
    """

    def __init__(self) -> None:
        self.nodes: list[GossipsubTestNode] = []

    async def create_nodes(
        self, count: int, params: GossipsubParameters | None = None
    ) -> list[GossipsubTestNode]:
        """Create and return `count` new test nodes."""
        start = len(self.nodes)
        new_nodes = []
        for i in range(count):
            name = PEER_NAMES[start + i]
            node = GossipsubTestNode.create(name, params)
            self.nodes.append(node)
            new_nodes.append(node)
        return new_nodes

    async def start_all(self) -> None:
        """Start all nodes."""
        for node in self.nodes:
            await node.start()

    async def stop_all(self) -> None:
        """Stop all nodes."""
        for node in self.nodes:
            await node.stop()

    async def connect_full(self) -> None:
        """Connect all nodes in a full mesh topology.

        Every node can reach every other node directly.
        Useful for testing gossip with maximum connectivity.
        """
        for i, node_a in enumerate(self.nodes):
            for node_b in self.nodes[i + 1 :]:
                await node_a.connect_to(node_b)

    async def connect_chain(self) -> None:
        """Connect nodes in a linear chain: 0-1-2-...-N.

        Messages must hop through intermediaries. Tests multi-hop
        gossip propagation and relay behavior.
        """
        for i in range(len(self.nodes) - 1):
            await self.nodes[i].connect_to(self.nodes[i + 1])

    async def connect_ring(self) -> None:
        """Connect nodes in a ring: 0-1-2-...-N-0.

        Like a chain but with redundant path between endpoints.
        Tests that duplicate suppression works across alternate routes.
        """
        await self.connect_chain()
        if len(self.nodes) > 2:
            await self.nodes[-1].connect_to(self.nodes[0])

    async def subscribe_all(self, topic: TopicId) -> None:
        """Subscribe all nodes to a topic."""
        for node in self.nodes:
            node.subscribe(topic)
        # Let subscription broadcasts propagate.
        await asyncio.sleep(0.05)

    async def trigger_all_heartbeats(self) -> None:
        """Trigger one heartbeat on all nodes."""
        for node in self.nodes:
            await node.trigger_heartbeat()
        await asyncio.sleep(0.05)

    async def stabilize_mesh(self, topic: str, rounds: int = 3, settle_time: float = 0.05) -> None:
        """Run multiple heartbeat rounds to let meshes converge.

        One heartbeat is rarely enough. Each round lets nodes exchange
        GRAFT/PRUNE control messages and react to peer changes. Three
        rounds is typically sufficient for small test networks.
        """
        for _ in range(rounds):
            await self.trigger_all_heartbeats()
            await asyncio.sleep(settle_time)
