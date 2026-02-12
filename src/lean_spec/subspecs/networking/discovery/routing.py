"""
Discovery v5 Routing Table

Kademlia-style routing table for Node Discovery Protocol v5.1.

Node Table Structure

Nodes keep information about other nodes in their neighborhood. Neighbor nodes
are stored in a routing table consisting of 'k-buckets'. For each 0 <= i < 256,
every node keeps a k-bucket for nodes of logdistance(self, n) == i.

The protocol uses k = 16, meaning every k-bucket contains up to 16 node entries.
Entries are sorted by time last seen: least-recently seen at head, most-recently
seen at tail.

Distance Metric

The 'distance' between two node IDs is the bitwise XOR of the IDs, interpreted
as a big-endian number:

    distance(n1, n2) = n1 XOR n2

The logarithmic distance (length of differing suffix in bits) is used for
bucket assignment:

    logdistance(n1, n2) = log2(distance(n1, n2))

Bucket Eviction Policy

When a new node N1 is encountered, it can be inserted into the corresponding
bucket.

- If the bucket contains less than k entries, N1 is simply added.

- If the bucket already contains k entries, the liveness of the least recently seen
node N2 must be revalidated. If no reply is received from N2, it is considered dead,
removed, and N1 added to the front of the bucket.

Liveness Verification

Implementations should perform liveness checks asynchronously and occasionally
verify that a random node in a random bucket is live by sending PING. When
responding to FINDNODE, implementations must avoid relaying any nodes whose
liveness has not been verified.

References:
    - https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md
    - Maymounkov & Mazieres, "Kademlia: A Peer-to-peer Information System", 2002
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from lean_spec.subspecs.networking.enr import ENR
from lean_spec.subspecs.networking.types import ForkDigest, NodeId, SeqNumber

from .config import BUCKET_COUNT, K_BUCKET_SIZE
from .messages import Distance


def xor_distance(a: NodeId, b: NodeId) -> int:
    """
    Compute XOR distance between two node IDs.

    XOR distance is the fundamental metric in Kademlia networks:

        distance(n1, n2) = n1 XOR n2

    Properties:
        - Symmetric: d(a, b) == d(b, a)
        - Identity: d(a, a) == 0
        - Triangle inequality: d(a, c) <= d(a, b) XOR d(b, c)

    Args:
        a: First 32-byte node ID.
        b: Second 32-byte node ID.

    Returns:
        XOR of the two IDs as a big-endian integer (0 to 2^256 - 1).
    """
    return int.from_bytes(a, "big") ^ int.from_bytes(b, "big")


def log2_distance(a: NodeId, b: NodeId) -> Distance:
    """
    Compute log2 of XOR distance between two node IDs.

    Determines which k-bucket a node belongs to:

        logdistance(n1, n2) = log2(distance(n1, n2))

    Equivalent to the bit position of the highest differing bit.
    Used for bucket assignment in the routing table.

    Args:
        a: First 32-byte node ID.
        b: Second 32-byte node ID.

    Returns:
        Log2 distance (0-256). Returns 0 for identical IDs.
    """
    distance = xor_distance(a, b)
    if distance == 0:
        return Distance(0)
    return Distance(distance.bit_length())


@dataclass(slots=True)
class NodeEntry:
    """
    Entry in the routing table representing a discovered node.

    Tracks node identity and liveness information for routing decisions.
    Nodes should only be relayed in FINDNODE responses if verified is True.
    """

    node_id: NodeId
    """32-byte node identifier derived from keccak256(pubkey)."""

    enr_seq: SeqNumber = field(default_factory=lambda: SeqNumber(0))
    """Last known ENR sequence number. Used to detect stale records."""

    last_seen: float = 0.0
    """Unix timestamp of last successful contact."""

    endpoint: str | None = None
    """Network endpoint in 'ip:port' format."""

    verified: bool = False
    """True if node has responded to at least one PING. Required for relay."""

    enr: ENR | None = None
    """Full ENR record. Contains fork data for compatibility checks."""


@dataclass(slots=True)
class KBucket:
    """
    K-bucket holding nodes at a specific log2 distance range.

    Implements Kademlia's bucket semantics per the Discovery v5 spec:
    - Fixed capacity of k = 16 nodes
    - Least-recently seen at head, most-recently seen at tail
    - New nodes added to tail, eviction candidates at head

    Eviction Policy

    When full, ping the head node (least-recently seen).
    - If it responds, keep it and discard the new node.
    - If it fails, evict it and add the new node.

    Replacement Cache

    Implementations should maintain a 'replacement cache' alongside each bucket.
    This cache holds recently-seen nodes which would fall into the corresponding
    bucket but cannot become a member because it is at capacity. Once a bucket
    member becomes unresponsive, a replacement can be chosen from the cache.
    """

    nodes: list[NodeEntry] = field(default_factory=list)
    """Ordered list of node entries. Head = oldest, tail = newest."""

    @property
    def is_full(self) -> bool:
        """True if bucket has reached k = 16 capacity."""
        return len(self.nodes) >= K_BUCKET_SIZE

    @property
    def is_empty(self) -> bool:
        """True if bucket contains no nodes."""
        return len(self.nodes) == 0

    def __len__(self) -> int:
        """Number of nodes in this bucket."""
        return len(self.nodes)

    def __iter__(self) -> Iterator[NodeEntry]:
        """Iterate over nodes from oldest to newest."""
        return iter(self.nodes)

    def contains(self, node_id: NodeId) -> bool:
        """Check if node ID exists in this bucket."""
        return any(entry.node_id == node_id for entry in self.nodes)

    def get(self, node_id: NodeId) -> NodeEntry | None:
        """Retrieve node entry by ID. Returns None if not found."""
        for entry in self.nodes:
            if entry.node_id == node_id:
                return entry
        return None

    def add(self, entry: NodeEntry) -> bool:
        """
        Add or update a node in the bucket.

        - If the node exists, moves it to the tail (most recent).
        - If the bucket is full, returns False without adding.

        Note: Caller should implement eviction by pinging the head node
        when this returns False.

        Args:
            entry: Node entry to add.

        Returns:
            - True if node was added or updated,
            - False if bucket is full.
        """
        for i, existing in enumerate(self.nodes):
            if existing.node_id == entry.node_id:
                self.nodes.pop(i)
                self.nodes.append(entry)
                return True

        if self.is_full:
            return False

        self.nodes.append(entry)
        return True

    def remove(self, node_id: NodeId) -> bool:
        """
        Remove a node from the bucket.

        Args:
            node_id: 32-byte node ID to remove.

        Returns:
            - True if node was removed,
            - False if not found.
        """
        for i, entry in enumerate(self.nodes):
            if entry.node_id == node_id:
                self.nodes.pop(i)
                return True
        return False

    def head(self) -> NodeEntry | None:
        """Get least-recently seen node (eviction candidate)."""
        return self.nodes[0] if self.nodes else None

    def tail(self) -> NodeEntry | None:
        """Get most-recently seen node."""
        return self.nodes[-1] if self.nodes else None


@dataclass(slots=True)
class RoutingTable:
    """
    Kademlia routing table for Discovery v5.

    Organizes nodes into 256 k-buckets by XOR distance.
    Bucket i contains nodes with log2(distance) == i + 1.

    Fork Filtering

    When local_fork_digest is set:

    - Only peers with matching fork_digest are accepted
    - Prevents storing peers on incompatible forks
    - Requires eth2 ENR data to be present

    Lookup Algorithm

    Locates the k closest nodes to a target ID:

    1. Pick alpha (3) closest nodes from local table
    2. Send FINDNODE to each
    3. Add responses to routing table
    4. Repeat with next closest unqueried nodes
    5. Stop when k closest have been queried

    Table Maintenance

    - Track close neighbors
    - Regularly refresh stale buckets
    - Perform lookup for least-recently-refreshed bucket
    """

    local_id: NodeId
    """This node's 32-byte identifier derived from keccak256(pubkey)."""

    buckets: list[KBucket] = field(default_factory=lambda: [KBucket() for _ in range(BUCKET_COUNT)])
    """256 k-buckets indexed by log2 distance minus one."""

    local_fork_digest: ForkDigest | None = None
    """Our fork_digest for filtering incompatible peers. None disables filtering."""

    def bucket_index(self, node_id: NodeId) -> int:
        """
        Get bucket index for a node ID.

        Bucket i contains nodes with log2(distance) == i + 1.

        Args:
            node_id: 32-byte node ID to look up.

        Returns:
            Bucket index (0-255).
        """
        distance = log2_distance(self.local_id, node_id)
        return max(0, int(distance) - 1)

    def get_bucket(self, node_id: NodeId) -> KBucket:
        """Get the k-bucket containing nodes at this distance."""
        return self.buckets[self.bucket_index(node_id)]

    def is_fork_compatible(self, entry: NodeEntry) -> bool:
        """
        Check if a node entry is fork-compatible.

        If local_fork_digest is set, the entry must have an ENR with
        eth2 data containing the same fork_digest.

        Args:
            entry: Node entry to check.

        Returns:
            - True if compatible or filtering disabled,
            - False if fork_digest mismatch or missing eth2 data.
        """
        if self.local_fork_digest is None:
            return True

        if entry.enr is None:
            return False

        eth2_data = entry.enr.eth2_data
        if eth2_data is None:
            return False

        return eth2_data.fork_digest == self.local_fork_digest

    def add(self, entry: NodeEntry) -> bool:
        """
        Add a node to the routing table.

        Rejects nodes that are on incompatible forks when fork filtering
        is enabled (local_fork_digest is set).

        Args:
            entry: Node entry to add.

        Returns:
            - True if added/updated,
            - False if bucket full, adding self, or fork incompatible.
        """
        if entry.node_id == self.local_id:
            return False

        if not self.is_fork_compatible(entry):
            return False

        return self.get_bucket(entry.node_id).add(entry)

    def remove(self, node_id: NodeId) -> bool:
        """Remove a node from the routing table."""
        return self.get_bucket(node_id).remove(node_id)

    def get(self, node_id: NodeId) -> NodeEntry | None:
        """Get a node entry by ID. Returns None if not found."""
        return self.get_bucket(node_id).get(node_id)

    def contains(self, node_id: NodeId) -> bool:
        """Check if a node ID exists in the routing table."""
        return self.get(node_id) is not None

    def node_count(self) -> int:
        """Total number of nodes across all buckets."""
        return sum(len(bucket) for bucket in self.buckets)

    def closest_nodes(self, target: NodeId, count: int) -> list[NodeEntry]:
        """
        Find the closest nodes to a target ID.

        Used during Kademlia lookup to iteratively approach the target.
        The lookup initiator picks alpha closest nodes and sends FINDNODE
        requests, progressively querying closer nodes.

        Args:
            target: Target 32-byte node ID.
            count: Maximum nodes to return (typically k = 16).

        Returns:
            Nodes sorted by XOR distance to target, closest first.
        """
        all_nodes = [entry for bucket in self.buckets for entry in bucket]
        all_nodes.sort(key=lambda e: xor_distance(e.node_id, target))
        return all_nodes[:count]

    def nodes_at_distance(self, distance: Distance) -> list[NodeEntry]:
        """
        Get all nodes at a specific log2 distance.

        Used to respond to FINDNODE requests. The recipient returns nodes
        from its routing table at the requested distance.

        Args:
            distance: Log2 distance (1-256). Distance 0 returns own ENR.

        Returns:
            List of nodes at the specified distance.
        """
        dist_int = int(distance)
        if dist_int < 1 or dist_int > BUCKET_COUNT:
            return []
        return list(self.buckets[dist_int - 1])
