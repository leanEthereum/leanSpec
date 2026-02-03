"""
Discovery v5 service.

Main entry point for peer discovery over UDP.

Service Responsibilities:
- Bootstrap from known bootnodes
- Maintain routing table with discovered peers
- Perform periodic lookups to find new peers
- Handle incoming discovery requests
- Provide peers to higher-layer protocols

Lookup Algorithm:
1. Start with alpha closest nodes from routing table
2. Send FINDNODE to each, collecting responses
3. Add newly discovered nodes to routing table
4. Repeat with next closest unqueried nodes
5. Stop when k closest nodes have been queried

References:
- https://github.com/ethereum/devp2p/blob/master/discv5/discv5-theory.md
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from lean_spec.subspecs.networking.types import NodeId, SeqNumber
from lean_spec.types.uint import Uint8

from .codec import DiscoveryMessage
from .config import ALPHA, K_BUCKET_SIZE, DiscoveryConfig
from .keys import compute_node_id
from .messages import Distance, FindNode, Nodes, Ping, Pong, Port, TalkReq, TalkResp
from .routing import NodeEntry, RoutingTable, log2_distance
from .session import BondCache
from .transport import DiscoveryTransport

if TYPE_CHECKING:
    from lean_spec.subspecs.networking.enr import ENR

logger = logging.getLogger(__name__)

LOOKUP_PARALLELISM = ALPHA
"""Number of concurrent FINDNODE queries during lookup."""

REFRESH_INTERVAL_SECS = 3600
"""Interval between routing table refresh lookups (1 hour)."""

REVALIDATION_INTERVAL_SECS = 300
"""Interval between node liveness revalidation (5 minutes)."""


@dataclass
class LookupResult:
    """Result of a node lookup operation."""

    target: bytes
    """Target node ID that was searched for."""

    nodes: list[NodeEntry]
    """Nodes found, sorted by distance to target."""

    queried: int
    """Number of nodes queried during lookup."""


class DiscoveryService:
    """
    Main Discovery v5 service.

    Provides high-level peer discovery functionality:
    - find_node(): Lookup nodes close to a target ID
    - get_random_nodes(): Get random peers from routing table
    - get_peers_for_subnet(): Find peers for specific subnets

    The service runs background tasks for:
    - Table refresh (periodic lookups)
    - Node revalidation (PING liveness checks)
    - Session cleanup
    """

    def __init__(
        self,
        local_enr: ENR,
        private_key: bytes,
        config: DiscoveryConfig | None = None,
        bootnodes: list[ENR] | None = None,
    ):
        """
        Initialize the discovery service.

        Args:
            local_enr: Our ENR.
            private_key: Our 32-byte secp256k1 private key.
            config: Optional protocol configuration.
            bootnodes: Initial nodes to connect to.
        """
        self._local_enr = local_enr
        self._private_key = private_key
        self._config = config or DiscoveryConfig()
        self._bootnodes = bootnodes or []

        # Compute our node ID from public key.
        if local_enr.public_key is None:
            raise ValueError("Local ENR must have a public key")
        self._local_node_id = bytes(compute_node_id(bytes(local_enr.public_key)))

        # Initialize routing table.
        self._routing_table = RoutingTable(local_id=NodeId(self._local_node_id))

        # Initialize transport.
        self._transport = DiscoveryTransport(
            local_node_id=self._local_node_id,
            local_private_key=private_key,
            local_enr=local_enr,
            config=self._config,
        )

        # Bond tracking.
        self._bond_cache = BondCache()

        # ENR cache for known nodes.
        self._enr_cache: dict[bytes, ENR] = {}

        # Background tasks.
        self._tasks: list[asyncio.Task] = []
        self._running = False

        # TALKREQ handlers by protocol.
        self._talk_handlers: dict[bytes, Callable[[bytes, bytes], bytes]] = {}

        # Set up message handler.
        self._transport.set_message_handler(self._handle_message)

    async def start(self, host: str = "0.0.0.0", port: int = 9000) -> None:
        """
        Start the discovery service.

        Args:
            host: IP address to bind to.
            port: UDP port to bind to.
        """
        if self._running:
            return

        # Start transport.
        await self._transport.start(host, port)
        self._running = True

        # Bootstrap from bootnodes.
        await self._bootstrap()

        # Start background tasks.
        self._tasks.append(asyncio.create_task(self._refresh_loop()))
        self._tasks.append(asyncio.create_task(self._revalidation_loop()))
        self._tasks.append(asyncio.create_task(self._cleanup_loop()))

        logger.info(
            "Discovery service started on %s:%d with node ID %s",
            host,
            port,
            self._local_node_id.hex()[:16],
        )

    async def stop(self) -> None:
        """Stop the discovery service."""
        if not self._running:
            return

        self._running = False

        # Cancel background tasks.
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()

        # Stop transport.
        await self._transport.stop()

        logger.info("Discovery service stopped")

    async def find_node(self, target: bytes) -> LookupResult:
        """
        Perform a Kademlia lookup for a target node ID.

        Iteratively queries nodes progressively closer to the target.

        Args:
            target: 32-byte target node ID.

        Returns:
            LookupResult with found nodes sorted by distance.
        """
        if len(target) != 32:
            raise ValueError(f"Target must be 32 bytes, got {len(target)}")

        # Start with closest known nodes.
        target_id = NodeId(target)
        closest = self._routing_table.closest_nodes(target_id, K_BUCKET_SIZE)
        if not closest:
            return LookupResult(target=target, nodes=[], queried=0)

        queried: set[bytes] = set()
        seen: dict[bytes, NodeEntry] = {entry.node_id: entry for entry in closest}

        while True:
            # Find unqueried nodes closest to target.
            candidates = sorted(
                [e for e in seen.values() if e.node_id not in queried],
                key=lambda e: log2_distance(e.node_id, target_id),
            )[:LOOKUP_PARALLELISM]

            if not candidates:
                break

            # Query candidates in parallel.
            tasks = []
            for entry in candidates:
                queried.add(entry.node_id)
                addr = self._transport.get_node_address(entry.node_id)
                if addr is not None:
                    tasks.append(self._query_node(entry.node_id, addr, target))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, list):
                        for enr_bytes in result:
                            # Parse ENR from RLP and add to routing table.
                            self._process_discovered_enr(enr_bytes, seen)

        # Sort by distance to target.
        result_nodes = sorted(
            seen.values(),
            key=lambda e: log2_distance(e.node_id, NodeId(target)),
        )[:K_BUCKET_SIZE]

        return LookupResult(
            target=target,
            nodes=result_nodes,
            queried=len(queried),
        )

    def get_random_nodes(self, count: int = K_BUCKET_SIZE) -> list[NodeEntry]:
        """
        Get random nodes from the routing table.

        Useful for providing peers to connection manager.

        Args:
            count: Maximum nodes to return.

        Returns:
            List of random node entries.
        """
        all_nodes = []
        for bucket in self._routing_table.buckets:
            all_nodes.extend(bucket.nodes)

        if len(all_nodes) <= count:
            return all_nodes

        return random.sample(all_nodes, count)

    def get_nodes_at_distance(self, distance: int) -> list[NodeEntry]:
        """
        Get nodes at a specific log2 distance.

        Args:
            distance: Log2 distance (1-256).

        Returns:
            Nodes at that distance from our node ID.
        """
        return self._routing_table.nodes_at_distance(Distance(distance))

    def node_count(self) -> int:
        """Return total number of nodes in routing table."""
        return self._routing_table.node_count()

    def register_talk_handler(
        self,
        protocol: bytes,
        handler: Callable[[bytes, bytes], bytes],
    ) -> None:
        """
        Register a handler for TALKREQ messages.

        Args:
            protocol: Protocol identifier (e.g., b"eth2").
            handler: Function(node_id, request) -> response.
        """
        self._talk_handlers[protocol] = handler

    async def send_talk_request(
        self,
        node_id: bytes,
        protocol: bytes,
        request: bytes,
    ) -> bytes | None:
        """
        Send a TALKREQ to a node.

        Args:
            node_id: 32-byte destination node ID.
            protocol: Protocol identifier.
            request: Protocol-specific request.

        Returns:
            Response payload or None on timeout.
        """
        addr = self._transport.get_node_address(node_id)
        if addr is None:
            return None

        return await self._transport.send_talkreq(node_id, addr, protocol, request)

    async def _bootstrap(self) -> None:
        """Bootstrap from bootnodes."""
        for enr in self._bootnodes:
            try:
                node_id = enr.compute_node_id()
                if node_id is None:
                    continue

                # Register address and ENR.
                #
                # The transport needs the ENR to complete handshakes.
                # When we PING and receive WHOAREYOU, the transport looks up
                # the remote's public key from its ENR cache.
                if enr.ip4 and enr.udp_port:
                    addr = (enr.ip4, int(enr.udp_port))
                    self._transport.register_node_address(node_id, addr)
                    self._transport.register_enr(node_id, enr)
                    self._enr_cache[node_id] = enr

                    # Add to routing table.
                    entry = self._enr_to_entry(enr)
                    self._routing_table.add(entry)

                    # Ping to establish bond.
                    asyncio.create_task(self._ping_node(node_id, addr))

            except Exception as e:
                logger.debug("Failed to add bootnode: %s", e)

    async def _query_node(
        self,
        node_id: bytes,
        addr: tuple[str, int],
        target: bytes,
    ) -> list[bytes]:
        """Query a node for nodes close to target."""
        distance = int(log2_distance(NodeId(node_id), NodeId(target)))
        distances = [distance] if distance > 0 else [1, 2, 3]

        return await self._transport.send_findnode(node_id, addr, distances)

    async def _ping_node(self, node_id: bytes, addr: tuple[str, int]) -> bool:
        """Ping a node and update bond status."""
        pong = await self._transport.send_ping(node_id, addr)
        if pong is not None:
            self._bond_cache.add_bond(node_id)
            return True
        return False

    def _handle_message(
        self,
        remote_node_id: bytes,
        message: DiscoveryMessage,
        addr: tuple[str, int],
    ) -> None:
        """Handle an incoming message."""
        # Run handler in background.
        asyncio.create_task(self._process_message(remote_node_id, message, addr))

    async def _process_message(
        self,
        remote_node_id: bytes,
        message: DiscoveryMessage,
        addr: tuple[str, int],
    ) -> None:
        """Process an incoming message."""
        # Update node address.
        self._transport.register_node_address(remote_node_id, addr)

        if isinstance(message, Ping):
            await self._handle_ping(remote_node_id, message, addr)
        elif isinstance(message, FindNode):
            await self._handle_findnode(remote_node_id, message, addr)
        elif isinstance(message, TalkReq):
            await self._handle_talkreq(remote_node_id, message, addr)

    async def _handle_ping(
        self,
        remote_node_id: bytes,
        ping: Ping,
        addr: tuple[str, int],
    ) -> None:
        """
        Respond to a PING with a PONG message.

        PING serves two purposes in Discovery v5:

        1. Liveness check - verifies the node is reachable
        2. ENR exchange - allows nodes to learn each other's current ENR sequence

        The PONG response includes:

        - Our ENR sequence (so they can request updated ENR if needed)
        - Recipient endpoint (so they learn their external IP/port)
        """
        # Build PONG with our ENR sequence and their observed endpoint.
        #
        # The recipient_ip/port tells the sender what address we see them as.
        # This helps nodes behind NAT discover their public endpoint.
        #
        # Per spec, recipient_ip is raw bytes: 4 bytes for IPv4, 16 for IPv6.
        recipient_ip = self._encode_ip_address(addr[0])
        pong = Pong(
            request_id=ping.request_id,
            enr_seq=SeqNumber(self._local_enr.seq),
            recipient_ip=recipient_ip,
            recipient_port=Port(addr[1]),
        )

        # Send the response using the established session.
        sent = await self._transport.send_response(remote_node_id, addr, pong)

        if sent:
            # Successful PONG establishes mutual liveness.
            #
            # The remote proved they can reach us (by sending PING).
            # Our successful response proves we can reach them.
            # Mark them as bonded to allow future FINDNODE queries.
            self._bond_cache.add_bond(remote_node_id)

        logger.debug("Received PING from %s, sent PONG: %s", remote_node_id.hex()[:16], sent)

    async def _handle_findnode(
        self,
        remote_node_id: bytes,
        findnode: FindNode,
        addr: tuple[str, int],
    ) -> None:
        """
        Respond to a FINDNODE with a NODES message.

        FINDNODE is the core lookup operation in Kademlia.
        The requester specifies log2 distances, and we return nodes
        from those buckets in our routing table.

        Security: Only bonded nodes can query our routing table.
        This prevents amplification attacks where an attacker uses
        us to flood a victim with NODES responses.
        """
        # Require prior bonding before sharing routing table.
        #
        # Bonding means we have exchanged PING/PONG.
        # This prevents using our node as a reflector for amplification attacks.
        if not self._bond_cache.is_bonded(remote_node_id):
            logger.debug("FINDNODE from unbonded node %s", remote_node_id.hex()[:16])
            return

        # Collect ENRs from requested distance buckets.
        #
        # Distance 0 is special: it means "return your own ENR".
        # Distances 1-256 correspond to routing table buckets.
        enrs: list[bytes] = []
        for distance in findnode.distances:
            if int(distance) == 0:
                enrs.append(self._local_enr.to_rlp())
            else:
                for entry in self._routing_table.nodes_at_distance(distance):
                    if entry.enr is not None:
                        enrs.append(entry.enr.to_rlp())

        # Limit response size to prevent oversized packets.
        enrs = enrs[: self._config.max_nodes_response]

        # Build NODES response.
        #
        # The 'total' field indicates how many NODES messages to expect.
        # For simplicity, we send all results in one message.
        # Production implementations may split across multiple messages.
        nodes = Nodes(
            request_id=findnode.request_id,
            total=Uint8(1),
            enrs=enrs,
        )

        sent = await self._transport.send_response(remote_node_id, addr, nodes)
        logger.debug(
            "Received FINDNODE from %s for distances %s, sent %d ENRs: %s",
            remote_node_id.hex()[:16],
            [int(d) for d in findnode.distances],
            len(enrs),
            sent,
        )

    async def _handle_talkreq(
        self,
        remote_node_id: bytes,
        talkreq: TalkReq,
        addr: tuple[str, int],
    ) -> None:
        """
        Handle a TALKREQ by delegating to the registered protocol handler.

        TALKREQ enables application-specific protocols over Discovery v5.
        The protocol field identifies which handler should process the request.

        Common protocols built on TALKREQ:

        - Portal Network (state, history, beacon)
        - Light client sync
        - Custom peer-to-peer applications

        Unknown protocols receive an empty response (not an error).
        This allows graceful handling when protocols are not supported.
        """
        # Look up the handler for this protocol.
        handler = self._talk_handlers.get(talkreq.protocol)

        # Dispatch to handler or return empty response.
        #
        # Empty response for unknown protocols is per spec.
        # This avoids revealing which protocols we support
        # while still allowing the requester to complete their flow.
        response_data = b""
        if handler is not None:
            try:
                response_data = handler(remote_node_id, talkreq.request)
            except Exception as e:
                logger.debug("TALKREQ handler error: %s", e)

        # Build and send TALKRESP.
        talkresp = TalkResp(
            request_id=talkreq.request_id,
            response=response_data,
        )

        sent = await self._transport.send_response(remote_node_id, addr, talkresp)
        logger.debug("Received TALKREQ for protocol %s, sent response: %s", talkreq.protocol, sent)

    async def _refresh_loop(self) -> None:
        """Periodically refresh routing table."""
        while self._running:
            await asyncio.sleep(REFRESH_INTERVAL_SECS)
            try:
                # Perform lookup for random target.
                import os

                target = os.urandom(32)
                await self.find_node(target)
            except Exception as e:
                logger.debug("Refresh failed: %s", e)

    async def _revalidation_loop(self) -> None:
        """Periodically revalidate nodes."""
        while self._running:
            await asyncio.sleep(REVALIDATION_INTERVAL_SECS)
            try:
                # Pick a random node to revalidate.
                all_nodes = self.get_random_nodes(1)
                if all_nodes:
                    entry = all_nodes[0]
                    addr = self._transport.get_node_address(entry.node_id)
                    if addr is not None:
                        success = await self._ping_node(entry.node_id, addr)
                        if not success:
                            self._routing_table.remove(entry.node_id)
            except Exception as e:
                logger.debug("Revalidation failed: %s", e)

    async def _cleanup_loop(self) -> None:
        """Periodically clean up expired state."""
        while self._running:
            await asyncio.sleep(60)
            self._bond_cache.cleanup_expired()

    def _encode_ip_address(self, ip_str: str) -> bytes:
        """
        Encode an IP address string to raw bytes.

        Per Discovery v5 spec, IP addresses in PONG are raw bytes:
        - IPv4: 4 bytes
        - IPv6: 16 bytes

        Args:
            ip_str: IP address as dotted string (IPv4) or colon-separated hex (IPv6).

        Returns:
            Raw bytes representation of the IP address.
        """
        import ipaddress

        try:
            # Try IPv4 first.
            addr = ipaddress.ip_address(ip_str)
            return addr.packed
        except ValueError:
            # Fall back to returning as-is if somehow already bytes.
            if isinstance(ip_str, bytes):
                return ip_str
            # Last resort: encode as UTF-8 (shouldn't happen with valid IPs).
            return ip_str.encode()

    def _enr_to_entry(self, enr: ENR) -> NodeEntry:
        """Convert an ENR to a NodeEntry."""
        node_id = enr.compute_node_id()
        if node_id is None:
            raise ValueError("ENR has no valid node ID")

        endpoint = None
        if enr.ip4 and enr.udp_port:
            endpoint = f"{enr.ip4}:{enr.udp_port}"

        return NodeEntry(
            node_id=node_id,
            enr_seq=SeqNumber(enr.seq),
            endpoint=endpoint,
            enr=enr,
        )

    def _process_discovered_enr(
        self,
        enr_bytes: bytes,
        seen: dict[bytes, NodeEntry],
    ) -> None:
        """
        Parse and process a discovered ENR from NODES response.

        Parses the RLP-encoded ENR, validates it, and adds to:
        - The routing table (for future lookups)
        - The seen dict (for current lookup tracking)
        - The ENR cache (for handshake verification)
        - The address registry (for UDP communication)

        Args:
            enr_bytes: RLP-encoded ENR bytes from NODES response.
            seen: Dict tracking nodes seen during current lookup.
        """
        from lean_spec.subspecs.networking.enr import ENR

        try:
            # Parse ENR from RLP.
            enr = ENR.from_rlp(enr_bytes)

            # Validate the ENR has required fields.
            if not enr.is_valid():
                logger.debug("Invalid ENR: missing required fields")
                return

            node_id = enr.compute_node_id()
            if node_id is None:
                logger.debug("ENR has no valid node ID")
                return

            # Skip if this is our own ENR.
            if bytes(node_id) == self._local_node_id:
                return

            # Skip if already seen in this lookup.
            if bytes(node_id) in seen:
                return

            # Create routing table entry.
            entry = self._enr_to_entry(enr)

            # Add to seen dict for lookup tracking.
            seen[bytes(node_id)] = entry

            # Add to routing table for future lookups.
            self._routing_table.add(entry)

            # Cache ENR for handshake verification.
            self._enr_cache[bytes(node_id)] = enr
            self._transport.register_enr(bytes(node_id), enr)

            # Register address for communication.
            if enr.ip4 and enr.udp_port:
                addr = (enr.ip4, int(enr.udp_port))
                self._transport.register_node_address(bytes(node_id), addr)

            logger.debug("Discovered node %s via NODES", node_id.hex()[:16])

        except ValueError as e:
            logger.debug("Failed to parse ENR: %s", e)
        except Exception as e:
            logger.debug("Error processing discovered ENR: %s", e)
