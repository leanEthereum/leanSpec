"""
Test node wrapper and cluster manager for interop tests.

Provides in-process node spawning with asyncio.TaskGroup for clean lifecycle.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import cast

from lean_spec.subspecs.chain.config import ATTESTATION_COMMITTEE_COUNT
from lean_spec.subspecs.containers import Checkpoint, Validator
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.client import LiveNetworkEventSource
from lean_spec.subspecs.networking.peer.info import PeerInfo
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.types import ConnectionState
from lean_spec.subspecs.node import Node, NodeConfig
from lean_spec.subspecs.validator import ValidatorRegistry
from lean_spec.subspecs.validator.registry import ValidatorEntry
from lean_spec.subspecs.xmss import TARGET_SIGNATURE_SCHEME, SecretKey
from lean_spec.types import Bytes52, Uint64

from .diagnostics import PipelineDiagnostics
from .port_allocator import PortAllocator

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class TestNode:
    """
    Wrapper around a leanSpec Node for testing.

    Provides convenient access to node state and lifecycle.
    """

    node: Node
    """Underlying leanSpec node."""

    event_source: LiveNetworkEventSource
    """Network event source for connection management."""

    listen_addr: str
    """P2P listen address (e.g., '/ip4/127.0.0.1/udp/20600/quic-v1')."""

    index: int
    """Node index in the cluster."""

    _task: asyncio.Task[None] | None = field(default=None, repr=False)
    """Background task running the node."""

    _listener_task: asyncio.Task[None] | None = field(default=None, repr=False)
    """Background task for the QUIC listener."""

    @property
    def _store(self) -> Store:
        """Get the live store from sync_service (not the stale node.store snapshot)."""
        return self.node.sync_service.store

    @property
    def head_slot(self) -> int:
        """Current head slot."""
        head_block = self._store.blocks.get(self._store.head)
        return int(head_block.slot) if head_block else 0

    @property
    def finalized_slot(self) -> int:
        """Latest finalized slot."""
        return int(self._store.latest_finalized.slot)

    @property
    def justified_slot(self) -> int:
        """Latest justified slot."""
        return int(self._store.latest_justified.slot)

    @property
    def peer_count(self) -> int:
        """Number of connected peers.

        Reads the raw connection map rather than the peer manager,
        which is updated asynchronously and may lag behind.
        """
        return len(self.event_source._connections)

    def diagnostics(self) -> PipelineDiagnostics:
        """
        Take a point-in-time snapshot of this node's pipeline state.

        Values are read from the live mutable store and may differ between calls.
        """
        store = self._store

        # The safe target may not have a corresponding block yet
        # (e.g., during early startup before any blocks are produced).
        safe_block = store.blocks.get(store.safe_target)

        return PipelineDiagnostics(
            head_slot=self.head_slot,
            safe_target_slot=int(safe_block.slot) if safe_block else 0,
            finalized_slot=self.finalized_slot,
            justified_slot=self.justified_slot,
            gossip_signatures_count=len(store.gossip_signatures),
            new_aggregated_count=len(store.latest_new_aggregated_payloads),
            known_aggregated_count=len(store.latest_known_aggregated_payloads),
            block_count=len(store.blocks),
        )

    async def start(self) -> None:
        """Start the node in background."""
        self._task = asyncio.create_task(
            self.node.run(install_signal_handlers=False),
            name=f"node-{self.index}",
        )

    async def stop(self) -> None:
        """Stop the node gracefully."""
        # Signal the node and event source to stop.
        self.node.stop()
        self.event_source._running = False

        # Set the stop event on gossipsub to release waiting tasks.
        self.event_source._gossipsub_behavior._stop_event.set()

        # Cancel the listener task.
        if self._listener_task is not None and not self._listener_task.done():
            self._listener_task.cancel()
            try:
                await asyncio.wait_for(self._listener_task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass

        # Stop the event source (cancels gossip tasks).
        await self.event_source.stop()

        # Cancel the node task (it contains the TaskGroup with services).
        if self._task is not None and not self._task.done():
            self._task.cancel()
            try:
                await asyncio.wait_for(self._task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError, Exception):
                pass

    async def dial(self, addr: str, timeout: float = 10.0) -> bool:
        """
        Connect to a peer.

        Args:
            addr: Multiaddr of the peer.
            timeout: Dial timeout in seconds.

        Returns:
            True if connection succeeded.
        """
        try:
            peer_id = await asyncio.wait_for(self.event_source.dial(addr), timeout=timeout)
            return peer_id is not None
        except asyncio.TimeoutError:
            logger.warning("Dial to %s timed out after %.1fs", addr, timeout)
            return False


@dataclass(slots=True)
class NodeCluster:
    """
    Manages a cluster of test nodes.

    Handles node creation, topology setup, and lifecycle.
    """

    num_validators: int
    """Total validators across all nodes."""

    port_allocator: PortAllocator = field(default_factory=PortAllocator)
    """Port allocator for nodes."""

    nodes: list[TestNode] = field(default_factory=list)
    """Active test nodes."""

    _validators: Validators | None = field(default=None, repr=False)
    """Shared validator set."""

    _secret_keys: dict[int, SecretKey] = field(default_factory=dict, repr=False)
    """Secret keys by validator index."""

    _genesis_time: int = field(default=0, repr=False)
    """Genesis time for all nodes."""

    fork_digest: str = field(default="devnet0")
    """Fork digest for gossip topics."""

    def __post_init__(self) -> None:
        """Initialize validators and keys."""
        self._generate_validators()
        # Default genesis time for single-node starts.
        # start_all() overrides this to align with service start.
        self._genesis_time = int(time.time())

    def _generate_validators(self) -> None:
        """Generate validator keys and public info."""
        validators: list[Validator] = []
        scheme = TARGET_SIGNATURE_SCHEME

        # Use a number of active epochs within the scheme's lifetime.
        # TEST_CONFIG has LOG_LIFETIME=8 -> lifetime=256.
        # PROD_CONFIG has LOG_LIFETIME=32 -> lifetime=2^32.
        # Use the full lifetime to avoid exhausting prepared epochs during tests.
        num_active_epochs = int(scheme.config.LIFETIME)

        for i in range(self.num_validators):
            keypair = scheme.key_gen(Uint64(0), Uint64(num_active_epochs))
            self._secret_keys[i] = keypair.secret

            pubkey_bytes = keypair.public.encode_bytes()[:52]
            pubkey = Bytes52(pubkey_bytes.ljust(52, b"\x00"))

            validators.append(
                Validator(
                    pubkey=pubkey,
                    index=ValidatorIndex(i),
                )
            )

        self._validators = Validators(data=validators)

    async def start_node(
        self,
        node_index: int,
        validator_indices: list[int] | None = None,
        is_aggregator: bool = False,
        bootnodes: list[str] | None = None,
        *,
        start_services: bool = True,
    ) -> TestNode:
        """
        Start a new node.

        Args:
            node_index: Index for this node (for logging/identification).
            validator_indices: Which validators this node controls.
            is_aggregator: Whether this node is an aggregator.
            bootnodes: Addresses to connect to on startup.
            start_services: If True, start the node's services immediately.
                If False, call test_node.start() manually after mesh is stable.

        Returns:
            Started TestNode.
        """
        p2p_port = self.port_allocator.allocate_port()
        # QUIC over UDP is the only supported transport.
        # QUIC provides native multiplexing, flow control, and TLS 1.3 encryption.
        listen_addr = f"/ip4/127.0.0.1/udp/{p2p_port}/quic-v1"

        event_source = await LiveNetworkEventSource.create()
        event_source.set_fork_digest(self.fork_digest)

        validator_registry: ValidatorRegistry | None = None
        if validator_indices:
            registry = ValidatorRegistry()
            for idx in validator_indices:
                if idx in self._secret_keys:
                    registry.add(
                        ValidatorEntry(
                            index=ValidatorIndex(idx),
                            secret_key=self._secret_keys[idx],
                        )
                    )
            if len(registry) > 0:
                validator_registry = registry

        assert self._validators is not None, "Validators not initialized"
        config = NodeConfig(
            genesis_time=Uint64(self._genesis_time),
            validators=self._validators,
            event_source=event_source,
            network=event_source.reqresp_client,
            api_config=None,  # Disable API server for interop tests (not needed for P2P testing)
            validator_registry=validator_registry,
            fork_digest=self.fork_digest,
            is_aggregator=is_aggregator,
        )

        node = Node.from_genesis(config)

        # Initialize status so the SyncService can leave IDLE state and accept gossip.
        #
        # The sync service starts in IDLE and only accepts gossip in SYNCING/SYNCED.
        # We trigger a state transition by:
        # 1. Setting the status on the event source (for reqresp Status responses)
        # 2. Adding a synthetic peer to the peer manager with that status
        # 3. Calling on_peer_status to trigger IDLE -> SYNCING transition
        genesis_block = node.store.blocks[node.store.head]
        genesis_status = Status(
            finalized=node.store.latest_finalized,
            head=Checkpoint(root=node.store.head, slot=genesis_block.slot),
        )
        event_source.set_status(genesis_status)

        # Add synthetic "bootstrap" peer to the peer manager.
        #
        # The peer manager's update_status() silently ignores updates for unknown peers.
        # We must add the peer first so the status update takes effect.
        # Note: We cast the string to PeerId for type checking; runtime works with strings.
        bootstrap_id = cast(PeerId, "bootstrap")
        bootstrap_peer = PeerInfo(peer_id=bootstrap_id, state=ConnectionState.CONNECTED)
        node.sync_service.peer_manager.add_peer(bootstrap_peer)

        # Trigger sync service state transition.
        #
        # Call on_peer_status with the synthetic peer to transition from IDLE -> SYNCING.
        # This enables gossip block processing.
        await node.sync_service.on_peer_status(bootstrap_id, genesis_status)

        test_node = TestNode(
            node=node,
            event_source=event_source,
            listen_addr=listen_addr,
            index=node_index,
        )

        # Start listener in background (listen() calls serve_forever() which blocks).
        #
        # Set _running BEFORE starting the listener to avoid race conditions.
        # The network service checks _running when iterating over events.
        # If _running is False, the iteration stops immediately.
        event_source._running = True

        listener_task = asyncio.create_task(
            event_source.listen(listen_addr),
            name=f"listener-{node_index}",
        )

        # Give the listener a moment to bind the port.
        await asyncio.sleep(0.1)

        # Check if listener failed to start (e.g., port in use).
        if listener_task.done():
            try:
                listener_task.result()
            except OSError as e:
                raise RuntimeError(f"Failed to start listener on {listen_addr}: {e}") from e

        test_node._listener_task = listener_task

        await event_source.start_gossipsub()

        block_topic = f"/leanconsensus/{self.fork_digest}/block/ssz_snappy"
        aggregation_topic = f"/leanconsensus/{self.fork_digest}/aggregation/ssz_snappy"
        event_source.subscribe_gossip_topic(block_topic)
        event_source.subscribe_gossip_topic(aggregation_topic)

        # Determine subnets for our validators and subscribe.
        #
        # Validators only subscribe to the subnets they are assigned to.
        # This matches the Ethereum gossip specification.
        if validator_indices:
            for idx in validator_indices:
                subnet_id = idx % int(ATTESTATION_COMMITTEE_COUNT)
                topic = f"/leanconsensus/{self.fork_digest}/attestation_{subnet_id}/ssz_snappy"
                event_source.subscribe_gossip_topic(topic)

        # Optionally start the node's services.
        #
        # When start_services=False, the node networking is ready but validators
        # won't produce blocks/attestations until start() is called explicitly.
        # This allows the mesh to form before block production begins.
        if start_services:
            await test_node.start()

        if bootnodes:
            for addr in bootnodes:
                await test_node.dial(addr)

        self.nodes.append(test_node)
        # Log node startup with gossipsub instance ID for debugging.
        gs_id = event_source._gossipsub_behavior._instance_id % 0xFFFF
        logger.info(
            "Started node %d on %s (validators: %s, services=%s, GS=%x)",
            node_index,
            listen_addr,
            validator_indices,
            "running" if start_services else "pending",
            gs_id,
        )

        return test_node

    async def start_all(
        self,
        topology: list[tuple[int, int]],
        validators_per_node: list[list[int]] | None = None,
    ) -> None:
        """
        Start multiple nodes with given topology.

        Args:
            topology: List of (dialer_index, listener_index) connections.
            validators_per_node: Which validator indices each node controls.
        """
        node_indices = set()
        for dialer, listener in topology:
            node_indices.add(dialer)
            node_indices.add(listener)

        num_nodes = max(node_indices) + 1 if node_indices else 0

        if validators_per_node is None:
            validators_per_node = self._distribute_validators(num_nodes)

        # Set genesis time to coincide with service start.
        #
        # Phases 1-3 (node creation, connection, mesh stabilization) take ~10s.
        # Setting genesis 15s in the future provides margin for slow environments
        # (CI, heavy load) where setup may exceed 10s.
        # Prevents wasting slots before the mesh is ready.
        self._genesis_time = int(time.time()) + 15

        # Phase 1: Create nodes with networking ready but services not running.
        #
        # This allows the gossipsub mesh to form before validators start
        # producing blocks and attestations. Otherwise, early blocks/attestations
        # would be "Published message to 0 peers" because the mesh is empty.
        aggregator_indices = set(range(int(ATTESTATION_COMMITTEE_COUNT)))
        for i in range(num_nodes):
            validator_indices = validators_per_node[i] if i < len(validators_per_node) else []

            # A node is an aggregator if it controls any of the first
            # ATTESTATION_COMMITTEE_COUNT validators.
            is_node_aggregator = any(vid in aggregator_indices for vid in validator_indices)

            await self.start_node(
                i,
                validator_indices,
                is_aggregator=is_node_aggregator,
                start_services=False,
            )

            # Stagger node startup like Ream does.
            #
            # The bootnode (node 0) needs time to fully initialize its QUIC listener
            # and gossipsub behavior before other nodes connect. Without this delay,
            # the mesh may not form properly.
            if i == 0:
                await asyncio.sleep(2.0)

        await asyncio.sleep(0.5)

        # Phase 2: Establish peer connections.
        for dialer_idx, listener_idx in topology:
            dialer = self.nodes[dialer_idx]
            listener = self.nodes[listener_idx]
            success = await dialer.dial(listener.listen_addr)
            if success:
                logger.info("Connected node %d -> node %d", dialer_idx, listener_idx)
            else:
                logger.warning("Failed to connect node %d -> node %d", dialer_idx, listener_idx)

        # Phase 3: Wait for gossipsub mesh to stabilize.
        #
        # Gossipsub mesh formation requires:
        # 1. Heartbeats to run (every 0.7s)
        # 2. Subscription RPCs to be exchanged
        # 3. GRAFT messages to be sent and processed
        #
        # 5s allows ~7 heartbeats which is sufficient for mesh formation.
        await asyncio.sleep(5.0)

        # Phase 4: Start node services (validators, chain service, etc).
        #
        # Now that the mesh is formed, validators can publish blocks/attestations
        # and they will propagate to all mesh peers.
        logger.info("Mesh stable, starting node services...")
        for node in self.nodes:
            await node.start()

    def _distribute_validators(self, num_nodes: int) -> list[list[int]]:
        """
        Distribute validators evenly across nodes.

        Args:
            num_nodes: Number of nodes.

        Returns:
            List of validator indices for each node.
        """
        if num_nodes == 0:
            return []

        distribution: list[list[int]] = [[] for _ in range(num_nodes)]
        for i in range(self.num_validators):
            distribution[i % num_nodes].append(i)

        return distribution

    async def stop_all(self) -> None:
        """Stop all nodes gracefully."""
        for node in self.nodes:
            await node.stop()
        self.nodes.clear()
        logger.info("All nodes stopped")

    async def wait_for_finalization(
        self,
        target_slot: int,
        timeout: float = 120.0,
        poll_interval: float = 1.0,
    ) -> bool:
        """
        Wait until all nodes finalize to at least target_slot.

        Args:
            target_slot: Minimum finalized slot to wait for.
            timeout: Maximum wait time in seconds.
            poll_interval: Time between checks.

        Returns:
            True if all nodes reached target, False on timeout.
        """
        start = time.monotonic()

        while time.monotonic() - start < timeout:
            all_finalized = all(node.finalized_slot >= target_slot for node in self.nodes)

            if all_finalized:
                logger.info("All %d nodes finalized to slot %d", len(self.nodes), target_slot)
                return True

            slots = [node.finalized_slot for node in self.nodes]
            logger.debug("Finalized slots: %s (target: %d)", slots, target_slot)

            await asyncio.sleep(poll_interval)

        slots = [node.finalized_slot for node in self.nodes]
        logger.warning(
            "Timeout waiting for finalization. Slots: %s (target: %d)", slots, target_slot
        )
        return False

    async def wait_for_slot(
        self,
        target_slot: int,
        timeout: float = 60.0,
        poll_interval: float = 0.5,
    ) -> bool:
        """
        Wait until all nodes reach at least target_slot as head.

        Args:
            target_slot: Minimum head slot to wait for.
            timeout: Maximum wait time in seconds.
            poll_interval: Time between checks.

        Returns:
            True if all nodes reached target, False on timeout.
        """
        start = time.monotonic()

        while time.monotonic() - start < timeout:
            all_at_slot = all(node.head_slot >= target_slot for node in self.nodes)

            if all_at_slot:
                return True

            await asyncio.sleep(poll_interval)

        return False

    def log_diagnostics(self, phase: str) -> list[PipelineDiagnostics]:
        """
        Snapshot and log pipeline state for every node in the cluster.

        Takes a point-in-time snapshot of each node's consensus pipeline
        and logs a single summary line per node. Returns the snapshots
        for use in subsequent assertions.

        Args:
            phase: Human-readable label for the current test phase (appears in log output).

        Returns:
            One diagnostic snapshot per node, in node index order.
        """
        diags = [node.diagnostics() for node in self.nodes]
        for i, d in enumerate(diags):
            logger.info(
                "[%s] Node %d: head=%d safe=%d just=%d fin=%d blocks=%d gsigs=%d nagg=%d kagg=%d",
                phase,
                i,
                d.head_slot,
                d.safe_target_slot,
                d.justified_slot,
                d.finalized_slot,
                d.block_count,
                d.gossip_signatures_count,
                d.new_aggregated_count,
                d.known_aggregated_count,
            )
        return diags
