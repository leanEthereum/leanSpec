"""
Lean consensus node CLI entry point.

Run a minimal lean consensus client that can sync with other lean consensus nodes.

Usage::

    python -m lean_spec --genesis config.yaml --bootnode /ip4/127.0.0.1/tcp/9000
    python -m lean_spec --genesis config.yaml --bootnode enr:-IS4QHCYrYZbAKW...
    python -m lean_spec --genesis config.yaml --checkpoint-sync-url http://localhost:5052
    python -m lean_spec --genesis config.yaml --validator-keys ./keys --node-id lean_spec_0

Options:
    --genesis              Path to genesis YAML file (required)
    --bootnode             Bootnode address (multiaddr or ENR string, can be repeated)
    --listen               Address to listen on (default: /ip4/0.0.0.0/tcp/9001)
    --checkpoint-sync-url  URL to fetch finalized checkpoint state for fast sync
    --validator-keys       Path to validator keys directory
    --node-id              Node identifier for validator assignment (default: lean_spec_0)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from lean_spec.subspecs.chain.config import ATTESTATION_COMMITTEE_COUNT
from lean_spec.subspecs.containers import Block, BlockBody, Checkpoint, State
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.genesis import GenesisConfig
from lean_spec.subspecs.networking import compute_subnet_id
from lean_spec.subspecs.networking.client import LiveNetworkEventSource
from lean_spec.subspecs.networking.gossipsub import GossipTopic
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.node import Node, NodeConfig, get_local_validator_id
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.validator import ValidatorRegistry
from lean_spec.types import Bytes32, Uint64

# Fork identifier for gossip topics.
#
# Must match the fork string used by ream and other clients.
# For devnet, this is "devnet0".
GOSSIP_FORK_DIGEST = "devnet0"

logger = logging.getLogger(__name__)


def is_enr_string(bootnode: str) -> bool:
    """
    Check if bootnode string is an ENR (vs multiaddr).

    Uses prefix detection rather than attempting full parsing.
    This is both faster and avoids import overhead for simple checks.

    Per EIP-778, all ENR strings begin with "enr:" followed by base64url content.
    """
    return bootnode.startswith("enr:")


def resolve_bootnode(bootnode: str) -> str:
    """
    Resolve a bootnode string to a multiaddr.

    Supports both ENR and multiaddr formats for interoperability.
    Different tools emit different formats:

    - Lighthouse, Prysm: Often provide ENR strings
    - libp2p tools: Usually provide multiaddrs directly

    Args:
        bootnode: Either an ENR string (enr:-IS4Q...) or multiaddr (/ip4/.../tcp/...).

    Returns:
        Multiaddr string suitable for dialing.

    Raises:
        ValueError: If ENR is malformed or has no TCP connection info.
    """
    if is_enr_string(bootnode):
        from lean_spec.subspecs.networking.enr import ENR

        enr = ENR.from_string(bootnode)

        # ENR.multiaddr() returns None when the record lacks IP or TCP port.
        #
        # This happens with discovery-only ENRs that only contain UDP info.
        # We require TCP for libp2p connections.
        multiaddr = enr.multiaddr()
        if multiaddr is None:
            raise ValueError(f"ENR has no TCP connection info: {enr}")
        return multiaddr

    # Already a multiaddr string. Pass through without validation.
    #
    # Validation happens when dialing; early validation here would
    # duplicate logic and reduce flexibility for multiaddr extensions.
    return bootnode


def create_anchor_block(state: State) -> Block:
    """
    Create an anchor block from a checkpoint state.

    The forkchoice store requires a block to establish the starting point.
    We reconstruct this "anchor block" from the header embedded in the state.

    The body content does not matter for fork choice initialization.
    Only header fields (slot, parent, state root) establish the anchor.

    Args:
        state: The checkpoint state containing the latest block header.

    Returns:
        A Block suitable for initializing the forkchoice store.
    """
    header = state.latest_block_header

    # The state root in the header may be zero.
    #
    # Why? Block processing stores the header BEFORE computing post-state root.
    # This prevents circular dependency: state root depends on header, header
    # would depend on state root. The spec breaks this cycle by storing zero
    # initially, then filling it in when the next slot processes.
    #
    # For checkpoint sync, we may receive state at exactly the block's slot.
    # In this case, the state root was never filled in. We compute it now.
    state_root = header.state_root
    if state_root == Bytes32.zero():
        state_root = hash_tree_root(state)

    # Build a minimal body.
    #
    # Fork choice only cares about the block's identity (its hash) and
    # lineage (parent_root). The body content is irrelevant for anchoring.
    # We use an empty body because we lack the original block data.
    body = BlockBody(attestations=AggregatedAttestations(data=[]))

    return Block(
        slot=header.slot,
        proposer_index=header.proposer_index,
        parent_root=header.parent_root,
        state_root=state_root,
        body=body,
    )


def _init_from_genesis(
    genesis: GenesisConfig,
    event_source: LiveNetworkEventSource,
    validator_registry: ValidatorRegistry | None = None,
) -> Node:
    """
    Initialize a node from genesis configuration.

    Args:
        genesis: Genesis configuration with time and validators.
        event_source: Network transport for the node.
        validator_registry: Optional registry with validator secret keys.

    Returns:
        A fully initialized Node starting from genesis.
    """
    # Set initial status for handshakes.
    #
    # At genesis, our finalized and head are both the genesis block (unknown root).
    genesis_status = Status(
        finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
    )
    event_source.set_status(genesis_status)

    # Create node configuration.
    config = NodeConfig(
        genesis_time=genesis.genesis_time,
        validators=genesis.to_validators(),
        event_source=event_source,
        network=event_source.reqresp_client,
        validator_registry=validator_registry,
        fork_digest=GOSSIP_FORK_DIGEST,
    )

    # Create and return the node.
    return Node.from_genesis(config)


async def _init_from_checkpoint(
    checkpoint_sync_url: str,
    genesis: GenesisConfig,
    event_source: LiveNetworkEventSource,
    validator_registry: ValidatorRegistry | None = None,
) -> Node | None:
    """
    Initialize a node from a checkpoint state fetched from a remote node.

    Checkpoint sync trades trustlessness for speed. The node trusts the
    checkpoint source to provide a valid finalized state. This is acceptable
    because:

    - The state is finalized (2/3 of validators attested to it)
    - Users explicitly opt in via the CLI flag
    - The alternative (syncing from genesis) takes hours or days

    Processing steps:

    1. Fetch finalized state from checkpoint URL
    2. Verify structural validity
    3. Validate genesis time matches
    4. Create anchor block
    5. Initialize forkchoice store
    6. Return configured Node

    Args:
        checkpoint_sync_url: URL of the node to fetch checkpoint state from.
        genesis: Local genesis configuration for validation.
        event_source: Network transport for the node.
        validator_registry: Optional registry with validator secret keys.

    Returns:
        A fully initialized Node if successful, None if checkpoint sync failed.
    """
    from lean_spec.subspecs.api.client import (
        CheckpointSyncError,
        fetch_finalized_state,
        verify_checkpoint_state,
    )

    try:
        logger.info("Fetching checkpoint state from %s", checkpoint_sync_url)
        state = await fetch_finalized_state(checkpoint_sync_url, State)

        # Structural validation catches corrupted or malformed states.
        #
        # This is defense in depth. We trust the source, but still verify
        # basic invariants before using the state.
        if not await verify_checkpoint_state(state):
            logger.error("Checkpoint state verification failed")
            return None

        # Genesis time MUST match.
        #
        # This is our only protection against syncing to a different chain.
        # If genesis times differ, the checkpoint belongs to another network.
        # We reject rather than risk corrupting our view of the chain.
        #
        # We do NOT fall back to genesis sync on failure. That would silently
        # mask configuration errors and leave operators unaware their node
        # started from scratch instead of the checkpoint.
        if state.config.genesis_time != genesis.genesis_time:
            logger.error(
                "Genesis time mismatch: checkpoint=%d, local=%d",
                state.config.genesis_time,
                genesis.genesis_time,
            )
            return None

        # Create anchor block from checkpoint state.
        anchor_block = create_anchor_block(state)

        # Initialize forkchoice store from checkpoint.
        #
        # The store treats this as the new "genesis" for fork choice purposes.
        # All blocks before the checkpoint are effectively pruned.
        validator_id = get_local_validator_id(validator_registry)
        store = Store.get_forkchoice_store(state, anchor_block, validator_id)
        logger.info(
            "Initialized from checkpoint at slot %d (finalized=%s)",
            state.slot,
            store.latest_finalized.root.hex()[:16],
        )

        # Set initial status for handshakes based on checkpoint.
        checkpoint_status = Status(
            finalized=store.latest_finalized,
            head=Checkpoint(root=store.head, slot=store.blocks[store.head].slot),
        )
        event_source.set_status(checkpoint_status)

        # Use validators from checkpoint state, not genesis.
        #
        # The validator set evolves over time. Deposits add validators,
        # exits remove them. The checkpoint state reflects the current set.
        config = NodeConfig(
            genesis_time=genesis.genesis_time,
            validators=state.validators,
            event_source=event_source,
            network=event_source.reqresp_client,
            validator_registry=validator_registry,
            fork_digest=GOSSIP_FORK_DIGEST,
        )

        # Create node and inject checkpoint store.
        #
        # TODO: Add a dedicated factory method for cleaner API.
        node = Node.from_genesis(config)
        node.store = store
        node.sync_service.store = store

        return node

    except CheckpointSyncError as e:
        logger.error("Checkpoint sync failed: %s", e)
        return None


class ColoredFormatter(logging.Formatter):
    """Logging formatter with ANSI colors for better readability."""

    # ANSI color codes
    GREY = "\x1b[38;5;244m"
    BLUE = "\x1b[38;5;39m"
    GREEN = "\x1b[38;5;40m"
    YELLOW = "\x1b[38;5;220m"
    RED = "\x1b[38;5;196m"
    BOLD_RED = "\x1b[38;5;196;1m"
    CYAN = "\x1b[38;5;51m"
    RESET = "\x1b[0m"

    LEVEL_COLORS = {
        logging.DEBUG: GREY,
        logging.INFO: GREEN,
        logging.WARNING: YELLOW,
        logging.ERROR: RED,
        logging.CRITICAL: BOLD_RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with colors."""
        # Get color for this level
        color = self.LEVEL_COLORS.get(record.levelno, self.RESET)

        # Format timestamp in cyan
        timestamp = self.formatTime(record, self.datefmt)
        colored_time = f"{self.CYAN}{timestamp}{self.RESET}"

        # Format level name with color
        levelname = f"{color}{record.levelname:8}{self.RESET}"

        # Format logger name in blue
        name = f"{self.BLUE}{record.name}{self.RESET}"

        # Format message
        message = record.getMessage()

        return f"{colored_time} {levelname} {name}: {message}"


def setup_logging(verbose: bool = False, no_color: bool = False) -> None:
    """Configure logging for the node with optional colors."""
    level = logging.DEBUG if verbose else logging.INFO

    # Create handler
    handler = logging.StreamHandler()
    handler.setLevel(level)

    # Use colored formatter unless disabled
    if no_color:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        formatter = ColoredFormatter(datefmt="%Y-%m-%d %H:%M:%S")

    handler.setFormatter(formatter)

    # Configure root logger
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)


async def run_node(
    genesis_path: Path,
    bootnodes: list[str],
    listen_addr: str,
    checkpoint_sync_url: str | None = None,
    validator_keys_path: Path | None = None,
    node_id: str = "lean_spec_0",
    genesis_time_now: bool = False,
) -> None:
    """
    Run the lean consensus node.

    Args:
        genesis_path: Path to genesis YAML file (config.yaml).
        bootnodes: List of bootnode multiaddrs to connect to.
        listen_addr: Address to listen on.
        checkpoint_sync_url: Optional URL to fetch checkpoint state for fast sync.
        validator_keys_path: Optional path to validator keys directory.
        node_id: Node identifier for validator assignment.
        genesis_time_now: Override genesis time to current time for testing.
    """
    import time

    logger.info("Loading genesis from %s", genesis_path)
    genesis = GenesisConfig.from_yaml_file(genesis_path)

    # Override genesis time for testing if requested
    if genesis_time_now:
        original_time = genesis.genesis_time
        new_time = Uint64(int(time.time()))
        # Create new config with updated genesis time.
        #
        # GenesisConfig is frozen, so we use model_copy to create
        # a new instance with the updated field.
        genesis = genesis.model_copy(update={"genesis_time": new_time})
        logger.warning(
            "Overriding genesis time: %d -> %d (now)",
            original_time,
            new_time,
        )

    logger.info(
        "Genesis loaded: time=%d, validators=%d",
        genesis.genesis_time,
        len(genesis.genesis_validators),
    )

    # Load validator keys if path provided.
    #
    # The registry holds secret keys for validators assigned to this node.
    # Without a registry, the node runs in passive mode (sync only).
    #
    # Expected directory structure (ream/zeam compatible):
    #   validators.yaml - node to validator index mapping
    #   hash-sig-keys/validator-keys-manifest.yaml - key metadata and file paths
    validator_registry: ValidatorRegistry | None = None
    if validator_keys_path is not None:
        validators_yaml = validator_keys_path / "validators.yaml"
        manifest_path = validator_keys_path / "hash-sig-keys/validator-keys-manifest.yaml"

        if manifest_path.exists():
            validator_registry = ValidatorRegistry.from_yaml(
                node_id=node_id,
                validators_path=validators_yaml,
                manifest_path=manifest_path,
            )
        else:
            logger.error(
                "Validator keys manifest not found: %s",
                manifest_path,
            )

        if validator_registry is not None and len(validator_registry) > 0:
            logger.info(
                "Loaded %d validators for node %s: indices=%s",
                len(validator_registry),
                node_id,
                validator_registry.indices(),
            )
        elif validator_registry is not None:
            logger.warning("No validators assigned to node %s", node_id)

    event_source = LiveNetworkEventSource.create()

    # Subscribe to gossip topics.
    #
    # We subscribe before connecting to bootnodes so that when
    # we establish connections, we can immediately announce our
    # subscriptions to peers.
    block_topic = str(GossipTopic.block(GOSSIP_FORK_DIGEST))
    event_source.subscribe_gossip_topic(block_topic)
    # Subscribe to attestation subnet topics based on local validator id.
    validator_id = get_local_validator_id(validator_registry)
    if validator_id is None:
        subnet_id = 0
        logger.info("No local validator id; subscribing to attestation subnet %d", subnet_id)
    else:
        subnet_id = compute_subnet_id(validator_id, ATTESTATION_COMMITTEE_COUNT)
    attestation_subnet_topic = str(GossipTopic.attestation_subnet(GOSSIP_FORK_DIGEST, subnet_id))
    event_source.subscribe_gossip_topic(attestation_subnet_topic)
    logger.info("Subscribed to gossip topics: %s, %s", block_topic, attestation_subnet_topic)

    # Two initialization paths: checkpoint sync or genesis sync.
    #
    # Checkpoint sync (preferred for mainnet/testnets):
    #   - Downloads finalized state from trusted node
    #   - Skips weeks/months of historical block processing
    #   - Ready to participate in consensus within minutes
    #
    # Genesis sync (required for new networks):
    #   - Starts from block 0 with initial validator set
    #   - Must process every block to reach current head
    #   - Only practical for new or small networks
    node: Node | None
    if checkpoint_sync_url is not None:
        node = await _init_from_checkpoint(
            checkpoint_sync_url=checkpoint_sync_url,
            genesis=genesis,
            event_source=event_source,
            validator_registry=validator_registry,
        )
        if node is None:
            # Checkpoint sync failed. Exit rather than falling back.
            #
            # Silent fallback to genesis would surprise operators.
            # They explicitly requested checkpoint sync for a reason.
            return
    else:
        node = _init_from_genesis(
            genesis=genesis,
            event_source=event_source,
            validator_registry=validator_registry,
        )

    logger.info("Node initialized, peer_id=%s", event_source.connection_manager.peer_id)

    # Update status with actual head and finalized checkpoints.
    updated_status = Status(
        finalized=node.store.latest_finalized,
        head=Checkpoint(root=node.store.head, slot=node.store.blocks[node.store.head].slot),
    )
    event_source.set_status(updated_status)

    # Connect to bootnodes.
    #
    # Best-effort connection: failures don't abort the loop.
    # The node can still function if at least one bootnode connects.
    for bootnode in bootnodes:
        try:
            multiaddr = resolve_bootnode(bootnode)
            logger.info("Connecting to bootnode %s", multiaddr)
            peer_id = await event_source.dial(multiaddr)
            if peer_id:
                logger.info("Connected to bootnode, peer_id=%s", peer_id)
            else:
                logger.warning("Failed to connect to bootnode %s", multiaddr)
        except ValueError as e:
            # Truncate bootnode string in error logs.
            #
            # ENR strings can exceed 200 characters, making logs unreadable.
            # First 40 chars include the "enr:" prefix and enough to identify.
            logger.warning("Invalid bootnode %s: %s", bootnode[:40], e)

    # Start listening (in background).
    #
    # We start the listener as a background task, but give it a moment
    # to bind the port. If binding fails (e.g., port already in use),
    # we want to fail fast with a clear error rather than continue
    # running without the ability to accept incoming connections.
    listener_task = None
    if listen_addr:
        logger.info("Starting listener on %s", listen_addr)
        listener_task = asyncio.create_task(event_source.listen(listen_addr))

        # Give the listener a moment to bind the port.
        # If it fails immediately (e.g., "Address already in use"),
        # the task will complete with an exception.
        await asyncio.sleep(0.1)

        if listener_task.done():
            # Listener failed early - propagate the error.
            try:
                listener_task.result()
            except OSError as e:
                logger.error("Failed to start listener: %s", e)
                logger.error(
                    "Port may be in use. Run './scripts/run_leanspec.sh clean' to free ports."
                )
                return

    # Start gossipsub behavior.
    #
    # This starts the heartbeat loop and enables message forwarding.
    # Must be called after subscribing to topics and connecting to peers.
    logger.info("Starting gossipsub behavior...")
    await event_source.start_gossipsub()

    # Run the node.
    logger.info("Starting consensus node...")
    event_source._running = True
    await node.run()


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Lean consensus node",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--genesis",
        required=True,
        type=Path,
        help="Path to genesis YAML file (config.yaml)",
    )
    parser.add_argument(
        "--bootnode",
        action="append",
        default=[],
        dest="bootnodes",
        help="Bootnode address (multiaddr or ENR string, can be repeated)",
    )
    parser.add_argument(
        "--listen",
        default="/ip4/0.0.0.0/tcp/9001",
        help="Address to listen on (default: /ip4/0.0.0.0/tcp/9001)",
    )
    parser.add_argument(
        "--checkpoint-sync-url",
        type=str,
        default=None,
        help="URL to fetch finalized checkpoint state for fast sync (e.g., http://localhost:5052)",
    )
    parser.add_argument(
        "--validator-keys",
        type=Path,
        default=None,
        help="Path to validator keys directory",
    )
    parser.add_argument(
        "--node-id",
        type=str,
        default="lean_spec_0",
        help="Node identifier for validator assignment (default: lean_spec_0)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored logging output",
    )
    parser.add_argument(
        "--genesis-time-now",
        action="store_true",
        help="Override genesis time to current time (for testing)",
    )

    args = parser.parse_args()

    setup_logging(args.verbose, args.no_color)

    # Use asyncio.run with proper task cancellation on interrupt.
    # This ensures all tasks are cancelled and resources are released.
    try:
        asyncio.run(
            run_node(
                args.genesis,
                args.bootnodes,
                args.listen,
                args.checkpoint_sync_url,
                args.validator_keys,
                args.node_id,
                args.genesis_time_now,
            )
        )
    except KeyboardInterrupt:
        # asyncio.run() handles task cancellation, but we log for clarity.
        logger.info("Shutting down...")
    finally:
        # Force exit to ensure all threads/sockets are released.
        # This is important for QUIC which may have background threads.
        import os
        import sys

        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)


if __name__ == "__main__":
    main()
