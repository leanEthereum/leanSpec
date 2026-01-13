"""
Lean consensus node CLI entry point.

Run a minimal lean consensus client that can sync with other lean consensus nodes.

Usage::

    python -m lean_spec --genesis genesis.json --bootnode /ip4/127.0.0.1/tcp/9000

Options:
    --genesis       Path to genesis JSON file (required)
    --bootnode      Multiaddr of bootnode to connect to (can be repeated)
    --listen        Address to listen on (default: /ip4/0.0.0.0/tcp/9000)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from lean_spec.subspecs.containers import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.genesis import GenesisConfig
from lean_spec.subspecs.networking.client import LiveNetworkEventSource
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.node import Node, NodeConfig
from lean_spec.types import Bytes32

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the node."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def run_node(
    genesis_path: Path,
    bootnodes: list[str],
    listen_addr: str,
) -> None:
    """
    Run the lean consensus node.

    Args:
        genesis_path: Path to genesis JSON file.
        bootnodes: List of bootnode multiaddrs to connect to.
        listen_addr: Address to listen on.
    """
    # Load genesis configuration.
    logger.info("Loading genesis from %s", genesis_path)
    genesis = GenesisConfig.from_json_file(genesis_path)
    logger.info(
        "Genesis loaded: time=%d, validators=%d",
        genesis.genesis_time,
        len(genesis.genesis_validators),
    )

    # Create network transport.
    event_source = LiveNetworkEventSource.create()

    # Create initial status for handshakes.
    #
    # At genesis, our finalized and head are both the genesis block.
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
    )

    # Create the node.
    node = Node.from_genesis(config)
    logger.info("Node initialized, peer_id=%s", event_source.connection_manager.peer_id)

    # Update status with actual genesis block root.
    #
    # At genesis, the head and finalized are both the genesis block.
    # The store.head is initialized to the genesis block root.
    genesis_root = node.store.head
    updated_status = Status(
        finalized=Checkpoint(root=genesis_root, slot=Slot(0)),
        head=Checkpoint(root=genesis_root, slot=Slot(0)),
    )
    event_source.set_status(updated_status)

    # Connect to bootnodes.
    for bootnode in bootnodes:
        logger.info("Connecting to bootnode %s", bootnode)
        peer_id = await event_source.dial(bootnode)
        if peer_id:
            logger.info("Connected to bootnode, peer_id=%s", peer_id)
        else:
            logger.warning("Failed to connect to bootnode %s", bootnode)

    # Start listening (in background).
    if listen_addr:
        logger.info("Starting listener on %s", listen_addr)
        asyncio.create_task(event_source.listen(listen_addr))

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
        help="Path to genesis JSON file",
    )
    parser.add_argument(
        "--bootnode",
        action="append",
        default=[],
        dest="bootnodes",
        help="Bootnode multiaddr (can be repeated)",
    )
    parser.add_argument(
        "--listen",
        default="/ip4/0.0.0.0/tcp/9000",
        help="Address to listen on (default: /ip4/0.0.0.0/tcp/9000)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    setup_logging(args.verbose)

    try:
        asyncio.run(run_node(args.genesis, args.bootnodes, args.listen))
    except KeyboardInterrupt:
        logger.info("Shutting down...")


if __name__ == "__main__":
    main()
