"""
Run sequence for the lean consensus node.

A linearised boot in five steps:

1. Bring observability up.
2. Materialise the boot anchor.
3. Wire the event source and its subscriptions.
4. Construct the node from the validated configuration.
5. Start serving inbound traffic, then run to shutdown.

Each step has a single purpose.
A reader can trace the spec invariants top to bottom.
"""

from __future__ import annotations

import logging

from lean_spec.node.chain.config import ATTESTATION_COMMITTEE_COUNT
from lean_spec.node.metrics import PrometheusObserver, registry as metrics
from lean_spec.node.networking.client import LiveNetworkEventSource
from lean_spec.node.networking.gossipsub import GossipTopic
from lean_spec.node.node import Node, NodeConfig
from lean_spec.node.observability import set_observer
from lean_spec.spec.forks import SubnetId

from .bootstrap import NodeBootstrap

logger = logging.getLogger(__name__)


async def _build_event_source(boot: NodeBootstrap) -> LiveNetworkEventSource:
    """Construct the event source and apply its pre-serving wiring."""
    # Spin up the QUIC transport and gossipsub plumbing.
    event_source = await LiveNetworkEventSource.create()

    # Pin the network identity carried by every topic id and Status message.
    event_source.set_network_name(boot.fork.GOSSIP_DIGEST)

    # A peer that meshes with us before the topic exists drops our heartbeat.
    block_topic = GossipTopic.block(boot.fork.GOSSIP_DIGEST).to_topic_id()
    event_source.subscribe_gossip_topic(block_topic)
    logger.info("Subscribed to block gossip topic: %s", block_topic)

    # Validator-owned subnets carry the attestations the mesh must propagate.
    # Missing one of them breaks the attestation flow for that validator.
    subnets: set[SubnetId] = {
        idx.compute_subnet_id(ATTESTATION_COMMITTEE_COUNT) for idx in boot.registry.indices()
    }

    # Aggregator extras are advisory subnets the operator wants this node to see.
    # They are ignored on non-aggregator nodes, which the bootstrap layer enforces.
    if boot.is_aggregator:
        subnets.update(boot.aggregate_subnet_ids)

    # Subscribe to every owned subnet under its fork-scoped topic id.
    for subnet_id in subnets:
        topic = GossipTopic.attestation_subnet(boot.fork.GOSSIP_DIGEST, subnet_id).to_topic_id()
        event_source.subscribe_gossip_topic(topic)
        logger.info("Subscribed to attestation subnet %d", subnet_id)

    # A passive non-aggregator node owns no subnets.
    #
    # That is a valid configuration; we just log it.
    if not subnets:
        logger.info("Not subscribing to any attestation subnet")

    return event_source


async def run_node(boot: NodeBootstrap) -> None:
    """
    Run the consensus node to shutdown.

    Args:
        boot: Validated, fully resolved boot configuration.
    """
    # Observability comes up first.
    #
    # Later construction paths emit metrics and register meters as they wire up.
    metrics.init(name="leanspec-node", version="0.0.1")
    set_observer(PrometheusObserver())

    # Materialise the starting point: genesis or checkpoint-synced anchor.
    anchor = await boot.build_anchor()

    # Wire transport and topic subscriptions before any peer can reach us.
    event_source = await _build_event_source(boot)

    # Construct the node with the anchor store and event source attached.
    node = Node.from_genesis(
        NodeConfig(
            genesis_time=boot.genesis.genesis_time,
            validators=anchor.validators,
            event_source=event_source,
            network=event_source.reqresp_client,
            fork=boot.fork,
            validator_registry=boot.registry,
            network_name=boot.fork.GOSSIP_DIGEST,
            is_aggregator=boot.is_aggregator,
            api_config=boot.api_config,
            anchor_store=anchor.store,
        )
    )

    logger.info("Node initialized, peer_id=%s", event_source.connection_manager.peer_id)

    # Bring the listener and outbound dialer online in the spec-required order.
    await event_source.start_serving(
        status=anchor.initial_status,
        current_slot_lookup=node.clock.current_slot,
        listen_addr=boot.listen_addr,
        bootnode_multiaddrs=boot.bootnode_multiaddrs,
    )

    # Run all services concurrently until shutdown is signalled.
    logger.info("Starting consensus node...")
    await node.run()
