"""Tests for the consensus node run sequence."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from consensus_testing.keys import XmssKeyManager
from lean_spec.cli import NodeBootstrap
from lean_spec.cli.run import _build_event_source
from lean_spec.node.genesis import GenesisConfig
from lean_spec.node.networking.gossipsub import GossipTopic
from lean_spec.node.validator import ValidatorRegistry
from lean_spec.node.validator.registry import ValidatorEntry
from lean_spec.spec.forks import DEFAULT_REGISTRY, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.config import ATTESTATION_COMMITTEE_COUNT


class _RecordingEventSource:
    """In-test fake that records what the builder configures on it."""

    def __init__(self) -> None:
        self.network_name: str | None = None
        self.topics: list[str] = []

    def set_network_name(self, name: str) -> None:
        self.network_name = name

    def subscribe_gossip_topic(self, topic: str) -> None:
        self.topics.append(topic)


@pytest.fixture
def make_boot() -> Callable[..., NodeBootstrap]:
    """Construct a NodeBootstrap with passive defaults that any field can override."""

    def _build(**overrides: Any) -> NodeBootstrap:
        # Defaults model a minimal passive node: no validators, no peers, no listener.
        defaults: dict[str, Any] = {
            "genesis": GenesisConfig.model_validate(
                {"GENESIS_TIME": 1000, "GENESIS_VALIDATORS": []}
            ),
            "registry": ValidatorRegistry(),
            "fork": DEFAULT_REGISTRY.current,
            "bootnode_multiaddrs": (),
            "listen_address": None,
            "checkpoint_sync_url": None,
            "node_id": "lean_spec_0",
            "is_aggregator": False,
        }
        return NodeBootstrap(**{**defaults, **overrides})

    return _build


@pytest.fixture
def one_validator_registry() -> ValidatorRegistry:
    """Registry holding a single XMSS keypair at validator index zero."""
    # Borrow a real precomputed keypair from the shared XMSS manager.
    km = XmssKeyManager.shared(max_slot=Slot(10))
    kp = km[ValidatorIndex(0)]
    registry = ValidatorRegistry()
    registry.add(
        ValidatorEntry(
            index=ValidatorIndex(0),
            attestation_secret_key=kp.attestation_keypair.secret_key,
            proposal_secret_key=kp.proposal_keypair.secret_key,
        )
    )
    return registry


@pytest.fixture
def run_build() -> Callable[[NodeBootstrap], Awaitable[_RecordingEventSource]]:
    """Run the event-source builder against a recording fake and return it."""

    async def _run(boot: NodeBootstrap) -> _RecordingEventSource:
        # Intercept the live transport factory so the builder sees the fake.
        source = _RecordingEventSource()
        with patch(
            "lean_spec.cli.run.LiveNetworkEventSource.create",
            new_callable=AsyncMock,
            return_value=source,
        ):
            await _build_event_source(boot)
        return source

    return _run


class TestBuildEventSource:
    """Tests for the pre-serving event-source wiring."""

    async def test_passive_node_subscribes_only_to_block_topic(
        self,
        make_boot: Callable[..., NodeBootstrap],
        run_build: Callable[[NodeBootstrap], Awaitable[_RecordingEventSource]],
    ) -> None:
        """A non-aggregator with no owned validators subscribes only to the block topic."""
        boot = make_boot()

        source = await run_build(boot)

        block_topic = GossipTopic.block(boot.fork.GOSSIP_DIGEST).to_topic_id()
        assert source.topics == [block_topic]

    async def test_owned_validator_adds_its_subnet(
        self,
        make_boot: Callable[..., NodeBootstrap],
        run_build: Callable[[NodeBootstrap], Awaitable[_RecordingEventSource]],
        one_validator_registry: ValidatorRegistry,
    ) -> None:
        """One owned validator adds exactly one attestation subnet topic."""
        boot = make_boot(registry=one_validator_registry)

        source = await run_build(boot)

        block_topic = GossipTopic.block(boot.fork.GOSSIP_DIGEST).to_topic_id()
        subnet_id = ValidatorIndex(0).compute_subnet_id(ATTESTATION_COMMITTEE_COUNT)
        subnet_topic = GossipTopic.attestation_subnet(
            boot.fork.GOSSIP_DIGEST, subnet_id
        ).to_topic_id()
        assert source.topics == [block_topic, subnet_topic]

    async def test_network_identity_pinned_on_event_source(
        self,
        make_boot: Callable[..., NodeBootstrap],
        run_build: Callable[[NodeBootstrap], Awaitable[_RecordingEventSource]],
    ) -> None:
        """The fork's gossip digest is set on the event source before any subscription."""
        boot = make_boot()

        source = await run_build(boot)

        assert source.network_name == boot.fork.GOSSIP_DIGEST
