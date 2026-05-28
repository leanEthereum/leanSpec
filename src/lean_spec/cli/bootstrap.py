"""
Validated, resolved configuration for a node boot.

The boundary between argument parsing and the run sequence.
The run sequence consumes the validated value without further guards.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from lean_spec.node.anchor import Anchor
from lean_spec.node.api import ApiServerConfig
from lean_spec.node.genesis import GenesisConfig
from lean_spec.node.networking.enr import ENR
from lean_spec.node.validator import ValidatorRegistry
from lean_spec.spec.forks import DEFAULT_REGISTRY, ForkProtocol, SubnetId

from .args import CliArgs

logger = logging.getLogger(__name__)


class CliValidationError(ValueError):
    """Raised when CLI arguments fail cross-field validation."""


@dataclass(frozen=True, slots=True)
class NodeBootstrap:
    """
    Validated, file-loaded view of what a node needs to start.

    Every field is fully resolved:

    - bootnode strings are concrete multiaddrs,
    - aggregate subnet ids are parsed integers,
    - the genesis file is already on disk and loaded.
    """

    genesis: GenesisConfig
    """Loaded genesis configuration."""

    registry: ValidatorRegistry
    """Loaded validator registry.

    The registry is empty when no key directory was supplied."""

    fork: ForkProtocol
    """Active fork specification driving state and store construction."""

    bootnode_multiaddrs: tuple[str, ...]
    """Multiaddrs ready to dial.

    Any ENR inputs are already resolved to plain multiaddrs."""

    listen_addr: str | None
    """Inbound listen address.

    A value of None means a dial-only configuration."""

    checkpoint_sync_url: str | None
    """Peer URL for fetching a finalized state.

    A value of None means genesis sync."""

    node_id: str
    """Node identifier used during validator-key loading."""

    is_aggregator: bool
    """Whether this node performs attestation aggregation."""

    aggregate_subnet_ids: tuple[SubnetId, ...] = field(default=())
    """Additional subnets the aggregator subscribes to.

    Sits on top of the subnets derived from owned validators."""

    api_config: ApiServerConfig | None = field(default=None)
    """API server configuration.

    A value of None disables the API and the metrics endpoint."""

    @classmethod
    def from_cli_args(cls, args: CliArgs) -> NodeBootstrap:
        """
        Resolve and validate CLI arguments into a boot configuration.

        Args:
            args: Parsed CLI arguments.

        Returns:
            A boot configuration with every field resolved.

        Raises:
            CliValidationError: If any cross-field invariant is violated.
            FileNotFoundError: If the validator key manifest is missing.
        """
        # Aggregator role guard.
        #
        # An aggregator with no owned validators has no role in the network.
        if args.is_aggregator and args.validator_keys_path is None:
            raise CliValidationError(
                "--is-aggregator requires --validator-keys to be set; "
                "an aggregator with no validators has no role in the network"
            )

        # Extra subnets.
        #
        # Only valid in aggregator mode.
        # Absent input maps to an empty tuple.
        aggregate_subnet_ids: tuple[SubnetId, ...] = ()
        if args.aggregate_subnet_ids_raw:
            if not args.is_aggregator:
                raise CliValidationError("--aggregate-subnet-ids requires --is-aggregator")
            try:
                aggregate_subnet_ids = tuple(
                    SubnetId(int(s.strip()))
                    for s in args.aggregate_subnet_ids_raw.split(",")
                    if s.strip()
                )
            except ValueError as exc:
                raise CliValidationError(
                    "--aggregate-subnet-ids expects comma-separated integers, "
                    f"got {args.aggregate_subnet_ids_raw!r}"
                ) from exc

        # Genesis load.
        logger.info("Loading genesis from %s", args.genesis_path)
        genesis = GenesisConfig.from_yaml_file(args.genesis_path)
        logger.info(
            "Genesis loaded: time=%d, validators=%d",
            genesis.genesis_time,
            len(genesis.genesis_validators),
        )

        # Validator registry load.
        # - An empty registry covers two cases.
        # - No key path was given, or the path mapped to no validators.
        #
        # Both produce a passive node.
        registry = (
            ValidatorRegistry()
            if args.validator_keys_path is None
            else ValidatorRegistry.from_keys_directory(
                node_id=args.node_id, base_dir=args.validator_keys_path
            )
        )
        if len(registry) > 0:
            logger.info(
                "Loaded %d validators for node %s: indices=%s",
                len(registry),
                args.node_id,
                registry.indices(),
            )
        elif args.validator_keys_path is not None:
            logger.warning("No validators assigned to node %s", args.node_id)

        # An empty registry leaves the aggregator role with nothing to do.
        if args.is_aggregator and len(registry) == 0:
            raise CliValidationError(
                f"--is-aggregator set but no validators are assigned to node {args.node_id}; "
                "check validators.yaml mapping or --node-id"
            )

        # Bootnode resolution.
        #
        # Each input is either a bare multiaddr or an ENR record.
        # Failing fast at boot beats reporting an opaque dial-time error.
        bootnode_multiaddrs: list[str] = []
        for bootnode in args.bootnodes:
            # Bare multiaddrs pass through; the dial path validates them later.
            if not bootnode.startswith("enr:"):
                bootnode_multiaddrs.append(bootnode)
                continue

            # Decode the signed ENR envelope from its base64 text form.
            enr = ENR.from_string(bootnode)

            # Reject records whose RLP layout breaks the ENR schema.
            if not enr.is_valid():
                raise CliValidationError(f"ENR structurally invalid: {enr}")

            # Reject forged records whose signature does not match the public key.
            if not enr.verify_signature():
                raise CliValidationError(f"ENR signature verification failed: {enr}")

            # Reject records that omit the UDP endpoint needed for QUIC dialing.
            multiaddr = enr.multiaddr()
            if multiaddr is None:
                raise CliValidationError(f"ENR has no UDP connection info: {enr}")

            bootnode_multiaddrs.append(multiaddr)

        return cls(
            genesis=genesis,
            registry=registry,
            fork=DEFAULT_REGISTRY.current,
            bootnode_multiaddrs=tuple(bootnode_multiaddrs),
            listen_addr=args.listen_addr or None,
            checkpoint_sync_url=args.checkpoint_sync_url,
            node_id=args.node_id,
            is_aggregator=args.is_aggregator,
            aggregate_subnet_ids=aggregate_subnet_ids,
            api_config=ApiServerConfig(port=args.api_port) if args.api_port > 0 else None,
        )

    async def build_anchor(self) -> Anchor:
        """
        Build the boot anchor for this configuration.

        Without a checkpoint URL the node syncs from genesis.
        With one, the anchor is fetched from a peer.
        Both paths return the same shape.
        """
        if self.checkpoint_sync_url is None:
            return Anchor.from_genesis(self.genesis)

        logger.info("Fetching checkpoint state from %s", self.checkpoint_sync_url)
        return await Anchor.from_checkpoint(
            url=self.checkpoint_sync_url,
            genesis=self.genesis,
            fork=self.fork,
            validator_id=self.registry.primary_index(),
        )
