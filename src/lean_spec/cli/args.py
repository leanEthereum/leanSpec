"""Argument-vector boundary for the lean consensus node."""

from __future__ import annotations

import argparse
from pathlib import Path

from pydantic import StrictBool

from lean_spec.types import StrictBaseModel


class CliArgs(StrictBaseModel):
    """
    Typed view of the parsed command line.

    Cross-field validation lives one layer up.
    The parser stays a pure transport between the OS and the rest of the node.
    """

    genesis_path: Path
    """Path to the genesis YAML file."""

    bootnodes: tuple[str, ...]
    """Raw bootnode strings, each either a multiaddr or an ENR."""

    listen_addr: str
    """Multiaddr the node binds for inbound QUIC connections."""

    checkpoint_sync_url: str | None
    """URL of a peer serving a finalized state for checkpoint sync."""

    validator_keys_path: Path | None
    """Directory containing the ream/zeam validator key layout, if any."""

    node_id: str
    """Identifier looked up in validators.yaml to find this node's indices."""

    verbose: StrictBool
    """When true, log at DEBUG instead of INFO."""

    no_color: StrictBool
    """When true, drop ANSI colors from log output."""

    is_aggregator: StrictBool
    """When true, the node performs attestation aggregation."""

    aggregate_subnet_ids_raw: str | None
    """Comma-separated extra subnet ids, resolved one layer up."""

    api_port: int
    """Port for the API server and Prometheus scrape endpoint.

    A value of zero disables both endpoints."""


def parse_args(argv: list[str] | None = None) -> CliArgs:
    """
    Parse an argument vector into the typed view.

    Args:
        argv: Argument vector to parse.
            Passing None defers to the standard parser's default of sys.argv.

    Returns:
        The parsed arguments as a frozen value type.
    """
    parser = argparse.ArgumentParser(
        description="Lean consensus node",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--genesis",
        required=True,
        type=Path,
        dest="genesis_path",
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
        default="/ip4/0.0.0.0/udp/9001/quic-v1",
        dest="listen_addr",
        help="Address to listen on (default: /ip4/0.0.0.0/udp/9001/quic-v1)",
    )
    parser.add_argument(
        "--checkpoint-sync-url",
        type=str,
        default=None,
        dest="checkpoint_sync_url",
        help="URL to fetch finalized checkpoint state for fast sync",
    )
    parser.add_argument(
        "--validator-keys",
        type=Path,
        default=None,
        dest="validator_keys_path",
        help="Path to validator keys directory",
    )
    parser.add_argument(
        "--node-id",
        type=str,
        default="lean_spec_0",
        dest="node_id",
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
        dest="no_color",
        help="Disable colored logging output",
    )
    parser.add_argument(
        "--is-aggregator",
        action="store_true",
        dest="is_aggregator",
        help="Enable aggregator mode (node performs attestation aggregation)",
    )
    parser.add_argument(
        "--aggregate-subnet-ids",
        type=str,
        default=None,
        dest="aggregate_subnet_ids_raw",
        metavar="SUBNETS",
        help=(
            "Comma-separated attestation subnet IDs to additionally subscribe and aggregate "
            "(e.g. '0,1,2'). Requires --is-aggregator."
        ),
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=5052,
        dest="api_port",
        metavar="PORT",
        help="Port for API server and /metrics (default: 5052). Set 0 to disable.",
    )
    namespace = parser.parse_args(argv)
    return CliArgs(
        genesis_path=namespace.genesis_path,
        bootnodes=tuple(namespace.bootnodes),
        listen_addr=namespace.listen_addr,
        checkpoint_sync_url=namespace.checkpoint_sync_url,
        validator_keys_path=namespace.validator_keys_path,
        node_id=namespace.node_id,
        verbose=namespace.verbose,
        no_color=namespace.no_color,
        is_aggregator=namespace.is_aggregator,
        aggregate_subnet_ids_raw=namespace.aggregate_subnet_ids_raw,
        api_port=namespace.api_port,
    )
