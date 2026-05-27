"""Tests for the argument-vector parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from lean_spec.cli import CliArgs, parse_args


class TestParseArgsDefaults:
    """Defaults for every optional flag."""

    def test_only_genesis_populates_defaults(self) -> None:
        """A minimal invocation fills every other field with its documented default."""
        assert parse_args(["--genesis", "config.yaml"]) == CliArgs(
            genesis_path=Path("config.yaml"),
            bootnodes=(),
            listen_addr="/ip4/0.0.0.0/udp/9001/quic-v1",
            checkpoint_sync_url=None,
            validator_keys_path=None,
            node_id="lean_spec_0",
            verbose=False,
            no_color=False,
            is_aggregator=False,
            aggregate_subnet_ids_raw=None,
            api_port=5052,
        )


class TestParseArgsFullFlagSet:
    """Every supported flag together produces the matching typed view."""

    def test_full_flag_set_round_trip(self, tmp_path: Path) -> None:
        """Every flag set on the command line shows up in the parsed value."""
        keys_dir = tmp_path / "keys"
        assert parse_args(
            [
                "--genesis",
                "g.yaml",
                "--bootnode",
                "/ip4/1.1.1.1/udp/9000/quic-v1",
                "--listen",
                "/ip4/0.0.0.0/udp/9100/quic-v1",
                "--checkpoint-sync-url",
                "http://localhost:5052",
                "--validator-keys",
                str(keys_dir),
                "--node-id",
                "node_7",
                "--verbose",
                "--no-color",
                "--is-aggregator",
                "--aggregate-subnet-ids",
                "0,1",
                "--api-port",
                "8080",
            ]
        ) == CliArgs(
            genesis_path=Path("g.yaml"),
            bootnodes=("/ip4/1.1.1.1/udp/9000/quic-v1",),
            listen_addr="/ip4/0.0.0.0/udp/9100/quic-v1",
            checkpoint_sync_url="http://localhost:5052",
            validator_keys_path=keys_dir,
            node_id="node_7",
            verbose=True,
            no_color=True,
            is_aggregator=True,
            aggregate_subnet_ids_raw="0,1",
            api_port=8080,
        )


class TestBootnodeRepetition:
    """Repeated bootnode flags accumulate in order."""

    def test_repeated_bootnode_preserves_order(self) -> None:
        """Three repeats produce a tuple of three strings in input order."""
        args = parse_args(
            [
                "--genesis",
                "g.yaml",
                "--bootnode",
                "a",
                "--bootnode",
                "b",
                "--bootnode",
                "c",
            ]
        )
        assert args.bootnodes == ("a", "b", "c")


class TestApiPort:
    """Round-trip parsing for the API port flag."""

    @pytest.mark.parametrize("port", [0, 8080])
    def test_api_port_round_trip(self, port: int) -> None:
        """The parsed port equals the integer passed on the command line."""
        args = parse_args(["--genesis", "g.yaml", "--api-port", str(port)])
        assert args.api_port == port


class TestRequiredArguments:
    """Missing required flags exit via the standard parser."""

    def test_genesis_is_required(self) -> None:
        """Omitting the genesis flag causes argparse to exit the process."""
        with pytest.raises(SystemExit):
            parse_args([])


class TestBooleanFlags:
    """Each boolean flag flips its dedicated field."""

    def test_is_aggregator_flag(self) -> None:
        """The aggregator flag sets its field to true."""
        assert parse_args(["--genesis", "g.yaml", "--is-aggregator"]).is_aggregator is True

    def test_no_color_flag(self) -> None:
        """The no-color flag sets its field to true."""
        assert parse_args(["--genesis", "g.yaml", "--no-color"]).no_color is True

    def test_verbose_long_form(self) -> None:
        """The long verbose flag sets its field to true."""
        assert parse_args(["--genesis", "g.yaml", "--verbose"]).verbose is True

    def test_verbose_short_form(self) -> None:
        """The short verbose flag sets the same field as the long form."""
        assert parse_args(["--genesis", "g.yaml", "-v"]).verbose is True
