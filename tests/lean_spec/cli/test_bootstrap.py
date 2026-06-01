"""Tests for the validated, file-loaded boot configuration."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Callable
from unittest.mock import AsyncMock, patch

import pytest
from consensus_testing.keys import XmssKeyManager
from Crypto.Hash import keccak
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from lean_spec.cli import CliValidationError, NodeBootstrap, parse_args
from lean_spec.node.api import ApiServerConfig
from lean_spec.node.networking.enr.rlp import RLPItem, encode_rlp
from lean_spec.spec.forks import Slot, SubnetId, ValidatorIndex

MULTIADDR_IPV4 = "/ip4/127.0.0.1/udp/9000/quic-v1"
"""Valid QUIC multiaddr used to exercise the pass-through resolution path."""


@pytest.fixture(scope="session")
def enr_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """One secp256k1 keypair shared across the whole session."""
    private_key = ec.generate_private_key(ec.SECP256K1())
    compressed_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    return private_key, compressed_public_key


@pytest.fixture(scope="session")
def make_enr(
    enr_keypair: tuple[ec.EllipticCurvePrivateKey, bytes],
) -> Callable[..., str]:
    """Build a signed ENR string for the given IP and optional UDP port."""
    private_key, compressed_public_key = enr_keypair

    def _sign(content_items: list[RLPItem]) -> bytes:
        # Hash the RLP-encoded content with keccak-256 and sign the digest.
        content_rlp = encode_rlp(content_items)
        digest = keccak.new(digest_bits=256, data=content_rlp).digest()
        signature_der = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

        # Convert DER-encoded signature to the 64-byte r-then-s form ENR expects.
        r, s = decode_dss_signature(signature_der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def _build(ip_bytes: bytes, udp_port: int | None = None) -> str:
        # Content items must keep keys sorted lexicographically.
        content_items: list[RLPItem] = [
            b"\x01",
            b"id",
            b"v4",
            b"ip",
            ip_bytes,
            b"secp256k1",
            compressed_public_key,
        ]

        # UDP port is optional; absent means the record has no dialable endpoint.
        if udp_port is not None:
            content_items.extend([b"udp", udp_port.to_bytes(2, "big")])

        # Wrap content with the signature and base64-url-encode for the text form.
        signature = _sign(content_items)
        rlp_data = encode_rlp([signature, *content_items])
        b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")
        return f"enr:{b64_content}"

    return _build


@pytest.fixture
def enr_with_udp(make_enr: Callable[..., str]) -> str:
    """Signed ENR for 192.168.1.1 with UDP port 9000."""
    return make_enr(b"\xc0\xa8\x01\x01", 9000)


@pytest.fixture
def enr_without_udp(make_enr: Callable[..., str]) -> str:
    """Signed ENR for 192.168.1.1 with no UDP port."""
    return make_enr(b"\xc0\xa8\x01\x01")


@pytest.fixture
def genesis_yaml(tmp_path: Path) -> Path:
    """Write a minimal genesis YAML to a temporary path."""
    path = tmp_path / "genesis.yaml"
    path.write_text("GENESIS_TIME: 1000\nGENESIS_VALIDATORS: []\n")
    return path


@pytest.fixture
def validator_keys_directory(tmp_path: Path) -> Path:
    """Materialise a one-validator key directory the registry loader accepts."""
    # The registry loader expects the ream/zeam two-file layout.
    keys_root = tmp_path / "keys"
    hash_signature_directory = keys_root / "hash-sig-keys"
    hash_signature_directory.mkdir(parents=True)

    # Borrow a real precomputed XMSS keypair from the shared manager.
    km = XmssKeyManager.shared(max_slot=Slot(10))
    kp = km[ValidatorIndex(0)]

    # Drop both secret keys to disk under the names the manifest references.
    (hash_signature_directory / "att_key_0.ssz").write_bytes(
        kp.attestation_keypair.secret_key.encode_bytes()
    )
    (hash_signature_directory / "prop_key_0.ssz").write_bytes(
        kp.proposal_keypair.secret_key.encode_bytes()
    )

    # Manifest carries one validator with placeholder public keys.
    # The loader does not verify the public_keys against the secret keys here.
    manifest = hash_signature_directory / "validator-keys-manifest.yaml"
    manifest.write_text(
        "key_scheme: SIGTopLevelTargetSumLifetime32Dim64Base8\n"
        "hash_function: Poseidon2\n"
        "encoding: TargetSum\n"
        "lifetime: 32\n"
        "log_num_active_epochs: 5\n"
        "num_active_epochs: 32\n"
        "num_validators: 1\n"
        "validators:\n"
        "  - index: 0\n"
        f"    attestation_public_key_hex: '0x{'00' * 52}'\n"
        f"    proposal_public_key_hex: '0x{'00' * 52}'\n"
        "    attestation_private_key_file: att_key_0.ssz\n"
        "    proposal_private_key_file: prop_key_0.ssz\n"
    )

    # Node-to-validator mapping assigns the only validator to the default node id.
    (keys_root / "validators.yaml").write_text("lean_spec_0: [0]\n")
    return keys_root


@pytest.fixture
def make_boot(genesis_yaml: Path) -> Callable[..., NodeBootstrap]:
    """Build a boot configuration from extra CLI tokens, auto-prefixing the genesis flag."""

    def _build(*extra: str) -> NodeBootstrap:
        return NodeBootstrap.from_cli_args(parse_args(["--genesis", str(genesis_yaml), *extra]))

    return _build


class TestBootnodeResolution:
    """Tests for bootnode resolution at the CLI boundary."""

    def test_multiaddr_passes_through(self, make_boot: Callable[..., NodeBootstrap]) -> None:
        """A bare multiaddr is kept as-is."""
        boot = make_boot("--bootnode", MULTIADDR_IPV4)
        assert boot.bootnode_multiaddrs == (MULTIADDR_IPV4,)

    def test_enr_resolves_to_multiaddr(
        self, make_boot: Callable[..., NodeBootstrap], enr_with_udp: str
    ) -> None:
        """An ENR carrying UDP info expands to its dialable multiaddr view."""
        boot = make_boot("--bootnode", enr_with_udp)
        assert boot.bootnode_multiaddrs == ("/ip4/192.168.1.1/udp/9000/quic-v1",)

    def test_enr_without_udp_rejected(
        self, make_boot: Callable[..., NodeBootstrap], enr_without_udp: str
    ) -> None:
        """An ENR lacking UDP info is rejected before any dial attempt."""
        with pytest.raises(CliValidationError, match=r"no UDP connection info"):
            make_boot("--bootnode", enr_without_udp)

    def test_malformed_enr_rejected(self, make_boot: Callable[..., NodeBootstrap]) -> None:
        """A malformed ENR fails at RLP decoding."""
        with pytest.raises(ValueError, match=r"Invalid RLP"):
            make_boot("--bootnode", "enr:YWJj")

    def test_mixed_inputs_preserve_order(
        self, make_boot: Callable[..., NodeBootstrap], enr_with_udp: str
    ) -> None:
        """Mixed multiaddr and ENR inputs resolve into a single ordered tuple."""
        boot = make_boot(
            "--bootnode",
            MULTIADDR_IPV4,
            "--bootnode",
            enr_with_udp,
            "--bootnode",
            "/ip4/10.0.0.1/udp/8000/quic-v1",
        )
        assert boot.bootnode_multiaddrs == (
            MULTIADDR_IPV4,
            "/ip4/192.168.1.1/udp/9000/quic-v1",
            "/ip4/10.0.0.1/udp/8000/quic-v1",
        )

    def test_no_bootnodes_resolves_empty_tuple(
        self, make_boot: Callable[..., NodeBootstrap]
    ) -> None:
        """No bootnode flags resolve to an empty tuple."""
        assert make_boot().bootnode_multiaddrs == ()


class TestNodeBootstrapValidation:
    """Tests for the CLI argument validator."""

    def test_aggregator_without_validator_keys_rejected(
        self, make_boot: Callable[..., NodeBootstrap]
    ) -> None:
        """The aggregator flag requires a validator keys path."""
        with pytest.raises(CliValidationError, match="--is-aggregator requires --validator-keys"):
            make_boot("--is-aggregator")


class TestAggregateSubnetIds:
    """Tests for parsing the extra-subnets flag."""

    def test_empty_string_parses_to_empty_tuple(
        self, make_boot: Callable[..., NodeBootstrap]
    ) -> None:
        """An empty extras string resolves to an empty subnet tuple."""
        boot = make_boot("--aggregate-subnet-ids", "")
        assert boot.aggregate_subnet_ids == ()

    def test_valid_extras_parse_into_tuple(
        self, make_boot: Callable[..., NodeBootstrap], validator_keys_directory: Path
    ) -> None:
        """A comma list with aggregator mode and a populated registry resolves in order."""
        boot = make_boot(
            "--validator-keys",
            str(validator_keys_directory),
            "--is-aggregator",
            "--aggregate-subnet-ids",
            "1,2,3",
        )
        assert boot.aggregate_subnet_ids == (SubnetId(1), SubnetId(2), SubnetId(3))

    def test_extras_without_aggregator_rejected(
        self, make_boot: Callable[..., NodeBootstrap]
    ) -> None:
        """Subnet extras without aggregator mode raise a typed validation error."""
        with pytest.raises(CliValidationError, match="requires --is-aggregator"):
            make_boot("--aggregate-subnet-ids", "1,2,3")

    def test_malformed_extras_rejected(
        self, make_boot: Callable[..., NodeBootstrap], tmp_path: Path
    ) -> None:
        """A non-integer token in the extras list raises a typed validation error."""
        # The integer parser runs before any registry load.
        # Any non-empty validator-keys path is enough to reach the parse branch.
        with pytest.raises(CliValidationError, match="comma-separated integers"):
            make_boot(
                "--validator-keys",
                str(tmp_path / "keys"),
                "--is-aggregator",
                "--aggregate-subnet-ids",
                "1,abc,3",
            )


class TestApiConfigResolution:
    """Tests for the api_config field on the boot configuration."""

    def test_zero_port_disables_api(self, make_boot: Callable[..., NodeBootstrap]) -> None:
        """A port of zero leaves the API configuration unset."""
        boot = make_boot("--api-port", "0")
        assert boot.api_config is None

    def test_non_zero_port_enables_api(self, make_boot: Callable[..., NodeBootstrap]) -> None:
        """A non-zero port produces an API configuration carrying that port."""
        boot = make_boot("--api-port", "5052")
        assert boot.api_config == ApiServerConfig(port=5052)


class TestListenAddressResolution:
    """Tests for the listen-address field on the boot configuration."""

    def test_empty_listen_address_becomes_none(
        self, make_boot: Callable[..., NodeBootstrap]
    ) -> None:
        """An empty listen string resolves to no listener."""
        boot = make_boot("--listen", "")
        assert boot.listen_address is None


class TestBuildAnchor:
    """Tests for the async anchor builder method."""

    async def test_no_checkpoint_calls_from_genesis(
        self, make_boot: Callable[..., NodeBootstrap]
    ) -> None:
        """Without a checkpoint URL the boot delegates to the synchronous genesis builder."""
        boot = make_boot()
        anchor = await boot.build_anchor()

        assert anchor.store is None
        assert anchor.validators == boot.genesis.to_validators()

    async def test_checkpoint_url_calls_from_checkpoint(
        self, make_boot: Callable[..., NodeBootstrap]
    ) -> None:
        """With a checkpoint URL the boot delegates to the asynchronous checkpoint builder.

        The real checkpoint path needs a fetched state plus a constructed store.
        A dispatch-via-mock keeps the test focused on the dispatch contract.
        """
        boot = make_boot("--checkpoint-sync-url", "http://localhost:5052")

        sentinel = object()
        with patch(
            "lean_spec.cli.bootstrap.Anchor.from_checkpoint",
            new_callable=AsyncMock,
            return_value=sentinel,
        ) as from_checkpoint:
            anchor = await boot.build_anchor()

        assert anchor is sentinel
        await_args = from_checkpoint.await_args
        assert await_args is not None
        assert await_args.kwargs == {
            "url": "http://localhost:5052",
            "genesis": boot.genesis,
            "fork": boot.fork,
            "validator_index": boot.registry.primary_index(),
        }
