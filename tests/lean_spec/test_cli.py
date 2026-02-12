"""Tests for CLI functions.

Tests the ENR detection, bootnode resolution, and checkpoint sync functionality
used by the CLI.
"""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, patch

import pytest
from Crypto.Hash import keccak
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature

from lean_spec.__main__ import (
    _init_from_checkpoint,
    create_anchor_block,
    is_enr_string,
    resolve_bootnode,
)
from lean_spec.subspecs.containers import Block, BlockBody
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.genesis import GenesisConfig
from lean_spec.subspecs.node import Node
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.checkpoint_sync import CheckpointSyncError
from lean_spec.types import Bytes32, Uint64
from lean_spec.types.rlp import encode_rlp
from tests.lean_spec.helpers import make_genesis_state

# Generate a test keypair once for all ENR tests.
_TEST_PRIVATE_KEY = ec.generate_private_key(ec.SECP256K1())
_TEST_PUBLIC_KEY = _TEST_PRIVATE_KEY.public_key()
_TEST_COMPRESSED_PUBKEY = _TEST_PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.CompressedPoint,
)


def _sign_enr_content(content_items: list[bytes]) -> bytes:
    """Sign ENR content and return 64-byte r||s signature."""
    content_rlp = encode_rlp(content_items)

    k = keccak.new(digest_bits=256)
    k.update(content_rlp)
    digest = k.digest()

    signature_der = _TEST_PRIVATE_KEY.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(signature_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _make_enr_with_udp(ip_bytes: bytes, udp_port: int) -> str:
    """Create a properly signed ENR string with IPv4 and UDP port."""
    # Content items (keys must be sorted).
    content_items: list[bytes] = [
        b"\x01",  # seq = 1
        b"id",
        b"v4",
        b"ip",
        ip_bytes,
        b"secp256k1",
        _TEST_COMPRESSED_PUBKEY,
        b"udp",
        udp_port.to_bytes(2, "big"),
    ]
    signature = _sign_enr_content(content_items)

    rlp_data = encode_rlp([signature] + content_items)
    b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")
    return f"enr:{b64_content}"


def _make_enr_with_ipv6_udp(ip6_bytes: bytes, udp_port: int) -> str:
    """Create a properly signed ENR string with IPv6 and UDP port."""
    content_items: list[bytes] = [
        b"\x01",  # seq = 1
        b"id",
        b"v4",
        b"ip6",
        ip6_bytes,
        b"secp256k1",
        _TEST_COMPRESSED_PUBKEY,
        b"udp",
        udp_port.to_bytes(2, "big"),
    ]
    signature = _sign_enr_content(content_items)

    rlp_data = encode_rlp([signature] + content_items)
    b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")
    return f"enr:{b64_content}"


def _make_enr_without_udp(ip_bytes: bytes) -> str:
    """Create a properly signed ENR string with IPv4 but no UDP port."""
    content_items: list[bytes] = [
        b"\x01",  # seq = 1
        b"id",
        b"v4",
        b"ip",
        ip_bytes,
        b"secp256k1",
        _TEST_COMPRESSED_PUBKEY,
    ]
    signature = _sign_enr_content(content_items)

    rlp_data = encode_rlp([signature] + content_items)
    b64_content = base64.urlsafe_b64encode(rlp_data).decode("utf-8").rstrip("=")
    return f"enr:{b64_content}"


# Pre-built test ENRs
ENR_WITH_UDP = _make_enr_with_udp(b"\xc0\xa8\x01\x01", 9000)  # 192.168.1.1:9000
ENR_WITH_IPV6_UDP = _make_enr_with_ipv6_udp(b"\x00" * 15 + b"\x01", 9000)  # ::1:9000
ENR_WITHOUT_UDP = _make_enr_without_udp(b"\xc0\xa8\x01\x01")  # 192.168.1.1, no UDP

# Valid multiaddr strings (QUIC format)
MULTIADDR_IPV4 = "/ip4/127.0.0.1/udp/9000/quic-v1"
MULTIADDR_IPV6 = "/ip6/::1/udp/9000/quic-v1"


class TestIsEnrString:
    """Tests for is_enr_string() detection function."""

    def test_enr_string_detected(self) -> None:
        """Valid ENR prefix returns True."""
        assert is_enr_string("enr:-IS4QHCYrYZbAKW...") is True

    def test_enr_prefix_minimal(self) -> None:
        """Minimal ENR prefix 'enr:' returns True."""
        assert is_enr_string("enr:") is True

    def test_enr_with_valid_content(self) -> None:
        """Full valid ENR string returns True."""
        assert is_enr_string(ENR_WITH_UDP) is True

    def test_multiaddr_not_detected(self) -> None:
        """Multiaddr string returns False."""
        assert is_enr_string(MULTIADDR_IPV4) is False
        assert is_enr_string(MULTIADDR_IPV6) is False

    def test_empty_string(self) -> None:
        """Empty string returns False."""
        assert is_enr_string("") is False

    def test_enode_not_detected(self) -> None:
        """enode:// format returns False."""
        enode = "enode://abc123@127.0.0.1:30303"
        assert is_enr_string(enode) is False

    def test_similar_prefix_not_detected(self) -> None:
        """Strings with similar but incorrect prefixes return False."""
        assert is_enr_string("ENR:") is False  # Case sensitive
        assert is_enr_string("enr") is False  # Missing colon
        assert is_enr_string("enr-") is False  # Wrong separator
        assert is_enr_string("enrs:") is False  # Extra character

    def test_whitespace_prefix_not_detected(self) -> None:
        """Whitespace before prefix returns False."""
        assert is_enr_string(" enr:abc") is False
        assert is_enr_string("\tenr:abc") is False


class TestResolveBootnode:
    """Tests for resolve_bootnode() resolution function."""

    def test_resolve_multiaddr_unchanged(self) -> None:
        """Multiaddr strings are returned unchanged."""
        assert resolve_bootnode(MULTIADDR_IPV4) == MULTIADDR_IPV4
        assert resolve_bootnode(MULTIADDR_IPV6) == MULTIADDR_IPV6

    def test_resolve_arbitrary_multiaddr_unchanged(self) -> None:
        """Any non-ENR string passes through unchanged."""
        # The function does not validate multiaddr format
        arbitrary = "/some/arbitrary/path"
        assert resolve_bootnode(arbitrary) == arbitrary

    def test_resolve_valid_enr_with_udp(self) -> None:
        """ENR with IPv4+UDP extracts QUIC multiaddr correctly."""
        result = resolve_bootnode(ENR_WITH_UDP)
        assert result == "/ip4/192.168.1.1/udp/9000/quic-v1"

    def test_resolve_enr_ipv6(self) -> None:
        """ENR with IPv6+UDP extracts QUIC multiaddr correctly."""
        result = resolve_bootnode(ENR_WITH_IPV6_UDP)
        # IPv6 loopback ::1 formatted as full hex
        assert "/ip6/" in result
        assert "/udp/9000/quic-v1" in result

    def test_resolve_enr_without_udp_raises(self) -> None:
        """ENR without UDP port raises ValueError."""
        with pytest.raises(ValueError, match=r"no UDP connection info"):
            resolve_bootnode(ENR_WITHOUT_UDP)

    def test_resolve_invalid_enr_raises(self) -> None:
        """Malformed ENR raises ValueError."""
        # Valid base64 but invalid RLP structure
        with pytest.raises(ValueError, match=r"Invalid RLP"):
            resolve_bootnode("enr:YWJj")  # "abc" in base64, not valid RLP structure

        # Another invalid RLP - too short for ENR
        with pytest.raises(ValueError, match=r"(Invalid RLP|at least signature)"):
            resolve_bootnode("enr:wA")  # Single byte 0xc0 = empty list

    def test_resolve_enr_prefix_only_raises(self) -> None:
        """ENR with prefix only (no content) raises ValueError."""
        with pytest.raises(ValueError):
            resolve_bootnode("enr:")

    def test_resolve_enr_with_different_ports(self) -> None:
        """ENR resolution handles various port numbers."""
        # Port 30303
        enr_30303 = _make_enr_with_udp(b"\x7f\x00\x00\x01", 30303)
        result = resolve_bootnode(enr_30303)
        assert result == "/ip4/127.0.0.1/udp/30303/quic-v1"

        # Port 1 (minimum valid)
        enr_1 = _make_enr_with_udp(b"\x7f\x00\x00\x01", 1)
        result = resolve_bootnode(enr_1)
        assert result == "/ip4/127.0.0.1/udp/1/quic-v1"

        # Port 65535 (maximum)
        enr_max = _make_enr_with_udp(b"\x7f\x00\x00\x01", 65535)
        result = resolve_bootnode(enr_max)
        assert result == "/ip4/127.0.0.1/udp/65535/quic-v1"

    def test_resolve_enr_with_different_ips(self) -> None:
        """ENR resolution handles various IPv4 addresses."""
        test_cases = [
            (b"\x00\x00\x00\x00", "0.0.0.0"),
            (b"\xff\xff\xff\xff", "255.255.255.255"),
            (b"\x0a\x00\x00\x01", "10.0.0.1"),
        ]
        for ip_bytes, expected_ip in test_cases:
            enr = _make_enr_with_udp(ip_bytes, 9000)
            result = resolve_bootnode(enr)
            assert result == f"/ip4/{expected_ip}/udp/9000/quic-v1"


class TestMixedBootnodes:
    """Integration tests for mixed bootnode types."""

    def test_mixed_bootnodes_list(self) -> None:
        """Process a list containing both ENR and multiaddr."""
        bootnodes = [
            MULTIADDR_IPV4,
            ENR_WITH_UDP,
            "/ip4/10.0.0.1/udp/8000/quic-v1",
        ]

        resolved = [resolve_bootnode(b) for b in bootnodes]

        assert resolved[0] == MULTIADDR_IPV4
        assert resolved[1] == "/ip4/192.168.1.1/udp/9000/quic-v1"
        assert resolved[2] == "/ip4/10.0.0.1/udp/8000/quic-v1"

    def test_filter_invalid_enrs(self) -> None:
        """Demonstrate filtering out invalid ENRs from a bootnode list."""
        bootnodes = [
            MULTIADDR_IPV4,
            ENR_WITHOUT_UDP,  # Invalid - no UDP
            ENR_WITH_UDP,
        ]

        resolved = []
        for bootnode in bootnodes:
            try:
                resolved.append(resolve_bootnode(bootnode))
            except ValueError:
                continue  # Skip invalid

        assert len(resolved) == 2
        assert resolved[0] == MULTIADDR_IPV4
        assert resolved[1] == "/ip4/192.168.1.1/udp/9000/quic-v1"


class TestCreateAnchorBlock:
    """Tests for create_anchor_block() function."""

    def test_computes_state_root_when_zero(self) -> None:
        """State root is computed when header has zero state root."""
        # Arrange: Create a genesis state (header has zero state root)
        state = make_genesis_state(num_validators=3, genesis_time=1000)

        # Verify the header has zero state root
        assert state.latest_block_header.state_root == Bytes32.zero()

        # Act
        anchor_block = create_anchor_block(state)

        # Assert: State root should be computed from the state
        expected_state_root = hash_tree_root(state)
        assert anchor_block.state_root == expected_state_root
        assert anchor_block.state_root != Bytes32.zero()

    def test_preserves_non_zero_state_root(self) -> None:
        """Non-zero state root in header is preserved."""
        # Arrange: Create a state and process a slot to fill in state root
        state = make_genesis_state(num_validators=3, genesis_time=1000)
        # Process slot advances and fills in the state root
        state_with_root = state.process_slots(Slot(1))

        # The state root should now be non-zero in the header
        assert state_with_root.latest_block_header.state_root != Bytes32.zero()

        # Act
        anchor_block = create_anchor_block(state_with_root)

        # Assert: State root is preserved from the header
        assert anchor_block.state_root == state_with_root.latest_block_header.state_root

    def test_preserves_header_fields(self) -> None:
        """Slot, proposer_index, and parent_root are preserved from header."""
        # Arrange
        state = make_genesis_state(num_validators=3, genesis_time=1000)
        header = state.latest_block_header

        # Act
        anchor_block = create_anchor_block(state)

        # Assert: Core header fields are preserved
        assert anchor_block.slot == header.slot
        assert anchor_block.proposer_index == header.proposer_index
        assert anchor_block.parent_root == header.parent_root

    def test_creates_empty_body(self) -> None:
        """Block body contains empty attestations list."""
        # Arrange
        state = make_genesis_state(num_validators=3, genesis_time=1000)

        # Act
        anchor_block = create_anchor_block(state)

        # Assert: Body has empty attestations
        assert len(anchor_block.body.attestations) == 0

    def test_anchor_block_structure_is_valid(self) -> None:
        """Anchor block has all required fields populated."""
        # Arrange
        state = make_genesis_state(num_validators=5, genesis_time=2000)

        # Act
        anchor_block = create_anchor_block(state)

        # Assert: Block has proper structure
        assert isinstance(anchor_block, Block)
        assert isinstance(anchor_block.slot, Slot)
        assert isinstance(anchor_block.proposer_index, Uint64)
        assert isinstance(anchor_block.parent_root, Bytes32)
        assert isinstance(anchor_block.state_root, Bytes32)
        assert isinstance(anchor_block.body, BlockBody)
        assert isinstance(anchor_block.body.attestations, AggregatedAttestations)


class TestInitFromCheckpoint:
    """Tests for _init_from_checkpoint() async function."""

    async def test_checkpoint_sync_genesis_time_mismatch_returns_none(self) -> None:
        """Returns None when checkpoint state genesis time differs from local config."""
        # Arrange: Create checkpoint state with genesis_time=1000
        checkpoint_state = make_genesis_state(num_validators=3, genesis_time=1000)

        # Local genesis config with different genesis_time=2000
        local_genesis = GenesisConfig.model_validate(
            {
                "GENESIS_TIME": 2000,
                "GENESIS_VALIDATORS": [],
            }
        )

        # Mock the checkpoint sync client functions
        mock_event_source = AsyncMock()

        with (
            patch(
                "lean_spec.__main__.fetch_finalized_state",
                new_callable=AsyncMock,
                return_value=checkpoint_state,
            ),
            patch(
                "lean_spec.__main__.verify_checkpoint_state",
                new_callable=AsyncMock,
                return_value=True,
            ),
        ):
            # Act
            result = await _init_from_checkpoint(
                checkpoint_sync_url="http://localhost:5052",
                genesis=local_genesis,
                event_source=mock_event_source,
            )

        # Assert: Returns None due to genesis time mismatch
        assert result is None

    async def test_checkpoint_sync_verification_failure_returns_none(self) -> None:
        """Returns None when checkpoint state verification fails."""
        # Arrange
        checkpoint_state = make_genesis_state(num_validators=3, genesis_time=1000)
        local_genesis = GenesisConfig.model_validate(
            {
                "GENESIS_TIME": 1000,
                "GENESIS_VALIDATORS": [],
            }
        )

        mock_event_source = AsyncMock()

        with (
            patch(
                "lean_spec.__main__.fetch_finalized_state",
                new_callable=AsyncMock,
                return_value=checkpoint_state,
            ),
            patch(
                "lean_spec.__main__.verify_checkpoint_state",
                new_callable=AsyncMock,
                return_value=False,  # Verification fails
            ),
        ):
            # Act
            result = await _init_from_checkpoint(
                checkpoint_sync_url="http://localhost:5052",
                genesis=local_genesis,
                event_source=mock_event_source,
            )

        # Assert
        assert result is None

    async def test_checkpoint_sync_network_error_returns_none(self) -> None:
        """Returns None when network error occurs during fetch."""
        # Arrange
        local_genesis = GenesisConfig.model_validate(
            {
                "GENESIS_TIME": 1000,
                "GENESIS_VALIDATORS": [],
            }
        )

        mock_event_source = AsyncMock()

        with patch(
            "lean_spec.__main__.fetch_finalized_state",
            new_callable=AsyncMock,
            side_effect=CheckpointSyncError("Network error: connection refused"),
        ):
            # Act
            result = await _init_from_checkpoint(
                checkpoint_sync_url="http://localhost:5052",
                genesis=local_genesis,
                event_source=mock_event_source,
            )

        # Assert
        assert result is None

    async def test_checkpoint_sync_success_returns_node(self) -> None:
        """Successful checkpoint sync returns initialized Node."""
        # Arrange: Create matching genesis times
        genesis_time = 1000
        checkpoint_state = make_genesis_state(num_validators=3, genesis_time=genesis_time)

        local_genesis = GenesisConfig.model_validate(
            {
                "GENESIS_TIME": genesis_time,
                "GENESIS_VALIDATORS": [],
            }
        )

        # Create a mock event source with required attributes
        mock_event_source = AsyncMock()
        mock_event_source.reqresp_client = AsyncMock()

        with (
            patch(
                "lean_spec.__main__.fetch_finalized_state",
                new_callable=AsyncMock,
                return_value=checkpoint_state,
            ),
            patch(
                "lean_spec.__main__.verify_checkpoint_state",
                new_callable=AsyncMock,
                return_value=True,
            ),
        ):
            # Act
            result = await _init_from_checkpoint(
                checkpoint_sync_url="http://localhost:5052",
                genesis=local_genesis,
                event_source=mock_event_source,
            )

        # Assert: Returns a Node instance
        assert result is not None
        assert isinstance(result, Node)

        # Verify the node's store was initialized
        assert result.store is not None

    async def test_checkpoint_sync_http_status_error_returns_none(self) -> None:
        """Returns None when HTTP status error occurs."""
        # Arrange
        local_genesis = GenesisConfig.model_validate(
            {
                "GENESIS_TIME": 1000,
                "GENESIS_VALIDATORS": [],
            }
        )

        mock_event_source = AsyncMock()

        with patch(
            "lean_spec.__main__.fetch_finalized_state",
            new_callable=AsyncMock,
            side_effect=CheckpointSyncError("HTTP error 404: Not Found"),
        ):
            # Act
            result = await _init_from_checkpoint(
                checkpoint_sync_url="http://localhost:5052",
                genesis=local_genesis,
                event_source=mock_event_source,
            )

        # Assert
        assert result is None
