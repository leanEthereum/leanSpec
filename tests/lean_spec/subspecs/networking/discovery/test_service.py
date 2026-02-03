"""
Tests for Discovery v5 service layer.

Tests the DiscoveryService class.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lean_spec.subspecs.networking.discovery.config import DiscoveryConfig
from lean_spec.subspecs.networking.discovery.routing import NodeEntry
from lean_spec.subspecs.networking.discovery.service import (
    DiscoveryService,
    LookupResult,
)
from lean_spec.subspecs.networking.enr import ENR
from lean_spec.subspecs.networking.types import NodeId, SeqNumber
from lean_spec.types import Bytes64, Uint64


@pytest.fixture
def local_private_key():
    """Private key for testing."""
    return bytes.fromhex("66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628")


@pytest.fixture
def local_enr():
    """Create a minimal local ENR for testing."""
    return ENR(
        signature=Bytes64(bytes(64)),
        seq=Uint64(1),
        pairs={
            "id": b"v4",
            "secp256k1": bytes.fromhex(
                "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
            ),
            "ip": bytes([127, 0, 0, 1]),
            "udp": (9000).to_bytes(2, "big"),
        },
    )


@pytest.fixture
def remote_node_id():
    """Remote node ID for testing."""
    return bytes.fromhex("aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb")


class TestDiscoveryServiceInit:
    """Tests for DiscoveryService initialization."""

    def test_init_creates_required_components(self, local_enr, local_private_key):
        """Service initializes all required components."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        assert service._local_enr is local_enr
        assert service._private_key == local_private_key
        assert service._routing_table is not None
        assert service._transport is not None
        assert service._bond_cache is not None
        assert not service._running

    def test_init_with_custom_config(self, local_enr, local_private_key):
        """Service accepts custom configuration."""
        config = DiscoveryConfig(request_timeout_secs=30.0)

        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
            config=config,
        )

        assert service._config.request_timeout_secs == 30.0

    def test_init_with_bootnodes(self, local_enr, local_private_key):
        """Service accepts bootnodes list."""
        bootnode = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": bytes.fromhex(
                    "02a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
                ),
            },
        )

        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
            bootnodes=[bootnode],
        )

        assert len(service._bootnodes) == 1

    def test_init_requires_public_key_in_enr(self, local_private_key):
        """Service requires ENR to have a public key."""
        enr_without_pubkey = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"id": b"v4"},
        )

        with pytest.raises(ValueError, match="must have a public key"):
            DiscoveryService(
                local_enr=enr_without_pubkey,
                private_key=local_private_key,
            )


class TestDiscoveryServiceTalkHandlers:
    """Tests for TALK protocol handlers."""

    def test_register_talk_handler(self, local_enr, local_private_key):
        """TALK handlers can be registered."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        handler = MagicMock(return_value=b"response")
        service.register_talk_handler(b"test", handler)

        assert service._talk_handlers[b"test"] is handler

    def test_multiple_talk_handlers(self, local_enr, local_private_key):
        """Multiple TALK handlers for different protocols."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        handler1 = MagicMock(return_value=b"response1")
        handler2 = MagicMock(return_value=b"response2")

        service.register_talk_handler(b"proto1", handler1)
        service.register_talk_handler(b"proto2", handler2)

        assert service._talk_handlers[b"proto1"] is handler1
        assert service._talk_handlers[b"proto2"] is handler2


class TestDiscoveryServiceNodeOperations:
    """Tests for node operations."""

    def test_get_random_nodes_empty_table(self, local_enr, local_private_key):
        """Get random nodes from empty table returns empty list."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        nodes = service.get_random_nodes(10)
        assert nodes == []

    def test_get_random_nodes_with_entries(self, local_enr, local_private_key):
        """Get random nodes returns up to requested count."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        # Add some nodes to routing table.
        for i in range(5):
            node_id = bytes([i]) + bytes(31)
            entry = NodeEntry(node_id=NodeId(node_id), enr_seq=SeqNumber(1))
            service._routing_table.add(entry)

        nodes = service.get_random_nodes(3)
        assert len(nodes) <= 3

    def test_get_nodes_at_distance(self, local_enr, local_private_key):
        """Get nodes at specific distance."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        nodes = service.get_nodes_at_distance(128)
        assert isinstance(nodes, list)

    def test_node_count_empty_table(self, local_enr, local_private_key):
        """Node count for empty table is zero."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        assert service.node_count() == 0


class TestLookupResult:
    """Tests for LookupResult dataclass."""

    def test_create_lookup_result(self):
        """LookupResult stores all fields."""
        target = bytes(32)
        nodes = [NodeEntry(node_id=NodeId(bytes(32)), enr_seq=SeqNumber(1))]

        result = LookupResult(target=target, nodes=nodes, queried=5)

        assert result.target == target
        assert result.nodes == nodes
        assert result.queried == 5

    def test_empty_lookup_result(self):
        """LookupResult can have empty nodes list."""
        result = LookupResult(target=bytes(32), nodes=[], queried=0)

        assert result.nodes == []
        assert result.queried == 0


class TestDiscoveryServiceLifecycle:
    """Tests for service lifecycle."""

    @pytest.mark.anyio
    async def test_start_sets_running_flag(self, local_enr, local_private_key):
        """Starting service sets running flag."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        with patch.object(service._transport, "start", new=AsyncMock()):
            await service.start("127.0.0.1", 9000)

        assert service._running

        # Clean up.
        with patch.object(service._transport, "stop", new=AsyncMock()):
            await service.stop()

    @pytest.mark.anyio
    async def test_start_is_idempotent(self, local_enr, local_private_key):
        """Starting already-running service does nothing."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        with patch.object(service._transport, "start", new=AsyncMock()) as mock_start:
            await service.start("127.0.0.1", 9000)
            await service.start("127.0.0.1", 9000)

            assert mock_start.call_count == 1

        with patch.object(service._transport, "stop", new=AsyncMock()):
            await service.stop()

    @pytest.mark.anyio
    async def test_stop_clears_running_flag(self, local_enr, local_private_key):
        """Stopping service clears running flag."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        with patch.object(service._transport, "start", new=AsyncMock()):
            await service.start("127.0.0.1", 9000)

        with patch.object(service._transport, "stop", new=AsyncMock()):
            await service.stop()

        assert not service._running

    @pytest.mark.anyio
    async def test_stop_is_idempotent(self, local_enr, local_private_key):
        """Stopping already-stopped service does nothing."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        # Stop without starting.
        with patch.object(service._transport, "stop", new=AsyncMock()) as mock_stop:
            await service.stop()
            await service.stop()

            # Should not call transport.stop if not running.
            assert mock_stop.call_count == 0


class TestFindNode:
    """Tests for find_node lookup operation."""

    @pytest.mark.anyio
    async def test_find_node_invalid_target_length(self, local_enr, local_private_key):
        """find_node rejects targets that aren't 32 bytes."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        with pytest.raises(ValueError, match="32 bytes"):
            await service.find_node(b"too short")

    @pytest.mark.anyio
    async def test_find_node_empty_table(self, local_enr, local_private_key):
        """find_node with empty routing table returns empty result."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        result = await service.find_node(bytes(32))

        assert result.target == bytes(32)
        assert result.nodes == []
        assert result.queried == 0


# ==============================================================================
# Phase 5: Address Handling Tests - ENR Address Extraction
# ==============================================================================


class TestENRAddressExtraction:
    """Extract endpoints from ENR."""

    def test_enr_ip4_extraction(self, local_private_key):
        """Extract IPv4 address from ENR."""
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": bytes.fromhex(
                    "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
                ),
                "ip": bytes([127, 0, 0, 1]),
                "udp": (9000).to_bytes(2, "big"),
            },
        )

        # Check IPv4 extraction.
        assert enr.ip4 == "127.0.0.1"
        assert enr.udp_port == 9000

    def test_enr_ip6_extraction(self, local_private_key):
        """Extract IPv6 address from ENR."""
        # IPv6 loopback ::1
        ipv6_bytes = bytes(15) + b"\x01"

        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": bytes.fromhex(
                    "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
                ),
                "ip6": ipv6_bytes,
                "udp6": (9000).to_bytes(2, "big"),
            },
        )

        # Check IPv6 extraction. ENR returns expanded form.
        assert enr.ip6 is not None
        assert "0001" in enr.ip6  # Contains the ::1 part

    def test_enr_dual_stack_has_both(self, local_private_key):
        """ENR with both IPv4 and IPv6 extracts both."""
        ipv6_bytes = bytes(15) + b"\x01"

        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": bytes.fromhex(
                    "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
                ),
                "ip": bytes([192, 168, 1, 1]),
                "udp": (9000).to_bytes(2, "big"),
                "ip6": ipv6_bytes,
                "udp6": (9001).to_bytes(2, "big"),
            },
        )

        # Both should be available.
        assert enr.ip4 == "192.168.1.1"
        assert enr.ip6 is not None

    def test_enr_missing_ip_returns_none(self, local_private_key):
        """ENR without IP returns None for ip4."""
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": bytes.fromhex(
                    "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
                ),
            },
        )

        assert enr.ip4 is None
        assert enr.udp_port is None


class TestServiceIPAddressEncoding:
    """Tests for IP address encoding in service layer."""

    @pytest.fixture
    def local_enr(self):
        """Create a minimal local ENR for testing."""
        return ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": bytes.fromhex(
                    "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
                ),
                "ip": bytes([127, 0, 0, 1]),
                "udp": (9000).to_bytes(2, "big"),
            },
        )

    @pytest.fixture
    def local_private_key(self):
        """Private key for testing."""
        return bytes.fromhex("66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628")

    def test_encode_ipv4_loopback(self, local_enr, local_private_key):
        """Encode IPv4 loopback address."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        encoded = service._encode_ip_address("127.0.0.1")

        assert encoded == b"\x7f\x00\x00\x01"
        assert len(encoded) == 4

    def test_encode_ipv4_common_addresses(self, local_enr, local_private_key):
        """Encode common IPv4 addresses."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        test_cases = [
            ("0.0.0.0", b"\x00\x00\x00\x00"),
            ("192.168.1.1", b"\xc0\xa8\x01\x01"),
            ("10.0.0.1", b"\x0a\x00\x00\x01"),
            ("255.255.255.255", b"\xff\xff\xff\xff"),
        ]

        for ip_str, expected_bytes in test_cases:
            encoded = service._encode_ip_address(ip_str)
            assert encoded == expected_bytes
            assert len(encoded) == 4

    def test_encode_ipv6_loopback(self, local_enr, local_private_key):
        """Encode IPv6 loopback address."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        encoded = service._encode_ip_address("::1")

        expected = bytes(15) + b"\x01"
        assert encoded == expected
        assert len(encoded) == 16

    def test_encode_ipv6_common_addresses(self, local_enr, local_private_key):
        """Encode common IPv6 addresses."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        # :: (all zeros)
        encoded_zeros = service._encode_ip_address("::")
        assert encoded_zeros == bytes(16)

        # ::1 (loopback)
        encoded_loopback = service._encode_ip_address("::1")
        assert encoded_loopback == bytes(15) + b"\x01"


# ==============================================================================
# Phase 8: Service Lookup Operations Tests
# ==============================================================================


class TestLookupAlgorithm:
    """Iterative Kademlia lookup tests."""

    @pytest.fixture
    def local_enr(self):
        """Create a minimal local ENR for testing."""
        return ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": bytes.fromhex(
                    "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
                ),
                "ip": bytes([127, 0, 0, 1]),
                "udp": (9000).to_bytes(2, "big"),
            },
        )

    @pytest.fixture
    def local_private_key(self):
        """Private key for testing."""
        return bytes.fromhex("66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628")

    @pytest.mark.anyio
    async def test_lookup_with_no_seeds_returns_empty(self, local_enr, local_private_key):
        """Lookup with empty routing table returns empty result."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
        )

        target = bytes(32)
        result = await service.find_node(target)

        assert result.target == target
        assert result.nodes == []
        assert result.queried == 0

    def test_lookup_result_tracks_queries(self, local_enr, local_private_key):
        """LookupResult tracks number of queries made."""
        result = LookupResult(
            target=bytes(32),
            nodes=[],
            queried=5,
        )

        assert result.queried == 5

    def test_lookup_result_contains_nodes(self, local_enr, local_private_key):
        """LookupResult contains found nodes."""
        from lean_spec.subspecs.networking.types import NodeId

        nodes = [NodeEntry(node_id=NodeId(bytes([i]) + bytes(31))) for i in range(3)]

        result = LookupResult(
            target=bytes(32),
            nodes=nodes,
            queried=3,
        )

        assert len(result.nodes) == 3


class TestBootstrap:
    """Bootnode initialization tests."""

    @pytest.fixture
    def local_enr(self):
        """Create a minimal local ENR for testing."""
        return ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": bytes.fromhex(
                    "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91"
                ),
                "ip": bytes([127, 0, 0, 1]),
                "udp": (9000).to_bytes(2, "big"),
            },
        )

    @pytest.fixture
    def local_private_key(self):
        """Private key for testing."""
        return bytes.fromhex("66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628")

    def test_service_accepts_bootnodes(self, local_enr, local_private_key):
        """Service accepts bootnodes in constructor."""
        bootnode = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": bytes.fromhex(
                    "02a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
                ),
                "ip": bytes([192, 168, 1, 1]),
                "udp": (30303).to_bytes(2, "big"),
            },
        )

        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
            bootnodes=[bootnode],
        )

        assert len(service._bootnodes) == 1

    def test_service_accepts_multiple_bootnodes(self, local_enr, local_private_key):
        """Service accepts multiple bootnodes."""
        bootnodes = []
        for i in range(5):
            bootnode = ENR(
                signature=Bytes64(bytes(64)),
                seq=Uint64(i + 1),
                pairs={
                    "id": b"v4",
                    "secp256k1": bytes.fromhex(
                        "02a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
                    ),
                    "ip": bytes([192, 168, 1, i + 1]),
                    "udp": (30303 + i).to_bytes(2, "big"),
                },
            )
            bootnodes.append(bootnode)

        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
            bootnodes=bootnodes,
        )

        assert len(service._bootnodes) == 5

    def test_service_handles_empty_bootnodes(self, local_enr, local_private_key):
        """Service handles empty bootnodes list."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
            bootnodes=[],
        )

        assert len(service._bootnodes) == 0

    def test_service_handles_none_bootnodes(self, local_enr, local_private_key):
        """Service handles None bootnodes."""
        service = DiscoveryService(
            local_enr=local_enr,
            private_key=local_private_key,
            bootnodes=None,
        )

        assert len(service._bootnodes) == 0
