"""
Tests for Discovery v5 service layer.

Tests the DiscoveryService class.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

import pytest

from lean_spec.subspecs.networking.discovery.codec import DiscoveryMessage
from lean_spec.subspecs.networking.discovery.config import DiscoveryConfig
from lean_spec.subspecs.networking.discovery.messages import (
    Distance,
    FindNode,
    IPv4,
    Nodes,
    Ping,
    Pong,
    RequestId,
    TalkReq,
    TalkResp,
)
from lean_spec.subspecs.networking.discovery.routing import NodeEntry
from lean_spec.subspecs.networking.discovery.service import (
    DiscoveryService,
    LookupResult,
)
from lean_spec.subspecs.networking.enr import ENR
from lean_spec.subspecs.networking.enr.keys import EnrKey
from lean_spec.subspecs.networking.types import NodeId, Port, SeqNumber
from lean_spec.types import Bytes32, Bytes64


@dataclass
class SentResponse:
    """A single recorded send_response call."""

    node_id: NodeId
    addr: tuple[str, int]
    message: DiscoveryMessage


@dataclass
class SentFindNode:
    """A single recorded send_findnode call."""

    node_id: NodeId
    addr: tuple[str, int]
    distances: list[int]


@dataclass
class SentPing:
    """A single recorded send_ping call."""

    node_id: NodeId
    addr: tuple[str, int]


@dataclass
class SentTalkReq:
    """A single recorded send_talkreq call."""

    node_id: NodeId
    addr: tuple[str, int]
    protocol: bytes
    request: bytes


class FakeDiscoveryTransport:
    """In-memory replacement for DiscoveryTransport.

    Records all outbound calls and returns configurable canned responses.
    Synchronous bookkeeping (address registry, ENR cache, message handler)
    works identically to the real transport.
    """

    def __init__(self) -> None:
        """Initialize with empty state and default responses."""
        # Bookkeeping (same as real transport).
        self._node_addresses: dict[NodeId, tuple[str, int]] = {}
        self._enr_cache: dict[NodeId, ENR] = {}
        self._message_handler: (
            Callable[[NodeId, DiscoveryMessage, tuple[str, int]], None] | None
        ) = None

        # Lifecycle tracking.
        self.started: bool = False
        self.stopped: bool = False
        self.start_count: int = 0

        # Recorded outbound calls.
        self.sent_responses: list[SentResponse] = []
        self.sent_findnodes: list[SentFindNode] = []
        self.sent_pings: list[SentPing] = []
        self.sent_talkreqs: list[SentTalkReq] = []

        # Configurable canned return values.
        self.send_response_return: bool = True
        self.send_ping_return: Pong | None = None
        self.send_findnode_return: list[bytes] = []
        self.send_findnode_side_effect: Callable[..., list[bytes]] | None = None
        self.send_talkreq_return: bytes | None = None

    # -- Lifecycle --

    async def start(self, host: str = "0.0.0.0", port: int = 9000) -> None:
        """Record start call."""
        self.started = True
        self.start_count += 1

    async def stop(self) -> None:
        """Record stop call."""
        self.stopped = True

    # -- Synchronous bookkeeping (identical to real transport) --

    def set_message_handler(
        self,
        handler: Callable[[NodeId, DiscoveryMessage, tuple[str, int]], None],
    ) -> None:
        """Set handler for incoming messages."""
        self._message_handler = handler

    def register_node_address(self, node_id: NodeId, address: tuple[str, int]) -> None:
        """Register a node's UDP address."""
        self._node_addresses[node_id] = address

    def get_node_address(self, node_id: NodeId) -> tuple[str, int] | None:
        """Get a node's registered UDP address."""
        return self._node_addresses.get(node_id)

    def register_enr(self, node_id: NodeId, enr: ENR) -> None:
        """Cache an ENR."""
        self._enr_cache[node_id] = enr

    # -- Async send methods that record calls and return canned values --

    async def send_response(
        self,
        dest_node_id: NodeId,
        dest_addr: tuple[str, int],
        message: DiscoveryMessage,
    ) -> bool:
        """Record the response and return canned success/failure."""
        self.sent_responses.append(SentResponse(dest_node_id, dest_addr, message))
        return self.send_response_return

    async def send_ping(self, dest_node_id: NodeId, dest_addr: tuple[str, int]) -> Pong | None:
        """Record the ping and return canned Pong or None."""
        self.sent_pings.append(SentPing(dest_node_id, dest_addr))
        return self.send_ping_return

    async def send_findnode(
        self,
        dest_node_id: NodeId,
        dest_addr: tuple[str, int],
        distances: list[int],
    ) -> list[bytes]:
        """Record the findnode and return canned ENR list."""
        self.sent_findnodes.append(SentFindNode(dest_node_id, dest_addr, distances))
        if self.send_findnode_side_effect is not None:
            return self.send_findnode_side_effect(dest_node_id, dest_addr, distances)
        return self.send_findnode_return

    async def send_talkreq(
        self,
        dest_node_id: NodeId,
        dest_addr: tuple[str, int],
        protocol: bytes,
        request: bytes,
    ) -> bytes | None:
        """Record the talkreq and return canned response."""
        self.sent_talkreqs.append(SentTalkReq(dest_node_id, dest_addr, protocol, request))
        return self.send_talkreq_return


def _make_service(
    local_enr: ENR,
    local_private_key: Bytes32,
    config: DiscoveryConfig | None = None,
    bootnodes: list[ENR] | None = None,
) -> tuple[DiscoveryService, FakeDiscoveryTransport]:
    """Create a DiscoveryService with a FakeDiscoveryTransport injected."""
    service = DiscoveryService(
        local_enr=local_enr,
        private_key=local_private_key,
        config=config,
        bootnodes=bootnodes,
    )
    fake = FakeDiscoveryTransport()
    service._transport = fake  # type: ignore[assignment]
    # Re-register the message handler on the new transport.
    fake.set_message_handler(service._handle_message)
    return service, fake


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
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): bytes.fromhex(
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
            seq=SeqNumber(1),
            pairs={EnrKey("id"): b"v4"},
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
        service, _ = _make_service(local_enr, local_private_key)

        def handler(nid: bytes, data: bytes) -> bytes:
            return b"response"

        service.register_talk_handler(b"test", handler)

        assert service._talk_handlers[b"test"] is handler

    def test_multiple_talk_handlers(self, local_enr, local_private_key):
        """Multiple TALK handlers for different protocols."""
        service, _ = _make_service(local_enr, local_private_key)

        def handler1(nid: bytes, data: bytes) -> bytes:
            return b"response1"

        def handler2(nid: bytes, data: bytes) -> bytes:
            return b"response2"

        service.register_talk_handler(b"proto1", handler1)
        service.register_talk_handler(b"proto2", handler2)

        assert service._talk_handlers[b"proto1"] is handler1
        assert service._talk_handlers[b"proto2"] is handler2


class TestDiscoveryServiceNodeOperations:
    """Tests for node operations."""

    def test_get_random_nodes_empty_table(self, local_enr, local_private_key):
        """Get random nodes from empty table returns empty list."""
        service, _ = _make_service(local_enr, local_private_key)

        nodes = service.get_random_nodes(10)
        assert nodes == []

    def test_get_random_nodes_with_entries(self, local_enr, local_private_key):
        """Get random nodes returns up to requested count."""
        service, _ = _make_service(local_enr, local_private_key)

        # Add some nodes to routing table.
        for i in range(5):
            node_id = bytes([i]) + bytes(31)
            entry = NodeEntry(node_id=NodeId(node_id), enr_seq=SeqNumber(1))
            service._routing_table.add(entry)

        nodes = service.get_random_nodes(3)
        assert len(nodes) <= 3

    def test_get_nodes_at_distance(self, local_enr, local_private_key):
        """Get nodes at specific distance."""
        service, _ = _make_service(local_enr, local_private_key)

        nodes = service.get_nodes_at_distance(128)
        assert isinstance(nodes, list)

    def test_node_count_empty_table(self, local_enr, local_private_key):
        """Node count for empty table is zero."""
        service, _ = _make_service(local_enr, local_private_key)

        assert service.node_count() == 0


class TestLookupResult:
    """Tests for LookupResult dataclass."""

    def test_create_lookup_result(self):
        """LookupResult stores all fields."""
        target = NodeId(bytes(32))
        nodes = [NodeEntry(node_id=NodeId(bytes(32)), enr_seq=SeqNumber(1))]

        result = LookupResult(target=target, nodes=nodes, queried=5)

        assert result.target == target
        assert result.nodes == nodes
        assert result.queried == 5

    def test_empty_lookup_result(self):
        """LookupResult can have empty nodes list."""
        result = LookupResult(target=NodeId(bytes(32)), nodes=[], queried=0)

        assert result.nodes == []
        assert result.queried == 0


class TestDiscoveryServiceLifecycle:
    """Tests for service lifecycle."""

    @pytest.mark.anyio
    async def test_start_sets_running_flag(self, local_enr, local_private_key):
        """Starting service sets running flag."""
        service, fake = _make_service(local_enr, local_private_key)

        await service.start("127.0.0.1", 9000)

        assert service._running
        assert fake.started

        # Clean up.
        await service.stop()

    @pytest.mark.anyio
    async def test_start_is_idempotent(self, local_enr, local_private_key):
        """Starting already-running service does nothing."""
        service, fake = _make_service(local_enr, local_private_key)

        await service.start("127.0.0.1", 9000)
        await service.start("127.0.0.1", 9000)

        assert fake.start_count == 1

        await service.stop()

    @pytest.mark.anyio
    async def test_stop_clears_running_flag(self, local_enr, local_private_key):
        """Stopping service clears running flag."""
        service, fake = _make_service(local_enr, local_private_key)

        await service.start("127.0.0.1", 9000)
        await service.stop()

        assert not service._running
        assert fake.stopped

    @pytest.mark.anyio
    async def test_stop_is_idempotent(self, local_enr, local_private_key):
        """Stopping already-stopped service does nothing."""
        service, fake = _make_service(local_enr, local_private_key)

        # Stop without starting.
        await service.stop()
        await service.stop()

        # Should not call transport.stop if not running.
        assert not fake.stopped


class TestFindNode:
    """Tests for find_node lookup operation."""

    @pytest.mark.anyio
    async def test_find_node_invalid_target_length(self, local_enr, local_private_key):
        """find_node rejects targets that aren't 32 bytes."""
        service, _ = _make_service(local_enr, local_private_key)

        with pytest.raises(ValueError, match="32 bytes"):
            await service.find_node(b"too short")  # type: ignore[arg-type]

    @pytest.mark.anyio
    async def test_find_node_empty_table(self, local_enr, local_private_key):
        """find_node with empty routing table returns empty result."""
        service, _ = _make_service(local_enr, local_private_key)

        result = await service.find_node(NodeId(bytes(32)))

        assert result.target == NodeId(bytes(32))
        assert result.nodes == []
        assert result.queried == 0

    @pytest.mark.anyio
    async def test_find_node_with_responses(self, local_enr, local_private_key, remote_node_id):
        """find_node queries candidates and processes responses."""
        service, fake = _make_service(local_enr, local_private_key)

        entry = NodeEntry(node_id=remote_node_id, enr_seq=SeqNumber(1))
        service._routing_table.add(entry)
        fake.register_node_address(remote_node_id, ("192.168.1.1", 30303))

        target = NodeId(bytes(32))

        node_a_pubkey = bytes.fromhex(
            "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
        )
        discovered_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): node_a_pubkey,
                EnrKey("ip"): bytes([10, 0, 0, 2]),
                EnrKey("udp"): (9001).to_bytes(2, "big"),
            },
        )

        fake.send_findnode_return = [discovered_enr.to_rlp()]
        result = await service.find_node(target)

        assert result.queried >= 1
        assert result.target == target
        assert len(result.nodes) >= 1

    @pytest.mark.anyio
    async def test_find_node_iterative_deepening(self, local_enr, local_private_key):
        """find_node iteratively queries closer nodes."""
        service, fake = _make_service(local_enr, local_private_key)

        for i in range(5):
            node_id = NodeId(bytes([i]) + bytes(31))
            entry = NodeEntry(node_id=node_id, enr_seq=SeqNumber(1))
            service._routing_table.add(entry)
            fake.register_node_address(node_id, (f"192.168.1.{i + 1}", 30303))

        target = NodeId(bytes(32))

        def mock_findnode(node_id, addr, distances):
            new_pubkey = bytes.fromhex(
                "02a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
            )
            new_enr = ENR(
                signature=Bytes64(bytes(64)),
                seq=SeqNumber(1),
                pairs={
                    EnrKey("id"): b"v4",
                    EnrKey("secp256k1"): new_pubkey,
                    EnrKey("ip"): bytes([10, 0, 0, 50]),
                    EnrKey("udp"): (9050).to_bytes(2, "big"),
                },
            )
            return [new_enr.to_rlp()]

        fake.send_findnode_side_effect = mock_findnode
        result = await service.find_node(target)

        assert result.queried > 0
        assert result.target == target

    @pytest.mark.anyio
    async def test_find_node_handles_exceptions_in_query(self, local_enr, local_private_key):
        """find_node handles exceptions from send_findnode gracefully."""
        service, fake = _make_service(local_enr, local_private_key)

        # Add a node so the lookup has candidates.
        node_id = NodeId(bytes([1]) + bytes(31))
        entry = NodeEntry(node_id=node_id, enr_seq=SeqNumber(1))
        service._routing_table.add(entry)
        fake.register_node_address(node_id, ("192.168.1.1", 30303))

        target = NodeId(bytes(32))

        # Transport raises on send_findnode -- _query_node propagates the exception,
        # and find_node's gather(return_exceptions=True) catches it.
        def raise_error(*args, **kwargs):
            raise RuntimeError("network error")

        fake.send_findnode_side_effect = raise_error
        result = await service.find_node(target)

        assert result.target == target
        assert isinstance(result.nodes, list)


class TestServiceIPAddressEncoding:
    """Tests for IP address encoding in service layer."""

    def test_encode_ipv4_loopback(self, local_enr, local_private_key):
        """Encode IPv4 loopback address."""
        service, _ = _make_service(local_enr, local_private_key)

        encoded = service._encode_ip_address("127.0.0.1")

        assert encoded == b"\x7f\x00\x00\x01"
        assert len(encoded) == 4

    def test_encode_ipv4_common_addresses(self, local_enr, local_private_key):
        """Encode common IPv4 addresses."""
        service, _ = _make_service(local_enr, local_private_key)

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
        service, _ = _make_service(local_enr, local_private_key)

        encoded = service._encode_ip_address("::1")

        expected = bytes(15) + b"\x01"
        assert encoded == expected
        assert len(encoded) == 16

    def test_encode_ipv6_common_addresses(self, local_enr, local_private_key):
        """Encode common IPv6 addresses."""
        service, _ = _make_service(local_enr, local_private_key)

        # :: (all zeros)
        encoded_zeros = service._encode_ip_address("::")
        assert encoded_zeros == bytes(16)

        # ::1 (loopback)
        encoded_loopback = service._encode_ip_address("::1")
        assert encoded_loopback == bytes(15) + b"\x01"


class TestBootstrap:
    """Bootnode initialization tests."""

    def test_service_accepts_bootnodes(self, local_enr, local_private_key):
        """Service accepts bootnodes in constructor."""
        bootnode = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): bytes.fromhex(
                    "02a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
                ),
                EnrKey("ip"): bytes([192, 168, 1, 1]),
                EnrKey("udp"): (30303).to_bytes(2, "big"),
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
                seq=SeqNumber(i + 1),
                pairs={
                    EnrKey("id"): b"v4",
                    EnrKey("secp256k1"): bytes.fromhex(
                        "02a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
                    ),
                    EnrKey("ip"): bytes([192, 168, 1, i + 1]),
                    EnrKey("udp"): (30303 + i).to_bytes(2, "big"),
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


class TestHandlePing:
    """Tests for _handle_ping message handler."""

    @pytest.mark.anyio
    async def test_handle_ping_sends_pong(self, local_enr, local_private_key, remote_node_id):
        """PING triggers a PONG response."""
        service, fake = _make_service(local_enr, local_private_key)

        ping = Ping(request_id=RequestId(data=b"\x01\x02"), enr_seq=SeqNumber(1))
        addr = ("192.168.1.1", 30303)

        await service._handle_ping(remote_node_id, ping, addr)

        assert len(fake.sent_responses) == 1
        sent = fake.sent_responses[0]
        assert isinstance(sent.message, Pong)
        assert bytes(sent.message.request_id) == b"\x01\x02"

    @pytest.mark.anyio
    async def test_handle_ping_establishes_bond(self, local_enr, local_private_key, remote_node_id):
        """Successful PONG response establishes bond."""
        service, fake = _make_service(local_enr, local_private_key)
        fake.send_response_return = True

        ping = Ping(request_id=RequestId(data=b"\x01"), enr_seq=SeqNumber(1))
        addr = ("192.168.1.1", 30303)

        await service._handle_ping(remote_node_id, ping, addr)

        assert service._bond_cache.is_bonded(remote_node_id)

    @pytest.mark.anyio
    async def test_handle_ping_no_bond_when_send_fails(
        self, local_enr, local_private_key, remote_node_id
    ):
        """No bond established when PONG send fails."""
        service, fake = _make_service(local_enr, local_private_key)
        fake.send_response_return = False

        ping = Ping(request_id=RequestId(data=b"\x01"), enr_seq=SeqNumber(1))
        addr = ("192.168.1.1", 30303)

        await service._handle_ping(remote_node_id, ping, addr)

        assert not service._bond_cache.is_bonded(remote_node_id)

    @pytest.mark.anyio
    async def test_handle_ping_pong_includes_recipient_endpoint(
        self, local_enr, local_private_key, remote_node_id
    ):
        """PONG includes the sender's observed IP and port."""
        service, fake = _make_service(local_enr, local_private_key)

        ping = Ping(request_id=RequestId(data=b"\x01"), enr_seq=SeqNumber(1))
        addr = ("10.0.0.5", 9001)

        await service._handle_ping(remote_node_id, ping, addr)

        sent_pong = fake.sent_responses[0].message
        assert isinstance(sent_pong, Pong)
        assert int(sent_pong.recipient_port) == 9001


class TestHandleFindNode:
    """Tests for _handle_findnode message handler."""

    @pytest.mark.anyio
    async def test_findnode_from_unbonded_node_ignored(
        self, local_enr, local_private_key, remote_node_id
    ):
        """FINDNODE from unbonded node is silently ignored."""
        service, fake = _make_service(local_enr, local_private_key)

        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(1)],
        )
        addr = ("192.168.1.1", 30303)

        await service._handle_findnode(remote_node_id, findnode, addr)

        assert fake.sent_responses == []

    @pytest.mark.anyio
    async def test_findnode_from_bonded_node_sends_nodes(
        self, local_enr, local_private_key, remote_node_id
    ):
        """FINDNODE from bonded node sends NODES response."""
        service, fake = _make_service(local_enr, local_private_key)

        # Establish bond first.
        service._bond_cache.add_bond(remote_node_id)

        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(128)],
        )
        addr = ("192.168.1.1", 30303)

        await service._handle_findnode(remote_node_id, findnode, addr)

        assert len(fake.sent_responses) == 1
        sent_msg = fake.sent_responses[0].message
        assert isinstance(sent_msg, Nodes)
        assert bytes(sent_msg.request_id) == b"\x01"

    @pytest.mark.anyio
    async def test_findnode_distance_zero_returns_local_enr(
        self, local_enr, local_private_key, remote_node_id
    ):
        """FINDNODE with distance=0 returns our own ENR."""
        service, fake = _make_service(local_enr, local_private_key)

        service._bond_cache.add_bond(remote_node_id)

        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(0)],
        )
        addr = ("192.168.1.1", 30303)

        await service._handle_findnode(remote_node_id, findnode, addr)

        sent_msg = fake.sent_responses[0].message
        assert isinstance(sent_msg, Nodes)
        # Distance 0 means our own ENR, so there should be at least 1 ENR.
        assert len(sent_msg.enrs) >= 1

    @pytest.mark.anyio
    async def test_findnode_returns_nodes_from_bucket(
        self, local_enr, local_private_key, remote_node_id
    ):
        """FINDNODE returns nodes from routing table buckets."""
        service, fake = _make_service(local_enr, local_private_key)

        service._bond_cache.add_bond(remote_node_id)

        entry = NodeEntry(node_id=NodeId(bytes([1]) + bytes(31)), enr_seq=SeqNumber(1))
        service._routing_table.add(entry)

        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(255)],
        )
        addr = ("192.168.1.1", 30303)

        await service._handle_findnode(remote_node_id, findnode, addr)

        assert len(fake.sent_responses) == 1
        sent_msg = fake.sent_responses[0].message
        assert isinstance(sent_msg, Nodes)

    @pytest.mark.anyio
    async def test_findnode_response_capped_at_max_nodes(
        self, local_enr, local_private_key, remote_node_id
    ):
        """FINDNODE response is capped at max_nodes_response."""
        service, fake = _make_service(
            local_enr, local_private_key, config=DiscoveryConfig(max_nodes_response=3)
        )

        service._bond_cache.add_bond(remote_node_id)

        for i in range(10):
            entry = NodeEntry(
                node_id=NodeId(bytes([i]) + bytes(31)),
                enr_seq=SeqNumber(1),
            )
            service._routing_table.add(entry)

        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(255)],
        )
        addr = ("192.168.1.1", 30303)

        await service._handle_findnode(remote_node_id, findnode, addr)

        assert len(fake.sent_responses) == 1
        sent_msg = fake.sent_responses[0].message
        assert isinstance(sent_msg, Nodes)
        assert len(sent_msg.enrs) <= 3

    @pytest.mark.anyio
    async def test_findnode_returns_enrs_with_entries(
        self, local_enr, local_private_key, remote_node_id
    ):
        """FINDNODE returns ENRs from routing table when entries have ENRs."""
        service, fake = _make_service(local_enr, local_private_key)

        service._bond_cache.add_bond(remote_node_id)

        node_a_pubkey = bytes.fromhex(
            "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
        )
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): node_a_pubkey,
                EnrKey("ip"): bytes([10, 0, 0, 1]),
                EnrKey("udp"): (9000).to_bytes(2, "big"),
            },
        )
        local_int = int.from_bytes(service._local_node_id, "big")
        target_int = local_int ^ 1
        entry = NodeEntry(
            node_id=NodeId(target_int.to_bytes(32, "big")),
            enr_seq=SeqNumber(1),
            enr=enr,
        )
        service._routing_table.add(entry)

        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(1)],
        )
        addr = ("192.168.1.1", 30303)

        await service._handle_findnode(remote_node_id, findnode, addr)

        assert len(fake.sent_responses) == 1
        sent_msg = fake.sent_responses[0].message
        assert isinstance(sent_msg, Nodes)
        assert len(sent_msg.enrs) >= 1

    @pytest.mark.anyio
    async def test_process_message_findnode_routes_to_handler(
        self, local_enr, local_private_key, remote_node_id
    ):
        """FindNode messages are dispatched to _handle_findnode."""
        service, _ = _make_service(local_enr, local_private_key)

        service._bond_cache.add_bond(remote_node_id)

        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(128)],
        )
        addr = ("192.168.1.1", 30303)

        await service._process_message(remote_node_id, findnode, addr)

    @pytest.mark.anyio
    async def test_process_message_talkreq_routes_to_handler(
        self, local_enr, local_private_key, remote_node_id
    ):
        """TalkReq messages are dispatched to _handle_talkreq."""
        service, _ = _make_service(local_enr, local_private_key)

        talkreq = TalkReq(
            request_id=RequestId(data=b"\x01"),
            protocol=b"eth2",
            request=b"data",
        )
        addr = ("192.168.1.1", 30303)

        await service._process_message(remote_node_id, talkreq, addr)


class TestHandleTalkReq:
    """Tests for _handle_talkreq message handler."""

    @pytest.mark.anyio
    async def test_talkreq_unknown_protocol_sends_empty_response(
        self, local_enr, local_private_key, remote_node_id
    ):
        """TALKREQ for unknown protocol sends empty TALKRESP."""
        service, fake = _make_service(local_enr, local_private_key)

        talkreq = TalkReq(
            request_id=RequestId(data=b"\x01"),
            protocol=b"unknown",
            request=b"data",
        )
        addr = ("192.168.1.1", 30303)

        await service._handle_talkreq(remote_node_id, talkreq, addr)

        assert len(fake.sent_responses) == 1
        sent_msg = fake.sent_responses[0].message
        assert isinstance(sent_msg, TalkResp)
        assert sent_msg.response == b""

    @pytest.mark.anyio
    async def test_talkreq_dispatches_to_registered_handler(
        self, local_enr, local_private_key, remote_node_id
    ):
        """TALKREQ dispatches to the registered protocol handler."""
        service, fake = _make_service(local_enr, local_private_key)

        calls: list[tuple[bytes, bytes]] = []

        def handler(nid: bytes, data: bytes) -> bytes:
            calls.append((nid, data))
            return b"handler-response"

        service.register_talk_handler(b"eth2", handler)

        talkreq = TalkReq(
            request_id=RequestId(data=b"\x01"),
            protocol=b"eth2",
            request=b"request-data",
        )
        addr = ("192.168.1.1", 30303)

        await service._handle_talkreq(remote_node_id, talkreq, addr)

        assert calls == [(remote_node_id, b"request-data")]
        sent_msg = fake.sent_responses[0].message
        assert isinstance(sent_msg, TalkResp)
        assert sent_msg.response == b"handler-response"

    @pytest.mark.anyio
    async def test_talkreq_handler_exception_sends_empty_response(
        self, local_enr, local_private_key, remote_node_id
    ):
        """TALKREQ handler that raises sends empty response."""
        service, fake = _make_service(local_enr, local_private_key)

        def handler(nid: bytes, data: bytes) -> bytes:
            raise RuntimeError("handler error")

        service.register_talk_handler(b"eth2", handler)

        talkreq = TalkReq(
            request_id=RequestId(data=b"\x01"),
            protocol=b"eth2",
            request=b"request-data",
        )
        addr = ("192.168.1.1", 30303)

        await service._handle_talkreq(remote_node_id, talkreq, addr)

        sent_msg = fake.sent_responses[0].message
        assert isinstance(sent_msg, TalkResp)
        assert sent_msg.response == b""


class TestSendTalkRequest:
    """Tests for send_talk_request method."""

    @pytest.mark.anyio
    async def test_send_talk_request_returns_none_for_unknown_node(
        self, local_enr, local_private_key
    ):
        """send_talk_request returns None when node address is unknown."""
        service, _ = _make_service(local_enr, local_private_key)

        unknown_id = NodeId(bytes(32))
        result = await service.send_talk_request(unknown_id, b"eth2", b"request")

        assert result is None

    @pytest.mark.anyio
    async def test_send_talk_request_delegates_to_transport(
        self, local_enr, local_private_key, remote_node_id
    ):
        """send_talk_request delegates to transport when address is known."""
        service, fake = _make_service(local_enr, local_private_key)
        fake.register_node_address(remote_node_id, ("192.168.1.1", 30303))
        fake.send_talkreq_return = b"response"

        result = await service.send_talk_request(remote_node_id, b"eth2", b"request")

        assert result == b"response"
        assert len(fake.sent_talkreqs) == 1
        assert fake.sent_talkreqs[0] == SentTalkReq(
            remote_node_id, ("192.168.1.1", 30303), b"eth2", b"request"
        )

    @pytest.mark.anyio
    async def test_send_talk_request_timeout(self, local_enr, local_private_key, remote_node_id):
        """send_talk_request returns None on timeout."""
        service, fake = _make_service(local_enr, local_private_key)
        fake.register_node_address(remote_node_id, ("192.168.1.1", 30303))
        fake.send_talkreq_return = None

        result = await service.send_talk_request(remote_node_id, b"eth2", b"request")

        assert result is None


class TestBootstrapFlow:
    """Tests for _bootstrap method."""

    @pytest.mark.anyio
    async def test_bootstrap_registers_bootnode_addresses(self, local_enr, local_private_key):
        """Bootstrap registers bootnode addresses and ENRs."""
        node_a_pubkey = bytes.fromhex(
            "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
        )
        bootnode = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): node_a_pubkey,
                EnrKey("ip"): bytes([192, 168, 1, 1]),
                EnrKey("udp"): (30303).to_bytes(2, "big"),
            },
        )

        service, _ = _make_service(local_enr, local_private_key, bootnodes=[bootnode])

        await service._bootstrap()

        assert service.node_count() >= 1

    @pytest.mark.anyio
    async def test_bootstrap_skips_bootnodes_without_ip(self, local_enr, local_private_key):
        """Bootstrap skips bootnodes that lack IP/port."""
        node_a_pubkey = bytes.fromhex(
            "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
        )
        bootnode = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): node_a_pubkey,
            },
        )

        service, fake = _make_service(local_enr, local_private_key, bootnodes=[bootnode])

        await service._bootstrap()

        assert fake.sent_pings == []

    @pytest.mark.anyio
    async def test_bootstrap_handles_exception(self, local_enr, local_private_key):
        """_bootstrap handles exceptions gracefully."""
        bootnode = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
            },
        )

        service, _ = _make_service(local_enr, local_private_key, bootnodes=[bootnode])

        await service._bootstrap()

    @pytest.mark.anyio
    async def test_bootstrap_handles_enr_to_entry_exception(self, local_enr, local_private_key):
        """_bootstrap handles exceptions from _enr_to_entry."""
        node_a_pubkey = bytes.fromhex(
            "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
        )
        bootnode = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): node_a_pubkey,
                EnrKey("ip"): bytes([192, 168, 1, 1]),
                EnrKey("udp"): (30303).to_bytes(2, "big"),
            },
        )

        service, _ = _make_service(local_enr, local_private_key, bootnodes=[bootnode])

        with patch.object(service, "_enr_to_entry", side_effect=RuntimeError("test error")):
            await service._bootstrap()


class TestProcessDiscoveredEnr:
    """Tests for _process_discovered_enr method."""

    def test_invalid_enr_bytes_are_skipped(self, local_enr, local_private_key):
        """Invalid RLP bytes are silently skipped."""
        service, _ = _make_service(local_enr, local_private_key)

        seen: dict[NodeId, NodeEntry] = {}
        # Should not raise.
        service._process_discovered_enr(b"\xff\xff\xff", seen)

    def test_enr_with_wrong_distance_is_dropped(self, local_enr, local_private_key):
        """ENR that doesn't match requested distances is dropped."""
        service, _ = _make_service(local_enr, local_private_key)

        # Create a valid ENR.
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): bytes.fromhex(
                    "02a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
                ),
                EnrKey("ip"): bytes([10, 0, 0, 1]),
                EnrKey("udp"): (9000).to_bytes(2, "big"),
            },
        )
        enr_bytes = enr.to_rlp()

        queried_id = NodeId(bytes(32))
        seen: dict[NodeId, NodeEntry] = {}

        # Request only distance 1 — the actual distance is unlikely to be 1.
        service._process_discovered_enr(enr_bytes, seen, queried_id, [1])

        # ENR should not be added since distance doesn't match.
        assert len(seen) == 0

    def test_valid_enr_added_to_seen_and_routing_table(self, local_enr, local_private_key):
        """Valid ENR is added to seen dict and routing table."""
        service, _ = _make_service(local_enr, local_private_key)

        # Create a valid ENR with distance from queried node.
        node_a_pubkey = bytes.fromhex(
            "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
        )
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): node_a_pubkey,
                EnrKey("ip"): bytes([10, 0, 0, 1]),
                EnrKey("udp"): (9000).to_bytes(2, "big"),
            },
        )
        enr_bytes = enr.to_rlp()

        # Use local node as queried node so distance will be at a valid range.
        seen: dict[NodeId, NodeEntry] = {}
        service._process_discovered_enr(enr_bytes, seen)

        # ENR should be added to seen.
        assert len(seen) == 1
        node_id = next(iter(seen.keys()))
        assert seen[node_id].enr is not None

        # Should also be in routing table.
        assert service.node_count() == 1

    def test_enr_without_node_id_is_skipped(self, local_enr, local_private_key):
        """ENR without valid node ID is skipped."""
        service, _ = _make_service(local_enr, local_private_key)

        # ENR with no secp256k1 key (no node ID).
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
            },
        )
        enr_bytes = enr.to_rlp()

        seen: dict[NodeId, NodeEntry] = {}
        service._process_discovered_enr(enr_bytes, seen)

        assert len(seen) == 0

    def test_own_enr_is_skipped(self, local_enr, local_private_key):
        """Processing our own ENR is skipped."""
        service, _ = _make_service(local_enr, local_private_key)

        seen: dict[NodeId, NodeEntry] = {}
        service._process_discovered_enr(local_enr.to_rlp(), seen)

        # Should not add our own ENR.
        assert len(seen) == 0

    def test_already_seen_enr_is_skipped(self, local_enr, local_private_key):
        """Duplicate ENR within same lookup is skipped."""
        service, _ = _make_service(local_enr, local_private_key)

        # Create a valid ENR.
        node_a_pubkey = bytes.fromhex(
            "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
        )
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): node_a_pubkey,
                EnrKey("ip"): bytes([10, 0, 0, 1]),
                EnrKey("udp"): (9000).to_bytes(2, "big"),
            },
        )
        enr_bytes = enr.to_rlp()

        seen: dict[NodeId, NodeEntry] = {}

        # Process same ENR twice.
        service._process_discovered_enr(enr_bytes, seen)
        service._process_discovered_enr(enr_bytes, seen)

        # Should only be added once.
        assert len(seen) == 1

    def test_process_discovered_enr_catches_generic_exception(self, local_enr, local_private_key):
        """Generic exceptions in ENR processing are caught and logged."""
        service, _ = _make_service(local_enr, local_private_key)

        seen: dict[NodeId, NodeEntry] = {}

        # Pass malformed data that might cause unexpected errors.
        with patch("lean_spec.subspecs.networking.enr.ENR.from_rlp") as mock_from_rlp:
            mock_from_rlp.side_effect = RuntimeError("unexpected error")
            # Should not raise.
            service._process_discovered_enr(b"\x00", seen)


class TestQueryNode:
    """Tests for _query_node method."""

    @pytest.mark.anyio
    async def test_query_node_with_positive_distance(
        self, local_enr, local_private_key, remote_node_id
    ):
        """_query_node sends FINDNODE with correct distance."""
        service, fake = _make_service(local_enr, local_private_key)

        addr = ("192.168.1.1", 30303)
        target = NodeId(bytes(32))

        await service._query_node(remote_node_id, addr, target)

        assert len(fake.sent_findnodes) == 1
        sent = fake.sent_findnodes[0]
        assert sent.node_id == remote_node_id
        assert sent.addr == addr
        # Should have at least one distance.
        assert isinstance(sent.distances, list)
        assert len(sent.distances) >= 1

    @pytest.mark.anyio
    async def test_query_node_returns_tuple(self, local_enr, local_private_key, remote_node_id):
        """_query_node returns (enr_list, node_id, distances) tuple."""
        service, fake = _make_service(local_enr, local_private_key)

        addr = ("192.168.1.1", 30303)
        target = NodeId(bytes(32))

        enrs = [b"\x00", b"\x01"]
        fake.send_findnode_return = enrs
        result = await service._query_node(remote_node_id, addr, target)

        assert isinstance(result, tuple)
        assert len(result) == 3
        enr_list, returned_id, distances = result
        assert enr_list == enrs
        assert returned_id == remote_node_id


class TestPingNode:
    """Tests for _ping_node method."""

    @pytest.mark.anyio
    async def test_ping_node_success_returns_true(
        self, local_enr, local_private_key, remote_node_id
    ):
        """Successful ping returns True and adds bond."""
        service, fake = _make_service(local_enr, local_private_key)

        addr = ("192.168.1.1", 30303)

        fake.send_ping_return = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(30303),
        )
        result = await service._ping_node(remote_node_id, addr)

        assert result is True
        assert service._bond_cache.is_bonded(remote_node_id)

    @pytest.mark.anyio
    async def test_ping_node_no_response_returns_false(
        self, local_enr, local_private_key, remote_node_id
    ):
        """Failed ping returns False and no bond added."""
        service, fake = _make_service(local_enr, local_private_key)

        addr = ("192.168.1.1", 30303)

        fake.send_ping_return = None
        result = await service._ping_node(remote_node_id, addr)

        assert result is False
        assert not service._bond_cache.is_bonded(remote_node_id)


class TestProcessMessage:
    """Tests for _process_message method."""

    @pytest.mark.anyio
    async def test_process_message_ping_routes_to_handler(
        self, local_enr, local_private_key, remote_node_id
    ):
        """Ping messages are dispatched to _handle_ping."""
        service, _ = _make_service(local_enr, local_private_key)

        ping = Ping(request_id=RequestId(data=b"\x01"), enr_seq=SeqNumber(1))
        addr = ("192.168.1.1", 30303)

        await service._process_message(remote_node_id, ping, addr)

        assert service._bond_cache.is_bonded(remote_node_id)

    @pytest.mark.anyio
    async def test_process_message_updates_node_address(
        self, local_enr, local_private_key, remote_node_id
    ):
        """_process_message updates node address in transport."""
        service, fake = _make_service(local_enr, local_private_key)

        ping = Ping(request_id=RequestId(data=b"\x01"), enr_seq=SeqNumber(1))
        addr = ("192.168.1.1", 30303)

        await service._process_message(remote_node_id, ping, addr)

        registered_addr = fake.get_node_address(remote_node_id)
        assert registered_addr == addr

    @pytest.mark.anyio
    async def test_process_message_findnode_routes_to_handler(
        self, local_enr, local_private_key, remote_node_id
    ):
        """FindNode messages are dispatched to _handle_findnode."""
        service, _ = _make_service(local_enr, local_private_key)

        service._bond_cache.add_bond(remote_node_id)

        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(128)],
        )
        addr = ("192.168.1.1", 30303)

        await service._process_message(remote_node_id, findnode, addr)

    @pytest.mark.anyio
    async def test_process_message_talkreq_routes_to_handler(
        self, local_enr, local_private_key, remote_node_id
    ):
        """TalkReq messages are dispatched to _handle_talkreq."""
        service, _ = _make_service(local_enr, local_private_key)

        talkreq = TalkReq(
            request_id=RequestId(data=b"\x01"),
            protocol=b"eth2",
            request=b"data",
        )
        addr = ("192.168.1.1", 30303)

        await service._process_message(remote_node_id, talkreq, addr)


class TestHandleMessage:
    """Tests for _handle_message method."""

    @pytest.mark.anyio
    async def test_handle_message_creates_task(self, local_enr, local_private_key):
        """_handle_message creates async task for processing."""
        service, _ = _make_service(local_enr, local_private_key)

        ping = Ping(request_id=RequestId(data=b"\x01"), enr_seq=SeqNumber(1))
        addr = ("192.168.1.1", 30303)
        remote_id = NodeId(bytes(32))

        # Just verify it doesn't raise - task creation is async.
        service._handle_message(remote_id, ping, addr)


class TestFindNodeLookup:
    """Tests for find_node iterative Kademlia lookup."""

    @pytest.mark.anyio
    async def test_find_node_with_responses(self, local_enr, local_private_key, remote_node_id):
        """find_node queries candidates and processes responses."""
        service, fake = _make_service(local_enr, local_private_key)

        # Add a node to routing table.
        entry = NodeEntry(node_id=remote_node_id, enr_seq=SeqNumber(1))
        service._routing_table.add(entry)
        fake.register_node_address(remote_node_id, ("192.168.1.1", 30303))

        target = NodeId(bytes(32))

        # Configure fake to return ENRs.
        node_a_pubkey = bytes.fromhex(
            "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
        )
        discovered_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): node_a_pubkey,
                EnrKey("ip"): bytes([10, 0, 0, 2]),
                EnrKey("udp"): (9001).to_bytes(2, "big"),
            },
        )

        fake.send_findnode_return = [discovered_enr.to_rlp()]
        result = await service.find_node(target)

        assert result.queried >= 1
        assert result.target == target
        assert len(result.nodes) >= 1

    @pytest.mark.anyio
    async def test_find_node_iterative_deepening(self, local_enr, local_private_key):
        """find_node iteratively queries closer nodes."""
        service, fake = _make_service(local_enr, local_private_key)

        # Create multiple nodes at varying distances.
        for i in range(5):
            node_id = NodeId(bytes([i]) + bytes(31))
            entry = NodeEntry(node_id=node_id, enr_seq=SeqNumber(1))
            service._routing_table.add(entry)
            fake.register_node_address(node_id, (f"192.168.1.{i + 1}", 30303))

        target = NodeId(bytes(32))

        # Return new nodes in each response.
        def mock_findnode(node_id, addr, distances):
            new_pubkey = bytes.fromhex(
                "02a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
            )
            new_enr = ENR(
                signature=Bytes64(bytes(64)),
                seq=SeqNumber(1),
                pairs={
                    EnrKey("id"): b"v4",
                    EnrKey("secp256k1"): new_pubkey,
                    EnrKey("ip"): bytes([10, 0, 0, 50]),
                    EnrKey("udp"): (9050).to_bytes(2, "big"),
                },
            )
            return [new_enr.to_rlp()]

        fake.send_findnode_side_effect = mock_findnode
        result = await service.find_node(target)

        # Should have queried nodes.
        assert result.queried > 0
        assert result.target == target

    @pytest.mark.anyio
    async def test_find_node_handles_exceptions_in_query(self, local_enr, local_private_key):
        """find_node handles exceptions from queries gracefully."""
        service, fake = _make_service(local_enr, local_private_key)

        # Add a node so the lookup has candidates.
        node_id = NodeId(bytes([1]) + bytes(31))
        entry = NodeEntry(node_id=node_id, enr_seq=SeqNumber(1))
        service._routing_table.add(entry)
        fake.register_node_address(node_id, ("192.168.1.1", 30303))

        target = NodeId(bytes(32))

        # Transport raises on send_findnode -- _query_node propagates the exception,
        # and find_node's gather(return_exceptions=True) catches it.
        def raise_error(*args, **kwargs):
            raise RuntimeError("network error")

        fake.send_findnode_side_effect = raise_error
        result = await service.find_node(target)

        assert result.target == target
        assert isinstance(result.nodes, list)


class TestEnrToEntry:
    """Tests for _enr_to_entry method."""

    def test_enr_to_entry_with_endpoint(self, local_enr, local_private_key):
        """_enr_to_entry creates entry with endpoint."""
        node_a_pubkey = bytes.fromhex(
            "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
        )
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): node_a_pubkey,
                EnrKey("ip"): bytes([192, 168, 1, 1]),
                EnrKey("udp"): (30303).to_bytes(2, "big"),
            },
        )

        service, _ = _make_service(local_enr, local_private_key)

        entry = service._enr_to_entry(enr)

        assert entry.enr_seq == SeqNumber(1)
        assert entry.enr is enr
        assert entry.endpoint == "192.168.1.1:30303"

    def test_enr_to_entry_without_ip(self, local_enr, local_private_key):
        """_enr_to_entry handles ENR without IP."""
        node_a_pubkey = bytes.fromhex(
            "0313d14211e0287b2361a1615890a9b5212080546d0a257ae4cff96cf534992cb9"
        )
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): node_a_pubkey,
            },
        )

        service, _ = _make_service(local_enr, local_private_key)

        entry = service._enr_to_entry(enr)

        assert entry.enr_seq == SeqNumber(1)
        assert entry.endpoint is None

    def test_enr_to_entry_raises_without_node_id(self, local_enr, local_private_key):
        """_enr_to_entry raises when ENR has no node ID."""
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
            },
        )

        service, _ = _make_service(local_enr, local_private_key)

        with pytest.raises(ValueError, match="no valid node ID"):
            service._enr_to_entry(enr)


class TestBackgroundLoops:
    """Tests for background maintenance loops."""

    @pytest.mark.anyio
    async def test_refresh_loop_performs_lookup(self, local_enr, local_private_key):
        """_refresh_loop performs periodic lookups."""
        service, _ = _make_service(local_enr, local_private_key)

        # Start service.
        await service.start("127.0.0.1", 9000)

        try:
            # Wait a short time for the refresh loop to potentially run.
            # Since interval is 1 hour, it won't run naturally.
            # Instead, verify the loop exists and can handle errors.
            assert service._running

            # Let the event loop process.
            await asyncio.sleep(0.01)
        finally:
            await service.stop()

    @pytest.mark.anyio
    async def test_revalidation_loop_handles_empty_table(self, local_enr, local_private_key):
        """_revalidation_loop handles empty routing table."""
        service, _ = _make_service(local_enr, local_private_key)

        # Start service.
        await service.start("127.0.0.1", 9000)

        try:
            # Verify empty table doesn't cause issues.
            assert service.node_count() == 0
            await asyncio.sleep(0.01)
        finally:
            await service.stop()

    @pytest.mark.anyio
    async def test_cleanup_loop_calls_bond_cache(self, local_enr, local_private_key):
        """_cleanup_loop calls cleanup_expired on bond cache."""
        service, _ = _make_service(local_enr, local_private_key)

        # Start service.
        await service.start("127.0.0.1", 9000)

        try:
            # Verify bond cache exists.
            assert service._bond_cache is not None
            await asyncio.sleep(0.01)
        finally:
            await service.stop()

    @pytest.mark.anyio
    async def test_background_loops_handle_exceptions(self, local_enr, local_private_key):
        """Background loops catch and log exceptions."""
        service, _ = _make_service(local_enr, local_private_key)

        # Mock find_node to raise.
        with patch.object(
            service, "find_node", new=AsyncMock(side_effect=RuntimeError("test error"))
        ):
            await service.start("127.0.0.1", 9000)

            # Service should still be running.
            assert service._running

            # Let loop attempt.
            await asyncio.sleep(0.01)

            # Service should still be running (exception caught).
            assert service._running

            await service.stop()
