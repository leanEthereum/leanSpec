"""
Tests for Discovery v5 UDP transport layer.

Tests the DiscoveryTransport and DiscoveryProtocol classes.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.exceptions import InvalidTag

from lean_spec.subspecs.networking.discovery.config import DiscoveryConfig
from lean_spec.subspecs.networking.discovery.handshake import HandshakeError, HandshakeResult
from lean_spec.subspecs.networking.discovery.messages import (
    Distance,
    FindNode,
    IPv4,
    Nodes,
    Nonce,
    PacketFlag,
    Ping,
    Pong,
    Port,
    RequestId,
    TalkResp,
)
from lean_spec.subspecs.networking.discovery.packet import (
    HandshakeAuthdata,
    PacketHeader,
    decode_packet_header,
    encode_message_authdata,
    encode_packet,
)
from lean_spec.subspecs.networking.discovery.session import Session
from lean_spec.subspecs.networking.discovery.transport import (
    DiscoveryProtocol,
    DiscoveryTransport,
    PendingMultiRequest,
    PendingRequest,
)
from lean_spec.subspecs.networking.enr import ENR
from lean_spec.subspecs.networking.enr.keys import EnrKey
from lean_spec.subspecs.networking.types import NodeId, SeqNumber
from lean_spec.types import Bytes16, Bytes32, Bytes33, Bytes64, Uint8
from tests.lean_spec.subspecs.networking.discovery.conftest import NODE_B_PUBKEY


@pytest.fixture
async def started_transport(
    local_node_id: NodeId,
    local_private_key: Bytes32,
    local_enr: ENR,
) -> AsyncIterator[tuple[DiscoveryTransport, MagicMock]]:
    """Start a DiscoveryTransport with a mocked UDP socket.

    Yields (transport, mock_udp) where mock_udp is the DatagramTransport mock.
    """
    transport = DiscoveryTransport(
        local_node_id=local_node_id,
        local_private_key=local_private_key,
        local_enr=local_enr,
    )
    mock_udp = MagicMock(spec=asyncio.DatagramTransport)
    with patch.object(
        asyncio.get_event_loop(),
        "create_datagram_endpoint",
        new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
    ):
        await transport.start("127.0.0.1", 9000)
    yield transport, mock_udp
    await transport.stop()


class TestDiscoveryProtocol:
    """Tests for DiscoveryProtocol async UDP handler."""

    def test_connection_made_stores_transport(self):
        """Protocol stores transport reference on connection."""
        mock_handler = MagicMock()
        protocol = DiscoveryProtocol(mock_handler)

        mock_transport = MagicMock(spec=asyncio.DatagramTransport)
        protocol.connection_made(mock_transport)

        assert protocol._transport is mock_transport

    @pytest.mark.anyio
    async def test_datagram_received_dispatches_to_handler(self):
        """Received datagrams are dispatched to the handler."""
        mock_handler = MagicMock()
        mock_handler._handle_packet = AsyncMock()

        protocol = DiscoveryProtocol(mock_handler)

        data = b"test packet data"
        addr = ("127.0.0.1", 9000)

        protocol.datagram_received(data, addr)

        # Give the task a chance to run.
        await asyncio.sleep(0.01)

        mock_handler._handle_packet.assert_called_once_with(data, addr)

    def test_error_received_logs_warning(self):
        """UDP errors are logged."""
        mock_handler = MagicMock()
        protocol = DiscoveryProtocol(mock_handler)

        # Should not raise.
        protocol.error_received(Exception("test error"))

    def test_connection_lost_handles_none_exc(self):
        """Connection lost with no exception is handled."""
        mock_handler = MagicMock()
        protocol = DiscoveryProtocol(mock_handler)

        # Should not raise.
        protocol.connection_lost(None)

    def test_connection_lost_handles_exception(self):
        """Connection lost with exception is handled."""
        mock_handler = MagicMock()
        protocol = DiscoveryProtocol(mock_handler)

        # Should not raise.
        protocol.connection_lost(Exception("connection error"))


class TestDiscoveryTransport:
    """Tests for DiscoveryTransport."""

    def test_init_creates_required_components(self, local_node_id, local_private_key, local_enr):
        """Transport initializes all required components."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        assert transport._local_node_id == local_node_id
        assert transport._local_private_key == local_private_key
        assert transport._local_enr == local_enr
        assert transport._session_cache is not None
        assert transport._handshake_manager is not None
        assert not transport._running

    def test_init_with_custom_config(self, local_node_id, local_private_key, local_enr):
        """Transport accepts custom configuration."""
        config = DiscoveryConfig(request_timeout_secs=30.0)

        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        assert transport._config.request_timeout_secs == 30.0

    def test_register_node_address(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """Node addresses can be registered and retrieved."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        addr = ("192.168.1.1", 30303)
        transport.register_node_address(remote_node_id, addr)

        assert transport.get_node_address(remote_node_id) == addr

    def test_get_node_address_returns_none_for_unknown(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """Getting unknown node address returns None."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        assert transport.get_node_address(remote_node_id) is None

    def test_set_message_handler(self, local_node_id, local_private_key, local_enr):
        """Message handler can be set."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        handler = MagicMock()
        transport.set_message_handler(handler)

        assert transport._message_handler is handler

    def test_register_enr(self, local_node_id, local_private_key, local_enr, remote_node_id):
        """ENRs can be registered and retrieved."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        remote_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={EnrKey("id"): b"v4"},
        )

        transport.register_enr(remote_node_id, remote_enr)

        assert transport.get_enr(remote_node_id) is remote_enr

    @pytest.mark.anyio
    async def test_start_creates_udp_endpoint(self, local_node_id, local_private_key, local_enr):
        """Starting transport creates UDP endpoint."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        # Mock the event loop's create_datagram_endpoint.
        mock_transport_obj = MagicMock(spec=asyncio.DatagramTransport)
        mock_protocol_obj = MagicMock(spec=DiscoveryProtocol)

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport_obj, mock_protocol_obj)),
        ):
            await transport.start("127.0.0.1", 9000)

        assert transport._running

        # Clean up.
        await transport.stop()

    @pytest.mark.anyio
    async def test_start_is_idempotent(self, local_node_id, local_private_key, local_enr):
        """Starting an already-started transport does nothing."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        mock_transport_obj = MagicMock(spec=asyncio.DatagramTransport)
        mock_protocol_obj = MagicMock(spec=DiscoveryProtocol)

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport_obj, mock_protocol_obj)),
        ) as mock_create:
            await transport.start("127.0.0.1", 9000)
            await transport.start("127.0.0.1", 9000)

            # Should only be called once.
            assert mock_create.call_count == 1

        await transport.stop()

    @pytest.mark.anyio
    async def test_stop_closes_transport(
        self, started_transport: tuple[DiscoveryTransport, MagicMock]
    ):
        """Stopping transport closes UDP socket."""
        transport, mock_udp = started_transport

        await transport.stop()

        assert not transport._running
        mock_udp.close.assert_called_once()

    @pytest.mark.anyio
    async def test_stop_cancels_pending_requests(
        self, started_transport: tuple[DiscoveryTransport, MagicMock]
    ):
        """Stopping transport cancels all pending requests."""
        transport, _ = started_transport

        # Add a pending request.
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        request_id = RequestId(data=b"\x01\x02\x03\x04")
        pending = PendingRequest(
            request_id=request_id,
            dest_node_id=NodeId(bytes(32)),
            sent_at=loop.time(),
            nonce=Nonce(bytes(12)),
            message=Ping(request_id=request_id, enr_seq=SeqNumber(1)),
            future=future,
        )
        transport._pending_requests[pending.request_id] = pending

        await transport.stop()

        assert future.cancelled()
        assert len(transport._pending_requests) == 0

    @pytest.mark.anyio
    async def test_stop_is_idempotent(self, local_node_id, local_private_key, local_enr):
        """Stopping an already-stopped transport does nothing."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        # Stop without starting should not raise.
        await transport.stop()
        await transport.stop()


class TestSendResponse:
    """Tests for sending response messages."""

    @pytest.mark.anyio
    async def test_send_response_without_session_returns_false(
        self,
        started_transport: tuple[DiscoveryTransport, MagicMock],
        remote_node_id: NodeId,
    ):
        """Sending response without session fails gracefully."""
        transport, _ = started_transport

        pong = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(9000),
        )

        result = await transport.send_response(remote_node_id, ("192.168.1.1", 30303), pong)

        assert result is False

    @pytest.mark.anyio
    async def test_send_response_without_transport_returns_false(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """Sending response without starting transport fails."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        pong = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(9000),
        )

        result = await transport.send_response(remote_node_id, ("192.168.1.1", 30303), pong)

        assert result is False


class TestMultiPacketNodesCollection:
    """FINDNODE response collection with total > 1.

    When results exceed UDP MTU, NODES responses are split across
    multiple packets. The `total` field indicates expected count.
    """

    def test_pending_multi_request_queue_usage(self):
        """Response queue collects multiple messages."""

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def test_queue():
            queue: asyncio.Queue = asyncio.Queue()

            request_id = RequestId(data=b"\x01\x02\x03\x04")
            pending = PendingMultiRequest(
                request_id=request_id,
                dest_node_id=NodeId(bytes(32)),
                sent_at=123.456,
                nonce=Nonce(bytes(12)),
                message=FindNode(request_id=request_id, distances=[Distance(256)]),
                response_queue=queue,
                expected_total=3,
                received_count=0,
            )

            # Simulate receiving 3 messages.
            ping1 = Ping(request_id=RequestId(data=b"\x01"), enr_seq=SeqNumber(1))
            ping2 = Ping(request_id=RequestId(data=b"\x02"), enr_seq=SeqNumber(2))
            ping3 = Ping(request_id=RequestId(data=b"\x03"), enr_seq=SeqNumber(3))
            await pending.response_queue.put(ping1)
            await pending.response_queue.put(ping2)
            await pending.response_queue.put(ping3)

            # Queue should have all messages.
            assert pending.response_queue.qsize() == 3

            # Retrieve messages.
            msg1 = await pending.response_queue.get()
            msg2 = await pending.response_queue.get()
            msg3 = await pending.response_queue.get()

            assert msg1 is ping1
            assert msg2 is ping2
            assert msg3 is ping3

        loop.run_until_complete(test_queue())
        loop.close()


class TestNodesResponseAccumulation:
    """Tests for accumulating ENRs from multiple NODES responses."""

    def test_empty_nodes_response_handling(self):
        """NODES with total=0 indicates no results."""

        nodes = Nodes(
            request_id=RequestId(data=b"\x01"),
            total=Uint8(0),
            enrs=[],
        )

        assert int(nodes.total) == 0
        assert nodes.enrs == []

    def test_single_nodes_response_collection(self):
        """Single NODES response with total=1."""

        nodes = Nodes(
            request_id=RequestId(data=b"\x01"),
            total=Uint8(1),
            enrs=[b"enr1", b"enr2"],
        )

        assert int(nodes.total) == 1
        assert len(nodes.enrs) == 2

    def test_multiple_nodes_responses_expected(self):
        """Multiple NODES messages share same request_id."""

        request_id = RequestId(data=b"\x01\x02\x03\x04")

        nodes1 = Nodes(
            request_id=request_id,
            total=Uint8(3),
            enrs=[b"enr1", b"enr2"],
        )

        nodes2 = Nodes(
            request_id=request_id,
            total=Uint8(3),
            enrs=[b"enr3", b"enr4"],
        )

        nodes3 = Nodes(
            request_id=request_id,
            total=Uint8(3),
            enrs=[b"enr5"],
        )

        # All messages share same request_id.
        assert bytes(nodes1.request_id) == bytes(nodes2.request_id) == bytes(nodes3.request_id)

        # Each has same total.
        assert int(nodes1.total) == int(nodes2.total) == int(nodes3.total) == 3

        # Accumulate all ENRs.
        all_enrs = nodes1.enrs + nodes2.enrs + nodes3.enrs
        assert len(all_enrs) == 5


class TestRequestResponseCorrelation:
    """Request ID matching and timeout handling tests."""

    def test_request_id_bytes_for_dict_lookup(self):
        """Request ID bytes work as dict key for lookup."""
        pending_requests: dict[bytes, PendingRequest] = {}

        loop = asyncio.new_event_loop()

        request_id_1 = b"\x01\x02\x03\x04"
        request_id_2 = b"\x05\x06\x07\x08"

        future1: asyncio.Future = loop.create_future()
        future2: asyncio.Future = loop.create_future()

        message1 = Ping(request_id=RequestId(data=request_id_1), enr_seq=SeqNumber(1))
        message2 = Ping(request_id=RequestId(data=request_id_2), enr_seq=SeqNumber(2))

        pending1 = PendingRequest(
            request_id=RequestId(data=request_id_1),
            dest_node_id=NodeId(bytes(32)),
            sent_at=loop.time(),
            nonce=Nonce(bytes(12)),
            message=message1,
            future=future1,
        )

        pending2 = PendingRequest(
            request_id=RequestId(data=request_id_2),
            dest_node_id=NodeId(bytes(32)),
            sent_at=loop.time(),
            nonce=Nonce(bytes(12)),
            message=message2,
            future=future2,
        )

        # Store in dict.
        pending_requests[request_id_1] = pending1
        pending_requests[request_id_2] = pending2

        # Lookup by request_id.
        assert pending_requests.get(request_id_1) is pending1
        assert pending_requests.get(request_id_2) is pending2
        assert pending_requests.get(b"\xff\xff\xff\xff") is None

        loop.close()


class TestPendingRequestsManagement:
    """Tests for pending requests dict management."""

    @pytest.mark.anyio
    async def test_pending_requests_dict_initialized_empty(
        self, local_node_id, local_private_key, local_enr
    ):
        """Transport starts with empty pending requests."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        assert len(transport._pending_requests) == 0
        assert len(transport._pending_multi_requests) == 0

    @pytest.mark.anyio
    async def test_pending_requests_cleared_on_stop(
        self, started_transport: tuple[DiscoveryTransport, MagicMock]
    ):
        """Stop clears all pending requests."""
        transport, _ = started_transport

        # Add some pending requests.
        loop = asyncio.get_running_loop()
        for i in range(3):
            future: asyncio.Future = loop.create_future()
            request_id = RequestId(data=bytes([i]))
            pending = PendingRequest(
                request_id=request_id,
                dest_node_id=NodeId(bytes(32)),
                sent_at=loop.time(),
                nonce=Nonce(bytes(12)),
                message=Ping(request_id=request_id, enr_seq=SeqNumber(i)),
                future=future,
            )
            transport._pending_requests[pending.request_id] = pending

        assert len(transport._pending_requests) == 3

        await transport.stop()

        # All should be cleared.
        assert len(transport._pending_requests) == 0

    @pytest.mark.anyio
    async def test_pending_request_futures_cancelled_on_stop(
        self, started_transport: tuple[DiscoveryTransport, MagicMock]
    ):
        """Stop cancels all pending request futures."""
        transport, _ = started_transport

        loop = asyncio.get_running_loop()
        futures = []
        for i in range(3):
            future: asyncio.Future = loop.create_future()
            futures.append(future)
            request_id = RequestId(data=bytes([i]))
            pending = PendingRequest(
                request_id=request_id,
                dest_node_id=NodeId(bytes(32)),
                sent_at=loop.time(),
                nonce=Nonce(bytes(12)),
                message=Ping(request_id=request_id, enr_seq=SeqNumber(i)),
                future=future,
            )
            transport._pending_requests[pending.request_id] = pending

        await transport.stop()

        # All futures should be cancelled.
        for future in futures:
            assert future.cancelled()


class TestSendPing:
    """Tests for send_ping method."""

    @pytest.mark.anyio
    async def test_send_ping_requires_started_transport(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_ping raises if transport not started."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        with pytest.raises(RuntimeError, match="Transport not started"):
            await transport.send_ping(remote_node_id, ("192.168.1.1", 30303))

    @pytest.mark.anyio
    async def test_send_ping_returns_none_on_timeout(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_ping returns None when no response arrives before timeout."""
        config = DiscoveryConfig(request_timeout_secs=0.05)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        result = await transport.send_ping(remote_node_id, ("192.168.1.1", 30303))

        assert result is None
        mock_udp.sendto.assert_called_once()

        await transport.stop()

    @pytest.mark.anyio
    async def test_send_ping_sends_packet_to_correct_address(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_ping sends a packet to the specified address."""
        config = DiscoveryConfig(request_timeout_secs=0.05)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        dest_addr = ("192.168.1.1", 30303)
        await transport.send_ping(remote_node_id, dest_addr)

        # Verify the packet was sent to the correct address.
        args = mock_udp.sendto.call_args
        assert args[0][1] == dest_addr

        await transport.stop()

    @pytest.mark.anyio
    async def test_send_ping_registers_node_address(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_ping registers the destination address for future use."""
        config = DiscoveryConfig(request_timeout_secs=0.05)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        dest_addr = ("192.168.1.1", 30303)
        await transport.send_ping(remote_node_id, dest_addr)

        assert transport.get_node_address(remote_node_id) == dest_addr

        await transport.stop()


class TestSendFindNode:
    """Tests for send_findnode method."""

    @pytest.mark.anyio
    async def test_send_findnode_requires_started_transport(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_findnode raises if transport not started."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        with pytest.raises(RuntimeError, match="Transport not started"):
            await transport.send_findnode(remote_node_id, ("192.168.1.1", 30303), [1, 2])

    @pytest.mark.anyio
    async def test_send_findnode_returns_empty_on_timeout(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_findnode returns empty list when no response arrives."""
        config = DiscoveryConfig(request_timeout_secs=0.05)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        result = await transport.send_findnode(remote_node_id, ("192.168.1.1", 30303), [1, 2, 3])

        assert result == []
        mock_udp.sendto.assert_called_once()

        await transport.stop()

    @pytest.mark.anyio
    async def test_send_findnode_sends_packet_to_correct_address(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_findnode sends a packet to the specified address."""
        config = DiscoveryConfig(request_timeout_secs=0.05)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        dest_addr = ("10.0.0.1", 9001)
        await transport.send_findnode(remote_node_id, dest_addr, [256])

        args = mock_udp.sendto.call_args
        assert args[0][1] == dest_addr

        await transport.stop()


class TestSendTalkReq:
    """Tests for send_talkreq method."""

    @pytest.mark.anyio
    async def test_send_talkreq_requires_started_transport(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_talkreq raises if transport not started."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        with pytest.raises(RuntimeError, match="Transport not started"):
            await transport.send_talkreq(
                remote_node_id, ("192.168.1.1", 30303), b"eth2", b"request"
            )

    @pytest.mark.anyio
    async def test_send_talkreq_returns_none_on_timeout(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_talkreq returns None when no response arrives."""
        config = DiscoveryConfig(request_timeout_secs=0.05)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        result = await transport.send_talkreq(
            remote_node_id, ("192.168.1.1", 30303), b"eth2", b"request"
        )

        assert result is None
        mock_udp.sendto.assert_called_once()

        await transport.stop()


class TestHandleDecodedMessage:
    """Tests for _handle_decoded_message dispatch."""

    @pytest.mark.anyio
    async def test_response_completes_pending_request_future(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """A decoded response message completes the matching pending request future."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        loop = asyncio.get_running_loop()
        future: asyncio.Future[Pong | None] = loop.create_future()
        request_id = RequestId(data=b"\x01\x02\x03\x04")

        pending = PendingRequest(
            request_id=request_id,
            dest_node_id=remote_node_id,
            sent_at=loop.time(),
            nonce=Nonce(bytes(12)),
            message=Ping(request_id=request_id, enr_seq=SeqNumber(1)),
            future=future,
        )
        transport._pending_requests[request_id] = pending

        pong = Pong(
            request_id=request_id,
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(9000),
        )

        await transport._handle_decoded_message(remote_node_id, pong, ("192.168.1.1", 30303))

        assert future.done()
        assert await future is pong

    @pytest.mark.anyio
    async def test_response_enqueued_for_multi_request(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """A decoded NODES message is enqueued for pending multi-request."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        request_id = RequestId(data=b"\x01\x02\x03\x04")
        queue: asyncio.Queue = asyncio.Queue()

        multi_pending = PendingMultiRequest(
            request_id=request_id,
            dest_node_id=remote_node_id,
            sent_at=0.0,
            nonce=Nonce(bytes(12)),
            message=FindNode(request_id=request_id, distances=[Distance(256)]),
            response_queue=queue,
            expected_total=None,
            received_count=0,
        )
        transport._pending_multi_requests[request_id] = multi_pending

        nodes = Nodes(
            request_id=request_id,
            total=Uint8(1),
            enrs=[b"enr1"],
        )

        await transport._handle_decoded_message(remote_node_id, nodes, ("192.168.1.1", 30303))

        assert queue.qsize() == 1
        assert await queue.get() is nodes

    @pytest.mark.anyio
    async def test_unmatched_message_dispatched_to_handler(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """A message with no matching pending request goes to the message handler."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        handler = MagicMock()
        transport.set_message_handler(handler)

        ping = Ping(
            request_id=RequestId(data=b"\xff\xff"),
            enr_seq=SeqNumber(1),
        )

        await transport._handle_decoded_message(remote_node_id, ping, ("192.168.1.1", 30303))

        handler.assert_called_once_with(remote_node_id, ping, ("192.168.1.1", 30303))

    @pytest.mark.anyio
    async def test_unmatched_message_without_handler_is_silent(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """A message with no handler and no pending request is silently dropped."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        ping = Ping(
            request_id=RequestId(data=b"\xff\xff"),
            enr_seq=SeqNumber(1),
        )

        # Should not raise.
        await transport._handle_decoded_message(remote_node_id, ping, ("192.168.1.1", 30303))

    @pytest.mark.anyio
    async def test_decoded_message_touches_session(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """Processing a decoded message calls touch on the session cache."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        with patch.object(transport._session_cache, "touch") as mock_touch:
            ping = Ping(
                request_id=RequestId(data=b"\xff"),
                enr_seq=SeqNumber(1),
            )
            await transport._handle_decoded_message(remote_node_id, ping, ("192.168.1.1", 30303))

            mock_touch.assert_called_once_with(remote_node_id, "192.168.1.1", Port(30303))


class TestHandlePacketDispatch:
    """Tests for _handle_packet routing logic."""

    @pytest.mark.anyio
    async def test_invalid_packet_is_silently_dropped(
        self, local_node_id, local_private_key, local_enr
    ):
        """Malformed packets are dropped without raising."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        # Garbage data that can't be decoded.
        await transport._handle_packet(b"\x00" * 10, ("192.168.1.1", 30303))

    @pytest.mark.anyio
    async def test_short_packet_is_silently_dropped(
        self, local_node_id, local_private_key, local_enr
    ):
        """Packets shorter than minimum size are dropped."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        await transport._handle_packet(b"", ("192.168.1.1", 30303))


class TestHandleMessage:
    """Tests for _handle_message (ordinary MESSAGE packets)."""

    @pytest.mark.anyio
    async def test_message_without_session_sends_whoareyou(
        self, local_node_id, local_private_key, local_enr
    ):
        """MESSAGE from unknown sender triggers WHOAREYOU."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        src_id = NodeId(bytes(range(32)))
        authdata = encode_message_authdata(src_id)

        header = PacketHeader(
            flag=PacketFlag.MESSAGE,
            nonce=Nonce(bytes(12)),
            authdata=authdata,
        )

        with patch.object(transport, "_send_whoareyou", new=AsyncMock()) as mock_whoareyou:
            await transport._handle_message(header, b"\x00" * 32, ("192.168.1.1", 30303), b"ad")

            mock_whoareyou.assert_called_once()


class TestSendWhoareyou:
    """Tests for _send_whoareyou method."""

    @pytest.mark.anyio
    async def test_send_whoareyou_without_transport_is_noop(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """_send_whoareyou does nothing if transport not started."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        # Should not raise.
        await transport._send_whoareyou(remote_node_id, Nonce(bytes(12)), ("192.168.1.1", 30303))

    @pytest.mark.anyio
    async def test_send_whoareyou_sends_packet(
        self,
        started_transport: tuple[DiscoveryTransport, MagicMock],
        remote_node_id: NodeId,
    ):
        """_send_whoareyou sends a WHOAREYOU packet via UDP."""
        transport, mock_udp = started_transport

        await transport._send_whoareyou(remote_node_id, Nonce(bytes(12)), ("192.168.1.1", 30303))

        mock_udp.sendto.assert_called_once()
        args = mock_udp.sendto.call_args
        assert args[0][1] == ("192.168.1.1", 30303)

    @pytest.mark.anyio
    async def test_send_whoareyou_uses_cached_enr_seq(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """_send_whoareyou uses cached ENR seq instead of hardcoded 0."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        # Register a remote ENR with seq=42.
        remote_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(42),
            pairs={EnrKey("id"): b"v4"},
        )
        transport.register_enr(remote_node_id, remote_enr)

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        with patch.object(
            transport._handshake_manager,
            "create_whoareyou",
            wraps=transport._handshake_manager.create_whoareyou,
        ) as mock_create:
            await transport._send_whoareyou(
                remote_node_id, Nonce(bytes(12)), ("192.168.1.1", 30303)
            )

            # Verify enr_seq=42 was passed, not 0.
            call_kwargs = mock_create.call_args
            assert call_kwargs[1]["remote_enr_seq"] == SeqNumber(42)

        await transport.stop()


class TestSendPingNonPong:
    """Tests for send_ping returning None on non-Pong responses."""

    @pytest.mark.anyio
    async def test_send_ping_returns_none_on_non_pong(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_ping returns None when response is not a Pong."""
        config = DiscoveryConfig(request_timeout_secs=0.1)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        request_id = RequestId(data=b"\x01\x02\x03\x04")
        nodes = Nodes(
            request_id=request_id,
            total=Uint8(1),
            enrs=[],
        )

        with patch.object(transport, "_send_request", new=AsyncMock(return_value=nodes)):
            result = await transport.send_ping(remote_node_id, ("192.168.1.1", 30303))

        assert result is None

        await transport.stop()

    @pytest.mark.anyio
    async def test_send_ping_returns_pong_on_pong_response(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_ping returns Pong response when received."""
        config = DiscoveryConfig(request_timeout_secs=0.1)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        request_id = RequestId(data=b"\x01\x02\x03\x04")
        pong = Pong(
            request_id=request_id,
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(9000),
        )

        with patch.object(transport, "_send_request", new=AsyncMock(return_value=pong)):
            result = await transport.send_ping(remote_node_id, ("192.168.1.1", 30303))

        assert result == pong

        await transport.stop()


class TestSendFindNodeNonNodes:
    """Tests for send_findnode handling non-Nodes responses."""

    @pytest.mark.anyio
    async def test_send_findnode_ignores_non_nodes_responses(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_findnode ignores responses that are not NODES."""
        config = DiscoveryConfig(request_timeout_secs=0.1)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        request_id = RequestId(data=b"\x01\x02\x03\x04")
        pong = Pong(
            request_id=request_id,
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(9000),
        )

        with patch.object(
            transport, "_send_multi_response_request", new=AsyncMock(return_value=[pong])
        ):
            result = await transport.send_findnode(remote_node_id, ("192.168.1.1", 30303), [256])

        assert result == []

        await transport.stop()

    @pytest.mark.anyio
    async def test_send_findnode_extracts_enrs_from_nodes(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_findnode extracts ENRs from NODES responses."""
        config = DiscoveryConfig(request_timeout_secs=0.1)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        request_id = RequestId(data=b"\x01\x02\x03\x04")
        nodes = Nodes(
            request_id=request_id,
            total=Uint8(1),
            enrs=[b"enr1", b"enr2"],
        )

        with patch.object(
            transport, "_send_multi_response_request", new=AsyncMock(return_value=[nodes])
        ):
            result = await transport.send_findnode(remote_node_id, ("192.168.1.1", 30303), [256])

        assert result == [b"enr1", b"enr2"]

        await transport.stop()


class TestMultiResponseTimeout:
    """Tests for multi-response collection timeout handling."""

    @pytest.mark.anyio
    async def test_multi_response_deadline_elapsed(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """Multi-response collection exits when deadline has passed."""
        config = DiscoveryConfig(request_timeout_secs=0.0)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        mock_protocol = MagicMock(spec=DiscoveryProtocol)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, mock_protocol)),
        ):
            await transport.start("127.0.0.1", 9000)

        with patch.object(
            transport, "_send_multi_response_request", new=AsyncMock(return_value=[])
        ):
            result = await transport.send_findnode(remote_node_id, ("192.168.1.1", 30303), [256])

        assert result == []

        await transport.stop()

    @pytest.mark.anyio
    async def test_multi_response_nodes_handling(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """Multi-response collection handles NODES responses correctly."""
        config = DiscoveryConfig(request_timeout_secs=5.0)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        mock_protocol = MagicMock(spec=DiscoveryProtocol)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, mock_protocol)),
        ):
            await transport.start("127.0.0.1", 9000)

        request_id = RequestId(data=b"\x01\x02\x03\x04")
        nodes1 = Nodes(request_id=request_id, total=Uint8(2), enrs=[b"enr1"])
        nodes2 = Nodes(request_id=request_id, total=Uint8(2), enrs=[b"enr2"])

        with patch.object(
            transport,
            "_send_multi_response_request",
            new=AsyncMock(return_value=[nodes1, nodes2]),
        ):
            result = await transport.send_findnode(remote_node_id, ("192.168.1.1", 30303), [256])

        assert result == [b"enr1", b"enr2"]

        await transport.stop()


class TestSendMultiResponseRequest:
    """Tests for _send_multi_response_request directly."""

    @pytest.mark.anyio
    async def test_send_multi_response_request_timeout_zero(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """_send_multi_response_request exits immediately with timeout=0."""
        config = DiscoveryConfig(request_timeout_secs=0.0)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        mock_protocol = MagicMock(spec=DiscoveryProtocol)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, mock_protocol)),
        ):
            await transport.start("127.0.0.1", 9000)

        request_id = RequestId(data=b"\x01\x02\x03\x04")
        findnode = FindNode(request_id=request_id, distances=[Distance(256)])

        result = await transport._send_multi_response_request(
            remote_node_id, ("192.168.1.1", 30303), findnode
        )

        assert result == []

        await transport.stop()

    @pytest.mark.anyio
    async def test_send_multi_response_request_collects_responses(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """_send_multi_response_request collects multiple NODES responses."""
        config = DiscoveryConfig(request_timeout_secs=1.0)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        mock_protocol = MagicMock(spec=DiscoveryProtocol)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, mock_protocol)),
        ):
            await transport.start("127.0.0.1", 9000)

        request_id = RequestId(data=b"\x01\x02\x03\x04")
        findnode = FindNode(request_id=request_id, distances=[Distance(256)])

        async def feed_responses():
            await asyncio.sleep(0.01)
            nodes1 = Nodes(request_id=request_id, total=Uint8(2), enrs=[b"enr1"])
            nodes2 = Nodes(request_id=request_id, total=Uint8(2), enrs=[b"enr2"])
            transport._pending_multi_requests[request_id].response_queue.put_nowait(nodes1)
            await asyncio.sleep(0.01)
            transport._pending_multi_requests[request_id].response_queue.put_nowait(nodes2)

        task = asyncio.create_task(
            transport._send_multi_response_request(remote_node_id, ("192.168.1.1", 30303), findnode)
        )
        feed_task = asyncio.create_task(feed_responses())

        result = await task
        await feed_task

        assert result == [
            Nodes(request_id=request_id, total=Uint8(2), enrs=[b"enr1"]),
            Nodes(request_id=request_id, total=Uint8(2), enrs=[b"enr2"]),
        ]

        await transport.stop()


class TestSendTalkReqNonTalkResp:
    """Tests for send_talkreq returning None on non-TalkResp responses."""

    @pytest.mark.anyio
    async def test_send_talkreq_returns_none_on_non_talkresp(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_talkreq returns None when response is not a TalkResp."""
        config = DiscoveryConfig(request_timeout_secs=0.1)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        request_id = RequestId(data=b"\x01\x02\x03\x04")
        pong = Pong(
            request_id=request_id,
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(9000),
        )

        with patch.object(transport, "_send_request", new=AsyncMock(return_value=pong)):
            result = await transport.send_talkreq(
                remote_node_id, ("192.168.1.1", 30303), b"eth2", b"request"
            )

        assert result is None

        await transport.stop()

    @pytest.mark.anyio
    async def test_send_talkreq_returns_response_on_talkresp(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_talkreq returns response when TalkResp is received."""
        config = DiscoveryConfig(request_timeout_secs=0.1)
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
            config=config,
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        request_id = RequestId(data=b"\x01\x02\x03\x04")
        response = b"eth2 response data"
        talkresp = TalkResp(
            request_id=request_id,
            response=response,
        )

        with patch.object(transport, "_send_request", new=AsyncMock(return_value=talkresp)):
            result = await transport.send_talkreq(
                remote_node_id, ("192.168.1.1", 30303), b"eth2", b"request"
            )

        assert result == response

        await transport.stop()


class TestBuildMessagePacketDummyKey:
    """Tests for _build_message_packet without existing session."""

    @pytest.mark.anyio
    async def test_build_message_packet_uses_dummy_key_without_session(
        self,
        started_transport: tuple[DiscoveryTransport, MagicMock],
        remote_node_id: NodeId,
    ):
        """_build_message_packet uses dummy key when no session exists."""
        transport, _ = started_transport

        with patch.object(
            transport._handshake_manager,
            "start_handshake",
        ) as mock_start:
            packet = transport._build_message_packet(
                remote_node_id,
                ("192.168.1.1", 30303),
                Nonce(bytes(12)),
                b"test message",
            )

            mock_start.assert_called_once_with(remote_node_id)
            assert packet is not None

    @pytest.mark.anyio
    async def test_build_message_packet_uses_session_key_with_session(
        self,
        started_transport: tuple[DiscoveryTransport, MagicMock],
        remote_node_id: NodeId,
    ):
        """_build_message_packet uses session key when session exists."""
        transport, _ = started_transport

        transport._session_cache.create(
            remote_node_id,
            send_key=Bytes16(bytes(16)),
            recv_key=Bytes16(bytes(range(16))),
            is_initiator=True,
            ip="192.168.1.1",
            port=Port(30303),
        )

        with patch.object(
            transport._handshake_manager,
            "start_handshake",
        ) as mock_start:
            packet = transport._build_message_packet(
                remote_node_id,
                ("192.168.1.1", 30303),
                Nonce(bytes(12)),
                b"test message",
            )

            mock_start.assert_not_called()
            assert packet is not None


class TestHandlePacketRouting:
    """Tests for _handle_packet routing to WHOAREYOU and HANDSHAKE handlers."""

    @pytest.mark.anyio
    async def test_handle_packet_routes_whoareyou(
        self, local_node_id, local_private_key, local_enr
    ):
        """WHOAREYOU packets are routed to _handle_whoareyou."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        packet_data = encode_packet(
            dest_node_id=local_node_id,
            flag=PacketFlag.WHOAREYOU,
            nonce=Nonce(bytes(12)),
            authdata=bytes(24),
            message=bytes(32),
        )

        with patch.object(transport, "_handle_whoareyou", new=AsyncMock()) as mock_handler:
            await transport._handle_packet(packet_data, ("192.168.1.1", 30303))
            mock_handler.assert_called_once()

    @pytest.mark.anyio
    async def test_handle_packet_routes_handshake(
        self, local_node_id, local_private_key, local_enr
    ):
        """HANDSHAKE packets are routed to _handle_handshake."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        packet_data = encode_packet(
            dest_node_id=local_node_id,
            flag=PacketFlag.HANDSHAKE,
            nonce=Nonce(bytes(12)),
            authdata=bytes(65),
            message=b"encrypted",
            encryption_key=Bytes16(bytes(16)),
        )

        with patch.object(transport, "_handle_handshake", new=AsyncMock()) as mock_handler:
            await transport._handle_packet(packet_data, ("192.168.1.1", 30303))
            mock_handler.assert_called_once()

    @pytest.mark.anyio
    async def test_handle_packet_routes_message(self, local_node_id, local_private_key, local_enr):
        """MESSAGE packets are routed to _handle_message."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        packet_data = encode_packet(
            dest_node_id=local_node_id,
            flag=PacketFlag.MESSAGE,
            nonce=Nonce(bytes(12)),
            authdata=encode_message_authdata(NodeId(bytes(range(32)))),
            message=b"encrypted",
            encryption_key=Bytes16(bytes(16)),
        )

        with patch.object(transport, "_handle_message", new=AsyncMock()) as mock_handler:
            await transport._handle_packet(packet_data, ("192.168.1.1", 30303))
            mock_handler.assert_called_once()


class TestHandleWhoareyou:
    """Tests for _handle_whoareyou edge cases."""

    @pytest.mark.anyio
    async def test_handle_whoareyou_no_matching_request(
        self, local_node_id, local_private_key, local_enr
    ):
        """_handle_whoareyou returns when no pending request matches nonce."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        id_nonce = bytes(16)
        authdata = id_nonce + (1).to_bytes(8, "big")
        packet_data = encode_packet(
            dest_node_id=local_node_id,
            flag=PacketFlag.WHOAREYOU,
            nonce=Nonce(bytes(12)),
            authdata=authdata,
            message=bytes(32),
        )

        with patch.object(transport._handshake_manager, "start_handshake"):
            await transport._handle_packet(packet_data, ("192.168.1.1", 30303))

    @pytest.mark.anyio
    async def test_handle_whoareyou_no_cached_enr(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """_handle_whoareyou returns when no cached ENR for remote."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        loop = asyncio.get_running_loop()
        nonce = Nonce(bytes(12))
        future: asyncio.Future = loop.create_future()
        request_id = RequestId(data=b"\x01")
        pending = PendingRequest(
            request_id=request_id,
            dest_node_id=remote_node_id,
            sent_at=loop.time(),
            nonce=nonce,
            message=Ping(request_id=request_id, enr_seq=SeqNumber(1)),
            future=future,
        )
        transport._pending_requests[pending.request_id] = pending

        id_nonce = bytes(16)
        authdata = id_nonce + (1).to_bytes(8, "big")
        raw_packet = encode_packet(
            dest_node_id=local_node_id,
            flag=PacketFlag.WHOAREYOU,
            nonce=Nonce(bytes(12)),
            authdata=authdata,
            message=bytes(32),
        )

        header, _, _ = decode_packet_header(local_node_id, raw_packet)

        with patch.object(
            transport._handshake_manager,
            "get_cached_enr",
            return_value=None,
        ):
            await transport._handle_whoareyou(header, bytes(24), ("192.168.1.1", 30303), raw_packet)

    @pytest.mark.anyio
    async def test_handle_whoareyou_matching_request_sends_handshake(
        self,
        started_transport: tuple[DiscoveryTransport, MagicMock],
        local_node_id: NodeId,
        remote_node_id: NodeId,
    ):
        """_handle_whoareyou sends HANDSHAKE when pending request matches."""
        transport, mock_udp = started_transport

        nonce_bytes = bytes(12)
        loop = asyncio.get_running_loop()
        nonce = Nonce(nonce_bytes)
        future: asyncio.Future = loop.create_future()
        pending = PendingRequest(
            request_id=RequestId(data=b"\x01"),
            dest_node_id=remote_node_id,
            sent_at=loop.time(),
            nonce=nonce,
            message=Ping(request_id=RequestId(data=b"\x01"), enr_seq=SeqNumber(1)),
            future=future,
        )
        transport._pending_requests[pending.request_id] = pending

        remote_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): NODE_B_PUBKEY,
            },
        )

        authdata = bytes(34)
        mock_response_authdata = authdata
        mock_send_key = Bytes16(bytes(16))
        mock_recv_key = Bytes16(bytes(range(16)))

        with (
            patch.object(
                transport._handshake_manager,
                "get_cached_enr",
                return_value=remote_enr,
            ),
            patch.object(
                transport._handshake_manager,
                "create_handshake_response",
                return_value=(mock_response_authdata, mock_send_key, mock_recv_key),
            ),
        ):
            id_nonce = bytes(16)
            whoareyou_authdata = id_nonce + (1).to_bytes(8, "big")
            raw_packet = encode_packet(
                dest_node_id=local_node_id,
                flag=PacketFlag.WHOAREYOU,
                nonce=nonce,
                authdata=whoareyou_authdata,
                message=bytes(32),
            )

            header, _, _ = decode_packet_header(local_node_id, raw_packet)
            await transport._handle_whoareyou(header, bytes(24), ("192.168.1.1", 30303), raw_packet)

            mock_udp.sendto.assert_called()

    @pytest.mark.anyio
    async def test_handle_whoareyou_handshake_error(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """_handle_whoareyou handles HandshakeError gracefully."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        loop = asyncio.get_running_loop()
        nonce = Nonce(bytes(12))
        future: asyncio.Future = loop.create_future()
        request_id = RequestId(data=b"\x01")
        pending = PendingRequest(
            request_id=request_id,
            dest_node_id=remote_node_id,
            sent_at=loop.time(),
            nonce=nonce,
            message=Ping(request_id=request_id, enr_seq=SeqNumber(1)),
            future=future,
        )
        transport._pending_requests[pending.request_id] = pending

        remote_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): NODE_B_PUBKEY,
            },
        )

        id_nonce = bytes(16)
        authdata = id_nonce + (1).to_bytes(8, "big")
        raw_packet = encode_packet(
            dest_node_id=local_node_id,
            flag=PacketFlag.WHOAREYOU,
            nonce=Nonce(bytes(12)),
            authdata=authdata,
            message=bytes(32),
        )

        header, message_bytes, _ = decode_packet_header(local_node_id, raw_packet)

        with (
            patch.object(
                transport._handshake_manager,
                "get_cached_enr",
                return_value=remote_enr,
            ),
            patch.object(
                transport._handshake_manager,
                "create_handshake_response",
                side_effect=HandshakeError("test error"),
            ),
        ):
            await transport._handle_whoareyou(
                header, message_bytes, ("192.168.1.1", 30303), raw_packet
            )

        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        loop = asyncio.get_running_loop()
        nonce = Nonce(bytes(12))
        future: asyncio.Future = loop.create_future()
        request_id = RequestId(data=b"\x01")
        pending = PendingRequest(
            request_id=request_id,
            dest_node_id=remote_node_id,
            sent_at=loop.time(),
            nonce=nonce,
            message=Ping(request_id=request_id, enr_seq=SeqNumber(1)),
            future=future,
        )
        transport._pending_requests[pending.request_id] = pending

        remote_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=SeqNumber(1),
            pairs={
                EnrKey("id"): b"v4",
                EnrKey("secp256k1"): NODE_B_PUBKEY,
            },
        )

        id_nonce = bytes(16)
        authdata = id_nonce + (1).to_bytes(8, "big")
        raw_packet = encode_packet(
            dest_node_id=local_node_id,
            flag=PacketFlag.WHOAREYOU,
            nonce=Nonce(bytes(12)),
            authdata=authdata,
            message=bytes(32),
        )

        header, message_bytes, _ = decode_packet_header(local_node_id, raw_packet)

        with (
            patch.object(
                transport._handshake_manager,
                "get_cached_enr",
                return_value=remote_enr,
            ),
            patch.object(
                transport._handshake_manager,
                "create_handshake_response",
                side_effect=HandshakeError("test error"),
            ),
        ):
            await transport._handle_whoareyou(
                header, message_bytes, ("192.168.1.1", 30303), raw_packet
            )


class TestHandleHandshake:
    """Tests for _handle_handshake."""

    @pytest.mark.anyio
    async def test_handle_handshake_completes_and_dispatches(
        self, local_node_id, local_private_key, local_enr
    ):
        """_handle_handshake completes handshake and dispatches message."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        remote_node_id = NodeId(bytes(range(32)))
        session = Session(
            node_id=remote_node_id,
            recv_key=Bytes16(bytes(range(16))),
            send_key=Bytes16(bytes(range(16))),
            created_at=0.0,
            last_seen=0.0,
            is_initiator=False,
        )
        result = HandshakeResult(session=session, remote_enr=None)

        mock_authdata = HandshakeAuthdata(
            src_id=remote_node_id,
            sig_size=64,
            eph_key_size=33,
            id_signature=Bytes64(bytes(64)),
            eph_pubkey=Bytes33(bytes(range(33))),
            record=None,
        )

        pong = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(9000),
        )

        with (
            patch(
                "lean_spec.subspecs.networking.discovery.transport.decode_handshake_authdata",
                return_value=mock_authdata,
            ),
            patch.object(
                transport._handshake_manager,
                "handle_handshake",
                return_value=result,
            ),
            patch(
                "lean_spec.subspecs.networking.discovery.transport.decrypt_message",
                return_value=b"decrypted",
            ),
            patch(
                "lean_spec.subspecs.networking.discovery.transport.decode_message",
                return_value=pong,
            ),
            patch.object(
                transport,
                "_handle_decoded_message",
                new=AsyncMock(),
            ) as mock_dispatch,
        ):
            header = MagicMock()
            header.authdata = bytes(65)
            header.nonce = Nonce(bytes(12))

            await transport._handle_handshake(header, b"encrypted", ("192.168.1.1", 30303), b"ad")

            mock_dispatch.assert_called_once()

    @pytest.mark.anyio
    async def test_handle_handshake_empty_message_skips_decryption(
        self, local_node_id, local_private_key, local_enr
    ):
        """_handle_handshake skips decryption when message_bytes is empty."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        remote_node_id = NodeId(bytes(range(32)))
        session = Session(
            node_id=remote_node_id,
            recv_key=Bytes16(bytes(range(16))),
            send_key=Bytes16(bytes(range(16))),
            created_at=0.0,
            last_seen=0.0,
            is_initiator=False,
        )
        result = HandshakeResult(session=session, remote_enr=None)

        mock_authdata = HandshakeAuthdata(
            src_id=remote_node_id,
            sig_size=64,
            eph_key_size=33,
            id_signature=Bytes64(bytes(64)),
            eph_pubkey=Bytes33(bytes(range(33))),
            record=None,
        )

        with (
            patch(
                "lean_spec.subspecs.networking.discovery.transport.decode_handshake_authdata",
                return_value=mock_authdata,
            ),
            patch.object(
                transport._handshake_manager,
                "handle_handshake",
                return_value=result,
            ),
            patch(
                "lean_spec.subspecs.networking.discovery.transport.decrypt_message",
            ) as mock_decrypt,
            patch.object(
                transport,
                "_handle_decoded_message",
                new=AsyncMock(),
            ) as mock_dispatch,
        ):
            header = MagicMock()
            header.authdata = bytes(65)
            header.nonce = Nonce(bytes(12))

            await transport._handle_handshake(header, b"", ("192.168.1.1", 30303), b"ad")

            mock_decrypt.assert_not_called()
            mock_dispatch.assert_not_called()

    @pytest.mark.anyio
    async def test_handle_handshake_error(self, local_node_id, local_private_key, local_enr):
        """_handle_handshake handles errors gracefully."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        remote_node_id = NodeId(bytes(range(32)))
        mock_authdata = HandshakeAuthdata(
            src_id=remote_node_id,
            sig_size=64,
            eph_key_size=33,
            id_signature=Bytes64(bytes(64)),
            eph_pubkey=Bytes33(bytes(range(33))),
            record=None,
        )

        with (
            patch(
                "lean_spec.subspecs.networking.discovery.transport.decode_handshake_authdata",
                return_value=mock_authdata,
            ),
            patch.object(
                transport._handshake_manager,
                "handle_handshake",
                side_effect=HandshakeError("test error"),
            ),
        ):
            header = MagicMock()
            header.authdata = bytes(65)

            await transport._handle_handshake(header, b"", ("192.168.1.1", 30303), b"")


class TestHandleMessageDecryption:
    """Tests for _handle_message decryption failure path."""

    @pytest.mark.anyio
    async def test_handle_message_decryption_failure_sends_whoareyou(
        self, local_node_id, local_private_key, local_enr
    ):
        """Decryption failure triggers WHOAREYOU response."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        src_id = NodeId(bytes(range(32)))
        transport._session_cache.create(
            src_id,
            send_key=Bytes16(bytes(16)),
            recv_key=Bytes16(bytes(range(16))),
            is_initiator=False,
            ip="192.168.1.1",
            port=Port(30303),
        )

        authdata = encode_message_authdata(src_id)

        header = PacketHeader(
            flag=PacketFlag.MESSAGE,
            nonce=Nonce(bytes(12)),
            authdata=authdata,
        )

        with (
            patch(
                "lean_spec.subspecs.networking.discovery.transport.decrypt_message",
                side_effect=InvalidTag(),
            ),
            patch.object(
                transport,
                "_send_whoareyou",
                new=AsyncMock(),
            ) as mock_whoareyou,
        ):
            await transport._handle_message(header, b"encrypted", ("192.168.1.1", 30303), b"ad")

            mock_whoareyou.assert_called_once()


class TestSendResponseWithSession:
    """Tests for send_response with existing session."""

    @pytest.mark.anyio
    async def test_send_response_with_session(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """send_response encrypts and sends when session exists."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        transport._session_cache.create(
            remote_node_id,
            send_key=Bytes16(bytes(16)),
            recv_key=Bytes16(bytes(range(16))),
            is_initiator=False,
            ip="192.168.1.1",
            port=Port(30303),
        )

        mock_udp = MagicMock(spec=asyncio.DatagramTransport)
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock(spec=DiscoveryProtocol))),
        ):
            await transport.start("127.0.0.1", 9000)

        pong = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(9000),
        )

        result = await transport.send_response(remote_node_id, ("192.168.1.1", 30303), pong)

        assert result is True
        mock_udp.sendto.assert_called_once()

        await transport.stop()
