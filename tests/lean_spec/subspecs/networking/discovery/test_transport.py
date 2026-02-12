"""
Tests for Discovery v5 UDP transport layer.

Tests the DiscoveryTransport and DiscoveryProtocol classes.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lean_spec.subspecs.networking.discovery.config import DiscoveryConfig
from lean_spec.subspecs.networking.discovery.messages import (
    IPv4,
    Nodes,
    Nonce,
    PacketFlag,
    Ping,
    Pong,
    Port,
    RequestId,
)
from lean_spec.subspecs.networking.discovery.transport import (
    DiscoveryProtocol,
    DiscoveryTransport,
    PendingMultiRequest,
    PendingRequest,
)
from lean_spec.subspecs.networking.enr import ENR
from lean_spec.subspecs.networking.types import NodeId
from lean_spec.types import Bytes64, Uint64
from lean_spec.types.uint import Uint8


class TestDiscoveryProtocol:
    """Tests for DiscoveryProtocol async UDP handler."""

    def test_connection_made_stores_transport(self):
        """Protocol stores transport reference on connection."""
        mock_handler = MagicMock()
        protocol = DiscoveryProtocol(mock_handler)

        mock_transport = MagicMock()
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
            seq=Uint64(1),
            pairs={"id": b"v4"},
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
        mock_transport_obj = MagicMock()
        mock_protocol_obj = MagicMock()

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

        mock_transport_obj = MagicMock()
        mock_protocol_obj = MagicMock()

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
    async def test_stop_closes_transport(self, local_node_id, local_private_key, local_enr):
        """Stopping transport closes UDP socket."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        mock_transport_obj = MagicMock()
        mock_protocol_obj = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport_obj, mock_protocol_obj)),
        ):
            await transport.start("127.0.0.1", 9000)

        await transport.stop()

        assert not transport._running
        mock_transport_obj.close.assert_called_once()

    @pytest.mark.anyio
    async def test_stop_cancels_pending_requests(self, local_node_id, local_private_key, local_enr):
        """Stopping transport cancels all pending requests."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        mock_transport_obj = MagicMock()
        mock_protocol_obj = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport_obj, mock_protocol_obj)),
        ):
            await transport.start("127.0.0.1", 9000)

        # Add a pending request.
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        pending = PendingRequest(
            request_id=b"\x01\x02\x03\x04",
            dest_node_id=NodeId(bytes(32)),
            sent_at=loop.time(),
            nonce=bytes(12),
            message=MagicMock(),
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


class TestPendingRequest:
    """Tests for PendingRequest dataclass."""

    def test_create_pending_request(self):
        """PendingRequest stores all required fields."""
        loop = asyncio.new_event_loop()
        future: asyncio.Future = loop.create_future()

        message = Ping(request_id=RequestId(data=b"\x01"), enr_seq=Uint64(1))

        pending = PendingRequest(
            request_id=b"\x01\x02\x03\x04",
            dest_node_id=NodeId(bytes(32)),
            sent_at=123.456,
            nonce=bytes(12),
            message=message,
            future=future,
        )

        assert pending.request_id == b"\x01\x02\x03\x04"
        assert pending.dest_node_id == bytes(32)
        assert pending.sent_at == 123.456
        assert pending.nonce == bytes(12)
        assert pending.message is message
        assert pending.future is future

        loop.close()


class TestSendResponse:
    """Tests for sending response messages."""

    @pytest.mark.anyio
    async def test_send_response_without_session_returns_false(
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """Sending response without session fails gracefully."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        mock_transport_obj = MagicMock()
        mock_protocol_obj = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport_obj, mock_protocol_obj)),
        ):
            await transport.start("127.0.0.1", 9000)

        pong = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=Uint64(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(9000),
        )

        result = await transport.send_response(remote_node_id, ("192.168.1.1", 30303), pong)

        assert result is False

        await transport.stop()

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
            enr_seq=Uint64(1),
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

    def test_pending_multi_request_creation(self, local_node_id, local_private_key, local_enr):
        """PendingMultiRequest stores all required fields."""

        loop = asyncio.new_event_loop()
        queue: asyncio.Queue = asyncio.Queue()

        pending = PendingMultiRequest(
            request_id=b"\x01\x02\x03\x04",
            dest_node_id=NodeId(bytes(32)),
            sent_at=123.456,
            nonce=bytes(12),
            message=MagicMock(),
            response_queue=queue,
            expected_total=None,
            received_count=0,
        )

        assert pending.request_id == b"\x01\x02\x03\x04"
        assert pending.expected_total is None
        assert pending.received_count == 0

        loop.close()

    def test_pending_multi_request_expected_total_tracking(self):
        """expected_total is set from first NODES response."""

        loop = asyncio.new_event_loop()
        queue: asyncio.Queue = asyncio.Queue()

        pending = PendingMultiRequest(
            request_id=b"\x01\x02\x03\x04",
            dest_node_id=NodeId(bytes(32)),
            sent_at=123.456,
            nonce=bytes(12),
            message=MagicMock(),
            response_queue=queue,
            expected_total=None,
            received_count=0,
        )

        # Simulate receiving first NODES message with total=3.
        pending.expected_total = 3
        pending.received_count = 1

        assert pending.expected_total == 3
        assert pending.received_count == 1

        # Simulate receiving more.
        pending.received_count = 2
        assert pending.received_count < pending.expected_total

        pending.received_count = 3
        assert pending.received_count >= pending.expected_total

        loop.close()

    def test_pending_multi_request_queue_usage(self):
        """Response queue collects multiple messages."""

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def test_queue():
            queue: asyncio.Queue = asyncio.Queue()

            pending = PendingMultiRequest(
                request_id=b"\x01\x02\x03\x04",
                dest_node_id=NodeId(bytes(32)),
                sent_at=123.456,
                nonce=bytes(12),
                message=MagicMock(),
                response_queue=queue,
                expected_total=3,
                received_count=0,
            )

            # Simulate receiving 3 messages.
            ping1 = Ping(request_id=RequestId(data=b"\x01"), enr_seq=Uint64(1))
            ping2 = Ping(request_id=RequestId(data=b"\x02"), enr_seq=Uint64(2))
            ping3 = Ping(request_id=RequestId(data=b"\x03"), enr_seq=Uint64(3))
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

    def test_pending_request_stores_request_id(self):
        """PendingRequest stores request_id for matching."""
        loop = asyncio.new_event_loop()
        future: asyncio.Future = loop.create_future()

        message = Ping(request_id=RequestId(data=b"\x01\x02\x03\x04"), enr_seq=Uint64(1))

        pending = PendingRequest(
            request_id=b"\x01\x02\x03\x04",
            dest_node_id=NodeId(bytes(32)),
            sent_at=123.456,
            nonce=bytes(12),
            message=message,
            future=future,
        )

        # Request ID should be stored for matching.
        assert pending.request_id == b"\x01\x02\x03\x04"
        assert bytes(pending.message.request_id) == b"\x01\x02\x03\x04"

        loop.close()

    def test_pending_request_future_completion(self):
        """Pending request future can be completed with result."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def test_future():
            future: asyncio.Future = loop.create_future()

            message = Ping(request_id=RequestId(data=b"\x01"), enr_seq=Uint64(1))
            pending = PendingRequest(
                request_id=b"\x01",
                dest_node_id=NodeId(bytes(32)),
                sent_at=loop.time(),
                nonce=bytes(12),
                message=message,
                future=future,
            )

            # Future should not be done yet.
            assert not pending.future.done()

            # Complete the future with a response.
            response = Pong(
                request_id=RequestId(data=b"\x01"),
                enr_seq=Uint64(2),
                recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
                recipient_port=Port(9000),
            )
            pending.future.set_result(response)

            # Future should be done and contain response.
            assert pending.future.done()
            result = await pending.future
            assert result == response

        loop.run_until_complete(test_future())
        loop.close()

    def test_pending_request_future_cancellation(self):
        """Pending request future can be cancelled."""
        loop = asyncio.new_event_loop()

        future: asyncio.Future = loop.create_future()

        message = Ping(request_id=RequestId(data=b"\x01"), enr_seq=Uint64(1))
        pending = PendingRequest(
            request_id=b"\x01",
            dest_node_id=NodeId(bytes(32)),
            sent_at=loop.time(),
            nonce=bytes(12),
            message=message,
            future=future,
        )

        # Cancel the future.
        pending.future.cancel()

        assert pending.future.cancelled()

        loop.close()

    def test_request_id_bytes_for_dict_lookup(self):
        """Request ID bytes work as dict key for lookup."""
        pending_requests: dict[bytes, PendingRequest] = {}

        loop = asyncio.new_event_loop()

        request_id_1 = b"\x01\x02\x03\x04"
        request_id_2 = b"\x05\x06\x07\x08"

        future1: asyncio.Future = loop.create_future()
        future2: asyncio.Future = loop.create_future()

        message1 = Ping(request_id=RequestId(data=request_id_1), enr_seq=Uint64(1))
        message2 = Ping(request_id=RequestId(data=request_id_2), enr_seq=Uint64(2))

        pending1 = PendingRequest(
            request_id=request_id_1,
            dest_node_id=NodeId(bytes(32)),
            sent_at=loop.time(),
            nonce=bytes(12),
            message=message1,
            future=future1,
        )

        pending2 = PendingRequest(
            request_id=request_id_2,
            dest_node_id=NodeId(bytes(32)),
            sent_at=loop.time(),
            nonce=bytes(12),
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

    def test_pending_request_stores_nonce_for_whoareyou_matching(self):
        """Pending request stores nonce for WHOAREYOU matching.

        When WHOAREYOU is received, we match it to pending request via nonce.
        """
        loop = asyncio.new_event_loop()
        future: asyncio.Future = loop.create_future()

        nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"

        message = Ping(request_id=RequestId(data=b"\x01"), enr_seq=Uint64(1))
        pending = PendingRequest(
            request_id=b"\x01",
            dest_node_id=NodeId(bytes(32)),
            sent_at=loop.time(),
            nonce=nonce,
            message=message,
            future=future,
        )

        # Nonce should be stored for WHOAREYOU matching.
        assert pending.nonce == nonce
        assert len(pending.nonce) == 12

        loop.close()

    def test_pending_request_stores_message_for_retransmission(self):
        """Pending request stores original message for retransmission after handshake."""
        loop = asyncio.new_event_loop()
        future: asyncio.Future = loop.create_future()

        message = Ping(request_id=RequestId(data=b"\x01"), enr_seq=Uint64(42))
        pending = PendingRequest(
            request_id=b"\x01",
            dest_node_id=NodeId(bytes(32)),
            sent_at=loop.time(),
            nonce=bytes(12),
            message=message,
            future=future,
        )

        # Original message should be available for retransmission.
        assert pending.message is message
        assert int(pending.message.enr_seq) == 42

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
        self, local_node_id, local_private_key, local_enr
    ):
        """Stop clears all pending requests."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        mock_transport_obj = MagicMock()
        mock_protocol_obj = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport_obj, mock_protocol_obj)),
        ):
            await transport.start("127.0.0.1", 9000)

        # Add some pending requests.
        loop = asyncio.get_running_loop()
        for i in range(3):
            future: asyncio.Future = loop.create_future()
            pending = PendingRequest(
                request_id=bytes([i]),
                dest_node_id=NodeId(bytes(32)),
                sent_at=loop.time(),
                nonce=bytes(12),
                message=MagicMock(),
                future=future,
            )
            transport._pending_requests[pending.request_id] = pending

        assert len(transport._pending_requests) == 3

        await transport.stop()

        # All should be cleared.
        assert len(transport._pending_requests) == 0

    @pytest.mark.anyio
    async def test_pending_request_futures_cancelled_on_stop(
        self, local_node_id, local_private_key, local_enr
    ):
        """Stop cancels all pending request futures."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        mock_transport_obj = MagicMock()
        mock_protocol_obj = MagicMock()

        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_transport_obj, mock_protocol_obj)),
        ):
            await transport.start("127.0.0.1", 9000)

        loop = asyncio.get_running_loop()
        futures = []
        for i in range(3):
            future: asyncio.Future = loop.create_future()
            futures.append(future)
            pending = PendingRequest(
                request_id=bytes([i]),
                dest_node_id=NodeId(bytes(32)),
                sent_at=loop.time(),
                nonce=bytes(12),
                message=MagicMock(),
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

        mock_udp = MagicMock()
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock())),
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

        mock_udp = MagicMock()
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock())),
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

        mock_udp = MagicMock()
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock())),
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

        mock_udp = MagicMock()
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock())),
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

        mock_udp = MagicMock()
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock())),
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

        mock_udp = MagicMock()
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock())),
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
        request_id = b"\x01\x02\x03\x04"

        pending = PendingRequest(
            request_id=request_id,
            dest_node_id=remote_node_id,
            sent_at=loop.time(),
            nonce=bytes(12),
            message=MagicMock(),
            future=future,
        )
        transport._pending_requests[request_id] = pending

        pong = Pong(
            request_id=RequestId(data=request_id),
            enr_seq=Uint64(1),
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

        request_id = b"\x01\x02\x03\x04"
        queue: asyncio.Queue = asyncio.Queue()

        multi_pending = PendingMultiRequest(
            request_id=request_id,
            dest_node_id=remote_node_id,
            sent_at=0.0,
            nonce=bytes(12),
            message=MagicMock(),
            response_queue=queue,
            expected_total=None,
            received_count=0,
        )
        transport._pending_multi_requests[request_id] = multi_pending

        nodes = Nodes(
            request_id=RequestId(data=request_id),
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
            enr_seq=Uint64(1),
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
            enr_seq=Uint64(1),
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
                enr_seq=Uint64(1),
            )
            await transport._handle_decoded_message(remote_node_id, ping, ("192.168.1.1", 30303))

            mock_touch.assert_called_once_with(remote_node_id, "192.168.1.1", 30303)


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

        from lean_spec.subspecs.networking.discovery.packet import (
            PacketHeader,
            encode_message_authdata,
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
        self, local_node_id, local_private_key, local_enr, remote_node_id
    ):
        """_send_whoareyou sends a WHOAREYOU packet via UDP."""
        transport = DiscoveryTransport(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr=local_enr,
        )

        mock_udp = MagicMock()
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock())),
        ):
            await transport.start("127.0.0.1", 9000)

        await transport._send_whoareyou(remote_node_id, Nonce(bytes(12)), ("192.168.1.1", 30303))

        mock_udp.sendto.assert_called_once()
        args = mock_udp.sendto.call_args
        assert args[0][1] == ("192.168.1.1", 30303)

        await transport.stop()

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
            seq=Uint64(42),
            pairs={"id": b"v4"},
        )
        transport.register_enr(remote_node_id, remote_enr)

        mock_udp = MagicMock()
        with patch.object(
            asyncio.get_event_loop(),
            "create_datagram_endpoint",
            new=AsyncMock(return_value=(mock_udp, MagicMock())),
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
            assert call_kwargs[1]["remote_enr_seq"] == 42

        await transport.stop()
