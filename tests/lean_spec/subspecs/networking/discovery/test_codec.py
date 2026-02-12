"""Tests for Discovery v5 message codec."""

import pytest

from lean_spec.subspecs.networking.discovery.codec import (
    MessageDecodingError,
    MessageEncodingError,
    _decode_request_id,
    decode_message,
    encode_message,
    generate_request_id,
)
from lean_spec.subspecs.networking.discovery.messages import (
    Distance,
    FindNode,
    IPv4,
    IPv6,
    MessageType,
    Nodes,
    Ping,
    Pong,
    Port,
    RequestId,
    TalkReq,
    TalkResp,
)
from lean_spec.subspecs.networking.types import SeqNumber
from lean_spec.types.uint import Uint8


class TestPingCodec:
    """Tests for PING message encoding/decoding."""

    def test_encode_decode_roundtrip(self):
        """Test that PING encodes and decodes correctly."""
        ping = Ping(
            request_id=RequestId(data=b"\x01\x02\x03"),
            enr_seq=SeqNumber(42),
        )

        encoded = encode_message(ping)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Ping)
        assert bytes(decoded.request_id) == bytes(ping.request_id)
        assert decoded.enr_seq == ping.enr_seq

    def test_encode_starts_with_message_type(self):
        """Test that encoded PING starts with message type byte."""
        ping = Ping(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(0),
        )

        encoded = encode_message(ping)

        assert encoded[0] == MessageType.PING

    def test_zero_enr_seq(self):
        """Test PING with zero ENR sequence."""
        ping = Ping(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(0),
        )

        encoded = encode_message(ping)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Ping)
        assert decoded.enr_seq == SeqNumber(0)

    def test_large_enr_seq(self):
        """Test PING with large ENR sequence."""
        ping = Ping(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(2**63 - 1),
        )

        encoded = encode_message(ping)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Ping)
        assert decoded.enr_seq == ping.enr_seq


class TestPongCodec:
    """Tests for PONG message encoding/decoding."""

    def test_encode_decode_roundtrip(self):
        """Test that PONG encodes and decodes correctly."""
        pong = Pong(
            request_id=RequestId(data=b"\x01\x02\x03"),
            enr_seq=SeqNumber(42),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),  # 127.0.0.1
            recipient_port=Port(9000),
        )

        encoded = encode_message(pong)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Pong)
        assert bytes(decoded.request_id) == bytes(pong.request_id)
        assert decoded.enr_seq == pong.enr_seq
        assert decoded.recipient_ip == pong.recipient_ip
        assert decoded.recipient_port == pong.recipient_port

    def test_ipv6_address(self):
        """Test PONG with IPv6 address."""
        pong = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=IPv6(bytes(16)),  # ::0
            recipient_port=Port(9000),
        )

        encoded = encode_message(pong)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Pong)
        assert decoded.recipient_ip == IPv6(bytes(16))


class TestFindNodeCodec:
    """Tests for FINDNODE message encoding/decoding."""

    def test_encode_decode_roundtrip(self):
        """Test that FINDNODE encodes and decodes correctly."""
        findnode = FindNode(
            request_id=RequestId(data=b"\x01\x02\x03"),
            distances=[Distance(1), Distance(2), Distance(3)],
        )

        encoded = encode_message(findnode)
        decoded = decode_message(encoded)

        assert isinstance(decoded, FindNode)
        assert bytes(decoded.request_id) == bytes(findnode.request_id)
        assert decoded.distances == findnode.distances

    def test_empty_distances(self):
        """Test FINDNODE with empty distances list."""
        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[],
        )

        encoded = encode_message(findnode)
        decoded = decode_message(encoded)

        assert isinstance(decoded, FindNode)
        assert decoded.distances == []

    def test_distance_zero(self):
        """Test FINDNODE with distance 0 (request own ENR)."""
        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(0)],
        )

        encoded = encode_message(findnode)
        decoded = decode_message(encoded)

        assert isinstance(decoded, FindNode)
        assert decoded.distances == [Distance(0)]

    def test_distance_256(self):
        """Test FINDNODE with maximum distance 256."""
        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(256)],
        )

        encoded = encode_message(findnode)
        decoded = decode_message(encoded)

        assert isinstance(decoded, FindNode)
        assert decoded.distances == [Distance(256)]


class TestNodesCodec:
    """Tests for NODES message encoding/decoding."""

    def test_encode_decode_roundtrip(self):
        """Test that NODES encodes and decodes correctly."""
        nodes = Nodes(
            request_id=RequestId(data=b"\x01\x02\x03"),
            total=Uint8(2),
            enrs=[b"enr1", b"enr2"],
        )

        encoded = encode_message(nodes)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Nodes)
        assert bytes(decoded.request_id) == bytes(nodes.request_id)
        assert decoded.total == nodes.total
        assert decoded.enrs == nodes.enrs

    def test_empty_enrs(self):
        """Test NODES with empty ENRs list."""
        nodes = Nodes(
            request_id=RequestId(data=b"\x01"),
            total=Uint8(1),
            enrs=[],
        )

        encoded = encode_message(nodes)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Nodes)
        assert decoded.enrs == []

    def test_zero_total(self):
        """Test NODES with total=0."""
        nodes = Nodes(
            request_id=RequestId(data=b"\x01"),
            total=Uint8(0),
            enrs=[],
        )

        encoded = encode_message(nodes)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Nodes)
        assert decoded.total == Uint8(0)


class TestTalkReqCodec:
    """Tests for TALKREQ message encoding/decoding."""

    def test_encode_decode_roundtrip(self):
        """Test that TALKREQ encodes and decodes correctly."""
        talkreq = TalkReq(
            request_id=RequestId(data=b"\x01\x02\x03"),
            protocol=b"eth2",
            request=b"hello",
        )

        encoded = encode_message(talkreq)
        decoded = decode_message(encoded)

        assert isinstance(decoded, TalkReq)
        assert bytes(decoded.request_id) == bytes(talkreq.request_id)
        assert decoded.protocol == talkreq.protocol
        assert decoded.request == talkreq.request

    def test_empty_request(self):
        """Test TALKREQ with empty request."""
        talkreq = TalkReq(
            request_id=RequestId(data=b"\x01"),
            protocol=b"test",
            request=b"",
        )

        encoded = encode_message(talkreq)
        decoded = decode_message(encoded)

        assert isinstance(decoded, TalkReq)
        assert decoded.request == b""


class TestTalkRespCodec:
    """Tests for TALKRESP message encoding/decoding."""

    def test_encode_decode_roundtrip(self):
        """Test that TALKRESP encodes and decodes correctly."""
        talkresp = TalkResp(
            request_id=RequestId(data=b"\x01\x02\x03"),
            response=b"world",
        )

        encoded = encode_message(talkresp)
        decoded = decode_message(encoded)

        assert isinstance(decoded, TalkResp)
        assert bytes(decoded.request_id) == bytes(talkresp.request_id)
        assert decoded.response == talkresp.response

    def test_empty_response(self):
        """Test TALKRESP with empty response (protocol unknown)."""
        talkresp = TalkResp(
            request_id=RequestId(data=b"\x01"),
            response=b"",
        )

        encoded = encode_message(talkresp)
        decoded = decode_message(encoded)

        assert isinstance(decoded, TalkResp)
        assert decoded.response == b""


class TestDecodingErrors:
    """Tests for message decoding error handling."""

    def test_empty_data_raises(self):
        """Test that empty data raises MessageDecodingError."""
        with pytest.raises(MessageDecodingError, match="Message too short"):
            decode_message(b"")

    def test_single_byte_raises(self):
        """Test that single byte raises MessageDecodingError."""
        with pytest.raises(MessageDecodingError, match="Message too short"):
            decode_message(b"\x01")

    def test_unknown_message_type_raises(self):
        """Test that unknown message type raises MessageDecodingError."""
        with pytest.raises(MessageDecodingError, match="Unknown message type"):
            decode_message(b"\xff\xc0")  # Unknown type + empty RLP list

    def test_invalid_rlp_raises(self):
        """Test that invalid RLP raises MessageDecodingError."""
        with pytest.raises(MessageDecodingError):
            decode_message(b"\x01\xff\xff")  # PING type + invalid RLP


class TestEncodingErrors:
    """Tests for message encoding error handling."""

    def test_encode_unknown_type_raises(self):
        """Encoding an unsupported message type raises MessageEncodingError."""
        with pytest.raises(MessageEncodingError, match="Unknown message type"):
            encode_message("not_a_message")  # type: ignore[arg-type]


class TestRequestIdDecoding:
    """Tests for request ID decoding edge cases."""

    def test_request_id_too_long_raises(self):
        """Request ID longer than 8 bytes raises ValueError."""
        with pytest.raises(ValueError, match="Request ID too long"):
            _decode_request_id(bytes(9))


class TestRequestIdGeneration:
    """Tests for request ID generation."""

    def test_generates_8_byte_id(self):
        """Test that generated request ID is 8 bytes."""
        request_id = generate_request_id()
        assert len(request_id) == 8

    def test_generates_different_ids(self):
        """Test that each generation produces a different ID."""
        id1 = generate_request_id()
        id2 = generate_request_id()
        assert id1 != id2


class TestAddressEncoding:
    """IPv4 and IPv6 address handling in PONG messages."""

    def test_pong_ipv4_4_bytes(self):
        """PONG encodes IPv4 as 4 bytes."""
        pong = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),  # 127.0.0.1
            recipient_port=Port(9000),
        )

        assert len(pong.recipient_ip) == 4
        assert pong.recipient_ip == IPv4(b"\x7f\x00\x00\x01")

        # Encode and decode roundtrip.
        encoded = encode_message(pong)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Pong)
        assert decoded.recipient_ip == IPv4(b"\x7f\x00\x00\x01")

    def test_pong_ipv6_16_bytes(self):
        """PONG encodes IPv6 as 16 bytes."""
        # IPv6 loopback ::1
        ipv6_loopback = IPv6(bytes(15) + b"\x01")

        pong = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=ipv6_loopback,
            recipient_port=Port(9000),
        )

        assert len(pong.recipient_ip) == 16

        # Encode and decode roundtrip.
        encoded = encode_message(pong)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Pong)
        assert decoded.recipient_ip == ipv6_loopback

    def test_pong_common_ipv4_addresses(self):
        """Common IPv4 addresses encode correctly."""
        test_addresses = [
            (IPv4(b"\x00\x00\x00\x00"), "0.0.0.0"),
            (IPv4(b"\x7f\x00\x00\x01"), "127.0.0.1"),
            (IPv4(b"\xc0\xa8\x01\x01"), "192.168.1.1"),
            (IPv4(b"\xff\xff\xff\xff"), "255.255.255.255"),
        ]

        for ip_bytes, _ in test_addresses:
            pong = Pong(
                request_id=RequestId(data=b"\x01"),
                enr_seq=SeqNumber(1),
                recipient_ip=ip_bytes,
                recipient_port=Port(9000),
            )

            encoded = encode_message(pong)
            decoded = decode_message(encoded)

            assert isinstance(decoded, Pong)
            assert decoded.recipient_ip == ip_bytes

    def test_pong_common_ipv6_addresses(self):
        """Common IPv6 addresses encode correctly."""
        # ::1 (loopback)
        ipv6_loopback = IPv6(bytes(15) + b"\x01")

        # fe80::1 (link-local)
        ipv6_link_local = IPv6(b"\xfe\x80" + bytes(13) + b"\x01")

        test_addresses = [
            IPv6(bytes(16)),  # ::
            ipv6_loopback,  # ::1
            ipv6_link_local,  # fe80::1
        ]

        for ip_bytes in test_addresses:
            pong = Pong(
                request_id=RequestId(data=b"\x01"),
                enr_seq=SeqNumber(1),
                recipient_ip=ip_bytes,
                recipient_port=Port(9000),
            )

            encoded = encode_message(pong)
            decoded = decode_message(encoded)

            assert isinstance(decoded, Pong)
            assert decoded.recipient_ip == ip_bytes


class TestPortEncoding:
    """Port encoding in PONG messages."""

    def test_pong_port_common_values(self):
        """Common port values encode correctly."""
        test_ports = [
            80,  # HTTP
            443,  # HTTPS
            8545,  # Ethereum RPC
            9000,  # Discovery default
            30303,  # devp2p default
            65535,  # Maximum port
        ]

        for port_value in test_ports:
            pong = Pong(
                request_id=RequestId(data=b"\x01"),
                enr_seq=SeqNumber(1),
                recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
                recipient_port=Port(port_value),
            )

            encoded = encode_message(pong)
            decoded = decode_message(encoded)

            assert isinstance(decoded, Pong)
            assert int(decoded.recipient_port) == port_value

    def test_pong_port_boundary_values(self):
        """Port boundary values encode correctly."""
        # Minimum port (0 is valid in UDP)
        pong_min = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(0),
        )

        encoded = encode_message(pong_min)
        decoded = decode_message(encoded)
        assert isinstance(decoded, Pong)
        assert int(decoded.recipient_port) == 0

        # Maximum port
        pong_max = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),
            recipient_port=Port(65535),
        )

        encoded = encode_message(pong_max)
        decoded = decode_message(encoded)
        assert isinstance(decoded, Pong)
        assert int(decoded.recipient_port) == 65535
