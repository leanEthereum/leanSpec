"""
Tests for Discovery v5 protocol messages, types, and constants.

Validates that protocol constants, message types, custom types, and
configuration match the Discovery v5 specification.
"""

from __future__ import annotations

from lean_spec.subspecs.networking.discovery.config import (
    ALPHA,
    BOND_EXPIRY_SECS,
    BUCKET_COUNT,
    HANDSHAKE_TIMEOUT_SECS,
    K_BUCKET_SIZE,
    MAX_NODES_RESPONSE,
    REQUEST_TIMEOUT_SECS,
    DiscoveryConfig,
)
from lean_spec.subspecs.networking.discovery.messages import (
    MAX_REQUEST_ID_LENGTH,
    PROTOCOL_ID,
    PROTOCOL_VERSION,
    Distance,
    FindNode,
    IdNonce,
    IPv4,
    IPv6,
    MessageType,
    Nodes,
    Nonce,
    PacketFlag,
    Ping,
    Pong,
    Port,
    RequestId,
    TalkReq,
    TalkResp,
)
from lean_spec.subspecs.networking.discovery.packet import WhoAreYouAuthdata
from lean_spec.subspecs.networking.types import SeqNumber
from lean_spec.types.uint import Uint8, Uint16, Uint64
from tests.lean_spec.subspecs.networking.discovery.conftest import SPEC_ID_NONCE


class TestProtocolConstants:
    """Verify protocol constants match Discovery v5 specification."""

    def test_protocol_id(self):
        assert PROTOCOL_ID == b"discv5"
        assert len(PROTOCOL_ID) == 6

    def test_protocol_version(self):
        assert PROTOCOL_VERSION == 0x0001

    def test_max_request_id_length(self):
        assert MAX_REQUEST_ID_LENGTH == 8

    def test_k_bucket_size(self):
        assert K_BUCKET_SIZE == 16

    def test_alpha_concurrency(self):
        assert ALPHA == 3

    def test_bucket_count(self):
        assert BUCKET_COUNT == 256

    def test_request_timeout(self):
        assert REQUEST_TIMEOUT_SECS == 0.5

    def test_handshake_timeout(self):
        assert HANDSHAKE_TIMEOUT_SECS == 1.0

    def test_max_nodes_response(self):
        assert MAX_NODES_RESPONSE == 16

    def test_bond_expiry(self):
        assert BOND_EXPIRY_SECS == 86400


class TestCustomTypes:
    """Tests for custom Discovery v5 types."""

    def test_request_id_limit(self):
        req_id = RequestId(data=b"\x01\x02\x03\x04\x05\x06\x07\x08")
        assert len(req_id.data) == 8

    def test_request_id_variable_length(self):
        req_id = RequestId(data=b"\x01")
        assert len(req_id.data) == 1

    def test_ipv4_length(self):
        ip = IPv4(b"\xc0\xa8\x01\x01")
        assert len(ip) == 4

    def test_ipv6_length(self):
        ip = IPv6(b"\x00" * 15 + b"\x01")
        assert len(ip) == 16

    def test_id_nonce_length(self):
        nonce = IdNonce(b"\x01" * 16)
        assert len(nonce) == 16

    def test_nonce_length(self):
        nonce = Nonce(b"\x01" * 12)
        assert len(nonce) == 12

    def test_distance_type(self):
        d = Distance(256)
        assert isinstance(d, Uint16)

    def test_port_type(self):
        p = Port(30303)
        assert isinstance(p, Uint16)

    def test_enr_seq_type(self):
        seq = SeqNumber(42)
        assert isinstance(seq, Uint64)


class TestPacketFlag:
    """Tests for packet type flags."""

    def test_message_flag(self):
        assert PacketFlag.MESSAGE == 0

    def test_whoareyou_flag(self):
        assert PacketFlag.WHOAREYOU == 1

    def test_handshake_flag(self):
        assert PacketFlag.HANDSHAKE == 2


class TestMessageTypes:
    """Verify message type codes match wire protocol spec."""

    def test_ping_type(self):
        assert MessageType.PING == 0x01

    def test_pong_type(self):
        assert MessageType.PONG == 0x02

    def test_findnode_type(self):
        assert MessageType.FINDNODE == 0x03

    def test_nodes_type(self):
        assert MessageType.NODES == 0x04

    def test_talkreq_type(self):
        assert MessageType.TALKREQ == 0x05

    def test_talkresp_type(self):
        assert MessageType.TALKRESP == 0x06

    def test_experimental_types(self):
        assert MessageType.REGTOPIC == 0x07
        assert MessageType.TICKET == 0x08
        assert MessageType.REGCONFIRMATION == 0x09
        assert MessageType.TOPICQUERY == 0x0A


class TestDiscoveryConfig:
    """Tests for DiscoveryConfig."""

    def test_default_values(self):
        config = DiscoveryConfig()

        assert config.k_bucket_size == K_BUCKET_SIZE
        assert config.alpha == ALPHA
        assert config.request_timeout_secs == REQUEST_TIMEOUT_SECS
        assert config.handshake_timeout_secs == HANDSHAKE_TIMEOUT_SECS
        assert config.max_nodes_response == MAX_NODES_RESPONSE
        assert config.bond_expiry_secs == BOND_EXPIRY_SECS

    def test_custom_values(self):
        config = DiscoveryConfig(
            k_bucket_size=8,
            alpha=5,
            request_timeout_secs=2.0,
        )
        assert config.k_bucket_size == 8
        assert config.alpha == 5
        assert config.request_timeout_secs == 2.0


class TestPing:
    """Tests for PING message."""

    def test_creation_with_types(self):
        ping = Ping(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            enr_seq=SeqNumber(2),
        )

        assert ping.request_id.data == b"\x00\x00\x00\x01"
        assert ping.enr_seq == SeqNumber(2)

    def test_max_request_id_length(self):
        ping = Ping(
            request_id=RequestId(data=b"\x01\x02\x03\x04\x05\x06\x07\x08"),
            enr_seq=SeqNumber(1),
        )
        assert len(ping.request_id.data) == 8


class TestPong:
    """Tests for PONG message."""

    def test_creation_ipv4(self):
        pong = Pong(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            enr_seq=SeqNumber(42),
            recipient_ip=IPv4(b"\xc0\xa8\x01\x01"),
            recipient_port=Port(9000),
        )

        assert pong.enr_seq == SeqNumber(42)
        assert len(pong.recipient_ip) == 4
        assert pong.recipient_port == Port(9000)

    def test_creation_ipv6(self):
        ipv6 = IPv6(b"\x00" * 15 + b"\x01")
        pong = Pong(
            request_id=RequestId(data=b"\x01"),
            enr_seq=SeqNumber(1),
            recipient_ip=ipv6,
            recipient_port=Port(30303),
        )

        assert len(pong.recipient_ip) == 16


class TestFindNode:
    """Tests for FINDNODE message."""

    def test_single_distance(self):
        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(256)],
        )
        assert findnode.distances == [Distance(256)]

    def test_multiple_distances(self):
        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(0), Distance(1), Distance(255), Distance(256)],
        )
        assert Distance(0) in findnode.distances
        assert Distance(256) in findnode.distances

    def test_distance_zero_returns_self(self):
        findnode = FindNode(
            request_id=RequestId(data=b"\x01"),
            distances=[Distance(0)],
        )
        assert findnode.distances == [Distance(0)]


class TestNodes:
    """Tests for NODES message."""

    def test_single_response(self):
        nodes = Nodes(
            request_id=RequestId(data=b"\x01"),
            total=Uint8(1),
            enrs=[b"enr:-example"],
        )
        assert nodes.total == Uint8(1)
        assert len(nodes.enrs) == 1

    def test_multiple_responses(self):
        nodes = Nodes(
            request_id=RequestId(data=b"\x01"),
            total=Uint8(3),
            enrs=[b"enr1", b"enr2"],
        )
        assert nodes.total == Uint8(3)
        assert len(nodes.enrs) == 2


class TestTalkReq:
    """Tests for TALKREQ message."""

    def test_creation(self):
        req = TalkReq(
            request_id=RequestId(data=b"\x01"),
            protocol=b"portal",
            request=b"payload",
        )
        assert req.protocol == b"portal"
        assert req.request == b"payload"


class TestTalkResp:
    """Tests for TALKRESP message."""

    def test_creation(self):
        resp = TalkResp(
            request_id=RequestId(data=b"\x01"),
            response=b"response_data",
        )
        assert resp.response == b"response_data"

    def test_empty_response_unknown_protocol(self):
        resp = TalkResp(
            request_id=RequestId(data=b"\x01"),
            response=b"",
        )
        assert resp.response == b""


class TestWhoAreYouAuthdataConstruction:
    """Tests for WHOAREYOU authdata construction."""

    def test_creation(self):
        authdata = WhoAreYouAuthdata(
            id_nonce=IdNonce(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"),
            enr_seq=Uint64(0),
        )
        assert len(authdata.id_nonce) == 16
        assert authdata.enr_seq == Uint64(0)


class TestMessageConstructionFromTestVectors:
    """Test message construction using official Discovery v5 test vector inputs."""

    PING_REQUEST_ID = bytes.fromhex("00000001")
    PING_ENR_SEQ = 2

    def test_ping_message_construction(self):
        ping = Ping(
            request_id=RequestId(data=self.PING_REQUEST_ID),
            enr_seq=SeqNumber(self.PING_ENR_SEQ),
        )
        assert ping.request_id.data == self.PING_REQUEST_ID
        assert ping.enr_seq == SeqNumber(2)

    def test_whoareyou_authdata_construction(self):
        authdata = WhoAreYouAuthdata(
            id_nonce=IdNonce(SPEC_ID_NONCE),
            enr_seq=Uint64(0),
        )
        assert authdata.id_nonce == IdNonce(SPEC_ID_NONCE)
        assert authdata.enr_seq == Uint64(0)

    def test_plaintext_message_type(self):
        plaintext = bytes.fromhex("01c20101")
        assert plaintext[0] == MessageType.PING
