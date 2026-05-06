"""Test vectors for Discovery v5 message RLP encoding."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

IPV4_LOCALHOST = "0x7f000001"
"""127.0.0.1 as 4 raw bytes."""

IPV6_LOOPBACK = "0x00000000000000000000000000000001"
"""::1 as 16 raw bytes."""


# --- PING ---


def test_ping_typical(networking_codec: NetworkingCodecTestFiller) -> None:
    """PING with request_id=0x01 and enr_seq=1. Matches devp2p spec plaintext 01c20101."""
    networking_codec(
        codec_name="discv5_message",
        input={"type": "ping", "requestId": "0x01", "enrSeq": 1},
    )


def test_ping_leading_zeros_stripped(networking_codec: NetworkingCodecTestFiller) -> None:
    """PING with 4-byte request_id containing leading zeros. Stripped to minimal encoding."""
    networking_codec(
        codec_name="discv5_message",
        input={"type": "ping", "requestId": "0x00000001", "enrSeq": 1},
    )


def test_ping_seq_zero(networking_codec: NetworkingCodecTestFiller) -> None:
    """PING with enr_seq=0. Zero encodes as RLP empty bytes, not 0x00."""
    networking_codec(
        codec_name="discv5_message",
        input={"type": "ping", "requestId": "0x01", "enrSeq": 0},
    )


# --- PONG ---


def test_pong_ipv4(networking_codec: NetworkingCodecTestFiller) -> None:
    """PONG with IPv4 127.0.0.1 and port 30303."""
    networking_codec(
        codec_name="discv5_message",
        input={
            "type": "pong",
            "requestId": "0x01",
            "enrSeq": 1,
            "recipientIp": IPV4_LOCALHOST,
            "recipientPort": 30303,
        },
    )


def test_pong_ipv6(networking_codec: NetworkingCodecTestFiller) -> None:
    """PONG with IPv6 loopback (::1). 16-byte IP discriminates from IPv4."""
    networking_codec(
        codec_name="discv5_message",
        input={
            "type": "pong",
            "requestId": "0x01",
            "enrSeq": 1,
            "recipientIp": IPV6_LOOPBACK,
            "recipientPort": 9000,
        },
    )


def test_pong_port_zero(networking_codec: NetworkingCodecTestFiller) -> None:
    """PONG with port=0. Zero port encodes as RLP empty bytes."""
    networking_codec(
        codec_name="discv5_message",
        input={
            "type": "pong",
            "requestId": "0x01",
            "enrSeq": 1,
            "recipientIp": IPV4_LOCALHOST,
            "recipientPort": 0,
        },
    )


# --- FINDNODE ---


def test_findnode_single_distance(networking_codec: NetworkingCodecTestFiller) -> None:
    """FINDNODE requesting distance 256 (2-byte big-endian in nested RLP list)."""
    networking_codec(
        codec_name="discv5_message",
        input={"type": "findnode", "requestId": "0x01", "distances": [256]},
    )


def test_findnode_mixed_distances(networking_codec: NetworkingCodecTestFiller) -> None:
    """FINDNODE with distances [0, 1, 256]. Tests zero and multi-byte encoding."""
    networking_codec(
        codec_name="discv5_message",
        input={"type": "findnode", "requestId": "0x01", "distances": [0, 1, 256]},
    )


def test_findnode_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """FINDNODE with empty distance list."""
    networking_codec(
        codec_name="discv5_message",
        input={"type": "findnode", "requestId": "0x01", "distances": []},
    )


# --- NODES ---


def test_nodes_single_enr(networking_codec: NetworkingCodecTestFiller) -> None:
    """NODES response with total=1 and one ENR (raw RLP bytes)."""
    networking_codec(
        codec_name="discv5_message",
        input={
            "type": "nodes",
            "requestId": "0x01",
            "total": 1,
            "enrs": ["0xdeadbeef"],
        },
    )


def test_nodes_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """NODES response with total=0 and empty ENR list."""
    networking_codec(
        codec_name="discv5_message",
        input={"type": "nodes", "requestId": "0x01", "total": 0, "enrs": []},
    )


# --- TALKREQ ---


def test_talkreq_typical(networking_codec: NetworkingCodecTestFiller) -> None:
    """TALKREQ with protocol identifier and request payload."""
    networking_codec(
        codec_name="discv5_message",
        input={
            "type": "talkreq",
            "requestId": "0x01",
            "protocol": "0x" + b"discv5-test".hex(),
            "request": "0xdeadbeef",
        },
    )


def test_talkreq_empty_payload(networking_codec: NetworkingCodecTestFiller) -> None:
    """TALKREQ with empty request payload."""
    networking_codec(
        codec_name="discv5_message",
        input={
            "type": "talkreq",
            "requestId": "0x01",
            "protocol": "0x" + b"discv5-test".hex(),
            "request": "0x",
        },
    )


# --- TALKRESP ---


def test_talkresp_typical(networking_codec: NetworkingCodecTestFiller) -> None:
    """TALKRESP with response payload."""
    networking_codec(
        codec_name="discv5_message",
        input={
            "type": "talkresp",
            "requestId": "0x01",
            "response": "0xcafebabe",
        },
    )


def test_talkresp_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """TALKRESP with empty response."""
    networking_codec(
        codec_name="discv5_message",
        input={"type": "talkresp", "requestId": "0x01", "response": "0x"},
    )
