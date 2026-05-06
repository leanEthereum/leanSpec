"""Test vectors for gossipsub message ID computation."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

VALID_SNAPPY = "0x01000000"
"""Domain prefix for messages where snappy decompression succeeded."""

INVALID_SNAPPY = "0x00000000"
"""Domain prefix for messages where snappy decompression failed."""

BLOCK_TOPIC = "0x" + b"/leanconsensus/12345678/block/ssz_snappy".hex()
"""Hex-encoded topic bytes for a typical block topic string."""


# --- Valid snappy domain ---


def test_message_id_valid_snappy(networking_codec: NetworkingCodecTestFiller) -> None:
    """Message ID with valid-snappy domain and typical block data."""
    networking_codec(
        codec_name="gossip_message_id",
        input={
            "topic": BLOCK_TOPIC,
            "data": "0xdeadbeef",
            "domain": VALID_SNAPPY,
        },
    )


def test_message_id_valid_snappy_large_payload(networking_codec: NetworkingCodecTestFiller) -> None:
    """Message ID with valid-snappy domain and a larger payload."""
    networking_codec(
        codec_name="gossip_message_id",
        input={
            "topic": BLOCK_TOPIC,
            "data": "0x" + "ab" * 256,
            "domain": VALID_SNAPPY,
        },
    )


# --- Invalid snappy domain ---


def test_message_id_invalid_snappy(networking_codec: NetworkingCodecTestFiller) -> None:
    """Message ID with invalid-snappy domain and same data as the valid test."""
    networking_codec(
        codec_name="gossip_message_id",
        input={
            "topic": BLOCK_TOPIC,
            "data": "0xdeadbeef",
            "domain": INVALID_SNAPPY,
        },
    )


# --- Empty inputs ---


def test_message_id_empty_data(networking_codec: NetworkingCodecTestFiller) -> None:
    """Message ID with empty payload."""
    networking_codec(
        codec_name="gossip_message_id",
        input={
            "topic": BLOCK_TOPIC,
            "data": "0x",
            "domain": VALID_SNAPPY,
        },
    )


def test_message_id_empty_topic(networking_codec: NetworkingCodecTestFiller) -> None:
    """Message ID with empty topic string."""
    networking_codec(
        codec_name="gossip_message_id",
        input={
            "topic": "0x",
            "data": "0xdeadbeef",
            "domain": VALID_SNAPPY,
        },
    )


def test_message_id_both_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """Message ID with both topic and data empty."""
    networking_codec(
        codec_name="gossip_message_id",
        input={
            "topic": "0x",
            "data": "0x",
            "domain": VALID_SNAPPY,
        },
    )


# --- Domain differentiation ---


def test_message_id_domain_changes_id(networking_codec: NetworkingCodecTestFiller) -> None:
    """Same topic and data with invalid-snappy domain produces a different ID."""
    networking_codec(
        codec_name="gossip_message_id",
        input={
            "topic": "0x" + b"test-topic".hex(),
            "data": "0x" + b"hello world".hex(),
            "domain": INVALID_SNAPPY,
        },
    )


def test_message_id_domain_valid_same_data(networking_codec: NetworkingCodecTestFiller) -> None:
    """Same topic and data with valid-snappy domain for cross-reference."""
    networking_codec(
        codec_name="gossip_message_id",
        input={
            "topic": "0x" + b"test-topic".hex(),
            "data": "0x" + b"hello world".hex(),
            "domain": VALID_SNAPPY,
        },
    )
