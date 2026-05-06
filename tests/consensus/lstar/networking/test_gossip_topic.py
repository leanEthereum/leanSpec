"""Test vectors for gossipsub topic string encoding and parsing."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

FORK_DIGEST = "12345678"
"""Arbitrary fork digest used across topic tests."""


# --- Block topics ---


def test_block_topic(networking_codec: NetworkingCodecTestFiller) -> None:
    """Block topic with typical fork digest."""
    networking_codec(
        codec_name="gossip_topic",
        input={"kind": "block", "forkDigest": FORK_DIGEST},
    )


def test_block_topic_different_digest(networking_codec: NetworkingCodecTestFiller) -> None:
    """Block topic with a different fork digest to verify digest embedding."""
    networking_codec(
        codec_name="gossip_topic",
        input={"kind": "block", "forkDigest": "aabbccdd"},
    )


# --- Aggregation topics ---


def test_aggregation_topic(networking_codec: NetworkingCodecTestFiller) -> None:
    """Committee aggregation topic."""
    networking_codec(
        codec_name="gossip_topic",
        input={"kind": "aggregation", "forkDigest": FORK_DIGEST},
    )


# --- Attestation subnet topics ---


def test_attestation_subnet_zero(networking_codec: NetworkingCodecTestFiller) -> None:
    """Attestation subnet 0. First subnet ID."""
    networking_codec(
        codec_name="gossip_topic",
        input={"kind": "attestation", "forkDigest": FORK_DIGEST, "subnetId": 0},
    )


def test_attestation_subnet_seven(networking_codec: NetworkingCodecTestFiller) -> None:
    """Attestation subnet 7. Mid-range subnet ID."""
    networking_codec(
        codec_name="gossip_topic",
        input={"kind": "attestation", "forkDigest": FORK_DIGEST, "subnetId": 7},
    )


def test_attestation_subnet_63(networking_codec: NetworkingCodecTestFiller) -> None:
    """Attestation subnet 63. Last subnet in a 64-subnet network."""
    networking_codec(
        codec_name="gossip_topic",
        input={"kind": "attestation", "forkDigest": FORK_DIGEST, "subnetId": 63},
    )


# --- Edge cases ---


def test_block_topic_zero_digest(networking_codec: NetworkingCodecTestFiller) -> None:
    """Block topic with all-zero fork digest."""
    networking_codec(
        codec_name="gossip_topic",
        input={"kind": "block", "forkDigest": "00000000"},
    )


def test_block_topic_max_digest(networking_codec: NetworkingCodecTestFiller) -> None:
    """Block topic with all-0xff fork digest."""
    networking_codec(
        codec_name="gossip_topic",
        input={"kind": "block", "forkDigest": "ffffffff"},
    )
