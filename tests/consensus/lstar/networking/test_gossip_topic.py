"""Test vectors for gossipsub topic string encoding and parsing."""

import pytest

from consensus_testing import GossipTopicRoundtrip, NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

FORK_DIGEST = "12345678"
"""Arbitrary fork digest used across topic tests."""


def test_block_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A block topic round-trips through its string form.

    Given
    -----
    - a block topic kind.
    - a typical fork digest.

    When
    ----
    - the topic is formatted to a string and parsed back.

    Then
    ----
    - the parsed topic matches the input.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="block", network_name=FORK_DIGEST),
    )


def test_block_topic_different_digest(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A block topic embeds and recovers a different fork digest.

    Given
    -----
    - a block topic kind.
    - a fork digest distinct from the default.

    When
    ----
    - the topic is formatted to a string and parsed back.

    Then
    ----
    - the parsed topic matches the input.
    - the embedded digest survives the round-trip.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="block", network_name="aabbccdd"),
    )


def test_aggregation_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An aggregation topic round-trips through its string form.

    Given
    -----
    - an aggregation topic kind.
    - a typical fork digest.

    When
    ----
    - the topic is formatted to a string and parsed back.

    Then
    ----
    - the parsed topic matches the input.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="aggregation", network_name=FORK_DIGEST),
    )


def test_attestation_subnet_zero(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An attestation topic on the first subnet round-trips.

    Given
    -----
    - an attestation topic kind.
    - a typical fork digest.
    - subnet 0, the first subnet.

    When
    ----
    - the topic is formatted to a string and parsed back.

    Then
    ----
    - the parsed topic matches the input.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="attestation", network_name=FORK_DIGEST, subnet_id=0),
    )


def test_attestation_subnet_seven(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An attestation topic on a mid-range subnet round-trips.

    Given
    -----
    - an attestation topic kind.
    - a typical fork digest.
    - subnet 7, a mid-range subnet.

    When
    ----
    - the topic is formatted to a string and parsed back.

    Then
    ----
    - the parsed topic matches the input.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="attestation", network_name=FORK_DIGEST, subnet_id=7),
    )


def test_attestation_subnet_63(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An attestation topic on the last subnet round-trips.

    Given
    -----
    - an attestation topic kind.
    - a typical fork digest.
    - subnet 63, the last subnet in a 64-subnet network.

    When
    ----
    - the topic is formatted to a string and parsed back.

    Then
    ----
    - the parsed topic matches the input.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(
            topic_kind="attestation", network_name=FORK_DIGEST, subnet_id=63
        ),
    )


def test_block_topic_zero_digest(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A block topic with an all-zero fork digest round-trips.

    Given
    -----
    - a block topic kind.
    - an all-zero fork digest.

    When
    ----
    - the topic is formatted to a string and parsed back.

    Then
    ----
    - the parsed topic matches the input.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="block", network_name="00000000"),
    )


def test_block_topic_max_digest(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A block topic with an all-ones fork digest round-trips.

    Given
    -----
    - a block topic kind.
    - an all-0xff fork digest.

    When
    ----
    - the topic is formatted to a string and parsed back.

    Then
    ----
    - the parsed topic matches the input.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(topic_kind="block", network_name="ffffffff"),
    )
