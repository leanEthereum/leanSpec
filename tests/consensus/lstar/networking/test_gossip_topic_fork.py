"""Vectors for validating a gossipsub topic against an expected network name."""

import pytest

from consensus_testing import GossipTopicRoundtrip, NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


def test_gossip_topic_network_name_matches(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A topic whose network name matches the expected value validates.

    Given
    -----
    - a block topic built with a network name.
    - an expected network name equal to that name.

    When
    ----
    - the topic is validated against the expected network name.

    Then
    ----
    - validation passes.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(
            topic_kind="block", network_name="0x12345678", expected_network_name="0x12345678"
        ),
    )


def test_gossip_topic_network_name_mismatch(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A topic whose network name differs from the expected value is rejected.

    Given
    -----
    - a block topic built with one network name.
    - an expected network name different from that name.

    When
    ----
    - the topic is validated against the expected network name.

    Then
    ----
    - validation fails because the network names differ.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(
            topic_kind="block", network_name="0x12345678", expected_network_name="0xdeadbeef"
        ),
    )


def test_gossip_topic_network_name_match_on_attestation_subnet(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    An attestation-subnet topic validates its network name.

    Given
    -----
    - an attestation topic built with a network name.
    - a subnet id of 7.
    - an expected network name equal to the topic's network name.

    When
    ----
    - the topic is validated against the expected network name.

    Then
    ----
    - validation passes regardless of the kind and subnet id.
    """
    networking_codec_test(
        codec=GossipTopicRoundtrip(
            topic_kind="attestation",
            network_name="0xabcdef01",
            subnet_id=7,
            expected_network_name="0xabcdef01",
        ),
    )
