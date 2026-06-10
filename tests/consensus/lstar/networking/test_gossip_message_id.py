"""Test vectors for gossipsub message ID computation."""

import pytest

from consensus_testing import GossipMessageIdentifier, NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

VALID_SNAPPY = "0x01000000"
"""Domain prefix for messages where snappy decompression succeeded."""

INVALID_SNAPPY = "0x00000000"
"""Domain prefix for messages where snappy decompression failed."""

BLOCK_TOPIC = "0x" + b"/leanconsensus/12345678/block/ssz_snappy".hex()
"""Hex-encoded topic bytes for a typical block topic string."""


def test_message_id_valid_snappy(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A typical block message yields its message id under the valid-snappy domain.

    Given
    -----
    - a block topic.
    - a short payload.
    - the valid-snappy domain prefix.

    When
    ----
    - the message id is computed.

    Then
    ----
    - the message id matches the expected digest.
    """
    networking_codec_test(
        codec=GossipMessageIdentifier(topic=BLOCK_TOPIC, data="0xdeadbeef", domain=VALID_SNAPPY),
    )


def test_message_id_valid_snappy_large_payload(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    A larger payload yields its message id under the valid-snappy domain.

    Given
    -----
    - a block topic.
    - a 256-byte payload.
    - the valid-snappy domain prefix.

    When
    ----
    - the message id is computed.

    Then
    ----
    - the message id matches the expected digest.
    """
    networking_codec_test(
        codec=GossipMessageIdentifier(
            topic=BLOCK_TOPIC, data="0x" + "ab" * 256, domain=VALID_SNAPPY
        ),
    )


def test_message_id_invalid_snappy(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The invalid-snappy domain yields its own message id for the same data.

    Given
    -----
    - a block topic.
    - the same short payload used in the valid-snappy case.
    - the invalid-snappy domain prefix.

    When
    ----
    - the message id is computed.

    Then
    ----
    - the message id matches the expected digest.
    """
    networking_codec_test(
        codec=GossipMessageIdentifier(topic=BLOCK_TOPIC, data="0xdeadbeef", domain=INVALID_SNAPPY),
    )


def test_message_id_empty_data(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An empty payload still yields a message id.

    Given
    -----
    - a block topic.
    - an empty payload.
    - the valid-snappy domain prefix.

    When
    ----
    - the message id is computed.

    Then
    ----
    - the message id matches the expected digest.
    """
    networking_codec_test(
        codec=GossipMessageIdentifier(topic=BLOCK_TOPIC, data="0x", domain=VALID_SNAPPY),
    )


def test_message_id_empty_topic(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An empty topic still yields a message id.

    Given
    -----
    - an empty topic.
    - a short payload.
    - the valid-snappy domain prefix.

    When
    ----
    - the message id is computed.

    Then
    ----
    - the message id matches the expected digest.
    """
    networking_codec_test(
        codec=GossipMessageIdentifier(topic="0x", data="0xdeadbeef", domain=VALID_SNAPPY),
    )


def test_message_id_both_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An empty topic and empty payload still yield a message id.

    Given
    -----
    - an empty topic.
    - an empty payload.
    - the valid-snappy domain prefix.

    When
    ----
    - the message id is computed.

    Then
    ----
    - the message id matches the expected digest.
    """
    networking_codec_test(
        codec=GossipMessageIdentifier(topic="0x", data="0x", domain=VALID_SNAPPY),
    )


def test_message_id_domain_changes_id(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The invalid-snappy domain yields its own message id.

    Given
    -----
    - a short topic.
    - a short payload.
    - the invalid-snappy domain prefix.

    When
    ----
    - the message id is computed.

    Then
    ----
    - the message id matches the expected digest.
    """
    networking_codec_test(
        codec=GossipMessageIdentifier(
            topic="0x" + b"test-topic".hex(),
            data="0x" + b"hello world".hex(),
            domain=INVALID_SNAPPY,
        ),
    )


def test_message_id_domain_valid_same_data(
    networking_codec_test: NetworkingCodecTestFiller,
) -> None:
    """
    The valid-snappy domain yields its own message id for the same topic and data.

    Given
    -----
    - the same short topic as the invalid-snappy case.
    - the same short payload as the invalid-snappy case.
    - the valid-snappy domain prefix.

    When
    ----
    - the message id is computed.

    Then
    ----
    - the message id matches the expected digest.
    """
    networking_codec_test(
        codec=GossipMessageIdentifier(
            topic="0x" + b"test-topic".hex(), data="0x" + b"hello world".hex(), domain=VALID_SNAPPY
        ),
    )
