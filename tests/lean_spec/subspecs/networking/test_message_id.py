"""Tests for the message ID computation in GossipsubMessage."""

import snappy  # type: ignore[import-untyped]

from lean_spec.subspecs.networking.gossipsub import GossipsubMessage


def test_message_id_computation_basic() -> None:
    """Test basic message ID computation without snappy decompression."""
    message = GossipsubMessage(topic=b"test", data=b"hello")
    message_id = message.id

    # Verify the ID is exactly 20 bytes long
    assert len(message_id) == 20

    # Verify the ID is correct
    assert message_id == bytes.fromhex("a7f41aaccd241477955c981714eb92244c2efc98")


def test_message_id_computation_with_snappy() -> None:
    """Test the message ID computation with snappy."""
    message = GossipsubMessage(
        topic=b"test", data=snappy.compress(b"hello"), snappy_decompress=snappy.decompress
    )
    message_id = message.id

    assert len(message_id) == 20
    assert message_id == bytes.fromhex("2e40c861545cc5b46d2220062e7440b9190bc383")


def test_message_id_computation_with_invalid_snappy() -> None:
    """Test the message ID computation when snappy decompression fails."""

    def _raise_invalid_snappy(data: bytes) -> bytes:
        raise Exception("Invalid snappy")

    message = GossipsubMessage(
        topic=b"test", data=b"hello", snappy_decompress=_raise_invalid_snappy
    )
    message_id = message.id

    assert len(message_id) == 20
    # When snappy decompression fails, it should fall back to MESSAGE_DOMAIN_INVALID_SNAPPY
    # This should produce the same ID as the no-snappy case
    assert message_id == bytes.fromhex("a7f41aaccd241477955c981714eb92244c2efc98")


def test_message_id_caching() -> None:
    """Test that message ID is computed once and then cached."""
    call_count = 0

    def counting_decompress(data: bytes) -> bytes:
        nonlocal call_count
        call_count += 1
        return data

    message = GossipsubMessage(topic=b"test", data=b"hello", snappy_decompress=counting_decompress)

    # First access should trigger computation
    first_id = message.id
    assert call_count == 1

    # Second access should use cached value
    second_id = message.id
    assert call_count == 1  # Should not increment
    assert first_id == second_id
