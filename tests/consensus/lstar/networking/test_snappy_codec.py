"""Standalone snappy block and framing compression roundtrip vectors."""

import pytest

from consensus_testing import NetworkingCodecTestFiller, SnappyBlockRoundtrip, SnappyFrameRoundtrip

pytestmark = pytest.mark.valid_until("Lstar")


def test_snappy_block_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    Empty input roundtrips through the snappy block format.

    Given
    -----
    - empty input.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the compressed form is just the varint-encoded uncompressed length 0.
    """
    networking_codec_test(
        codec=SnappyBlockRoundtrip(data="0x"),
    )


def test_snappy_block_single_byte(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A single byte roundtrips through the snappy block format.

    Given
    -----
    - a one-byte input.
    - one byte is too short for copy commands.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the byte is encoded as a literal.
    """
    networking_codec_test(
        codec=SnappyBlockRoundtrip(data="0x42"),
    )


def test_snappy_block_short_string(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A short string roundtrips through the snappy block format.

    Given
    -----
    - a 17-byte ASCII string.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - small payloads use literal encoding.
    """
    networking_codec_test(
        codec=SnappyBlockRoundtrip(data="0x" + b"Hello, Ethereum!".hex()),
    )


def test_snappy_block_repeated_data(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    Highly repetitive data roundtrips through the snappy block format.

    Given
    -----
    - 1000 identical bytes.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the data compresses via copy commands.
    """
    networking_codec_test(
        codec=SnappyBlockRoundtrip(data="0x" + (b"\x41" * 1000).hex()),
    )


def test_snappy_block_alternating_pattern(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An alternating two-byte pattern roundtrips through the snappy block format.

    Given
    -----
    - a 1000-byte alternating two-byte pattern.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the data exercises copy back-references at offset 2.
    """
    networking_codec_test(
        codec=SnappyBlockRoundtrip(data="0x" + (b"\xab\xcd" * 500).hex()),
    )


def test_snappy_block_incompressible(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    Low-compressibility data roundtrips through the snappy block format.

    Given
    -----
    - 256 bytes of sequential values 0x00 to 0xff.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the data is mostly literals.
    """
    networking_codec_test(
        codec=SnappyBlockRoundtrip(data="0x" + bytes(range(256)).hex()),
    )


def test_snappy_block_at_block_boundary(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    Data exactly at the block size limit roundtrips through the snappy block format.

    Given
    -----
    - 65536 bytes of repeated data.
    - 65536 is the snappy block size limit.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    """
    networking_codec_test(
        codec=SnappyBlockRoundtrip(data="0x" + (b"\xfe" * 65536).hex()),
    )


def test_snappy_block_multi_block(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    Data past the block size limit roundtrips through the snappy block format.

    Given
    -----
    - 65537 bytes of repeated data.
    - 65537 is one byte past the block boundary.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the input forces multi-block handling.
    """
    networking_codec_test(
        codec=SnappyBlockRoundtrip(data="0x" + (b"\xfe" * 65537).hex()),
    )


def test_snappy_frame_empty(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    Empty input roundtrips through the snappy framing format.

    Given
    -----
    - empty input.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the compressed form is just the stream identifier chunk.
    """
    networking_codec_test(
        codec=SnappyFrameRoundtrip(data="0x"),
    )


def test_snappy_frame_short(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A short payload roundtrips through the snappy framing format.

    Given
    -----
    - a 16-byte payload.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the payload fits in a single compressed chunk.
    """
    networking_codec_test(
        codec=SnappyFrameRoundtrip(data="0x" + b"Ethereum Snappy!".hex()),
    )


def test_snappy_frame_compressible(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    Highly compressible data roundtrips through the snappy framing format.

    Given
    -----
    - 2048 repeated bytes.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the data fits in a single compressed chunk.
    """
    networking_codec_test(
        codec=SnappyFrameRoundtrip(data="0x" + (b"\x00" * 2048).hex()),
    )


def test_snappy_frame_incompressible(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    Low-compressibility data roundtrips through the snappy framing format.

    Given
    -----
    - 256 bytes of sequential values.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the data may produce an uncompressed chunk if expansion occurs.
    """
    networking_codec_test(
        codec=SnappyFrameRoundtrip(data="0x" + bytes(range(256)).hex()),
    )


def test_snappy_frame_at_chunk_boundary(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    Data exactly at the chunk size limit roundtrips through the snappy framing format.

    Given
    -----
    - 65536 bytes of repeated data.
    - 65536 is the framing chunk size limit.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    """
    networking_codec_test(
        codec=SnappyFrameRoundtrip(data="0x" + (b"\xab" * 65536).hex()),
    )


def test_snappy_frame_multi_chunk(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    Data past the chunk size limit roundtrips through the snappy framing format.

    Given
    -----
    - 65537 bytes of repeated data.
    - 65537 is one byte past the chunk boundary.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    - the input forces multiple framing chunks.
    """
    networking_codec_test(
        codec=SnappyFrameRoundtrip(data="0x" + (b"\xab" * 65537).hex()),
    )


def test_snappy_frame_ssz_like_payload(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A realistic SSZ-like payload roundtrips through the snappy framing format.

    Given
    -----
    - a 512-byte payload.
    - a 64-byte fixed header followed by 448 zero-padding bytes.

    When
    ----
    - the input is compressed then decompressed.

    Then
    ----
    - the output equals the original.
    """
    header = bytes(range(64))
    padding = b"\x00" * 448
    networking_codec_test(
        codec=SnappyFrameRoundtrip(data="0x" + (header + padding).hex()),
    )
