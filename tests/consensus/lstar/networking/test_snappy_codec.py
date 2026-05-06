"""Test vectors for standalone Snappy compression and decompression.

Both raw block format and Ethereum framing format are tested.
Client teams use these to verify their Snappy implementation
produces identical output before integrating with reqresp or gossip.
"""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


# --- Raw Snappy block format ---


def test_snappy_block_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """Empty input. Compressed output is just the varint-encoded uncompressed length (0)."""
    networking_codec(codec_name="snappy_block", input={"data": "0x"})


def test_snappy_block_single_byte(networking_codec: NetworkingCodecTestFiller) -> None:
    """Single byte. Too short for copy commands, must use a literal."""
    networking_codec(codec_name="snappy_block", input={"data": "0x42"})


def test_snappy_block_short_string(networking_codec: NetworkingCodecTestFiller) -> None:
    """Short ASCII string (17 bytes). Verifies literal encoding for small payloads."""
    networking_codec(
        codec_name="snappy_block",
        input={"data": "0x" + b"Hello, Ethereum!".hex()},
    )


def test_snappy_block_repeated_data(networking_codec: NetworkingCodecTestFiller) -> None:
    """1000 identical bytes. Highly compressible via copy commands."""
    networking_codec(
        codec_name="snappy_block",
        input={"data": "0x" + (b"\x41" * 1000).hex()},
    )


def test_snappy_block_alternating_pattern(networking_codec: NetworkingCodecTestFiller) -> None:
    """Alternating two-byte pattern (1000 bytes). Tests copy offset=2 back-references."""
    networking_codec(
        codec_name="snappy_block",
        input={"data": "0x" + (b"\xab\xcd" * 500).hex()},
    )


def test_snappy_block_incompressible(networking_codec: NetworkingCodecTestFiller) -> None:
    """Sequential bytes 0x00-0xFF (256 bytes). Low compressibility, mostly literals."""
    networking_codec(
        codec_name="snappy_block",
        input={"data": "0x" + bytes(range(256)).hex()},
    )


def test_snappy_block_at_block_boundary(networking_codec: NetworkingCodecTestFiller) -> None:
    """Exactly 65536 bytes of repeated data. Tests behavior at the Snappy block size limit."""
    networking_codec(
        codec_name="snappy_block",
        input={"data": "0x" + (b"\xfe" * 65536).hex()},
    )


def test_snappy_block_multi_block(networking_codec: NetworkingCodecTestFiller) -> None:
    """65537 bytes (one past block boundary). Forces multi-block handling."""
    networking_codec(
        codec_name="snappy_block",
        input={"data": "0x" + (b"\xfe" * 65537).hex()},
    )


# --- Snappy framing format (Ethereum wire format) ---


def test_snappy_frame_empty(networking_codec: NetworkingCodecTestFiller) -> None:
    """Empty payload. Output is just the stream identifier chunk."""
    networking_codec(codec_name="snappy_frame", input={"data": "0x"})


def test_snappy_frame_short(networking_codec: NetworkingCodecTestFiller) -> None:
    """Short payload (16 bytes). Fits in a single compressed chunk."""
    networking_codec(
        codec_name="snappy_frame",
        input={"data": "0x" + b"Ethereum Snappy!".hex()},
    )


def test_snappy_frame_compressible(networking_codec: NetworkingCodecTestFiller) -> None:
    """Highly compressible data (2048 repeated bytes). Single compressed chunk."""
    networking_codec(
        codec_name="snappy_frame",
        input={"data": "0x" + (b"\x00" * 2048).hex()},
    )


def test_snappy_frame_incompressible(networking_codec: NetworkingCodecTestFiller) -> None:
    """Sequential bytes (256). May produce an uncompressed chunk if expansion occurs."""
    networking_codec(
        codec_name="snappy_frame",
        input={"data": "0x" + bytes(range(256)).hex()},
    )


def test_snappy_frame_at_chunk_boundary(networking_codec: NetworkingCodecTestFiller) -> None:
    """Exactly 65536 bytes. Tests chunk size limit in framing format."""
    networking_codec(
        codec_name="snappy_frame",
        input={"data": "0x" + (b"\xab" * 65536).hex()},
    )


def test_snappy_frame_multi_chunk(networking_codec: NetworkingCodecTestFiller) -> None:
    """65537 bytes. Forces multiple framing chunks."""
    networking_codec(
        codec_name="snappy_frame",
        input={"data": "0x" + (b"\xab" * 65537).hex()},
    )


def test_snappy_frame_ssz_like_payload(networking_codec: NetworkingCodecTestFiller) -> None:
    """Realistic SSZ-like payload: fixed header + repeated zero padding (512 bytes)."""
    header = bytes(range(64))
    padding = b"\x00" * 448
    networking_codec(
        codec_name="snappy_frame",
        input={"data": "0x" + (header + padding).hex()},
    )
