"""Test vectors for Discovery v5 distance computations.

XOR distance and log2 distance are the foundation of Kademlia routing.
Every client must compute identical distances for correct peer discovery
and k-bucket assignment.
"""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")

# Official devp2p spec node IDs.
NODE_A = "0xaaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb"
NODE_B = "0xbbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9"

ZERO = "0x" + "00" * 32
MAX = "0x" + "ff" * 32
ONE = "0x" + "00" * 31 + "01"
TWO = "0x" + "00" * 31 + "02"
HIGH_BIT = "0x80" + "00" * 31
LOW_BYTE_80 = "0x" + "00" * 31 + "80"
BUCKET_9 = "0x" + "00" * 30 + "0100"


# --- XOR distance ---


def test_xor_distance_self(networking_codec: NetworkingCodecTestFiller) -> None:
    """XOR distance to self is always zero (identity property)."""
    networking_codec(codec_name="xor_distance", input={"nodeA": NODE_A, "nodeB": NODE_A})


def test_xor_distance_symmetric(networking_codec: NetworkingCodecTestFiller) -> None:
    """d(A, B) == d(B, A) (symmetry property)."""
    networking_codec(codec_name="xor_distance", input={"nodeA": NODE_A, "nodeB": NODE_B})


def test_xor_distance_symmetric_reverse(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Reverse order produces identical distance."""
    networking_codec(codec_name="xor_distance", input={"nodeA": NODE_B, "nodeB": NODE_A})


def test_xor_distance_max(networking_codec: NetworkingCodecTestFiller) -> None:
    """XOR of zero and all-ones produces maximum distance (2^256 - 1)."""
    networking_codec(codec_name="xor_distance", input={"nodeA": ZERO, "nodeB": MAX})


def test_xor_distance_adjacent(networking_codec: NetworkingCodecTestFiller) -> None:
    """XOR of 0x01 and 0x02 is 0x03 (lowest bits)."""
    networking_codec(codec_name="xor_distance", input={"nodeA": ONE, "nodeB": TWO})


def test_xor_distance_high_bit(networking_codec: NetworkingCodecTestFiller) -> None:
    """Single high bit difference. Distance = 2^255."""
    networking_codec(codec_name="xor_distance", input={"nodeA": HIGH_BIT, "nodeB": ZERO})


# --- Log2 distance (k-bucket assignment) ---


def test_log2_distance_self(networking_codec: NetworkingCodecTestFiller) -> None:
    """Log2 distance to self is 0."""
    networking_codec(codec_name="log2_distance", input={"nodeA": NODE_A, "nodeB": NODE_A})


def test_log2_distance_spec_nodes(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Log2 distance between official spec nodes A and B is 253."""
    networking_codec(codec_name="log2_distance", input={"nodeA": NODE_A, "nodeB": NODE_B})


def test_log2_distance_max(networking_codec: NetworkingCodecTestFiller) -> None:
    """Maximum log2 distance is 256 (all bits differ)."""
    networking_codec(codec_name="log2_distance", input={"nodeA": ZERO, "nodeB": MAX})


def test_log2_distance_bucket_1(networking_codec: NetworkingCodecTestFiller) -> None:
    """Single lowest bit difference lands in bucket 1."""
    networking_codec(codec_name="log2_distance", input={"nodeA": ZERO, "nodeB": ONE})


def test_log2_distance_bucket_2(networking_codec: NetworkingCodecTestFiller) -> None:
    """Bit 1 set lands in bucket 2."""
    networking_codec(codec_name="log2_distance", input={"nodeA": ZERO, "nodeB": TWO})


def test_log2_distance_bucket_8(networking_codec: NetworkingCodecTestFiller) -> None:
    """Byte boundary: 0x80 in last byte lands in bucket 8."""
    networking_codec(codec_name="log2_distance", input={"nodeA": ZERO, "nodeB": LOW_BYTE_80})


def test_log2_distance_bucket_9(networking_codec: NetworkingCodecTestFiller) -> None:
    """0x0100 in last two bytes lands in bucket 9."""
    networking_codec(codec_name="log2_distance", input={"nodeA": ZERO, "nodeB": BUCKET_9})


def test_log2_distance_bucket_256(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Highest bit only (0x80 in first byte) lands in bucket 256."""
    networking_codec(codec_name="log2_distance", input={"nodeA": ZERO, "nodeB": HIGH_BIT})
