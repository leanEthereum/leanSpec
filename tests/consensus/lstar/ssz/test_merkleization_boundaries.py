"""SSZ: hash_tree_root vectors at bit / chunk size boundaries."""

from typing import ClassVar

import pytest
from consensus_testing import SSZTestFiller

from lean_spec.types import (
    BaseBitlist,
    BaseBitvector,
    Boolean,
    SSZList,
    Uint64,
)

pytestmark = pytest.mark.valid_until("Lstar")


# Fixed-width bitvectors at bit- and chunk-boundary sizes.
# Existing suite covers 8 and 64; this fills the gaps.


class BoundaryBitvector1(BaseBitvector):
    """Single-bit vector. Minimal case: one bit occupies one byte."""

    LENGTH: ClassVar[int] = 1


class BoundaryBitvector7(BaseBitvector):
    """Seven-bit vector. One byte with the high bit left as padding."""

    LENGTH: ClassVar[int] = 7


class BoundaryBitvector9(BaseBitvector):
    """Nine-bit vector. Two bytes: the second carries a single bit."""

    LENGTH: ClassVar[int] = 9


class BoundaryBitvector255(BaseBitvector):
    """Just below one Merkle chunk. Final chunk holds 31 bytes of data and 1 pad byte."""

    LENGTH: ClassVar[int] = 255


class BoundaryBitvector256(BaseBitvector):
    """Exact Merkle-chunk boundary. One chunk, no padding."""

    LENGTH: ClassVar[int] = 256


class BoundaryBitvector257(BaseBitvector):
    """Just above one Merkle chunk. Second chunk holds one bit and mix-ins padding."""

    LENGTH: ClassVar[int] = 257


class BoundaryBitlist256(BaseBitlist):
    """Bitlist whose limit is exactly one Merkle chunk.

    When filled to the limit, the sentinel bit lands in a fresh byte.
    """

    LIMIT: ClassVar[int] = 256


class BoundaryUint64List32(SSZList[Uint64]):
    """Uint64 list with a 32-element cap. 3 elements span 24 bytes, shy of one chunk."""

    LIMIT: ClassVar[int] = 32
    ELEMENT_TYPE = Uint64


def test_bitvector_length_one_all_set(ssz: SSZTestFiller) -> None:
    """Single-bit vector with the bit set pins the minimal Merkle chunk layout."""
    ssz(
        type_name="BoundaryBitvector1",
        value=BoundaryBitvector1(data=[Boolean(True)]),
    )


def test_bitvector_length_seven_all_set(ssz: SSZTestFiller) -> None:
    """Seven-bit vector exercises the pre-byte-boundary pad bit."""
    ssz(
        type_name="BoundaryBitvector7",
        value=BoundaryBitvector7(data=[Boolean(True)] * 7),
    )


def test_bitvector_length_nine_all_set(ssz: SSZTestFiller) -> None:
    """Nine-bit vector straddles the single-byte boundary."""
    ssz(
        type_name="BoundaryBitvector9",
        value=BoundaryBitvector9(data=[Boolean(True)] * 9),
    )


def test_bitvector_length_255_all_set(ssz: SSZTestFiller) -> None:
    """255-bit vector is one bit shy of a full 32-byte Merkle chunk."""
    ssz(
        type_name="BoundaryBitvector255",
        value=BoundaryBitvector255(data=[Boolean(True)] * 255),
    )


def test_bitvector_length_256_all_set(ssz: SSZTestFiller) -> None:
    """256-bit vector fills exactly one Merkle chunk with no padding."""
    ssz(
        type_name="BoundaryBitvector256",
        value=BoundaryBitvector256(data=[Boolean(True)] * 256),
    )


def test_bitvector_length_257_all_set(ssz: SSZTestFiller) -> None:
    """257-bit vector forces a second Merkle chunk holding a single bit."""
    ssz(
        type_name="BoundaryBitvector257",
        value=BoundaryBitvector257(data=[Boolean(True)] * 257),
    )


def test_bitlist_filled_to_chunk_boundary_limit(ssz: SSZTestFiller) -> None:
    """Bitlist filled to a 256-bit limit places the sentinel at the start of a fresh byte.

    The trailing sentinel crosses into a new chunk, exercising the length-mixin
    ordering for bitlists whose limit sits on a Merkle-chunk edge.
    """
    ssz(
        type_name="BoundaryBitlist256",
        value=BoundaryBitlist256(data=[Boolean(True)] * 256),
    )


def test_uint64_list_with_misaligned_chunk_count(ssz: SSZTestFiller) -> None:
    """Three uint64 entries occupy 24 bytes, one byte shy of a full Merkle chunk.

    Pins the zero-pad / length-mixin behaviour for variable-length lists of
    fixed-size elements whose serialized length is not a multiple of 32.
    """
    ssz(
        type_name="BoundaryUint64List32",
        value=BoundaryUint64List32(data=[Uint64(1), Uint64(2), Uint64(3)]),
    )
