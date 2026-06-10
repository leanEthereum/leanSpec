"""SSZ: hash_tree_root vectors at bit / chunk size boundaries."""

from typing import ClassVar

import pytest

from consensus_testing import SSZTestFiller
from lean_spec.spec.ssz import BaseBitlist, BaseBitvector, Boolean, SSZList, Uint64

pytestmark = pytest.mark.valid_until("Lstar")


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
    """
    Bitlist whose limit is exactly one Merkle chunk.

    When filled to the limit, the sentinel bit lands in a fresh byte.
    """

    LIMIT: ClassVar[int] = 256


class BoundaryUint64List32(SSZList[Uint64]):
    """Uint64 list with a 32-element cap. 3 elements span 24 bytes, shy of one chunk."""

    LIMIT: ClassVar[int] = 32
    ELEMENT_TYPE = Uint64


def test_bitvector_length_one_all_set(ssz_test: SSZTestFiller) -> None:
    """
    A one-bit vector merkleizes to a stable root.

    Given
    -----
    - a one-bit vector with its only bit set.

    When
    ----
    - the value is merkleized.

    Then
    ----
    - the root matches the minimal single-chunk layout.
    """
    ssz_test(
        type_name="BoundaryBitvector1",
        value=BoundaryBitvector1(data=[Boolean(True)]),
    )


def test_bitvector_length_seven_all_set(ssz_test: SSZTestFiller) -> None:
    """
    A seven-bit vector merkleizes to a stable root.

    Given
    -----
    - a seven-bit vector with all bits set.
    - one pad bit before the byte boundary.

    When
    ----
    - the value is merkleized.

    Then
    ----
    - the root matches the expected single-chunk layout.
    """
    ssz_test(
        type_name="BoundaryBitvector7",
        value=BoundaryBitvector7(data=[Boolean(True)] * 7),
    )


def test_bitvector_length_nine_all_set(ssz_test: SSZTestFiller) -> None:
    """
    A nine-bit vector merkleizes to a stable root.

    Given
    -----
    - a nine-bit vector with all bits set.
    - data that straddles the single-byte boundary.

    When
    ----
    - the value is merkleized.

    Then
    ----
    - the root matches the expected two-byte layout.
    """
    ssz_test(
        type_name="BoundaryBitvector9",
        value=BoundaryBitvector9(data=[Boolean(True)] * 9),
    )


def test_bitvector_length_255_all_set(ssz_test: SSZTestFiller) -> None:
    """
    A 255-bit vector merkleizes to a stable root.

    Given
    -----
    - a 255-bit vector with all bits set.
    - one bit shy of a full 32-byte chunk.

    When
    ----
    - the value is merkleized.

    Then
    ----
    - the root matches the expected single-chunk layout.
    """
    ssz_test(
        type_name="BoundaryBitvector255",
        value=BoundaryBitvector255(data=[Boolean(True)] * 255),
    )


def test_bitvector_length_256_all_set(ssz_test: SSZTestFiller) -> None:
    """
    A 256-bit vector merkleizes to a stable root.

    Given
    -----
    - a 256-bit vector with all bits set.
    - data that fills exactly one chunk with no padding.

    When
    ----
    - the value is merkleized.

    Then
    ----
    - the root matches the exact single-chunk layout.
    """
    ssz_test(
        type_name="BoundaryBitvector256",
        value=BoundaryBitvector256(data=[Boolean(True)] * 256),
    )


def test_bitvector_length_257_all_set(ssz_test: SSZTestFiller) -> None:
    """
    A 257-bit vector merkleizes to a stable root.

    Given
    -----
    - a 257-bit vector with all bits set.
    - one bit that spills into a second chunk.

    When
    ----
    - the value is merkleized.

    Then
    ----
    - the root matches the expected two-chunk layout.
    """
    ssz_test(
        type_name="BoundaryBitvector257",
        value=BoundaryBitvector257(data=[Boolean(True)] * 257),
    )


def test_bitlist_filled_to_chunk_boundary_limit(ssz_test: SSZTestFiller) -> None:
    """
    A bitlist filled to a chunk-edge limit merkleizes to a stable root.

    Given
    -----
    - a bitlist capped at 256 bits, filled to its limit.
    - a sentinel that lands at the start of a fresh byte.

    When
    ----
    - the value is merkleized.

    Then
    ----
    - the root matches the expected length-mixin ordering.
    """
    ssz_test(
        type_name="BoundaryBitlist256",
        value=BoundaryBitlist256(data=[Boolean(True)] * 256),
    )


def test_uint64_list_with_misaligned_chunk_count(ssz_test: SSZTestFiller) -> None:
    """
    A uint64 list whose bytes span a partial chunk merkleizes to a stable root.

    Given
    -----
    - a uint64 list with three entries occupying 24 bytes.
    - a length one byte shy of a full 32-byte chunk.

    When
    ----
    - the value is merkleized.

    Then
    ----
    - the root matches the expected zero-pad and length-mixin layout.
    """
    ssz_test(
        type_name="BoundaryUint64List32",
        value=BoundaryUint64List32(data=[Uint64(1), Uint64(2), Uint64(3)]),
    )
