"""SSZ shapes leanSpec declares itself: frozen values, camelCase JSON, its own byte widths."""

import ssz

from lean_spec.base import CamelModel

Bytes32 = ssz.Root
"""The root type itself, since a sibling 32-byte vector would refuse to compare with a root."""


class ContainerInvariantError(Exception):
    """A leanSpec container refuses a value its own invariant does not admit."""


class Container(ssz.Container, CamelModel):
    """Ordered SSZ struct, frozen, with the camelCase JSON every spec type shares."""

    # Fork choice hands one state to every branch below a block root.
    # A branch that could write through it would rewrite history for its siblings.
    MUTABLE = False


class List[T: ssz.SSZType](ssz.List[T], CamelModel):
    """Frozen SSZ list, bounded by a declared limit."""

    MUTABLE = False


class Vector[T: ssz.SSZType](ssz.Vector[T], CamelModel):
    """Frozen SSZ vector, holding a declared number of elements."""

    MUTABLE = False


class BitList(ssz.BitList, CamelModel):
    """Frozen SSZ bitlist, bounded by a declared limit."""

    MUTABLE = False


class BitVector(ssz.BitVector, CamelModel):
    """Frozen SSZ bitvector, holding a declared number of bits."""

    MUTABLE = False


class ByteList(ssz.ByteList, CamelModel):
    """Frozen SSZ byte list, bounded by a declared limit."""

    MUTABLE = False


class Bytes4(ssz.ByteVector):
    """Fixed-size byte array of exactly 4 bytes."""

    LENGTH = 4


class Bytes16(ssz.ByteVector):
    """Fixed-size byte array of exactly 16 bytes (Poly1305 authentication tag)."""

    LENGTH = 16


class Bytes20(ssz.ByteVector):
    """Fixed-size byte array of exactly 20 bytes."""

    LENGTH = 20


class Bytes33(ssz.ByteVector):
    """Fixed-size byte array of exactly 33 bytes (compressed secp256k1 public key)."""

    LENGTH = 33


class Bytes52(ssz.ByteVector):
    """Fixed-size byte array of exactly 52 bytes."""

    LENGTH = 52


class Bytes64(ssz.ByteVector):
    """Fixed-size byte array of exactly 64 bytes (secp256k1 signature)."""

    LENGTH = 64


class ByteList512KiB(ByteList):
    """Variable-length byte list with a 512 KiB limit."""

    LIMIT = 512 * 1024
