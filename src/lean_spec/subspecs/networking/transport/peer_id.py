"""
PeerId derivation from public keys.

libp2p PeerIds are derived from the public key using multihash:
    1. Encode public key as protobuf (libp2p-crypto format)
    2. If encoded <= 42 bytes: PeerId = multihash(identity, encoded)
    3. If encoded > 42 bytes: PeerId = multihash(sha256, sha256(encoded))

Protobuf wire format (from crypto.proto):
    message PublicKey {
        required KeyType Type = 1;  // Field 1, varint
        required bytes Data = 2;    // Field 2, length-delimited
    }

Wire format:
    [0x08][type_varint][0x12][length_varint][key_bytes]

    - 0x08 = Tag for field 1 (field_number=1, wire_type=0 varint) = (1 << 3) | 0
    - 0x12 = Tag for field 2 (field_number=2, wire_type=2 length-delimited) = (2 << 3) | 2

For secp256k1 keys (33 bytes compressed), the encoded form is 37 bytes,
so we use the identity hash. The result is Base58-encoded for display.

This implementation uses secp256k1 for identity, matching ream, zeam,
and the standard Ethereum libp2p network.

References:
    - https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
    - https://github.com/libp2p/go-libp2p/blob/master/core/crypto/pb/crypto.proto
    - https://github.com/multiformats/multihash
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from lean_spec.subspecs.networking import varint

__all__ = [
    # Main types
    "PeerId",
    "PublicKeyProto",
    "Multihash",
    # Enums
    "KeyType",
    "MultihashCode",
    # Utility classes
    "Base58",
]


class KeyType(IntEnum):
    """
    libp2p-crypto key type codes (from crypto.proto KeyType enum).

    These identify the cryptographic algorithm used for the public key.
    """

    RSA = 0
    """RSA public key (DER-encoded PKIX format)."""

    ED25519 = 1
    """Ed25519 public key (32 bytes)."""

    SECP256K1 = 2
    """secp256k1 public key (33 bytes compressed, Bitcoin format)."""

    ECDSA = 3
    """ECDSA public key (ASN.1 DER encoded)."""


class MultihashCode(IntEnum):
    """
    Multihash function codes.

    Multihash is a self-describing hash format: [code][length][digest].
    The code identifies which hash function was used.

    See: https://github.com/multiformats/multihash
    """

    IDENTITY = 0x00
    """Identity "hash" - no hashing, just wraps the data."""

    SHA256 = 0x12
    """SHA-256 hash (32-byte output)."""


class _ProtobufTag(IntEnum):
    """
    Protobuf field tags for PublicKey message.

    Tag format: (field_number << 3) | wire_type
        - wire_type 0 = varint
        - wire_type 2 = length-delimited (bytes, string, embedded messages)
    """

    TYPE = 0x08  # (1 << 3) | 0 = field 1, varint
    """Tag for Type field: field 1, varint."""

    DATA = 0x12  # (2 << 3) | 2 = field 2, length-delimited
    """Tag for Data field: field 2, length-delimited bytes."""


class Base58:
    """
    Base58 encoding/decoding (Bitcoin-style alphabet).

    Base58 excludes visually ambiguous characters (0, O, I, l) making it
    suitable for human-readable identifiers like PeerIds.

    The alphabet is: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
    """

    ALPHABET: Final[str] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    """Base58 alphabet (Bitcoin style, excludes 0, O, I, l)."""

    @classmethod
    def encode(cls, data: bytes) -> str:
        """
        Encode bytes as Base58 string.

        Leading zero bytes become leading '1' characters.

        Args:
            data: Bytes to encode.

        Returns:
            Base58-encoded string.
        """
        # Count leading zeros (become leading '1's)
        leading_zeros = 0
        for byte in data:
            if byte == 0:
                leading_zeros += 1
            else:
                break

        # Convert to big integer and then to base58
        num = int.from_bytes(data, "big")
        result: list[str] = []

        while num > 0:
            num, remainder = divmod(num, 58)
            result.append(cls.ALPHABET[remainder])

        # Add leading '1's and reverse
        result.extend([cls.ALPHABET[0]] * leading_zeros)
        return "".join(reversed(result))

    @classmethod
    def decode(cls, s: str) -> bytes:
        """
        Decode Base58 string to bytes.

        Leading '1' characters become leading zero bytes.

        Args:
            s: Base58-encoded string.

        Returns:
            Decoded bytes.

        Raises:
            ValueError: If string contains invalid characters.
        """
        # Count leading '1's (they represent leading zeros)
        leading_ones = 0
        for char in s:
            if char == "1":
                leading_ones += 1
            else:
                break

        # Convert from base58 to integer
        num = 0
        for char in s:
            index = cls.ALPHABET.find(char)
            if index < 0:
                raise ValueError(f"Invalid Base58 character: {char!r}")
            num = num * 58 + index

        # Convert to bytes
        if num == 0:
            result = b""
        else:
            result = num.to_bytes((num.bit_length() + 7) // 8, "big")

        return b"\x00" * leading_ones + result


_IDENTITY_THRESHOLD: Final[int] = 42
"""Threshold for identity vs SHA256 hashing (from libp2p spec)"""


@dataclass(frozen=True, slots=True)
class Multihash:
    """
    A self-describing hash in multihash format.

    Format: [code (varint)][length (varint)][digest]

    For small data (<= 42 bytes), libp2p uses identity multihash (no hashing).
    For larger data, SHA256 is used.

    Attributes:
        code: Hash function identifier.
        digest: Hash output (or raw data for identity).
    """

    code: MultihashCode
    """Hash function used."""

    digest: bytes
    """Hash output or identity data."""

    def encode(self) -> bytes:
        """
        Encode as multihash bytes.

        Format: [code][length][digest]

        For simplicity, we use single-byte encoding for code and length
        since our digests are always small (identity <= 42, SHA256 = 32).

        Returns:
            Multihash-encoded bytes.

        Raises:
            ValueError: If digest exceeds single-byte length encoding (127 bytes).
        """
        if len(self.digest) > 127:
            raise ValueError(f"Digest too large for single-byte length: {len(self.digest)}")

        return bytes([self.code, len(self.digest)]) + self.digest

    @classmethod
    def identity(cls, data: bytes) -> Multihash:
        """
        Create an identity multihash (no hashing).

        Args:
            data: Data to wrap (must be <= 127 bytes).

        Returns:
            Identity multihash.

        Raises:
            ValueError: If data exceeds 127 bytes.
        """
        if len(data) > 127:
            raise ValueError("Identity multihash limited to 127 bytes")
        return cls(code=MultihashCode.IDENTITY, digest=data)

    @classmethod
    def sha256(cls, data: bytes) -> Multihash:
        """
        Create a SHA256 multihash.

        Args:
            data: Data to hash.

        Returns:
            SHA256 multihash.
        """
        return cls(code=MultihashCode.SHA256, digest=hashlib.sha256(data).digest())

    @classmethod
    def from_data(cls, data: bytes) -> Multihash:
        """
        Create a multihash using libp2p's size-based selection.

        For data <= 42 bytes: identity hash (no hashing)
        For data > 42 bytes: SHA256 hash

        This is the algorithm specified by libp2p for PeerId derivation.

        Args:
            data: Data to hash.

        Returns:
            Multihash with appropriate hash function.
        """
        if len(data) <= _IDENTITY_THRESHOLD:
            return cls.identity(data)
        else:
            return cls.sha256(data)


@dataclass(frozen=True, slots=True)
class PublicKeyProto:
    """
    A public key in libp2p-crypto protobuf format.

    This represents the wire format used by libp2p for encoding public keys
    before hashing to derive PeerIds.

    Protobuf schema:
        message PublicKey {
            required KeyType Type = 1;
            required bytes Data = 2;
        }

    Attributes:
        key_type: Cryptographic algorithm identifier.
        key_data: Raw public key bytes (format depends on key_type).
    """

    key_type: KeyType
    """Key algorithm type."""

    key_data: bytes
    """Raw public key bytes."""

    def encode(self) -> bytes:
        """
        Encode as protobuf wire format.

        Wire encoding:
            [0x08][type_varint][0x12][length_varint][key_bytes]

        The encoding follows deterministic protobuf requirements:
            1. Fields minimally encoded (varints use fewest bytes)
            2. Fields in tag order (Type first, then Data)
            3. All fields included

        Returns:
            Protobuf-encoded PublicKey message bytes.
        """
        # Field 1: Type (tag = 0x08, value = key_type as varint)
        type_field = bytes([_ProtobufTag.TYPE]) + varint.encode(self.key_type)

        # Field 2: Data (tag = 0x12, value = length-delimited bytes)
        data_field = bytes([_ProtobufTag.DATA]) + varint.encode(len(self.key_data)) + self.key_data

        return type_field + data_field


@dataclass(frozen=True, slots=True)
class PeerId:
    """
    A libp2p peer identifier.

    PeerIds uniquely identify peers in the network. They are derived from
    public keys via multihash and displayed as Base58 strings.

    The derivation process:
        1. Encode public key as protobuf
        2. Create multihash (identity if <= 42 bytes, SHA256 otherwise)
        3. Base58-encode for display

    String format (legacy, currently recommended by spec):
        - Ed25519 keys: "12D3KooW..." (identity multihash, 36 bytes)
        - secp256k1 keys: "16Uiu2..." (identity multihash, 37 bytes)
        - Large keys (RSA, ECDSA): "Qm..." (SHA256 multihash)

    Attributes:
        multihash: The underlying multihash bytes.
    """

    multihash: bytes
    """Raw multihash bytes (before Base58 encoding)."""

    def __str__(self) -> str:
        """Return Base58-encoded PeerId string (legacy format)."""
        return Base58.encode(self.multihash)

    def __repr__(self) -> str:
        """Return detailed representation."""
        return f"PeerId({self!s})"

    def to_base58(self) -> str:
        """
        Return Base58-encoded PeerId string.

        This is the legacy format currently recommended by the libp2p spec.

        Returns:
            Base58-encoded string suitable for display or serialization.
        """
        return Base58.encode(self.multihash)

    def to_bytes(self) -> bytes:
        """
        Return the raw multihash bytes.

        Returns:
            Multihash bytes (can be used for binary protocols).
        """
        return self.multihash

    @classmethod
    def from_base58(cls, s: str) -> PeerId:
        """
        Parse a Base58-encoded PeerId.

        Args:
            s: Base58-encoded PeerId string.

        Returns:
            Parsed PeerId.

        Raises:
            ValueError: If string is not valid Base58.
        """
        return cls(multihash=Base58.decode(s))

    @classmethod
    def from_bytes(cls, data: bytes) -> PeerId:
        """
        Create PeerId from raw multihash bytes.

        Args:
            data: Multihash bytes.

        Returns:
            PeerId wrapping the multihash.
        """
        return cls(multihash=data)

    @classmethod
    def from_public_key(cls, public_key: PublicKeyProto) -> PeerId:
        """
        Derive PeerId from a public key.

        This is the canonical derivation method following libp2p spec.

        Args:
            public_key: Public key in protobuf format.

        Returns:
            Derived PeerId.
        """
        encoded = public_key.encode()
        mh = Multihash.from_data(encoded)
        return cls(multihash=mh.encode())

    @classmethod
    def from_secp256k1(cls, public_key_bytes: bytes) -> PeerId:
        """
        Derive PeerId from a secp256k1 compressed public key.

        This is the standard method used by ream, zeam, and the Ethereum
        libp2p network for peer identification.

        Args:
            public_key_bytes: 33-byte compressed secp256k1 public key
                (starts with 0x02 or 0x03).

        Returns:
            Derived PeerId (starts with "16Uiu2..." for secp256k1).

        Raises:
            ValueError: If public key is not 33 bytes.
        """
        if len(public_key_bytes) != 33:
            raise ValueError(
                f"secp256k1 compressed key must be 33 bytes, got {len(public_key_bytes)}"
            )

        proto = PublicKeyProto(key_type=KeyType.SECP256K1, key_data=public_key_bytes)
        return cls.from_public_key(proto)

    @classmethod
    def derive(cls, key_data: bytes, key_type: KeyType) -> PeerId:
        """
        Derive PeerId from raw key bytes and type.

        Args:
            key_data: Raw public key bytes.
            key_type: Key algorithm type.

        Returns:
            Derived PeerId.
        """
        proto = PublicKeyProto(key_type=key_type, key_data=key_data)
        return cls.from_public_key(proto)
