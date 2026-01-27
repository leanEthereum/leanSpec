"""
Tests for PeerId derivation from public keys.

libp2p PeerIds are derived from public keys:
    1. Encode public key as protobuf (libp2p-crypto format)
    2. If encoded <= 42 bytes: PeerId = multihash(identity, encoded)
    3. If encoded > 42 bytes: PeerId = multihash(sha256, sha256(encoded))

Test vectors from the official libp2p spec:
    https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#test-vectors
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.networking import varint
from lean_spec.subspecs.networking.transport.identity import IdentityKeypair
from lean_spec.subspecs.networking.transport.peer_id import (
    Base58,
    KeyType,
    Multihash,
    MultihashCode,
    PeerId,
    PublicKeyProto,
)

# Protobuf tag constants for test assertions
_PROTOBUF_TAG_TYPE = 0x08  # (1 << 3) | 0 = field 1, varint
_PROTOBUF_TAG_DATA = 0x12  # (2 << 3) | 2 = field 2, length-delimited


class TestBase58:
    """Tests for Base58 encoding/decoding."""

    def test_base58_alphabet(self) -> None:
        """Base58 alphabet is Bitcoin-style (no 0, O, I, l)."""
        assert len(Base58.ALPHABET) == 58
        assert "0" not in Base58.ALPHABET
        assert "O" not in Base58.ALPHABET
        assert "I" not in Base58.ALPHABET
        assert "l" not in Base58.ALPHABET

    def test_base58_encode_empty(self) -> None:
        """Empty bytes encodes to empty string."""
        assert Base58.encode(b"") == ""

    def test_base58_encode_zero(self) -> None:
        """Zero byte encodes to '1'."""
        assert Base58.encode(b"\x00") == "1"

    def test_base58_encode_leading_zeros(self) -> None:
        """Leading zeros become leading '1's."""
        assert Base58.encode(b"\x00\x00\x01") == "112"

    def test_base58_encode_known_vectors(self) -> None:
        """Test known Base58 encodings."""
        # "Hello World" in Base58
        # (not standard test vector, but useful for sanity check)
        result = Base58.encode(b"Hello World")
        assert len(result) > 0
        assert all(c in Base58.ALPHABET for c in result)

    def test_base58_roundtrip(self) -> None:
        """Encode then decode returns original."""
        test_cases = [
            b"",
            b"\x00",
            b"\x00\x00",
            b"\x01",
            b"Hello",
            b"\x00\x01\x02\x03\x04",
            bytes(32),  # All zeros
            bytes(range(256)),  # All bytes
        ]

        for data in test_cases:
            encoded = Base58.encode(data)
            decoded = Base58.decode(encoded)
            assert decoded == data, f"Roundtrip failed for {data.hex()}"

    def test_base58_decode_invalid_char(self) -> None:
        """Decoding invalid characters raises ValueError."""
        with pytest.raises(ValueError, match="Invalid Base58 character"):
            Base58.decode("0")  # '0' not in Base58

        with pytest.raises(ValueError, match="Invalid Base58 character"):
            Base58.decode("O")  # 'O' not in Base58

        with pytest.raises(ValueError, match="Invalid Base58 character"):
            Base58.decode("I")  # 'I' not in Base58

        with pytest.raises(ValueError, match="Invalid Base58 character"):
            Base58.decode("l")  # 'l' not in Base58


class TestVarintEncoding:
    """Tests for varint encoding."""

    def test_encode_zero(self) -> None:
        """Zero encodes to single byte."""
        assert varint.encode_varint(0) == b"\x00"

    def test_encode_small_values(self) -> None:
        """Values < 128 encode to single byte."""
        assert varint.encode_varint(1) == b"\x01"
        assert varint.encode_varint(127) == b"\x7f"

    def test_encode_128(self) -> None:
        """128 requires two bytes."""
        assert varint.encode_varint(128) == b"\x80\x01"

    def test_encode_large_values(self) -> None:
        """Large values use multiple bytes."""
        assert varint.encode_varint(300) == b"\xac\x02"
        assert varint.encode_varint(16384) == b"\x80\x80\x01"

    def test_encode_negative_raises(self) -> None:
        """Negative values raise ValueError."""
        with pytest.raises(ValueError, match="non-negative"):
            varint.encode_varint(-1)


class TestMultihash:
    """Tests for multihash functions."""

    def test_identity_multihash_format(self) -> None:
        """Identity multihash: [0x00][length][data]."""
        data = b"test"
        mh = Multihash.identity(data)
        result = mh.encode()

        assert result[0] == MultihashCode.IDENTITY  # 0x00
        assert result[1] == len(data)  # 4
        assert result[2:] == data

    def test_identity_multihash_max_length(self) -> None:
        """Identity multihash limited to 127 bytes."""
        # 127 bytes should work
        data = bytes(127)
        mh = Multihash.identity(data)
        result = mh.encode()
        assert len(result) == 2 + 127

        # 128 bytes should fail
        with pytest.raises(ValueError, match="127 bytes"):
            Multihash.identity(bytes(128))

    def test_sha256_multihash_format(self) -> None:
        """SHA256 multihash: [0x12][0x20][32-byte hash]."""
        data = b"test data"
        mh = Multihash.sha256(data)
        result = mh.encode()

        assert result[0] == MultihashCode.SHA256  # 0x12
        assert result[1] == 32  # SHA256 output length
        assert len(result) == 2 + 32

    def test_sha256_multihash_deterministic(self) -> None:
        """Same input produces same multihash."""
        data = b"deterministic test"
        result1 = Multihash.sha256(data).encode()
        result2 = Multihash.sha256(data).encode()
        assert result1 == result2


class TestEncodePublicKey:
    """Tests for public key encoding.

    Protobuf wire format from libp2p-crypto:
        message PublicKey {
            required KeyType Type = 1;  // Field 1, varint
            required bytes Data = 2;    // Field 2, length-delimited
        }

    Wire encoding: [0x08][type_varint][0x12][length_varint][key_bytes]
    """

    def test_encode_format(self) -> None:
        """Encoded key: [0x08][type][0x12][length][key bytes]."""
        key_type = KeyType.SECP256K1
        key_data = bytes([0x02] + [0] * 32)  # 33 bytes compressed secp256k1

        proto = PublicKeyProto(key_type=key_type, key_data=key_data)
        encoded = proto.encode()

        # Field 1 tag (0x08 = field 1, varint)
        assert encoded[0] == _PROTOBUF_TAG_TYPE
        # Type value (2 = secp256k1)
        assert encoded[1] == key_type
        # Field 2 tag (0x12 = field 2, length-delimited)
        assert encoded[2] == _PROTOBUF_TAG_DATA
        # Length varint (33 = 0x21)
        assert encoded[3] == 0x21
        # Key data
        assert encoded[4:] == key_data

    def test_encode_different_types(self) -> None:
        """Different key types produce different encodings."""
        key_data = bytes(33)  # secp256k1 compressed is 33 bytes

        ed25519 = PublicKeyProto(key_type=KeyType.ED25519, key_data=key_data).encode()
        secp256k1 = PublicKeyProto(key_type=KeyType.SECP256K1, key_data=key_data).encode()

        assert ed25519 != secp256k1
        # Both start with 0x08 (type field tag)
        assert ed25519[0] == _PROTOBUF_TAG_TYPE
        assert secp256k1[0] == _PROTOBUF_TAG_TYPE
        # Type values differ (field 1 value)
        assert ed25519[1] == KeyType.ED25519  # 1
        assert secp256k1[1] == KeyType.SECP256K1  # 2

    def test_ed25519_encoding_matches_spec(self) -> None:
        """Test ED25519 encoding matches libp2p spec test vector.

        From: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#test-vectors
        """
        # Extract the public key bytes from the spec test vector
        # Full encoded: 080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e
        # Breakdown: 08 01 12 20 <32 bytes key>
        full_encoded = bytes.fromhex(
            "080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"
        )
        key_data = full_encoded[4:]  # Skip 08 01 12 20

        proto = PublicKeyProto(key_type=KeyType.ED25519, key_data=key_data)
        encoded = proto.encode()

        assert encoded == full_encoded

    def test_secp256k1_encoding_matches_spec(self) -> None:
        """Test secp256k1 encoding matches libp2p spec test vector.

        From: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#test-vectors
        """
        # Full encoded: 08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99
        # Breakdown: 08 02 12 21 <33 bytes key (compressed)>
        full_encoded = bytes.fromhex(
            "08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99"
        )
        key_data = full_encoded[4:]  # Skip 08 02 12 21

        proto = PublicKeyProto(key_type=KeyType.SECP256K1, key_data=key_data)
        encoded = proto.encode()

        assert encoded == full_encoded

    def test_ecdsa_encoding_matches_spec(self) -> None:
        """Test ECDSA encoding matches libp2p spec test vector.

        From: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#test-vectors
        """
        # Full encoded starts with: 0803125b...
        # Breakdown: 08 03 12 5b <91 bytes key>
        full_encoded = bytes.fromhex(
            "0803125b3059301306072a8648ce3d020106082a8648ce3d030107034200"
            "04de3d300fa36ae0e8f5d530899d83abab44abf3161f162a4bc901d8e6ec"
            "da020e8b6d5f8da30525e71d6851510c098e5c47c646a597fb4dcec034e9"
            "f77c409e62"
        )
        key_data = full_encoded[4:]  # Skip 08 03 12 5b

        proto = PublicKeyProto(key_type=KeyType.ECDSA, key_data=key_data)
        encoded = proto.encode()

        assert encoded == full_encoded


class TestDerivePeerId:
    """Tests for PeerId derivation."""

    def test_derive_from_secp256k1(self) -> None:
        """Derive PeerId from secp256k1 public key."""
        keypair = IdentityKeypair.generate()
        peer_id = PeerId.from_secp256k1(keypair.public_key_bytes())

        # Result should be a valid Base58 string
        peer_id_str = str(peer_id)
        assert len(peer_id_str) > 0
        assert all(c in Base58.ALPHABET for c in peer_id_str)
        # secp256k1 PeerIds start with "16Uiu2"
        assert peer_id_str.startswith("16Uiu2")

    def test_derive_deterministic(self) -> None:
        """Same key always produces same PeerId."""
        keypair = IdentityKeypair.generate()
        public_key_bytes = keypair.public_key_bytes()

        peer_id1 = PeerId.from_secp256k1(public_key_bytes)
        peer_id2 = PeerId.from_secp256k1(public_key_bytes)

        assert str(peer_id1) == str(peer_id2)

    def test_different_keys_different_peerids(self) -> None:
        """Different keys produce different PeerIds."""
        keypair1 = IdentityKeypair.generate()
        keypair2 = IdentityKeypair.generate()

        peer_id1 = PeerId.from_secp256k1(keypair1.public_key_bytes())
        peer_id2 = PeerId.from_secp256k1(keypair2.public_key_bytes())

        assert str(peer_id1) != str(peer_id2)

    def test_derive_general_function(self) -> None:
        """PeerId.derive() works with key data and type."""
        key_data = bytes([0x02] + [0] * 32)  # secp256k1 compressed format
        peer_id = PeerId.derive(key_data, KeyType.SECP256K1)

        peer_id_str = str(peer_id)
        assert len(peer_id_str) > 0
        assert all(c in Base58.ALPHABET for c in peer_id_str)

    def test_from_secp256k1_invalid_length(self) -> None:
        """from_secp256k1 rejects invalid key lengths."""
        with pytest.raises(ValueError, match="must be 33 bytes"):
            PeerId.from_secp256k1(bytes(32))

        with pytest.raises(ValueError, match="must be 33 bytes"):
            PeerId.from_secp256k1(bytes(34))


class TestPeerIdFormat:
    """Tests for PeerId format and structure."""

    def test_peer_id_uses_identity_hash_for_small_keys(self) -> None:
        """Small encoded keys use identity multihash."""
        # secp256k1 key: 33 bytes, encoded is 37 bytes (< 42)
        keypair = IdentityKeypair.generate()
        peer_id = PeerId.from_secp256k1(keypair.public_key_bytes())

        # Decode to verify structure
        decoded = Base58.decode(str(peer_id))

        # First byte should be identity hash (0x00)
        assert decoded[0] == MultihashCode.IDENTITY

    def test_peer_id_uses_sha256_for_large_keys(self) -> None:
        """Large encoded keys use SHA256 multihash."""
        # Create a key type that produces > 42 bytes encoded
        # A 128-byte key should exceed the limit
        large_key = bytes(128)
        peer_id = PeerId.derive(large_key, KeyType.RSA)

        decoded = Base58.decode(str(peer_id))

        # First byte should be SHA256 multihash code (0x12)
        assert decoded[0] == MultihashCode.SHA256
        # Second byte should be 32 (SHA256 output length)
        assert decoded[1] == 32


class TestKnownVectors:
    """Tests against known test vectors from the libp2p spec.

    Test vectors from:
    https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#test-vectors

    The spec provides hex-encoded protobuf public keys. We use these to:
        1. Verify our encoding matches the spec format
        2. Compute PeerIds from the spec's encoded keys
        3. Verify Base58 roundtrip encoding

    PeerId derivation algorithm:
        1. Encode public key as protobuf: [0x08][type][0x12][length][key_bytes]
        2. If encoded <= 42 bytes: multihash(identity, encoded)
        3. If encoded > 42 bytes: multihash(sha256, sha256(encoded))
        4. Base58 encode the multihash
    """

    def test_ed25519_from_spec_test_vector(self) -> None:
        """Test ED25519 key from libp2p spec test vectors.

        Spec test vector (encoded public key):
            080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e

        Structure: 08 (tag) 01 (Ed25519) 12 (tag) 20 (32 bytes) + key_data
        """
        # Encoded public key from spec test vectors table
        spec_encoded = bytes.fromhex(
            "080112201ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e"
        )

        # Verify structure
        assert len(spec_encoded) == 36  # 4 header + 32 key
        assert spec_encoded[0] == _PROTOBUF_TAG_TYPE  # 0x08
        assert spec_encoded[1] == KeyType.ED25519  # 0x01
        assert spec_encoded[2] == _PROTOBUF_TAG_DATA  # 0x12
        assert spec_encoded[3] == 32  # 0x20 = 32 byte key

        # Extract key data and verify re-encoding matches
        key_data = spec_encoded[4:]
        proto = PublicKeyProto(key_type=KeyType.ED25519, key_data=key_data)
        our_encoded = proto.encode()
        assert our_encoded == spec_encoded, "Our encoding must match spec"

        # Compute PeerId (36 bytes <= 42, uses identity multihash)
        multihash = Multihash.identity(spec_encoded).encode()
        peer_id = Base58.encode(multihash)

        # Expected PeerId computed from spec test vector
        expected_peer_id = "12D3KooWBtg3aaRMjxwedh83aGiUkwSxDwUZkzuJcfaqUmo7R3pq"
        assert peer_id == expected_peer_id

        # Verify roundtrip
        decoded = Base58.decode(peer_id)
        assert decoded == multihash

    def test_secp256k1_from_spec_test_vector(self) -> None:
        """Test secp256k1 key from libp2p spec test vectors.

        Spec test vector (encoded public key):
            08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99

        Structure: 08 (tag) 02 (secp256k1) 12 (tag) 21 (33 bytes) + key_data
        """
        # Encoded public key from spec test vectors table
        spec_encoded = bytes.fromhex(
            "08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99"
        )

        # Verify structure
        assert len(spec_encoded) == 37  # 4 header + 33 key
        assert spec_encoded[0] == _PROTOBUF_TAG_TYPE  # 0x08
        assert spec_encoded[1] == KeyType.SECP256K1  # 0x02
        assert spec_encoded[2] == _PROTOBUF_TAG_DATA  # 0x12
        assert spec_encoded[3] == 33  # 0x21 = 33 byte compressed key

        # Extract key data and verify re-encoding matches
        key_data = spec_encoded[4:]
        proto = PublicKeyProto(key_type=KeyType.SECP256K1, key_data=key_data)
        our_encoded = proto.encode()
        assert our_encoded == spec_encoded, "Our encoding must match spec"

        # Compute PeerId (37 bytes <= 42, uses identity multihash)
        multihash = Multihash.identity(spec_encoded).encode()
        peer_id = Base58.encode(multihash)

        # Expected PeerId computed from spec test vector
        expected_peer_id = "16Uiu2HAmLhLvBoYaoZfaMUKuibM6ac163GwKY74c5kiSLg5KvLpY"
        assert peer_id == expected_peer_id

        # Verify roundtrip
        decoded = Base58.decode(peer_id)
        assert decoded == multihash

    def test_ecdsa_from_spec_test_vector(self) -> None:
        """Test ECDSA key from libp2p spec test vectors.

        Spec test vector (encoded public key):
            0803125b3059301306072a8648ce3d020106082a8648ce3d030107034200
            04de3d300fa36ae0e8f5d530899d83abab44abf3161f162a4bc901d8e6ec
            da020e8b6d5f8da30525e71d6851510c098e5c47c646a597fb4dcec034e9
            f77c409e62

        Structure: 08 (tag) 03 (ECDSA) 12 (tag) 5b (91 bytes) + key_data
        """
        # Encoded public key from spec test vectors table
        spec_encoded = bytes.fromhex(
            "0803125b3059301306072a8648ce3d020106082a8648ce3d030107034200"
            "04de3d300fa36ae0e8f5d530899d83abab44abf3161f162a4bc901d8e6ec"
            "da020e8b6d5f8da30525e71d6851510c098e5c47c646a597fb4dcec034e9"
            "f77c409e62"
        )

        # Verify structure
        assert len(spec_encoded) == 95  # 4 header + 91 key
        assert spec_encoded[0] == _PROTOBUF_TAG_TYPE  # 0x08
        assert spec_encoded[1] == KeyType.ECDSA  # 0x03
        assert spec_encoded[2] == _PROTOBUF_TAG_DATA  # 0x12
        assert spec_encoded[3] == 91  # 0x5b = 91 byte key

        # Extract key data and verify re-encoding matches
        key_data = spec_encoded[4:]
        proto = PublicKeyProto(key_type=KeyType.ECDSA, key_data=key_data)
        our_encoded = proto.encode()
        assert our_encoded == spec_encoded, "Our encoding must match spec"

        # Compute PeerId (95 bytes > 42, uses SHA256 multihash)
        multihash = Multihash.sha256(spec_encoded).encode()
        peer_id = Base58.encode(multihash)

        # Expected PeerId computed from spec test vector
        expected_peer_id = "QmVMT29id3TUASyfZZ6k9hmNyc2nYabCo4uMSpDw4zrgDk"
        assert peer_id == expected_peer_id

        # Verify roundtrip
        decoded = Base58.decode(peer_id)
        assert decoded == multihash

    def test_ed25519_peer_id_prefix(self) -> None:
        """Verify ED25519 PeerIds start with '12D3KooW' prefix."""
        # Any 32-byte Ed25519 key should produce a PeerId starting with 12D3KooW
        # because the first bytes are: 00 24 08 01 (identity, 36, tag, Ed25519)
        key_data = bytes(32)  # All zeros
        proto = PublicKeyProto(key_type=KeyType.ED25519, key_data=key_data)
        encoded = proto.encode()
        multihash = Multihash.identity(encoded).encode()
        peer_id = Base58.encode(multihash)

        assert peer_id.startswith("12D3KooW")

    def test_secp256k1_peer_id_prefix(self) -> None:
        """Verify secp256k1 PeerIds start with '16Uiu2' prefix."""
        # Any 33-byte secp256k1 key should produce a PeerId starting with 16Uiu2
        # because the first bytes are: 00 25 08 02 (identity, 37, tag, secp256k1)
        # The exact prefix after "16Uiu2" varies based on key data
        key_data = bytes([0x02] + [0] * 32)  # Compressed format
        proto = PublicKeyProto(key_type=KeyType.SECP256K1, key_data=key_data)
        encoded = proto.encode()
        multihash = Multihash.identity(encoded).encode()
        peer_id = Base58.encode(multihash)

        # All secp256k1 PeerIds start with "16Uiu2" (from 00 25 08 02)
        assert peer_id.startswith("16Uiu2")

    def test_known_secp256k1_peer_id(self) -> None:
        """Test against a known secp256k1-derived PeerId.

        This matches the libp2p spec test vector.
        """
        # From spec: 08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99
        key_data = bytes.fromhex(
            "037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99"
        )
        peer_id = PeerId.from_secp256k1(key_data)

        # Expected PeerId from spec test vector
        expected = "16Uiu2HAmLhLvBoYaoZfaMUKuibM6ac163GwKY74c5kiSLg5KvLpY"
        assert str(peer_id) == expected

        # Verify roundtrip
        decoded = Base58.decode(str(peer_id))
        assert decoded[0] == MultihashCode.IDENTITY

    def test_peer_id_length_reasonable(self) -> None:
        """PeerId length is reasonable (not too long)."""
        keypair = IdentityKeypair.generate()
        peer_id = PeerId.from_secp256k1(keypair.public_key_bytes())

        # Identity-hash PeerId should be around 52-60 characters
        # (Base58 encoding of ~39 bytes: 2 multihash header + 37 encoded key)
        assert 40 <= len(str(peer_id)) <= 70


class TestIntegration:
    """Integration tests for PeerId with identity module."""

    def test_derive_from_generated_keypair(self) -> None:
        """Derive PeerId from freshly generated keypair."""
        keypair = IdentityKeypair.generate()
        peer_id = PeerId.from_secp256k1(keypair.public_key_bytes())

        assert len(str(peer_id)) > 0
        # Verify structure
        decoded = Base58.decode(str(peer_id))
        assert decoded[0] == MultihashCode.IDENTITY

    def test_keypair_to_peer_id_matches(self) -> None:
        """IdentityKeypair.to_peer_id() matches from_secp256k1()."""
        keypair = IdentityKeypair.generate()

        peer_id1 = keypair.to_peer_id()
        peer_id2 = PeerId.from_secp256k1(keypair.public_key_bytes())

        assert str(peer_id1) == str(peer_id2)

    def test_multiple_keypairs_unique_peerids(self) -> None:
        """Each keypair produces unique PeerId."""
        peer_ids = set()
        for _ in range(10):
            keypair = IdentityKeypair.generate()
            peer_id = PeerId.from_secp256k1(keypair.public_key_bytes())
            peer_ids.add(str(peer_id))

        # All 10 should be unique
        assert len(peer_ids) == 10
