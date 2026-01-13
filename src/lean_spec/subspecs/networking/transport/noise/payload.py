"""
libp2p-noise handshake payload for identity binding.

During the Noise XX handshake, peers exchange identity payloads that bind
their secp256k1 identity key to their X25519 Noise static key.

Payload format (protobuf-encoded):
    message NoiseHandshakePayload {
        bytes identity_key = 1;     // Protobuf-encoded PublicKey
        bytes identity_sig = 2;     // ECDSA signature
    }

The identity_key is itself a protobuf:
    message PublicKey {
        KeyType Type = 1;           // 2 = secp256k1
        bytes Data = 2;             // 33-byte compressed key
    }

The signature is computed over:
    "noise-libp2p-static-key:" || noise_static_public_key

This binding prevents an attacker from substituting their own Noise key
while claiming someone else's identity.

References:
    - https://github.com/libp2p/specs/blob/master/noise/README.md
"""

from __future__ import annotations

from dataclasses import dataclass

from lean_spec.subspecs.networking import varint

from ..identity import (
    IdentityKeypair,
    create_identity_proof,
    verify_identity_proof,
)
from ..peer_id import KeyType, PeerId, PublicKeyProto

# Protobuf field tags for NoiseHandshakePayload
_TAG_IDENTITY_KEY = 0x0A  # (1 << 3) | 2 = field 1, length-delimited
_TAG_IDENTITY_SIG = 0x12  # (2 << 3) | 2 = field 2, length-delimited


@dataclass(frozen=True, slots=True)
class NoiseIdentityPayload:
    """
    Identity payload exchanged during Noise handshake.

    Contains the secp256k1 identity public key and a signature proving
    ownership of both the identity key and the Noise static key.

    Attributes:
        identity_key: Protobuf-encoded secp256k1 public key.
        identity_sig: ECDSA-SHA256 signature over Noise static key.
    """

    identity_key: bytes
    """Protobuf-encoded PublicKey (KeyType + compressed secp256k1)."""

    identity_sig: bytes
    """DER-encoded ECDSA signature proving key binding."""

    def encode(self) -> bytes:
        """
        Encode as protobuf wire format.

        Returns:
            Protobuf-encoded NoiseHandshakePayload.
        """
        # Field 1: identity_key (length-delimited)
        field1 = (
            bytes([_TAG_IDENTITY_KEY]) + varint.encode(len(self.identity_key)) + self.identity_key
        )

        # Field 2: identity_sig (length-delimited)
        field2 = (
            bytes([_TAG_IDENTITY_SIG]) + varint.encode(len(self.identity_sig)) + self.identity_sig
        )

        return field1 + field2

    @classmethod
    def decode(cls, data: bytes) -> NoiseIdentityPayload:
        """
        Decode from protobuf wire format.

        Args:
            data: Protobuf-encoded payload.

        Returns:
            Decoded payload.

        Raises:
            ValueError: If data is malformed.
        """
        identity_key = b""
        identity_sig = b""

        offset = 0
        while offset < len(data):
            tag = data[offset]
            offset += 1

            # Decode length varint
            length, consumed = varint.decode(data, offset)
            offset += consumed

            if offset + length > len(data):
                raise ValueError("Truncated payload")

            value = data[offset : offset + length]
            offset += length

            if tag == _TAG_IDENTITY_KEY:
                identity_key = value
            elif tag == _TAG_IDENTITY_SIG:
                identity_sig = value

        if not identity_key:
            raise ValueError("Missing identity_key in payload")
        if not identity_sig:
            raise ValueError("Missing identity_sig in payload")

        return cls(identity_key=identity_key, identity_sig=identity_sig)

    @classmethod
    def create(
        cls,
        identity_keypair: IdentityKeypair,
        noise_public_key: bytes,
    ) -> NoiseIdentityPayload:
        """
        Create identity payload for Noise handshake.

        Args:
            identity_keypair: Our secp256k1 identity keypair.
            noise_public_key: Our 32-byte X25519 Noise static public key.

        Returns:
            Payload ready to be encoded and sent during handshake.
        """
        # Encode identity public key as protobuf
        proto = PublicKeyProto(
            key_type=KeyType.SECP256K1,
            key_data=identity_keypair.public_key_bytes(),
        )
        identity_key = proto.encode()

        # Create signature binding identity to Noise key
        identity_sig = create_identity_proof(identity_keypair, noise_public_key)

        return cls(identity_key=identity_key, identity_sig=identity_sig)

    def verify(self, noise_public_key: bytes) -> bool:
        """
        Verify the identity signature.

        Args:
            noise_public_key: Remote peer's 32-byte X25519 Noise static public key.

        Returns:
            True if signature is valid, False otherwise.
        """
        # Extract secp256k1 public key from protobuf
        identity_pubkey = self.extract_public_key()
        if identity_pubkey is None:
            return False

        return verify_identity_proof(identity_pubkey, noise_public_key, self.identity_sig)

    def extract_public_key(self) -> bytes | None:
        """
        Extract the secp256k1 public key from the encoded identity_key.

        Returns:
            33-byte compressed secp256k1 public key, or None if invalid.
        """
        # Parse the PublicKey protobuf
        # Format: [0x08][type][0x12][length][key_data]
        try:
            if len(self.identity_key) < 4:
                return None

            offset = 0

            # Field 1: Type (tag 0x08, varint)
            if self.identity_key[offset] != 0x08:
                return None
            offset += 1

            # Read type varint
            key_type, consumed = varint.decode(self.identity_key, offset)
            offset += consumed

            if key_type != KeyType.SECP256K1:
                return None

            # Field 2: Data (tag 0x12, length-delimited)
            if offset >= len(self.identity_key) or self.identity_key[offset] != 0x12:
                return None
            offset += 1

            # Read length varint
            length, consumed = varint.decode(self.identity_key, offset)
            offset += consumed

            if offset + length > len(self.identity_key):
                return None

            key_data = self.identity_key[offset : offset + length]

            # Verify it's a valid compressed secp256k1 key (33 bytes)
            if len(key_data) != 33:
                return None
            if key_data[0] not in (0x02, 0x03):
                return None

            return key_data

        except (IndexError, ValueError):
            return None

    def to_peer_id(self) -> PeerId | None:
        """
        Derive PeerId from the identity key in this payload.

        Returns:
            PeerId derived from secp256k1 identity key, or None if invalid.
        """
        pubkey = self.extract_public_key()
        if pubkey is None:
            return None
        return PeerId.from_secp256k1(pubkey)
