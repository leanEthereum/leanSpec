"""
secp256k1 identity keypair for libp2p.

libp2p uses secp256k1 for peer identity. The public key is encoded in
compressed format (33 bytes) and hashed to derive the PeerId.

This is the standard approach used by ream, zeam, and the broader
Ethereum libp2p network.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lean_spec.types import Bytes32, Bytes33

from ..peer_id import KeyType, PeerId, PublicKeyProto

__all__ = [
    "IdentityKeypair",
    "Secp256k1PublicKey",
]


@dataclass(frozen=True, slots=True)
class Secp256k1PublicKey:
    """Compressed secp256k1 public key (33 bytes)."""

    _key: ec.EllipticCurvePublicKey
    """The cryptography library's public key object"""

    @classmethod
    def from_bytes(cls, data: Bytes33) -> Secp256k1PublicKey:
        """
        Load from 33-byte compressed SEC1 format.

        Args:
            data: 33-byte compressed secp256k1 public key.

        Returns:
            Parsed public key.
        """
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), data)
        return cls(_key=key)

    def to_bytes(self) -> Bytes33:
        """
        Return the 33-byte compressed SEC1 encoding.

        The compressed format starts with 0x02 (even y) or 0x03 (odd y),
        followed by the 32-byte x coordinate.

        Returns:
            33-byte compressed public key.
        """
        return Bytes33(
            self._key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint,
            )
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify an ECDSA-SHA256 signature.

        Args:
            message: Original message that was signed.
            signature: DER-encoded ECDSA signature.

        Returns:
            True if signature is valid, False otherwise.
        """
        try:
            self._key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False


@dataclass(frozen=True, slots=True)
class IdentityKeypair:
    """
    secp256k1 keypair for libp2p identity.

    Used to derive PeerId and sign identity proofs during QUIC TLS handshake.
    """

    private_key: ec.EllipticCurvePrivateKey
    """The secp256k1 private key"""
    public_key: Secp256k1PublicKey
    """The corresponding secp256k1 public key"""

    @classmethod
    def generate(cls) -> IdentityKeypair:
        """
        Generate a new random secp256k1 keypair.

        Returns:
            A fresh identity keypair.
        """
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = Secp256k1PublicKey(_key=private_key.public_key())
        return cls(private_key=private_key, public_key=public_key)

    @classmethod
    def from_bytes(cls, data: Bytes32) -> IdentityKeypair:
        """
        Load keypair from raw private key bytes.

        Args:
            data: 32-byte secp256k1 private key.

        Returns:
            Identity keypair.
        """
        private_key = ec.derive_private_key(
            int.from_bytes(data, "big"),
            ec.SECP256K1(),
        )
        public_key = Secp256k1PublicKey(_key=private_key.public_key())
        return cls(private_key=private_key, public_key=public_key)

    def private_key_bytes(self) -> Bytes32:
        """
        Return the raw 32-byte private key.

        Returns:
            32-byte private key scalar.
        """
        private_numbers = self.private_key.private_numbers()
        return Bytes32(private_numbers.private_value.to_bytes(32, "big"))

    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with ECDSA-SHA256.

        Args:
            message: Data to sign.

        Returns:
            DER-encoded ECDSA signature.
        """
        return self.private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    def to_peer_id(self) -> PeerId:
        """
        Derive PeerId from this identity key.

        Uses the standard libp2p derivation:
        1. Encode public key as protobuf with KeyType.SECP256K1
        2. Apply multihash (identity for small keys, SHA256 for large)
        3. Base58 encode

        Returns:
            PeerId derived from this keypair.
        """
        proto = PublicKeyProto(
            key_type=KeyType.SECP256K1,
            key_data=self.public_key.to_bytes(),
        )
        return PeerId.from_public_key(proto)
