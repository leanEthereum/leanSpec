"""
secp256k1 identity keypair for libp2p.

libp2p uses secp256k1 for peer identity. The public key is encoded in
compressed format (33 bytes) and hashed to derive the PeerId.

This is the standard approach used by ream, zeam, and the broader
Ethereum libp2p network.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..peer_id import KeyType, PeerId, PublicKeyProto

__all__ = [
    "IdentityKeypair",
]


@dataclass(frozen=True, slots=True)
class IdentityKeypair:
    """
    secp256k1 keypair for libp2p identity.

    Used to derive PeerId and sign identity proofs during Noise handshake.

    Attributes:
        private_key: The secp256k1 private key.
    """

    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls) -> IdentityKeypair:
        """
        Generate a new random secp256k1 keypair.

        Returns:
            A fresh identity keypair.
        """
        private_key = ec.generate_private_key(ec.SECP256K1())
        return cls(private_key=private_key)

    @classmethod
    def from_bytes(cls, data: bytes) -> IdentityKeypair:
        """
        Load keypair from raw private key bytes.

        Args:
            data: 32-byte secp256k1 private key.

        Returns:
            Identity keypair.

        Raises:
            ValueError: If data is not a valid secp256k1 private key.
        """
        if len(data) != 32:
            raise ValueError(f"Expected 32 bytes, got {len(data)}")

        private_key = ec.derive_private_key(
            int.from_bytes(data, "big"),
            ec.SECP256K1(),
        )
        return cls(private_key=private_key)

    def private_key_bytes(self) -> bytes:
        """
        Return the raw 32-byte private key.

        Returns:
            32-byte private key scalar.
        """
        private_numbers = self.private_key.private_numbers()
        return private_numbers.private_value.to_bytes(32, "big")

    def public_key_bytes(self) -> bytes:
        """
        Return the compressed secp256k1 public key (33 bytes).

        The compressed format starts with 0x02 (even y) or 0x03 (odd y),
        followed by the 32-byte x coordinate.

        Returns:
            33-byte compressed public key.
        """
        public_key = self.private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

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
            key_data=self.public_key_bytes(),
        )
        return PeerId.from_public_key(proto)


def verify_signature(
    public_key_bytes: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """
    Verify an ECDSA-SHA256 signature.

    Args:
        public_key_bytes: 33-byte compressed secp256k1 public key.
        message: Original message that was signed.
        signature: DER-encoded ECDSA signature.

    Returns:
        True if signature is valid, False otherwise.
    """
    from cryptography.exceptions import InvalidSignature

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(),
        public_key_bytes,
    )

    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
