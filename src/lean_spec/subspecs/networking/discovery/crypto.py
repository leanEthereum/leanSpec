"""
Cryptographic primitives for Discovery v5.

Discovery v5 uses:
- AES-128-CTR for header masking
- AES-128-GCM for message encryption
- secp256k1 ECDH for key agreement (NOT X25519 like Noise)
- SHA256 for hashing and key derivation

Wire format notes:
- Header masking key: first 16 bytes of destination node ID
- Header masking IV: random 16 bytes included in packet
- Message encryption uses 12-byte nonce (from packet header)
- GCM tag is 16 bytes, appended to ciphertext

References:
- https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md
"""

from __future__ import annotations

import hashlib
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    Prehashed,
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lean_spec.types import Bytes12, Bytes16, Bytes32, Bytes33, Bytes64, Bytes65

COMPRESSED_PUBKEY_SIZE = 33
"""Compressed secp256k1 public key: 0x02/0x03 + 32-byte x coordinate."""

UNCOMPRESSED_PUBKEY_SIZE = 65
"""Uncompressed secp256k1 public key: 0x04 + 32-byte x + 32-byte y."""

AES_KEY_SIZE = 16
"""AES-128 key size in bytes."""

GCM_NONCE_SIZE = 12
"""AES-GCM nonce size in bytes."""

GCM_TAG_SIZE = 16
"""AES-GCM authentication tag size in bytes."""

CTR_IV_SIZE = 16
"""AES-CTR initialization vector size in bytes."""

ID_SIGNATURE_SIZE = 64
"""secp256k1 signature size (r || s, each 32 bytes)."""

ID_SIGNATURE_DOMAIN: Final = b"discovery v5 identity proof"
"""Domain separator for ID nonce signatures. Prevents cross-protocol reuse."""

_P: Final = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
"""secp256k1 field prime."""

_N: Final = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
"""secp256k1 curve order."""

_Gx: Final = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
"""secp256k1 generator x-coordinate."""

_Gy: Final = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
"""secp256k1 generator y-coordinate."""


def _modinv(a: int, m: int) -> int:
    """Compute modular inverse using Fermat's little theorem (m must be prime)."""
    return pow(a, m - 2, m)


def _point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    """Add two secp256k1 curve points."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return None

    if x1 == x2:
        # Point doubling.
        lam = (3 * x1 * x1 * _modinv(2 * y1, _P)) % _P
    else:
        lam = ((y2 - y1) * _modinv(x2 - x1, _P)) % _P

    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_mul(k: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    """Scalar multiplication using double-and-add."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _decompress_pubkey(data: bytes) -> tuple[int, int]:
    """Parse a compressed or uncompressed secp256k1 public key to (x, y)."""
    if len(data) == UNCOMPRESSED_PUBKEY_SIZE and data[0] == 0x04:
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:65], "big")
        return (x, y)

    if len(data) == COMPRESSED_PUBKEY_SIZE and data[0] in (0x02, 0x03):
        x = int.from_bytes(data[1:], "big")
        # Solve y^2 = x^3 + 7 (mod p).
        y_sq = (pow(x, 3, _P) + 7) % _P
        y = pow(y_sq, (_P + 1) // 4, _P)
        # Choose the correct parity.
        if (y & 1) != (data[0] & 1):
            y = _P - y
        return (x, y)

    raise ValueError(f"Invalid public key encoding: length={len(data)}")


def _compress_point(point: tuple[int, int]) -> Bytes33:
    """Encode a curve point as 33-byte compressed format."""
    x, y = point
    prefix = 0x02 if y % 2 == 0 else 0x03
    return Bytes33(bytes([prefix]) + x.to_bytes(32, "big"))


def aes_ctr_encrypt(key: Bytes16, iv: Bytes16, plaintext: bytes) -> bytes:
    """
    Encrypt using AES-128-CTR.

    Used for header masking in Discovery v5 packets.
    The masking key is derived from the destination node ID.

    Args:
        key: 16-byte AES key (dest_node_id[:16]).
        iv: 16-byte initialization vector (masking-iv from packet).
        plaintext: Data to encrypt (packet header).

    Returns:
        Ciphertext of same length as plaintext.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    if len(iv) != CTR_IV_SIZE:
        raise ValueError(f"IV must be {CTR_IV_SIZE} bytes, got {len(iv)}")

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_ctr_decrypt(key: Bytes16, iv: Bytes16, ciphertext: bytes) -> bytes:
    """
    Decrypt using AES-128-CTR.

    CTR mode is symmetric - encryption and decryption are identical operations.

    Args:
        key: 16-byte AES key.
        iv: 16-byte initialization vector.
        ciphertext: Data to decrypt.

    Returns:
        Decrypted plaintext.
    """
    return aes_ctr_encrypt(key, iv, ciphertext)


def aes_gcm_encrypt(key: Bytes16, nonce: Bytes12, plaintext: bytes, aad: bytes) -> bytes:
    """
    Encrypt using AES-128-GCM.

    Used for message encryption in Discovery v5.
    The authentication tag is appended to the ciphertext.

    Args:
        key: 16-byte AES key (session encryption key).
        nonce: 12-byte nonce (from packet header).
        plaintext: Message data to encrypt.
        aad: Additional authenticated data (packet header).

    Returns:
        Ciphertext with 16-byte authentication tag appended.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError(f"Nonce must be {GCM_NONCE_SIZE} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: Bytes16, nonce: Bytes12, ciphertext: bytes, aad: bytes) -> bytes:
    """
    Decrypt using AES-128-GCM.

    Verifies the authentication tag and decrypts if valid.

    Args:
        key: 16-byte AES key.
        nonce: 12-byte nonce.
        ciphertext: Ciphertext with 16-byte auth tag.
        aad: Additional authenticated data.

    Returns:
        Decrypted plaintext.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError(f"Nonce must be {GCM_NONCE_SIZE} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


def ecdh_agree(private_key_bytes: Bytes32, public_key_bytes: bytes) -> Bytes33:
    """
    Perform secp256k1 ECDH key agreement.

    Both parties compute the same shared secret from their private key
    and the other party's public key.

    Per Discovery v5 spec, the shared secret is the 33-byte compressed
    point resulting from scalar multiplication of the private key with
    the public key.

    Args:
        private_key_bytes: 32-byte secp256k1 private key scalar.
        public_key_bytes: 33-byte compressed or 65-byte uncompressed public key.

    Returns:
        33-byte shared secret (compressed point from ECDH).
    """
    if len(private_key_bytes) != 32:
        raise ValueError(f"Private key must be 32 bytes, got {len(private_key_bytes)}")

    scalar = int.from_bytes(private_key_bytes, "big")
    point = _decompress_pubkey(public_key_bytes)
    result = _point_mul(scalar, point)

    if result is None:
        raise ValueError("ECDH produced point at infinity")

    return _compress_point(result)


def generate_secp256k1_keypair() -> tuple[Bytes32, Bytes33]:
    """
    Generate a new secp256k1 keypair.

    Used to create ephemeral keys for ECDH during handshake.

    Returns:
        Tuple of (private_key_bytes, compressed_public_key_bytes).
        - private_key: 32-byte scalar
        - public_key: 33-byte compressed format
    """
    private_key = ec.generate_private_key(ec.SECP256K1())

    private_bytes = private_key.private_numbers().private_value.to_bytes(32, "big")
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )

    return Bytes32(private_bytes), Bytes33(public_bytes)


def pubkey_to_uncompressed(public_key_bytes: bytes) -> Bytes65:
    """
    Convert any secp256k1 public key to uncompressed format.

    Args:
        public_key_bytes: 33-byte compressed or 65-byte uncompressed public key.

    Returns:
        65-byte uncompressed public key (0x04 || x || y).
    """
    if len(public_key_bytes) == UNCOMPRESSED_PUBKEY_SIZE:
        return Bytes65(public_key_bytes)

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(),
        public_key_bytes,
    )
    return Bytes65(
        public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
    )


def sign_id_nonce(
    private_key_bytes: Bytes32,
    challenge_data: bytes,
    ephemeral_pubkey: Bytes33,
    dest_node_id: Bytes32,
) -> Bytes64:
    """
    Sign for handshake authentication.

    The signature proves identity ownership without revealing the private key.

    Per Discovery v5 spec:
        id-signature-input = "discovery v5 identity proof" || challenge-data ||
                            ephemeral-pubkey || node-id-B
        id-signature = sign(sha256(id-signature-input))

    Args:
        private_key_bytes: 32-byte secp256k1 private key.
        challenge_data: Full WHOAREYOU challenge data (masking-iv || static-header || authdata).
        ephemeral_pubkey: 33-byte compressed ephemeral public key.
        dest_node_id: 32-byte node ID of the WHOAREYOU sender (node-id-B).

    Returns:
        64-byte signature (r || s, each 32 bytes).
    """
    if len(private_key_bytes) != 32:
        raise ValueError(f"Private key must be 32 bytes, got {len(private_key_bytes)}")
    if len(dest_node_id) != 32:
        raise ValueError(f"Dest node ID must be 32 bytes, got {len(dest_node_id)}")

    # The signing input binds several values together per the spec:
    #
    # - Domain separator prevents cross-protocol signature reuse
    # - challenge_data provides freshness (full WHOAREYOU packet data)
    # - ephemeral_pubkey binds to this specific handshake
    # - dest_node_id (node-id-B) binds to the specific challenger
    #
    # Using the full challenge_data (not just id_nonce) ensures the signature
    # is bound to the exact WHOAREYOU packet received, preventing replay attacks.
    signing_input = ID_SIGNATURE_DOMAIN + challenge_data + ephemeral_pubkey + dest_node_id

    digest = hashlib.sha256(signing_input).digest()

    # Sign the pre-hashed digest.
    #
    # We use Prehashed because we've already computed SHA256.
    # The library expects the 32-byte digest directly.
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, "big"),
        ec.SECP256K1(),
    )

    der_signature = private_key.sign(
        digest, ec.ECDSA(Prehashed(hashes.SHA256()), deterministic_signing=True)
    )

    # Convert DER-encoded signature to fixed-size r||s format.
    #
    # ECDSA signatures in DER are variable length.
    # Discovery v5 uses fixed 64-byte r||s for consistency.
    r, s = decode_dss_signature(der_signature)
    return Bytes64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_id_nonce_signature(
    signature: Bytes64,
    challenge_data: bytes,
    ephemeral_pubkey: Bytes33,
    dest_node_id: Bytes32,
    public_key_bytes: Bytes33,
) -> bool:
    """
    Verify an ID nonce signature.

    Verifies that the signature was created by the holder of the private key
    corresponding to the given public key.

    Per Discovery v5 spec:
        id-signature-input = "discovery v5 identity proof" || challenge-data ||
                            ephemeral-pubkey || node-id-B
        Verify: signature matches sha256(id-signature-input)

    Args:
        signature: 64-byte signature (r || s).
        challenge_data: Full WHOAREYOU challenge data (masking-iv || static-header || authdata).
        ephemeral_pubkey: 33-byte compressed ephemeral public key.
        dest_node_id: 32-byte node ID of the WHOAREYOU sender (node-id-B).
        public_key_bytes: 33-byte compressed public key of the signer.

    Returns:
        True if signature is valid, False otherwise.
    """
    if len(signature) != ID_SIGNATURE_SIZE:
        return False
    if len(dest_node_id) != 32:
        return False

    # Build the signing input per spec:
    # domain-separator || challenge-data || ephemeral-pubkey || node-id-B
    input_data = ID_SIGNATURE_DOMAIN + challenge_data + ephemeral_pubkey + dest_node_id

    # Pre-hash with SHA256 since ECDSA verification expects a fixed-size digest.
    digest = hashlib.sha256(input_data).digest()

    # The cryptography library expects DER-encoded signatures, not raw r||s.
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der_signature = encode_dss_signature(r, s)

    # Return False on failure rather than raising, since invalid signatures
    # are expected during normal protocol operation (e.g., stale handshakes).
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            public_key_bytes,
        )
        public_key.verify(der_signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False
