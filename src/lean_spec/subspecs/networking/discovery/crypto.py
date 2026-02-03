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

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lean_spec.types import Bytes32

# Constants for secp256k1
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


def aes_ctr_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
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


def aes_ctr_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
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


def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
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


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
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


def ecdh_agree(private_key_bytes: bytes, public_key_bytes: bytes) -> Bytes32:
    """
    Perform secp256k1 ECDH key agreement.

    Both parties compute the same shared secret from their private key
    and the other party's public key.

    Args:
        private_key_bytes: 32-byte secp256k1 private key scalar.
        public_key_bytes: 33-byte compressed or 65-byte uncompressed public key.

    Returns:
        32-byte shared secret (x-coordinate of the resulting point).
    """
    if len(private_key_bytes) != 32:
        raise ValueError(f"Private key must be 32 bytes, got {len(private_key_bytes)}")

    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, "big"),
        ec.SECP256K1(),
    )

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(),
        public_key_bytes,
    )

    shared_key = private_key.exchange(ec.ECDH(), public_key)
    return Bytes32(shared_key)


def generate_secp256k1_keypair() -> tuple[bytes, bytes]:
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

    return private_bytes, public_bytes


def pubkey_to_compressed(public_key_bytes: bytes) -> bytes:
    """
    Convert any secp256k1 public key to compressed format.

    Args:
        public_key_bytes: 33-byte compressed or 65-byte uncompressed public key.

    Returns:
        33-byte compressed public key.
    """
    if len(public_key_bytes) == COMPRESSED_PUBKEY_SIZE:
        return public_key_bytes

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(),
        public_key_bytes,
    )
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )


def pubkey_to_uncompressed(public_key_bytes: bytes) -> bytes:
    """
    Convert any secp256k1 public key to uncompressed format.

    Args:
        public_key_bytes: 33-byte compressed or 65-byte uncompressed public key.

    Returns:
        65-byte uncompressed public key (0x04 || x || y).
    """
    if len(public_key_bytes) == UNCOMPRESSED_PUBKEY_SIZE:
        return public_key_bytes

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(),
        public_key_bytes,
    )
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def sign_id_nonce(
    private_key_bytes: bytes,
    challenge_data: bytes,
    ephemeral_pubkey: bytes,
    dest_node_id: bytes,
) -> bytes:
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
    import hashlib

    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

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
    domain_separator = b"discovery v5 identity proof"
    input_data = domain_separator + challenge_data + ephemeral_pubkey + dest_node_id

    digest = hashlib.sha256(input_data).digest()

    # Sign the pre-hashed digest.
    #
    # We use Prehashed because we've already computed SHA256.
    # The library expects the 32-byte digest directly.
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, "big"),
        ec.SECP256K1(),
    )

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    der_signature = private_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    # Convert DER-encoded signature to fixed-size r||s format.
    #
    # ECDSA signatures in DER are variable length.
    # Discovery v5 uses fixed 64-byte r||s for consistency.
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_id_nonce_signature(
    signature: bytes,
    challenge_data: bytes,
    ephemeral_pubkey: bytes,
    dest_node_id: bytes,
    public_key_bytes: bytes,
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
    import hashlib

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import (
        Prehashed,
        encode_dss_signature,
    )

    if len(signature) != ID_SIGNATURE_SIZE:
        return False
    if len(dest_node_id) != 32:
        return False

    # Build the signing input per spec:
    # domain-separator || challenge-data || ephemeral-pubkey || node-id-B
    domain_separator = b"discovery v5 identity proof"
    input_data = domain_separator + challenge_data + ephemeral_pubkey + dest_node_id

    # Hash the input.
    digest = hashlib.sha256(input_data).digest()

    # Convert r||s to DER format.
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der_signature = encode_dss_signature(r, s)

    # Verify the signature.
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            public_key_bytes,
        )
        public_key.verify(der_signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except (InvalidSignature, ValueError):
        return False
