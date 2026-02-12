"""
Key derivation for Discovery v5.

Discovery v5 derives session keys using HKDF-SHA256:
- Extract phase: HMAC-SHA256(salt=challenge_data, ikm=shared-secret)
- Expand phase: HMAC-SHA256(prk, info || 0x01)

The challenge_data is the concatenation of:
- masking-iv (16 bytes) from the WHOAREYOU packet
- static-header (23 bytes) - unmasked
- authdata (24 bytes for WHOAREYOU)

Using the full WHOAREYOU packet data as salt binds session keys to:
- The specific challenge (prevents replay across sessions)
- The packet structure (prevents malformed packet attacks)

The derived keys are:
- initiator_key: Used by the handshake initiator to encrypt messages
- recipient_key: Used by the handshake recipient to encrypt messages

References:
- https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md#session-keys
- RFC 5869 (HKDF)
"""

from __future__ import annotations

import hashlib
import hmac

from Crypto.Hash import keccak

from lean_spec.types import Bytes16, Bytes32, Bytes33

from .crypto import ecdh_agree, pubkey_to_uncompressed

DISCV5_KEY_AGREEMENT_INFO = b"discovery v5 key agreement"
"""Info string used in HKDF expansion for Discovery v5 key derivation."""

SESSION_KEY_SIZE = 16
"""Size of each session key in bytes (AES-128)."""


def derive_keys(
    secret: Bytes33,
    initiator_id: Bytes32,
    recipient_id: Bytes32,
    challenge_data: bytes,
) -> tuple[Bytes16, Bytes16]:
    """
    Derive session keys per Discovery v5 specification.

    Both parties derive the same pair of keys from:
    - The ECDH shared secret
    - Both node IDs (determines key direction)
    - The challenge_data from WHOAREYOU (prevents replay attacks)

    Key derivation:
        info = "discovery v5 key agreement" || initiator_id || recipient_id
        prk = HKDF-Extract(salt=challenge_data, ikm=secret)
        keys = HKDF-Expand(prk, info, 32)
        initiator_key = keys[:16]
        recipient_key = keys[16:32]

    Args:
        secret: 33-byte ECDH shared secret (compressed point).
        initiator_id: 32-byte node ID of the handshake initiator.
        recipient_id: 32-byte node ID of the handshake recipient.
        challenge_data: WHOAREYOU packet data (masking-iv || static-header || authdata).
            This is 63 bytes: 16 (iv) + 23 (static header) + 24 (authdata).

    Returns:
        Tuple of (initiator_key, recipient_key), each 16 bytes.

    The initiator uses initiator_key to encrypt and recipient_key to decrypt.
    The recipient uses recipient_key to encrypt and initiator_key to decrypt.
    """
    if len(secret) != 33:
        raise ValueError(f"Secret must be 33 bytes, got {len(secret)}")
    if len(initiator_id) != 32:
        raise ValueError(f"Initiator ID must be 32 bytes, got {len(initiator_id)}")
    if len(recipient_id) != 32:
        raise ValueError(f"Recipient ID must be 32 bytes, got {len(recipient_id)}")

    # HKDF-Extract: PRK = HMAC-SHA256(salt, IKM).
    #
    # Using challenge_data as salt binds session keys to the specific WHOAREYOU.
    # challenge_data = masking-iv || static-header || authdata
    # This includes the random id-nonce within authdata, providing replay protection.
    # The full packet structure prevents malformed packet attacks.
    prk = hmac.new(challenge_data, secret, hashlib.sha256).digest()

    # Include both node IDs in the info string.
    #
    # This binds keys to the specific communicating parties.
    # Prevents key confusion attacks where an attacker substitutes
    # their own node ID after observing a handshake.
    info = DISCV5_KEY_AGREEMENT_INFO + initiator_id + recipient_id

    # HKDF-Expand produces deterministic output from PRK.
    #
    # We need 32 bytes (two 16-byte AES keys).
    # SHA-256 outputs 32 bytes, so one round suffices.
    t1 = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

    initiator_key = Bytes16(t1[:SESSION_KEY_SIZE])
    recipient_key = Bytes16(t1[SESSION_KEY_SIZE : SESSION_KEY_SIZE * 2])

    return initiator_key, recipient_key


def derive_keys_from_pubkey(
    local_private_key: Bytes32,
    remote_public_key: bytes,
    local_node_id: Bytes32,
    remote_node_id: Bytes32,
    challenge_data: bytes,
    is_initiator: bool,
) -> tuple[Bytes16, Bytes16]:
    """
    Derive session keys from ECDH with automatic key ordering.

    Convenience function that performs ECDH and derives keys with
    proper initiator/recipient ordering.

    Args:
        local_private_key: Our 32-byte secp256k1 private key.
        remote_public_key: Peer's compressed public key.
        local_node_id: Our 32-byte node ID.
        remote_node_id: Peer's 32-byte node ID.
        challenge_data: WHOAREYOU packet data (masking-iv || static-header || authdata).
        is_initiator: True if we initiated the handshake.

    Returns:
        Tuple of (send_key, recv_key) for this party.
        - send_key: Use to encrypt outgoing messages.
        - recv_key: Use to decrypt incoming messages.
    """
    # Compute shared secret.
    secret = ecdh_agree(local_private_key, remote_public_key)

    # Determine key ordering based on who initiated.
    if is_initiator:
        initiator_key, recipient_key = derive_keys(
            secret, local_node_id, remote_node_id, challenge_data
        )
        # We are initiator: use initiator_key to send, recipient_key to receive.
        return initiator_key, recipient_key
    else:
        initiator_key, recipient_key = derive_keys(
            secret, remote_node_id, local_node_id, challenge_data
        )
        # We are recipient: use recipient_key to send, initiator_key to receive.
        return recipient_key, initiator_key


def compute_node_id(public_key_bytes: bytes) -> Bytes32:
    """
    Compute node ID from public key.

    Per Discovery v5 / EIP-778 "v4" identity scheme:
        node_id = keccak256(uncompressed_pubkey[1:])

    The hash is computed over the 64-byte x||y coordinates,
    excluding the 0x04 prefix byte.

    Args:
        public_key_bytes: Compressed (33 bytes) or uncompressed (65 bytes) public key.

    Returns:
        32-byte node ID.
    """
    # Ensure uncompressed format.
    uncompressed = pubkey_to_uncompressed(public_key_bytes)

    # Hash the 64-byte x||y (excluding 0x04 prefix).
    k = keccak.new(digest_bits=256)
    k.update(uncompressed[1:])
    return Bytes32(k.digest())
