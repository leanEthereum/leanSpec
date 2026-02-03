"""
Packet encoding/decoding for Discovery v5.

Discovery v5 packet structure::

    packet = masking-iv || masked-header || message
    masking-iv = random 16 bytes
    masked-header = aes-ctr(key=dest-id[:16], iv=masking-iv, header)
    header = static-header || authdata

Static header (23 bytes)::

    static-header = protocol-id || version || flag || nonce || authdata-size
    protocol-id = "discv5"
    version = 0x0001
    flag = 0/1/2 (message/whoareyou/handshake)
    nonce = 12 bytes
    authdata-size = 2 bytes (big-endian)

Authdata varies by packet type:

- MESSAGE (flag=0): src-id (32 bytes)
- WHOAREYOU (flag=1): id-nonce (16 bytes) || enr-seq (8 bytes)
- HANDSHAKE (flag=2): variable size with ephemeral key and signature

References:
- https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md#packet-encoding
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from enum import IntEnum

from lean_spec.types import Uint64

from .config import MAX_PACKET_SIZE, MIN_PACKET_SIZE
from .crypto import (
    AES_KEY_SIZE,
    COMPRESSED_PUBKEY_SIZE,
    CTR_IV_SIZE,
    GCM_NONCE_SIZE,
    ID_SIGNATURE_SIZE,
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
)
from .messages import PROTOCOL_ID, PROTOCOL_VERSION, IdNonce, Nonce, PacketFlag

STATIC_HEADER_SIZE = 23
"""Size of the static header in bytes: 6 + 2 + 1 + 12 + 2."""

MESSAGE_AUTHDATA_SIZE = 32
"""Authdata size for MESSAGE packets: src-id (32 bytes)."""

WHOAREYOU_AUTHDATA_SIZE = 24
"""Authdata size for WHOAREYOU packets: id-nonce (16) + enr-seq (8)."""

HANDSHAKE_HEADER_SIZE = 34
"""Fixed portion of handshake authdata: src-id (32) + sig-size (1) + eph-key-size (1)."""


class PacketType(IntEnum):
    """Packet type aliases matching PacketFlag for clarity."""

    MESSAGE = 0
    WHOAREYOU = 1
    HANDSHAKE = 2


@dataclass(frozen=True, slots=True)
class PacketHeader:
    """Decoded packet header."""

    flag: PacketFlag
    """Packet type: message, whoareyou, or handshake."""

    nonce: Nonce
    """12-byte message nonce."""

    authdata: bytes
    """Variable-length authentication data."""


@dataclass(frozen=True, slots=True)
class MessageAuthdata:
    """Authdata for MESSAGE packets (flag=0)."""

    src_id: bytes
    """Sender's 32-byte node ID."""


@dataclass(frozen=True, slots=True)
class WhoAreYouAuthdata:
    """Authdata for WHOAREYOU packets (flag=1)."""

    id_nonce: IdNonce
    """16-byte identity challenge nonce."""

    enr_seq: Uint64
    """Sender's last known ENR sequence for the target. 0 if unknown."""


@dataclass(frozen=True, slots=True)
class HandshakeAuthdata:
    """Authdata for HANDSHAKE packets (flag=2)."""

    src_id: bytes
    """Sender's 32-byte node ID."""

    sig_size: int
    """Size of the ID signature. 64 for v4 identity scheme."""

    eph_key_size: int
    """Size of ephemeral public key. 33 for compressed secp256k1."""

    id_signature: bytes
    """ID nonce signature proving identity ownership."""

    eph_pubkey: bytes
    """Ephemeral public key for ECDH."""

    record: bytes | None
    """RLP-encoded ENR, included if recipient's enr_seq was stale."""


def encode_packet(
    dest_node_id: bytes,
    src_node_id: bytes,
    flag: PacketFlag,
    nonce: bytes,
    authdata: bytes,
    message: bytes,
    encryption_key: bytes | None = None,
) -> bytes:
    """
    Encode a Discovery v5 packet.

    Args:
        dest_node_id: 32-byte destination node ID (for header masking).
        src_node_id: 32-byte source node ID (only used for logging/debugging).
        flag: Packet type flag.
        nonce: 12-byte message nonce.
        authdata: Authentication data (varies by packet type).
        message: Message payload (plaintext for WHOAREYOU, encrypted otherwise).
        encryption_key: 16-byte key for message encryption (None for WHOAREYOU).

    Returns:
        Complete encoded packet ready for UDP transmission.
    """
    if len(dest_node_id) != 32:
        raise ValueError(f"Destination node ID must be 32 bytes, got {len(dest_node_id)}")
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError(f"Nonce must be {GCM_NONCE_SIZE} bytes, got {len(nonce)}")

    # Fresh random IV for header masking.
    #
    # Using dest_node_id as the masking key is deterministic,
    # so the IV MUST be random to prevent ciphertext patterns.
    # Without randomness, identical packets would produce
    # identical masked headers, enabling traffic analysis.
    masking_iv = os.urandom(CTR_IV_SIZE)

    static_header = _encode_static_header(flag, nonce, len(authdata))
    header = static_header + authdata

    # Header masking hides protocol metadata from observers.
    #
    # The masking key is derived from the destination node ID.
    # Only the intended recipient can unmask the header.
    # This provides privacy without requiring key exchange.
    masking_key = dest_node_id[:AES_KEY_SIZE]
    masked_header = aes_ctr_encrypt(masking_key, masking_iv, header)

    if flag == PacketFlag.WHOAREYOU:
        # WHOAREYOU has no message payload.
        encrypted_message = message
    else:
        if encryption_key is None:
            raise ValueError("Encryption key required for non-WHOAREYOU packets")

        # Masked header as AAD prevents header tampering.
        #
        # The recipient verifies the header wasn't modified
        # without having to decrypt the payload first.
        encrypted_message = aes_gcm_encrypt(encryption_key, nonce, message, masked_header)

    # Assemble packet.
    packet = masking_iv + masked_header + encrypted_message

    if len(packet) > MAX_PACKET_SIZE:
        raise ValueError(f"Packet exceeds max size: {len(packet)} > {MAX_PACKET_SIZE}")

    return packet


def decode_packet_header(local_node_id: bytes, data: bytes) -> tuple[PacketHeader, bytes]:
    """
    Decode and unmask a Discovery v5 packet header.

    Args:
        local_node_id: Our 32-byte node ID (for header unmasking).
        data: Raw packet bytes.

    Returns:
        Tuple of (header, message_bytes).

    Raises:
        ValueError: If packet is malformed.
    """
    if len(data) < MIN_PACKET_SIZE:
        raise ValueError(f"Packet too small: {len(data)} < {MIN_PACKET_SIZE}")

    # Extract masking IV.
    masking_iv = data[:CTR_IV_SIZE]

    # Unmask enough to read the static header.
    masking_key = local_node_id[:AES_KEY_SIZE]
    masked_data = data[CTR_IV_SIZE:]

    # Decrypt static header first to get authdata size.
    static_header_masked = masked_data[:STATIC_HEADER_SIZE]
    static_header = aes_ctr_decrypt(masking_key, masking_iv, static_header_masked)

    # Parse static header.
    protocol_id = static_header[:6]
    if protocol_id != PROTOCOL_ID:
        raise ValueError(f"Invalid protocol ID: {protocol_id!r}")

    version = struct.unpack(">H", static_header[6:8])[0]
    if version != PROTOCOL_VERSION:
        raise ValueError(f"Unsupported protocol version: {version}")

    flag = PacketFlag(static_header[8])
    nonce = Nonce(static_header[9:21])
    authdata_size = struct.unpack(">H", static_header[21:23])[0]

    # Verify we have enough data for authdata.
    header_end = CTR_IV_SIZE + STATIC_HEADER_SIZE + authdata_size
    if len(data) < header_end:
        raise ValueError(f"Packet truncated: need {header_end}, have {len(data)}")

    # Decrypt the full header including authdata.
    full_masked_header = masked_data[: STATIC_HEADER_SIZE + authdata_size]
    full_header = aes_ctr_decrypt(masking_key, masking_iv, full_masked_header)
    authdata = full_header[STATIC_HEADER_SIZE:]

    # Message bytes are everything after the header.
    message_bytes = data[header_end:]

    return PacketHeader(flag=flag, nonce=nonce, authdata=authdata), message_bytes


def decode_message_authdata(authdata: bytes) -> MessageAuthdata:
    """Decode MESSAGE packet authdata."""
    if len(authdata) != MESSAGE_AUTHDATA_SIZE:
        raise ValueError(f"Invalid MESSAGE authdata size: {len(authdata)}")
    return MessageAuthdata(src_id=authdata)


def decode_whoareyou_authdata(authdata: bytes) -> WhoAreYouAuthdata:
    """Decode WHOAREYOU packet authdata."""
    if len(authdata) != WHOAREYOU_AUTHDATA_SIZE:
        raise ValueError(f"Invalid WHOAREYOU authdata size: {len(authdata)}")

    id_nonce = IdNonce(authdata[:16])
    enr_seq = Uint64(struct.unpack(">Q", authdata[16:24])[0])

    return WhoAreYouAuthdata(id_nonce=id_nonce, enr_seq=enr_seq)


def decode_handshake_authdata(authdata: bytes) -> HandshakeAuthdata:
    """Decode HANDSHAKE packet authdata."""
    if len(authdata) < HANDSHAKE_HEADER_SIZE:
        raise ValueError(f"Handshake authdata too small: {len(authdata)}")

    src_id = authdata[:32]
    sig_size = authdata[32]
    eph_key_size = authdata[33]

    expected_min = HANDSHAKE_HEADER_SIZE + sig_size + eph_key_size
    if len(authdata) < expected_min:
        raise ValueError(f"Handshake authdata truncated: {len(authdata)} < {expected_min}")

    offset = HANDSHAKE_HEADER_SIZE
    id_signature = authdata[offset : offset + sig_size]
    offset += sig_size

    eph_pubkey = authdata[offset : offset + eph_key_size]
    offset += eph_key_size

    record = authdata[offset:] if offset < len(authdata) else None

    return HandshakeAuthdata(
        src_id=src_id,
        sig_size=sig_size,
        eph_key_size=eph_key_size,
        id_signature=id_signature,
        eph_pubkey=eph_pubkey,
        record=record,
    )


def decrypt_message(
    encryption_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    masked_header: bytes,
) -> bytes:
    """
    Decrypt an encrypted message payload.

    Args:
        encryption_key: 16-byte session key.
        nonce: 12-byte nonce from packet header.
        ciphertext: Encrypted message with GCM tag.
        masked_header: Masked header bytes (used as AAD).

    Returns:
        Decrypted message plaintext.
    """
    return aes_gcm_decrypt(encryption_key, bytes(nonce), ciphertext, masked_header)


def encode_message_authdata(src_id: bytes) -> bytes:
    """Encode MESSAGE packet authdata."""
    if len(src_id) != 32:
        raise ValueError(f"Source ID must be 32 bytes, got {len(src_id)}")
    return src_id


def encode_whoareyou_authdata(id_nonce: bytes, enr_seq: int) -> bytes:
    """Encode WHOAREYOU packet authdata."""
    if len(id_nonce) != 16:
        raise ValueError(f"ID nonce must be 16 bytes, got {len(id_nonce)}")
    return id_nonce + struct.pack(">Q", enr_seq)


def encode_handshake_authdata(
    src_id: bytes,
    id_signature: bytes,
    eph_pubkey: bytes,
    record: bytes | None = None,
) -> bytes:
    """
    Encode HANDSHAKE packet authdata.

    Args:
        src_id: 32-byte source node ID.
        id_signature: 64-byte ID nonce signature.
        eph_pubkey: 33-byte compressed ephemeral public key.
        record: Optional RLP-encoded ENR.

    Returns:
        Encoded authdata bytes.
    """
    if len(src_id) != 32:
        raise ValueError(f"Source ID must be 32 bytes, got {len(src_id)}")
    if len(id_signature) != ID_SIGNATURE_SIZE:
        raise ValueError(f"Signature must be {ID_SIGNATURE_SIZE} bytes, got {len(id_signature)}")
    if len(eph_pubkey) != COMPRESSED_PUBKEY_SIZE:
        raise ValueError(
            f"Ephemeral pubkey must be {COMPRESSED_PUBKEY_SIZE} bytes, got {len(eph_pubkey)}"
        )

    authdata = src_id + bytes([len(id_signature), len(eph_pubkey)]) + id_signature + eph_pubkey

    if record is not None:
        authdata += record

    return authdata


def generate_nonce() -> Nonce:
    """Generate a random 12-byte message nonce."""
    return Nonce(os.urandom(GCM_NONCE_SIZE))


def generate_id_nonce() -> IdNonce:
    """Generate a random 16-byte identity challenge nonce."""
    return IdNonce(os.urandom(16))


def _encode_static_header(flag: PacketFlag, nonce: bytes, authdata_size: int) -> bytes:
    """Encode the 23-byte static header."""
    return (
        PROTOCOL_ID
        + struct.pack(">H", PROTOCOL_VERSION)
        + bytes([flag])
        + nonce
        + struct.pack(">H", authdata_size)
    )
