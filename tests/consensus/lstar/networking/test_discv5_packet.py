"""Discovery v5 packet framing: known-answer and rejection vectors.

Pins the exact wire-level encoding produced by the spec for each packet
type clients must emit. Uses deterministic masking IVs so the resulting
bytes are stable, and roundtrip-decodes the header to assert shape
preservation. Rejection vectors cover the public size and protocol-id
checks.
"""

import pytest
from consensus_testing import NetworkingCodecTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


DEST_NODE_ID = "0x" + "11" * 32
"""Fixed destination node ID. Its first 16 bytes act as the masking key."""

NONCE = "0x" + "22" * 12
"""Fixed 12-byte message nonce."""

MASKING_IV = "0x" + "33" * 16
"""Fixed 16-byte header-masking IV for deterministic packet bytes."""

ENCRYPTION_KEY = "0x" + "44" * 16
"""Fixed 16-byte AES-GCM encryption key for non-WHOAREYOU packets."""

SRC_NODE_ID = "0x" + "55" * 32
"""Fixed source node ID used inside MESSAGE and HANDSHAKE authdata."""

ID_NONCE = "0x" + "66" * 16
"""Fixed 16-byte ID nonce used inside WHOAREYOU authdata."""

ID_SIGNATURE = "0x" + "77" * 64
"""Fixed 64-byte ID-nonce signature used inside HANDSHAKE authdata."""

EPH_PUBKEY = "0x02" + "88" * 32
"""Fixed 33-byte compressed ephemeral public key (prefix byte then 32 bytes)."""

# An encrypted message payload the AES-GCM layer will accept; exact
# ciphertext bytes do not matter for packet-shape assertions.
MESSAGE_PAYLOAD = "0x" + "ab" * 16


def test_discv5_packet_message(networking_codec: NetworkingCodecTestFiller) -> None:
    """MESSAGE packet (flag=0) with known inputs pins the full wire bytes.

    Encodes a MESSAGE packet with a fixed destination node id, nonce,
    masking IV, encryption key, and source id. The fixture asserts
    the encoded packet round-trips through decode_packet_header with
    flag, nonce, and authdata preserved.
    """
    networking_codec(
        codec_name="discv5_packet",
        input={
            "packetType": "message",
            "destNodeId": DEST_NODE_ID,
            "nonce": NONCE,
            "maskingIv": MASKING_IV,
            "encryptionKey": ENCRYPTION_KEY,
            "srcId": SRC_NODE_ID,
            "message": MESSAGE_PAYLOAD,
        },
    )


def test_discv5_packet_whoareyou(networking_codec: NetworkingCodecTestFiller) -> None:
    """WHOAREYOU packet (flag=1) with known inputs pins the full wire bytes.

    WHOAREYOU carries no encrypted payload. The authdata is the 16-byte
    ID nonce concatenated with the 8-byte ENR sequence number.
    """
    networking_codec(
        codec_name="discv5_packet",
        input={
            "packetType": "whoareyou",
            "destNodeId": DEST_NODE_ID,
            "nonce": NONCE,
            "maskingIv": MASKING_IV,
            "idNonce": ID_NONCE,
            "enrSeq": 42,
        },
    )


def test_discv5_packet_handshake_without_record(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """HANDSHAKE packet (flag=2) without an embedded ENR record.

    Exercises the fixed-size authdata path where the record field is
    absent. Pins the encoded length and the roundtrip decode that reads
    sig-size / eph-key-size from the authdata header.
    """
    networking_codec(
        codec_name="discv5_packet",
        input={
            "packetType": "handshake",
            "destNodeId": DEST_NODE_ID,
            "nonce": NONCE,
            "maskingIv": MASKING_IV,
            "encryptionKey": ENCRYPTION_KEY,
            "srcId": SRC_NODE_ID,
            "idSignature": ID_SIGNATURE,
            "ephPubkey": EPH_PUBKEY,
            "message": MESSAGE_PAYLOAD,
        },
    )


def test_discv5_packet_decode_rejects_too_small(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Decoding a packet below MIN_PACKET_SIZE must raise ValueError.

    MIN_PACKET_SIZE is 63 bytes. A 10-byte blob cannot carry even the
    masking IV plus a static header, so the decoder must reject before
    any unmask work runs.
    """
    networking_codec(
        codec_name="decode_failure",
        input={
            "decoder": "discv5_packet",
            "localNodeId": DEST_NODE_ID,
            "bytes": "0x" + "00" * 10,
        },
        expect_exception=ValueError,
    )


def test_discv5_packet_decode_rejects_wrong_protocol_id(
    networking_codec: NetworkingCodecTestFiller,
) -> None:
    """Decoding with the wrong local node id (unmask key) surfaces the protocol-id check.

    The masking key is derived from the local node id. Decoding with a
    different node id than the packet was encoded for produces garbage
    for the static header; the decoder rejects because the protocol id
    bytes no longer read as 'discv5'.
    """
    # 63 bytes all zero; after unmask with any key, the first 6 bytes
    # produce pseudo-random output that will not spell "discv5".
    networking_codec(
        codec_name="decode_failure",
        input={
            "decoder": "discv5_packet",
            "localNodeId": DEST_NODE_ID,
            "bytes": "0x" + "00" * 63,
        },
        expect_exception=ValueError,
    )
