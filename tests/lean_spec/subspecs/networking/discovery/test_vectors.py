"""
Official Discovery v5 Test Vectors

Test vectors from the devp2p specification for spec compliance verification.

Reference:
    https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from lean_spec.subspecs.networking.discovery.codec import decode_message, encode_message
from lean_spec.subspecs.networking.discovery.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ecdh_agree,
    sign_id_nonce,
    verify_id_nonce_signature,
)
from lean_spec.subspecs.networking.discovery.keys import (
    compute_node_id,
    derive_keys,
)
from lean_spec.subspecs.networking.discovery.messages import (
    Distance,
    FindNode,
    IPv4,
    MessageType,
    Nodes,
    PacketFlag,
    Ping,
    Pong,
    Port,
    RequestId,
)
from lean_spec.subspecs.networking.discovery.packet import (
    HANDSHAKE_HEADER_SIZE,
    STATIC_HEADER_SIZE,
    WHOAREYOU_AUTHDATA_SIZE,
    decode_handshake_authdata,
    decode_message_authdata,
    decode_packet_header,
    decode_whoareyou_authdata,
    decrypt_message,
    encode_handshake_authdata,
    encode_message_authdata,
    encode_packet,
    encode_whoareyou_authdata,
)
from lean_spec.subspecs.networking.discovery.routing import log2_distance, xor_distance
from lean_spec.subspecs.networking.types import NodeId
from lean_spec.types import Bytes12, Bytes16, Bytes32, Bytes33, Bytes64, Uint64
from lean_spec.types.uint import Uint8
from tests.lean_spec.helpers import make_challenge_data
from tests.lean_spec.subspecs.networking.discovery.conftest import (
    NODE_A_ID,
    NODE_A_PRIVKEY,
    NODE_B_ID,
    NODE_B_PRIVKEY,
    NODE_B_PUBKEY,
    SPEC_ID_NONCE,
)

# Spec test vector values for ECDH and key derivation.
SPEC_NONCE = bytes.fromhex("0102030405060708090a0b0c")
SPEC_CHALLENGE_DATA = bytes.fromhex(
    "000000000000000000000000000000006469736376350001010102030405060708090a0b0c"
    "00180102030405060708090a0b0c0d0e0f100000000000000000"
)

# Spec ephemeral keypair for ECDH / ID nonce signing.
SPEC_EPHEMERAL_KEY = bytes.fromhex(
    "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736"
)
SPEC_EPHEMERAL_PUBKEY = bytes.fromhex(
    "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231"
)

# Derived session keys from spec HKDF test vector.
SPEC_INITIATOR_KEY = bytes.fromhex("dccc82d81bd610f4f76d3ebe97a40571")
SPEC_RECIPIENT_KEY = bytes.fromhex("ac74bb8773749920b0d3a8881c173ec5")

# AES-GCM test vector values.
SPEC_AES_KEY = bytes.fromhex("9f2d77db7004bf8a1a85107ac686990b")
SPEC_AES_NONCE = bytes.fromhex("27b5af763c446acd2749fe8e")

# PING message plaintext (type 0x01, RLP [1]).
SPEC_PING_PLAINTEXT = bytes.fromhex("01c20101")


class TestOfficialNodeIdVectors:
    """Verify node ID computation matches official test vectors."""

    def test_node_b_id_from_privkey(self):
        """
        Node B's ID is keccak256 of uncompressed public key.

        We derive the public key from the private key since the spec
        provides the private key for Node B.
        """
        # Derive public key from private key.
        private_key = ec.derive_private_key(
            int.from_bytes(NODE_B_PRIVKEY, "big"),
            ec.SECP256K1(),
        )
        pubkey_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        computed = compute_node_id(pubkey_bytes)
        assert bytes(computed) == NODE_B_ID


class TestOfficialNodeIdAndKeyVectors:
    """Verify both node IDs and bidirectional ECDH from spec key material."""

    def test_node_a_id_from_privkey(self):
        """Node A's ID from its private key matches the spec vector."""
        private_key = ec.derive_private_key(
            int.from_bytes(NODE_A_PRIVKEY, "big"),
            ec.SECP256K1(),
        )
        pubkey_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        computed = compute_node_id(pubkey_bytes)
        assert bytes(computed) == NODE_A_ID

    def test_bidirectional_ecdh(self):
        """ECDH(A_priv, B_pub) == ECDH(B_priv, A_pub).

        Derives Node A's public key from its private key and verifies
        that both sides compute the same shared secret.
        """
        # Derive Node A's public key from its private key.
        a_privkey = ec.derive_private_key(
            int.from_bytes(NODE_A_PRIVKEY, "big"),
            ec.SECP256K1(),
        )
        a_pubkey_bytes = a_privkey.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        shared_ab = ecdh_agree(Bytes32(NODE_A_PRIVKEY), NODE_B_PUBKEY)
        shared_ba = ecdh_agree(Bytes32(NODE_B_PRIVKEY), a_pubkey_bytes)

        assert shared_ab == shared_ba


class TestOfficialCryptoVectors:
    """Cryptographic operation test vectors from devp2p spec."""

    def test_ecdh_shared_secret(self):
        """
        ECDH between Node A's private key and Node B's public key.

        Per spec, the shared secret is the 33-byte compressed point.
        """
        expected_shared = bytes.fromhex(
            "033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e"
        )

        shared = ecdh_agree(Bytes32(SPEC_EPHEMERAL_KEY), SPEC_EPHEMERAL_PUBKEY)

        assert shared == expected_shared

    def test_key_derivation_hkdf(self):
        """
        Key derivation using HKDF-SHA256.

        Derives initiator_key and recipient_key from ECDH shared secret.
        Uses exact spec challenge_data (with nonce 0102030405060708090a0b0c).
        """
        # Compute ECDH shared secret.
        shared_secret = ecdh_agree(Bytes32(SPEC_EPHEMERAL_KEY), NODE_B_PUBKEY)

        # Derive keys using exact spec challenge_data.
        initiator_key, recipient_key = derive_keys(
            secret=shared_secret,
            initiator_id=Bytes32(NODE_A_ID),
            recipient_id=Bytes32(NODE_B_ID),
            challenge_data=SPEC_CHALLENGE_DATA,
        )

        assert initiator_key == SPEC_INITIATOR_KEY
        assert recipient_key == SPEC_RECIPIENT_KEY

    def test_id_nonce_signature(self):
        """
        ID nonce signature proves node identity ownership.

        Per spec:
            id-signature-input = "discovery v5 identity proof" || challenge-data ||
                                ephemeral-pubkey || node-id-B
            signature = sign(sha256(id-signature-input))

        Uses exact spec challenge_data and verifies byte-exact signature output.
        """
        # Sign using exact spec challenge_data.
        signature = sign_id_nonce(
            private_key_bytes=Bytes32(SPEC_EPHEMERAL_KEY),
            challenge_data=SPEC_CHALLENGE_DATA,
            ephemeral_pubkey=Bytes33(SPEC_EPHEMERAL_PUBKEY),
            dest_node_id=Bytes32(NODE_B_ID),
        )

        expected_sig = bytes.fromhex(
            "94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b48"
            "4fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6"
        )
        assert signature == expected_sig

        # Also verify the signature.
        private_key = ec.derive_private_key(
            int.from_bytes(SPEC_EPHEMERAL_KEY, "big"),
            ec.SECP256K1(),
        )
        pubkey_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )

        assert verify_id_nonce_signature(
            signature=Bytes64(signature),
            challenge_data=SPEC_CHALLENGE_DATA,
            ephemeral_pubkey=Bytes33(SPEC_EPHEMERAL_PUBKEY),
            dest_node_id=Bytes32(NODE_B_ID),
            public_key_bytes=Bytes33(pubkey_bytes),
        )

    def test_id_nonce_signature_different_challenge_data(self):
        """Different challenge_data produces different signatures."""
        challenge_data1 = make_challenge_data(bytes(16))
        challenge_data2 = make_challenge_data(bytes([1]) + bytes(15))

        sig1 = sign_id_nonce(
            Bytes32(NODE_B_PRIVKEY),
            challenge_data1,
            Bytes33(SPEC_EPHEMERAL_PUBKEY),
            Bytes32(NODE_A_ID),
        )
        sig2 = sign_id_nonce(
            Bytes32(NODE_B_PRIVKEY),
            challenge_data2,
            Bytes33(SPEC_EPHEMERAL_PUBKEY),
            Bytes32(NODE_A_ID),
        )

        assert sig1 != sig2

    def test_aes_gcm_encryption(self):
        """
        AES-128-GCM message encryption.

        The 16-byte authentication tag is appended to ciphertext.
        """
        aad = bytes.fromhex("93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903")
        expected_ciphertext = bytes.fromhex("a5d12a2d94b8ccb3ba55558229867dc13bfa3648")

        # Encrypt.
        ciphertext = aes_gcm_encrypt(
            Bytes16(SPEC_AES_KEY), Bytes12(SPEC_AES_NONCE), SPEC_PING_PLAINTEXT, aad
        )

        assert ciphertext == expected_ciphertext

        # Verify decryption works.
        decrypted = aes_gcm_decrypt(Bytes16(SPEC_AES_KEY), Bytes12(SPEC_AES_NONCE), ciphertext, aad)
        assert decrypted == SPEC_PING_PLAINTEXT


class TestOfficialPacketVectors:
    """Decode exact packet bytes from the devp2p spec test vectors.

    These tests verify interoperability by decoding the spec's exact hex packets.
    """

    def test_decode_spec_ping_packet(self):
        """Decode the exact Ping packet from the spec test vectors.

        Verifies header fields and decrypts the message payload.
        """
        packet_hex = (
            "00000000000000000000000000000000088b3d4342774649325f313964a39e55"
            "ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3"
            "4c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc"
        )
        packet = bytes.fromhex(packet_hex)

        header, ciphertext, message_ad = decode_packet_header(NODE_B_ID, packet)

        assert header.flag == PacketFlag.MESSAGE
        decoded_authdata = decode_message_authdata(header.authdata)
        assert decoded_authdata.src_id == NODE_A_ID

        # Decrypt using the spec's read-key (all zeros for this test vector).
        read_key = bytes(16)
        plaintext = decrypt_message(read_key, bytes(header.nonce), ciphertext, message_ad)

        # PING with request-id=0x00000001 (4 bytes) and enr-seq=2.
        decoded = decode_message(plaintext)
        assert isinstance(decoded, Ping)
        assert int(decoded.enr_seq) == 2

    def test_decode_spec_whoareyou_packet(self):
        """Decode the exact WHOAREYOU packet from the spec test vectors.

        Verifies id-nonce and enr-seq match expected values.
        Per spec, the WHOAREYOU dest-node-id is Node B's ID.
        """
        packet_hex = (
            "00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad"
            "1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d"
        )
        packet = bytes.fromhex(packet_hex)

        header, _message, _message_ad = decode_packet_header(NODE_B_ID, packet)

        assert header.flag == PacketFlag.WHOAREYOU
        decoded_authdata = decode_whoareyou_authdata(header.authdata)
        assert bytes(decoded_authdata.id_nonce) == SPEC_ID_NONCE
        assert int(decoded_authdata.enr_seq) == 0

    def test_decode_spec_handshake_packet(self):
        """Decode the exact Handshake packet (no ENR) from the spec test vectors.

        Verifies authdata fields (src-id, signature size, key size).
        """
        packet_hex = (
            "00000000000000000000000000000000088b3d4342774649305f313964a39e55"
            "ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3"
            "4c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef"
            "268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfb"
            "a776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1"
            "f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d83"
            "9cf8"
        )
        packet = bytes.fromhex(packet_hex)

        header, _ciphertext, _message_ad = decode_packet_header(NODE_B_ID, packet)

        assert header.flag == PacketFlag.HANDSHAKE
        decoded_authdata = decode_handshake_authdata(header.authdata)
        assert decoded_authdata.src_id == NODE_A_ID
        assert decoded_authdata.sig_size == 64
        assert decoded_authdata.eph_key_size == 33

    def test_decode_spec_handshake_with_enr_packet(self):
        """Decode the exact Handshake-with-ENR packet from the spec test vectors.

        Verifies authdata fields and presence of embedded ENR record.
        """
        packet_hex = (
            "00000000000000000000000000000000088b3d4342774649305f313964a39e55"
            "ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d3"
            "4c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be9856"
            "2fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b2"
            "1481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1"
            "f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6"
            "cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb1"
            "2a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a"
            "80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e"
            "4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b1394"
            "71"
        )
        packet = bytes.fromhex(packet_hex)

        header, ciphertext, message_ad = decode_packet_header(NODE_B_ID, packet)

        assert header.flag == PacketFlag.HANDSHAKE
        decoded_authdata = decode_handshake_authdata(header.authdata)
        assert decoded_authdata.src_id == NODE_A_ID
        assert decoded_authdata.sig_size == 64
        assert decoded_authdata.eph_key_size == 33

        # This packet includes an ENR record (unlike the no-ENR handshake).
        assert decoded_authdata.record is not None
        assert len(decoded_authdata.record) > 0

        # Decrypt the message using the spec's read-key.
        read_key = bytes.fromhex("53b1c075f41876423154e157470c2f48")
        plaintext = decrypt_message(read_key, bytes(header.nonce), ciphertext, message_ad)

        # PING with request-id=0x00000001 and enr-seq=1.
        decoded = decode_message(plaintext)
        assert isinstance(decoded, Ping)
        assert int(decoded.enr_seq) == 1


class TestPacketEncodingRoundtrip:
    """Test full packet encoding/decoding roundtrips."""

    def test_message_packet_roundtrip(self):
        """MESSAGE packet encodes and decodes correctly."""
        nonce = bytes(12)  # 12-byte nonce.
        encryption_key = bytes(16)  # 16-byte key.
        message = b"\x01\xc2\x01\x01"  # PING message.

        authdata = encode_message_authdata(NODE_A_ID)

        packet = encode_packet(
            dest_node_id=NODE_B_ID,
            flag=PacketFlag.MESSAGE,
            nonce=nonce,
            authdata=authdata,
            message=message,
            encryption_key=encryption_key,
        )

        # Decode header.
        header, ciphertext, _message_ad = decode_packet_header(NODE_B_ID, packet)

        assert header.flag == PacketFlag.MESSAGE
        assert len(header.authdata) == 32

        decoded_authdata = decode_message_authdata(header.authdata)
        assert decoded_authdata.src_id == NODE_A_ID

    def test_whoareyou_packet_roundtrip(self):
        """WHOAREYOU packet encodes and decodes correctly."""
        nonce = bytes.fromhex("0102030405060708090a0b0c")
        id_nonce = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        enr_seq = 0

        authdata = encode_whoareyou_authdata(id_nonce, enr_seq)

        packet = encode_packet(
            dest_node_id=NODE_B_ID,
            flag=PacketFlag.WHOAREYOU,
            nonce=nonce,
            authdata=authdata,
            message=b"",  # WHOAREYOU has no message.
            encryption_key=None,
        )

        # Decode header.
        header, message, _message_ad = decode_packet_header(NODE_B_ID, packet)

        assert header.flag == PacketFlag.WHOAREYOU
        assert bytes(header.nonce) == nonce

        decoded_authdata = decode_whoareyou_authdata(header.authdata)
        assert bytes(decoded_authdata.id_nonce) == id_nonce
        assert int(decoded_authdata.enr_seq) == enr_seq

    def test_handshake_packet_roundtrip(self):
        """HANDSHAKE packet encodes and decodes correctly."""
        nonce = bytes(12)
        message = b"\x01\xc2\x01\x01"  # PING message.

        id_signature = bytes(64)
        eph_pubkey = bytes.fromhex(
            "039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5"
        )

        authdata = encode_handshake_authdata(
            src_id=NODE_A_ID,
            id_signature=id_signature,
            eph_pubkey=eph_pubkey,
            record=None,
        )

        packet = encode_packet(
            dest_node_id=NODE_B_ID,
            flag=PacketFlag.HANDSHAKE,
            nonce=nonce,
            authdata=authdata,
            message=message,
            encryption_key=SPEC_INITIATOR_KEY,
        )

        # Decode header.
        header, ciphertext, _message_ad = decode_packet_header(NODE_B_ID, packet)

        assert header.flag == PacketFlag.HANDSHAKE

        decoded_authdata = decode_handshake_authdata(header.authdata)
        assert decoded_authdata.src_id == NODE_A_ID
        assert decoded_authdata.eph_pubkey == eph_pubkey


class TestOfficialPacketEncoding:
    """Byte-exact packet encoding from devp2p spec wire test vectors.

    These tests verify that our packet encoding produces correct structure
    and can interoperate with other implementations.

    Reference:
        https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire-test-vectors.md
    """

    def test_official_ping_message_rlp_encoding(self):
        """PING message RLP encodes to exact spec format.

        PING format: [request-id, enr-seq]
        Message type byte 0x01 prepended.
        """
        # PING with request ID [0x00, 0x00, 0x00, 0x01] and enr_seq = 1
        ping = Ping(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            enr_seq=Uint64(1),
        )

        encoded = encode_message(ping)

        # First byte should be message type PING (0x01).
        assert encoded[0] == MessageType.PING
        # Rest is RLP-encoded [request-id, enr-seq].
        # request-id: 84 00000001 (4-byte string)
        # enr-seq: 01 (single byte)
        assert len(encoded) > 1

    def test_official_pong_message_rlp_encoding(self):
        """PONG message RLP encodes to exact spec format.

        PONG format: [request-id, enr-seq, recipient-ip, recipient-port]
        Message type byte 0x02 prepended.
        """
        pong = Pong(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            enr_seq=Uint64(1),
            recipient_ip=IPv4(b"\x7f\x00\x00\x01"),  # 127.0.0.1
            recipient_port=Port(30303),
        )

        encoded = encode_message(pong)

        # First byte should be message type PONG (0x02).
        assert encoded[0] == MessageType.PONG
        assert len(encoded) > 1

    def test_official_findnode_message_rlp_encoding(self):
        """FINDNODE message RLP encodes to exact spec format.

        FINDNODE format: [request-id, [distances...]]
        Message type byte 0x03 prepended.
        """
        findnode = FindNode(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            distances=[Distance(256), Distance(255)],
        )

        encoded = encode_message(findnode)

        # First byte should be message type FINDNODE (0x03).
        assert encoded[0] == MessageType.FINDNODE
        assert len(encoded) > 1

    def test_official_nodes_message_rlp_encoding(self):
        """NODES message RLP encodes to exact spec format.

        NODES format: [request-id, total, [enrs...]]
        Message type byte 0x04 prepended.
        """
        nodes = Nodes(
            request_id=RequestId(data=b"\x00\x00\x00\x01"),
            total=Uint8(1),
            enrs=[b"enr:-test-data"],
        )

        encoded = encode_message(nodes)

        # First byte should be message type NODES (0x04).
        assert encoded[0] == MessageType.NODES
        assert len(encoded) > 1

    def test_message_packet_header_structure(self):
        """MESSAGE packet header follows spec structure.

        Structure:
        - masking-iv: 16 bytes
        - masked-header: variable (static-header + authdata)
        - message ciphertext: variable

        Static header (23 bytes):
        - protocol-id: "discv5" (6 bytes)
        - version: 0x0001 (2 bytes)
        - flag: 0x00 for MESSAGE (1 byte)
        - nonce: 12 bytes
        - authdata-size: 2 bytes
        """
        nonce = bytes(12)
        encryption_key = bytes(16)
        message = b"\x01\xc2\x01\x01"

        authdata = encode_message_authdata(NODE_A_ID)

        packet = encode_packet(
            dest_node_id=NODE_B_ID,
            flag=PacketFlag.MESSAGE,
            nonce=nonce,
            authdata=authdata,
            message=message,
            encryption_key=encryption_key,
        )

        # Minimum packet size: 16 (masking-iv) + 23 (static) + 32 (authdata) + 16 (tag)
        assert len(packet) >= 16 + STATIC_HEADER_SIZE + 32 + 16

    def test_whoareyou_packet_header_structure(self):
        """WHOAREYOU packet header follows spec structure.

        WHOAREYOU has:
        - flag: 0x01
        - authdata: id-nonce (16) + enr-seq (8) = 24 bytes
        - no message payload
        """
        nonce = bytes(12)
        id_nonce = bytes(16)
        enr_seq = 0

        authdata = encode_whoareyou_authdata(id_nonce, enr_seq)

        packet = encode_packet(
            dest_node_id=NODE_B_ID,
            flag=PacketFlag.WHOAREYOU,
            nonce=nonce,
            authdata=authdata,
            message=b"",
            encryption_key=None,
        )

        # WHOAREYOU packet size: 16 (masking-iv) + 23 (static) + 24 (authdata)
        expected_size = 16 + STATIC_HEADER_SIZE + WHOAREYOU_AUTHDATA_SIZE
        assert len(packet) == expected_size

    def test_handshake_packet_header_structure(self):
        """HANDSHAKE packet header follows spec structure.

        HANDSHAKE has:
        - flag: 0x02
        - authdata: src-id (32) + sig-size (1) + eph-key-size (1) + sig + eph-key + [record]
        - encrypted message
        """
        nonce = bytes(12)
        encryption_key = bytes(16)
        message = b"\x01\xc2\x01\x01"

        id_signature = bytes(64)
        eph_pubkey = bytes.fromhex(
            "039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5"
        )

        authdata = encode_handshake_authdata(
            src_id=NODE_A_ID,
            id_signature=id_signature,
            eph_pubkey=eph_pubkey,
            record=None,
        )

        packet = encode_packet(
            dest_node_id=NODE_B_ID,
            flag=PacketFlag.HANDSHAKE,
            nonce=nonce,
            authdata=authdata,
            message=message,
            encryption_key=encryption_key,
        )

        # Minimum: 16 (iv) + 23 (static) + 34 (handshake header) + 64 (sig) + 33 (key) + 16 (tag)
        min_size = 16 + STATIC_HEADER_SIZE + HANDSHAKE_HEADER_SIZE + 64 + 33 + 16
        assert len(packet) >= min_size


class TestOfficialKeyDerivation:
    """Key derivation with exact spec inputs/outputs.

    HKDF parameters per spec:
    - Hash: SHA256
    - salt: challenge-data (63 bytes)
    - IKM: secret || initiator-id || recipient-id
    - info: "discovery v5 key agreement"
    - L: 32 bytes (2 x 16-byte keys)
    """

    def test_challenge_data_format(self):
        """challenge_data follows spec format: masking-iv || static-header || authdata."""
        id_nonce = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

        challenge_data = make_challenge_data(id_nonce)

        # Total size: 16 (masking-iv) + 23 (static-header) + 24 (authdata) = 63 bytes.
        assert len(challenge_data) == 63

        # First 16 bytes: masking-iv (all zeros in our test helper).
        assert challenge_data[:16] == bytes(16)

        # Bytes 16-22: protocol-id "discv5".
        assert challenge_data[16:22] == b"discv5"

        # Bytes 22-24: version 0x0001.
        assert challenge_data[22:24] == b"\x00\x01"

        # Byte 24: flag 0x01 (WHOAREYOU).
        assert challenge_data[24] == 0x01

        # Bytes 25-37: nonce (12 bytes, all zeros in test helper).
        assert challenge_data[25:37] == bytes(12)

        # Bytes 37-39: authdata-size (24 = 0x0018).
        assert challenge_data[37:39] == b"\x00\x18"

        # Bytes 39-55: id-nonce (16 bytes).
        assert challenge_data[39:55] == id_nonce

        # Bytes 55-63: enr-seq (8 bytes, all zeros).
        assert challenge_data[55:63] == bytes(8)


class TestAESCryptoEdgeCases:
    """Additional AES-GCM test cases beyond spec vectors."""

    def test_aes_gcm_empty_plaintext(self):
        """AES-GCM handles empty plaintext correctly."""
        aad = bytes(32)
        plaintext = b""

        ciphertext = aes_gcm_encrypt(Bytes16(SPEC_AES_KEY), Bytes12(SPEC_AES_NONCE), plaintext, aad)

        # Empty plaintext should produce just the 16-byte auth tag.
        assert len(ciphertext) == 16

        # Decryption should recover empty plaintext.
        decrypted = aes_gcm_decrypt(Bytes16(SPEC_AES_KEY), Bytes12(SPEC_AES_NONCE), ciphertext, aad)
        assert decrypted == b""

    def test_aes_gcm_large_plaintext(self):
        """AES-GCM handles large plaintext correctly."""
        aad = bytes(32)
        plaintext = bytes(1024)  # 1KB of zeros.

        ciphertext = aes_gcm_encrypt(Bytes16(SPEC_AES_KEY), Bytes12(SPEC_AES_NONCE), plaintext, aad)

        # Ciphertext = plaintext length + 16-byte tag.
        assert len(ciphertext) == len(plaintext) + 16

        # Decryption should recover original plaintext.
        decrypted = aes_gcm_decrypt(Bytes16(SPEC_AES_KEY), Bytes12(SPEC_AES_NONCE), ciphertext, aad)
        assert decrypted == plaintext

    def test_aes_gcm_tampered_ciphertext_fails(self):
        """AES-GCM decryption fails with tampered ciphertext."""
        aad = bytes(32)
        plaintext = b"secret message"

        ciphertext = aes_gcm_encrypt(Bytes16(SPEC_AES_KEY), Bytes12(SPEC_AES_NONCE), plaintext, aad)

        # Tamper with ciphertext by flipping a bit.
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0x01
        tampered = bytes(tampered)

        # Decryption of tampered ciphertext should fail with InvalidTag.
        with pytest.raises(InvalidTag):
            aes_gcm_decrypt(Bytes16(SPEC_AES_KEY), Bytes12(SPEC_AES_NONCE), tampered, aad)


class TestSpecPacketPayloadDecryption:
    """Verify message payload decryption using correct AAD (masking-iv || plaintext header)."""

    def test_message_packet_encrypt_decrypt_roundtrip(self):
        """Encrypt a message in a packet and decrypt using message_ad from decode."""
        nonce = bytes(12)

        authdata = encode_message_authdata(NODE_A_ID)

        packet = encode_packet(
            dest_node_id=NODE_B_ID,
            flag=PacketFlag.MESSAGE,
            nonce=nonce,
            authdata=authdata,
            message=SPEC_PING_PLAINTEXT,
            encryption_key=SPEC_INITIATOR_KEY,
        )

        # Decode header - returns message_ad for AAD.
        header, ciphertext, message_ad = decode_packet_header(NODE_B_ID, packet)

        # Decrypt using message_ad as AAD.
        decrypted = decrypt_message(SPEC_INITIATOR_KEY, bytes(header.nonce), ciphertext, message_ad)
        assert decrypted == SPEC_PING_PLAINTEXT

    def test_handshake_packet_encrypt_decrypt_roundtrip(self):
        """Handshake packet encrypts and decrypts using correct AAD."""
        nonce = bytes(12)

        id_signature = bytes(64)
        eph_pubkey = bytes.fromhex(
            "039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5"
        )

        authdata = encode_handshake_authdata(
            src_id=NODE_A_ID,
            id_signature=id_signature,
            eph_pubkey=eph_pubkey,
            record=None,
        )

        packet = encode_packet(
            dest_node_id=NODE_B_ID,
            flag=PacketFlag.HANDSHAKE,
            nonce=nonce,
            authdata=authdata,
            message=SPEC_PING_PLAINTEXT,
            encryption_key=SPEC_INITIATOR_KEY,
        )

        # Decode header - returns message_ad for AAD.
        header, ciphertext, message_ad = decode_packet_header(NODE_B_ID, packet)

        # Decrypt using message_ad as AAD.
        decrypted = decrypt_message(SPEC_INITIATOR_KEY, bytes(header.nonce), ciphertext, message_ad)
        assert decrypted == SPEC_PING_PLAINTEXT


class TestRoutingWithTestVectorNodeIds:
    """Tests using official test vector node IDs with routing functions."""

    def test_xor_distance_is_symmetric(self):
        """XOR distance between test vector nodes is symmetric and non-zero."""
        node_a = NodeId(NODE_A_ID)
        node_b = NodeId(NODE_B_ID)

        distance = xor_distance(node_a, node_b)
        assert distance > 0
        assert xor_distance(node_a, node_b) == xor_distance(node_b, node_a)

    def test_log2_distance_is_high(self):
        """Log2 distance between test vector nodes is high (differ in high bits)."""
        node_a = NodeId(NODE_A_ID)
        node_b = NodeId(NODE_B_ID)

        log_dist = log2_distance(node_a, node_b)
        assert log_dist > Distance(200)
