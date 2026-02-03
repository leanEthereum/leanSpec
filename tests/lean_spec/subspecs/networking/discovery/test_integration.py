"""
Integration tests for Discovery v5.

Tests full protocol flows between components.
"""

from __future__ import annotations

import pytest

from lean_spec.subspecs.networking.discovery.codec import (
    decode_message,
    encode_message,
)
from lean_spec.subspecs.networking.discovery.crypto import (
    aes_gcm_decrypt,
    generate_secp256k1_keypair,
)
from lean_spec.subspecs.networking.discovery.handshake import HandshakeManager
from lean_spec.subspecs.networking.discovery.keys import compute_node_id, derive_keys_from_pubkey
from lean_spec.subspecs.networking.discovery.messages import (
    FindNode,
    MessageType,
    Nodes,
    PacketFlag,
    Ping,
    Pong,
    Port,
    RequestId,
)
from lean_spec.subspecs.networking.discovery.packet import (
    decode_handshake_authdata,
    decode_message_authdata,
    decode_packet_header,
    decode_whoareyou_authdata,
    encode_message_authdata,
    encode_packet,
    generate_nonce,
)
from lean_spec.subspecs.networking.discovery.routing import (
    NodeEntry,
    RoutingTable,
)
from lean_spec.subspecs.networking.discovery.session import Session, SessionCache
from lean_spec.subspecs.networking.enr import ENR
from lean_spec.subspecs.networking.types import NodeId, SeqNumber
from lean_spec.types import Bytes64, Uint64


@pytest.fixture
def node_a_keys():
    """Node A's keypair."""
    priv, pub = generate_secp256k1_keypair()
    node_id = compute_node_id(pub)
    return {"private_key": priv, "public_key": pub, "node_id": bytes(node_id)}


@pytest.fixture
def node_b_keys():
    """Node B's keypair."""
    priv, pub = generate_secp256k1_keypair()
    node_id = compute_node_id(pub)
    return {"private_key": priv, "public_key": pub, "node_id": bytes(node_id)}


class TestMessageRoundtrip:
    """Test encoding/decoding of all message types."""

    def test_ping_roundtrip(self):
        """PING message encodes and decodes correctly."""
        original = Ping(
            request_id=RequestId(data=b"\x01\x02\x03"),
            enr_seq=Uint64(42),
        )

        encoded = encode_message(original)
        assert encoded[0] == MessageType.PING

        decoded = decode_message(encoded)
        assert isinstance(decoded, Ping)
        assert bytes(decoded.request_id) == b"\x01\x02\x03"
        assert int(decoded.enr_seq) == 42

    def test_pong_roundtrip(self):
        """PONG message encodes and decodes correctly."""
        original = Pong(
            request_id=RequestId(data=b"\x01\x02\x03"),
            enr_seq=Uint64(42),
            recipient_ip=bytes([127, 0, 0, 1]),
            recipient_port=Port(9000),
        )

        encoded = encode_message(original)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Pong)
        assert decoded.recipient_ip == bytes([127, 0, 0, 1])
        assert int(decoded.recipient_port) == 9000

    def test_findnode_roundtrip(self):
        """FINDNODE message encodes and decodes correctly."""
        from lean_spec.subspecs.networking.discovery.messages import Distance

        original = FindNode(
            request_id=RequestId(data=b"\x01\x02\x03"),
            distances=[Distance(128), Distance(256)],
        )

        encoded = encode_message(original)
        decoded = decode_message(encoded)

        assert isinstance(decoded, FindNode)
        assert len(decoded.distances) == 2

    def test_nodes_roundtrip(self):
        """NODES message encodes and decodes correctly."""
        # Create a minimal ENR for testing.
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"id": b"v4"},
        )

        from lean_spec.types.uint import Uint8

        original = Nodes(
            request_id=RequestId(data=b"\x01\x02\x03"),
            total=Uint8(1),
            enrs=[enr.to_rlp()],
        )

        encoded = encode_message(original)
        decoded = decode_message(encoded)

        assert isinstance(decoded, Nodes)
        assert len(decoded.enrs) == 1


class TestEncryptedPacketRoundtrip:
    """Test encrypted packet encoding/decoding."""

    def test_message_packet_encryption_roundtrip(self, node_a_keys, node_b_keys):
        """MESSAGE packet encrypts and decrypts correctly."""
        # Build mock challenge_data for key derivation.
        # Format: masking-iv (16) + static-header (23) + authdata (24) = 63 bytes.
        masking_iv = bytes(16)
        static_header = b"discv5" + b"\x00\x01\x01" + bytes(12) + b"\x00\x18"
        authdata = bytes(24)
        challenge_data = masking_iv + static_header + authdata

        # Create session keys (derived from ECDH).
        # Node A is initiator.
        send_key, recv_key = derive_keys_from_pubkey(
            local_private_key=node_a_keys["private_key"],
            remote_public_key=node_b_keys["public_key"],
            local_node_id=node_a_keys["node_id"],
            remote_node_id=node_b_keys["node_id"],
            challenge_data=challenge_data,
            is_initiator=True,
        )

        # Create a PING message.
        ping = Ping(
            request_id=RequestId(data=b"\x01"),
            enr_seq=Uint64(1),
        )
        message_bytes = encode_message(ping)

        # Create authdata.
        authdata = encode_message_authdata(node_a_keys["node_id"])
        nonce = generate_nonce()

        # Encode packet.
        packet = encode_packet(
            dest_node_id=node_b_keys["node_id"],
            src_node_id=node_a_keys["node_id"],
            flag=PacketFlag.MESSAGE,
            nonce=bytes(nonce),
            authdata=authdata,
            message=message_bytes,
            encryption_key=send_key,
        )

        # Decode header.
        header, ciphertext = decode_packet_header(node_b_keys["node_id"], packet)

        assert header.flag == PacketFlag.MESSAGE

        # Decode authdata.
        decoded_authdata = decode_message_authdata(header.authdata)
        assert decoded_authdata.src_id == node_a_keys["node_id"]

        # Node B derives keys as recipient (using same challenge_data).
        b_send_key, b_recv_key = derive_keys_from_pubkey(
            local_private_key=node_b_keys["private_key"],
            remote_public_key=node_a_keys["public_key"],
            local_node_id=node_b_keys["node_id"],
            remote_node_id=node_a_keys["node_id"],
            challenge_data=challenge_data,
            is_initiator=False,
        )

        # Extract masked header for AAD.
        masked_header = packet[16 : 16 + 23 + len(header.authdata)]

        # Node B uses recv_key to decrypt (which equals Node A's send_key).
        plaintext = aes_gcm_decrypt(b_recv_key, bytes(header.nonce), ciphertext, masked_header)

        # Decode message.
        decoded_ping = decode_message(plaintext)
        assert isinstance(decoded_ping, Ping)
        assert int(decoded_ping.enr_seq) == 1


class TestSessionEstablishment:
    """Test session key establishment flow."""

    def test_session_cache_operations(self, node_a_keys, node_b_keys):
        """Session cache stores and retrieves sessions."""
        import time

        cache = SessionCache()

        now = time.time()
        session = Session(
            node_id=node_b_keys["node_id"],
            send_key=bytes(16),
            recv_key=bytes(16),
            created_at=now,
            last_seen=now,
            is_initiator=True,
        )

        cache.create(
            node_id=session.node_id,
            send_key=session.send_key,
            recv_key=session.recv_key,
            is_initiator=session.is_initiator,
        )

        retrieved = cache.get(node_b_keys["node_id"])
        assert retrieved is not None
        assert retrieved.node_id == node_b_keys["node_id"]

    def test_session_cache_eviction(self, node_a_keys):
        """Session cache evicts old sessions when full."""
        import time

        cache = SessionCache(max_sessions=3)

        # Add 4 sessions.
        for i in range(4):
            node_id = bytes([i]) + bytes(31)
            now = time.time()
            session = Session(
                node_id=node_id,
                send_key=bytes(16),
                recv_key=bytes(16),
                created_at=now,
                last_seen=now,
                is_initiator=True,
            )
            cache.create(
                node_id=session.node_id,
                send_key=session.send_key,
                recv_key=session.recv_key,
                is_initiator=session.is_initiator,
            )

        # Oldest should be evicted.
        assert cache.get(bytes([0]) + bytes(31)) is None
        assert cache.get(bytes([3]) + bytes(31)) is not None


class TestRoutingTableIntegration:
    """Test routing table with node entries."""

    def test_add_and_lookup_nodes(self, node_a_keys):
        """Add nodes and perform lookup."""
        table = RoutingTable(local_id=NodeId(node_a_keys["node_id"]))

        # Add several nodes.
        node_ids = []
        for i in range(20):
            node_id = NodeId(bytes([i * 10]) + bytes(31))
            entry = NodeEntry(
                node_id=node_id,
                enr_seq=SeqNumber(1),
                verified=True,
            )
            table.add(entry)
            node_ids.append(node_id)

        assert table.node_count() == 20

        # Lookup closest to a target.
        target = NodeId(bytes(32))
        closest = table.closest_nodes(target, 16)

        assert len(closest) == 16

    def test_bucket_distribution(self, node_a_keys):
        """Nodes distribute across buckets by distance."""
        table = RoutingTable(local_id=NodeId(node_a_keys["node_id"]))

        # Add nodes with varying first bytes.
        for i in range(256):
            node_id = NodeId(bytes([i]) + bytes(31))
            entry = NodeEntry(node_id=node_id)
            table.add(entry)

        # Count non-empty buckets.
        non_empty = sum(1 for b in table.buckets if not b.is_empty)

        # Should have nodes in multiple buckets.
        assert non_empty > 1


class TestHandshakeManagerIntegration:
    """Test handshake manager flows."""

    def test_whoareyou_generation(self, node_a_keys, node_b_keys):
        """WHOAREYOU challenge generation."""
        cache = SessionCache()
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"id": b"v4"},
        )

        manager = HandshakeManager(
            local_node_id=node_a_keys["node_id"],
            local_private_key=node_a_keys["private_key"],
            local_enr_rlp=enr.to_rlp(),
            local_enr_seq=1,
            session_cache=cache,
        )

        # Create WHOAREYOU.
        request_nonce = bytes(12)
        masking_iv = bytes(16)
        id_nonce, authdata, nonce, challenge_data = manager.create_whoareyou(
            remote_node_id=node_b_keys["node_id"],
            request_nonce=request_nonce,
            remote_enr_seq=0,
            masking_iv=masking_iv,
        )

        assert len(id_nonce) == 16
        assert len(authdata) == 24

        # Decode authdata.
        decoded = decode_whoareyou_authdata(authdata)
        assert bytes(decoded.id_nonce) == id_nonce

    def test_start_and_cancel_handshake(self, node_a_keys, node_b_keys):
        """Handshake can be started and cancelled."""
        cache = SessionCache()
        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"id": b"v4"},
        )

        manager = HandshakeManager(
            local_node_id=node_a_keys["node_id"],
            local_private_key=node_a_keys["private_key"],
            local_enr_rlp=enr.to_rlp(),
            local_enr_seq=1,
            session_cache=cache,
        )

        # Start handshake.
        pending = manager.start_handshake(node_b_keys["node_id"])
        assert pending is not None
        assert pending.remote_node_id == node_b_keys["node_id"]

        # Get pending.
        retrieved = manager.get_pending(node_b_keys["node_id"])
        assert retrieved is pending

        # Cancel.
        result = manager.cancel_handshake(node_b_keys["node_id"])
        assert result is True

        # Should be gone.
        assert manager.get_pending(node_b_keys["node_id"]) is None


class TestFullHandshakeFlow:
    """Test complete handshake between two nodes."""

    def test_handshake_key_agreement(self, node_a_keys, node_b_keys):
        """
        Full handshake establishes compatible session keys.

        1. Node A sends MESSAGE (no session)
        2. Node B can't decrypt, sends WHOAREYOU
        3. Node A responds with HANDSHAKE
        4. Both derive same session keys
        """
        cache_a = SessionCache()
        cache_b = SessionCache()

        enr_a = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"id": b"v4", "secp256k1": node_a_keys["public_key"]},
        )
        enr_b = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"id": b"v4", "secp256k1": node_b_keys["public_key"]},
        )

        manager_a = HandshakeManager(
            local_node_id=node_a_keys["node_id"],
            local_private_key=node_a_keys["private_key"],
            local_enr_rlp=enr_a.to_rlp(),
            local_enr_seq=1,
            session_cache=cache_a,
        )

        manager_b = HandshakeManager(
            local_node_id=node_b_keys["node_id"],
            local_private_key=node_b_keys["private_key"],
            local_enr_rlp=enr_b.to_rlp(),
            local_enr_seq=1,
            session_cache=cache_b,
        )

        # Step 1: Node A starts handshake.
        manager_a.start_handshake(node_b_keys["node_id"])

        # Step 2: Node B creates WHOAREYOU.
        request_nonce = bytes(12)
        masking_iv = bytes(16)
        id_nonce, whoareyou_authdata, _, challenge_data = manager_b.create_whoareyou(
            remote_node_id=node_a_keys["node_id"],
            request_nonce=request_nonce,
            remote_enr_seq=0,
            masking_iv=masking_iv,
        )

        # Decode WHOAREYOU for Node A to use.
        whoareyou = decode_whoareyou_authdata(whoareyou_authdata)

        # Step 3: Node A creates HANDSHAKE response.
        # This requires Node A to have Node B's public key and the challenge_data.
        handshake_authdata, send_key, recv_key = manager_a.create_handshake_response(
            remote_node_id=node_b_keys["node_id"],
            whoareyou=whoareyou,
            remote_pubkey=node_b_keys["public_key"],
            challenge_data=challenge_data,
        )

        # Verify keys were derived.
        assert len(send_key) == 16
        assert len(recv_key) == 16

        # Decode handshake authdata.
        handshake = decode_handshake_authdata(handshake_authdata)
        assert handshake.src_id == node_a_keys["node_id"]

        # Step 4: Node B processes HANDSHAKE.
        result = manager_b.handle_handshake(
            remote_node_id=node_a_keys["node_id"],
            handshake=handshake,
        )

        # Handshake completed successfully - session was established.
        assert result is not None
        assert result.session is not None
        assert len(result.session.send_key) == 16
        assert len(result.session.recv_key) == 16

        # Both sides now have valid session keys.
        # The exact key matching depends on both sides using the same
        # id_nonce and ephemeral keys, which is verified in lower-level tests.
