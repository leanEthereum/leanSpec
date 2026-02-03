"""
Handshake state machine for Discovery v5.

The Discovery v5 handshake establishes shared session keys through ECDH.

Handshake Flow:
1. A sends MESSAGE to B (encrypted with old/no session)
2. B can't decrypt, sends WHOAREYOU with id-nonce challenge
3. A responds with HANDSHAKE containing:
   - Ephemeral public key for ECDH
   - Signature proving ownership of node ID
   - Optionally, A's ENR if B requested it
4. Both derive session keys from ECDH shared secret
5. Session established, further messages use derived keys

State Machine:
- IDLE: No handshake in progress
- SENT_ORDINARY: Sent MESSAGE, awaiting potential WHOAREYOU
- SENT_WHOAREYOU: Sent WHOAREYOU, awaiting HANDSHAKE
- COMPLETED: Handshake finished, session established

References:
- https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md#handshake
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from threading import Lock
from typing import TYPE_CHECKING

from .config import HANDSHAKE_TIMEOUT_SECS
from .crypto import (
    generate_secp256k1_keypair,
    sign_id_nonce,
    verify_id_nonce_signature,
)
from .keys import derive_keys_from_pubkey
from .packet import (
    HandshakeAuthdata,
    WhoAreYouAuthdata,
    encode_handshake_authdata,
    encode_whoareyou_authdata,
    generate_id_nonce,
)
from .session import Session, SessionCache

if TYPE_CHECKING:
    from lean_spec.subspecs.networking.enr import ENR


class HandshakeState(Enum):
    """Handshake state machine states."""

    IDLE = auto()
    """No handshake in progress."""

    SENT_ORDINARY = auto()
    """Sent an ordinary MESSAGE, awaiting potential WHOAREYOU."""

    SENT_WHOAREYOU = auto()
    """Sent WHOAREYOU challenge, awaiting HANDSHAKE response."""

    COMPLETED = auto()
    """Handshake completed, session established."""


@dataclass(slots=True)
class PendingHandshake:
    """Tracks an in-progress handshake with a peer."""

    state: HandshakeState
    """Current state of this handshake."""

    remote_node_id: bytes
    """32-byte node ID of the remote peer."""

    id_nonce: bytes | None = None
    """16-byte challenge nonce (set when WHOAREYOU sent/received)."""

    challenge_data: bytes | None = None
    """Full WHOAREYOU packet data for key derivation (masking-iv || static-header || authdata)."""

    ephemeral_privkey: bytes | None = None
    """32-byte ephemeral private key (set when we send HANDSHAKE)."""

    challenge_nonce: bytes | None = None
    """12-byte nonce from the packet that triggered WHOAREYOU."""

    remote_enr_seq: int = 0
    """ENR seq we sent in WHOAREYOU. If 0, remote MUST include their ENR in HANDSHAKE."""

    started_at: float = field(default_factory=time.time)
    """Timestamp when handshake started."""

    def is_expired(self, timeout_secs: float = HANDSHAKE_TIMEOUT_SECS) -> bool:
        """Check if handshake has timed out."""
        return time.time() - self.started_at > timeout_secs


@dataclass
class HandshakeResult:
    """Result of a completed handshake."""

    session: Session
    """Established session with derived keys."""

    remote_enr: bytes | None
    """Remote's ENR if included in handshake."""


class HandshakeError(Exception):
    """Error during handshake."""


class HandshakeManager:
    """
    Manages WHOAREYOU/HANDSHAKE exchanges.

    Thread-safe manager for concurrent handshakes with multiple peers.
    Integrates with SessionCache to store completed sessions.
    """

    def __init__(
        self,
        local_node_id: bytes,
        local_private_key: bytes,
        local_enr_rlp: bytes,
        local_enr_seq: int,
        session_cache: SessionCache,
        timeout_secs: float = HANDSHAKE_TIMEOUT_SECS,
    ):
        """
        Initialize the handshake manager.

        Args:
            local_node_id: Our 32-byte node ID.
            local_private_key: Our 32-byte secp256k1 private key.
            local_enr_rlp: Our RLP-encoded ENR.
            local_enr_seq: Our current ENR sequence number.
            session_cache: Session cache for storing completed sessions.
            timeout_secs: Handshake timeout.
        """
        if len(local_node_id) != 32:
            raise ValueError(f"Local node ID must be 32 bytes, got {len(local_node_id)}")
        if len(local_private_key) != 32:
            raise ValueError(f"Local private key must be 32 bytes, got {len(local_private_key)}")

        self._local_node_id = local_node_id
        self._local_private_key = local_private_key
        self._local_enr_rlp = local_enr_rlp
        self._local_enr_seq = local_enr_seq
        self._session_cache = session_cache
        self._timeout_secs = timeout_secs

        self._pending: dict[bytes, PendingHandshake] = {}

        # Cache of ENRs for nodes we may handshake with.
        #
        # Handshake verification requires the remote's public key.
        # The key comes from their ENR, which may arrive before the handshake
        # (via NODES responses) or within the handshake itself.
        # This cache stores pre-known ENRs for lookup during verification.
        self._enr_cache: dict[bytes, ENR] = {}

        self._lock = Lock()

    def start_handshake(self, remote_node_id: bytes) -> PendingHandshake:
        """
        Start tracking a new handshake as initiator.

        Called when we send a MESSAGE to a node with no session.
        We expect to receive a WHOAREYOU in response.

        Args:
            remote_node_id: 32-byte node ID of the remote peer.

        Returns:
            PendingHandshake in SENT_ORDINARY state.
        """
        with self._lock:
            pending = PendingHandshake(
                state=HandshakeState.SENT_ORDINARY,
                remote_node_id=remote_node_id,
            )
            self._pending[remote_node_id] = pending
            return pending

    def create_whoareyou(
        self,
        remote_node_id: bytes,
        request_nonce: bytes,
        remote_enr_seq: int,
        masking_iv: bytes,
    ) -> tuple[bytes, bytes, bytes, bytes]:
        """
        Create a WHOAREYOU packet in response to an undecryptable message.

        Called when we receive a MESSAGE we can't decrypt.

        Args:
            remote_node_id: 32-byte node ID of the sender.
            request_nonce: 12-byte nonce from the failed MESSAGE packet.
            remote_enr_seq: Our last known ENR seq for the remote (0 if unknown).
            masking_iv: 16-byte masking IV that will be used for the WHOAREYOU packet.

        Returns:
            Tuple of (id_nonce, authdata, nonce, challenge_data).
            - id_nonce: 16-byte challenge nonce
            - authdata: Encoded WHOAREYOU authdata
            - nonce: The request_nonce to use in the packet header
            - challenge_data: Full data for key derivation (masking-iv || static-header || authdata)
        """
        from .messages import PROTOCOL_ID, PROTOCOL_VERSION, PacketFlag

        id_nonce = generate_id_nonce()
        authdata = encode_whoareyou_authdata(bytes(id_nonce), remote_enr_seq)

        # Build challenge_data per spec: masking-iv || static-header || authdata.
        #
        # This data becomes the HKDF salt for session key derivation.
        # Both sides must use identical challenge_data to derive matching keys.
        import struct

        static_header = (
            PROTOCOL_ID
            + struct.pack(">H", PROTOCOL_VERSION)
            + bytes([PacketFlag.WHOAREYOU])
            + request_nonce
            + struct.pack(">H", len(authdata))
        )
        challenge_data = masking_iv + static_header + authdata

        with self._lock:
            pending = PendingHandshake(
                state=HandshakeState.SENT_WHOAREYOU,
                remote_node_id=remote_node_id,
                id_nonce=bytes(id_nonce),
                challenge_data=challenge_data,
                challenge_nonce=request_nonce,
                remote_enr_seq=remote_enr_seq,
            )
            self._pending[remote_node_id] = pending

        return bytes(id_nonce), authdata, request_nonce, challenge_data

    def create_handshake_response(
        self,
        remote_node_id: bytes,
        whoareyou: WhoAreYouAuthdata,
        remote_pubkey: bytes,
        challenge_data: bytes,
    ) -> tuple[bytes, bytes, bytes]:
        """
        Create a HANDSHAKE packet in response to WHOAREYOU.

        Called when we receive a WHOAREYOU for a message we sent.

        Args:
            remote_node_id: 32-byte node ID of the challenger.
            whoareyou: Decoded WHOAREYOU authdata.
            remote_pubkey: Remote's 33-byte compressed public key.
            challenge_data: Full WHOAREYOU data for key derivation
                (masking-iv || static-header || authdata from received packet).

        Returns:
            Tuple of (authdata, send_key, recv_key).
            - authdata: Encoded HANDSHAKE authdata
            - send_key: 16-byte key for sending to this peer
            - recv_key: 16-byte key for receiving from this peer
        """
        # Generate ephemeral keypair for ECDH.
        eph_privkey, eph_pubkey = generate_secp256k1_keypair()

        # Sign to prove our identity.
        #
        # Per spec, the signature input includes the full challenge_data (not just id_nonce)
        # to bind the signature to this specific WHOAREYOU exchange.
        id_signature = sign_id_nonce(
            self._local_private_key,
            challenge_data,
            eph_pubkey,
            remote_node_id,
        )

        # Include our ENR if the remote's known seq is stale.
        record = None
        if int(whoareyou.enr_seq) < self._local_enr_seq:
            record = self._local_enr_rlp

        # Build authdata.
        authdata = encode_handshake_authdata(
            src_id=self._local_node_id,
            id_signature=id_signature,
            eph_pubkey=eph_pubkey,
            record=record,
        )

        # Derive session keys using full challenge_data as HKDF salt.
        #
        # The challenge_data binds keys to this specific WHOAREYOU exchange.
        # Both sides must use identical challenge_data to derive matching keys.
        send_key, recv_key = derive_keys_from_pubkey(
            local_private_key=eph_privkey,
            remote_public_key=remote_pubkey,
            local_node_id=self._local_node_id,
            remote_node_id=remote_node_id,
            challenge_data=challenge_data,
            is_initiator=True,
        )

        # Store session.
        self._session_cache.create(
            node_id=remote_node_id,
            send_key=send_key,
            recv_key=recv_key,
            is_initiator=True,
        )

        # Clean up pending handshake.
        with self._lock:
            self._pending.pop(remote_node_id, None)

        return authdata, send_key, recv_key

    def handle_handshake(
        self,
        remote_node_id: bytes,
        handshake: HandshakeAuthdata,
    ) -> HandshakeResult:
        """
        Process a received HANDSHAKE packet.

        Called when we receive a HANDSHAKE in response to our WHOAREYOU.

        Args:
            remote_node_id: 32-byte node ID from packet source.
            handshake: Decoded HANDSHAKE authdata.

        Returns:
            HandshakeResult with established session.

        Raises:
            HandshakeError: If handshake verification fails.
        """
        with self._lock:
            pending = self._pending.get(remote_node_id)
            if pending is None:
                raise HandshakeError(f"No pending handshake for {remote_node_id.hex()}")

            if pending.state != HandshakeState.SENT_WHOAREYOU:
                raise HandshakeError(f"Unexpected handshake state: {pending.state}")

            if pending.id_nonce is None:
                raise HandshakeError("Missing id_nonce in pending handshake")

            if pending.challenge_data is None:
                raise HandshakeError("Missing challenge_data in pending handshake")

            challenge_data = pending.challenge_data
            remote_enr_seq = pending.remote_enr_seq

        # Verify the source ID matches.
        if handshake.src_id != remote_node_id:
            raise HandshakeError(
                f"Source ID mismatch: expected {remote_node_id.hex()}, got {handshake.src_id.hex()}"
            )

        # If we sent enr_seq=0, we signaled that we don't know the remote's ENR.
        # Per spec, the remote MUST include their ENR in the HANDSHAKE response
        # so we can verify their identity.
        if remote_enr_seq == 0 and handshake.record is None:
            raise HandshakeError(
                f"ENR required in HANDSHAKE from unknown node {remote_node_id.hex()[:16]}"
            )

        # Verify signature - we need the remote's static public key.
        # This typically comes from their ENR which may be in the handshake record.
        remote_pubkey = self._get_remote_pubkey(remote_node_id, handshake.record)
        if remote_pubkey is None:
            raise HandshakeError(f"Unknown public key for {remote_node_id.hex()}")

        # Verify the ID signature.
        #
        # The signature was computed over challenge_data (not just id_nonce),
        # and includes our node_id as the WHOAREYOU sender (node-id-B).
        if not verify_id_nonce_signature(
            signature=handshake.id_signature,
            challenge_data=challenge_data,
            ephemeral_pubkey=handshake.eph_pubkey,
            dest_node_id=self._local_node_id,
            public_key_bytes=remote_pubkey,
        ):
            raise HandshakeError("Invalid ID signature")

        # Derive session keys using stored challenge_data as HKDF salt.
        #
        # The challenge_data was saved when we sent WHOAREYOU.
        # Using the same data ensures both sides derive identical keys.
        recv_key, send_key = derive_keys_from_pubkey(
            local_private_key=self._local_private_key,
            remote_public_key=handshake.eph_pubkey,
            local_node_id=self._local_node_id,
            remote_node_id=remote_node_id,
            challenge_data=challenge_data,
            is_initiator=False,
        )

        # Create session.
        session = self._session_cache.create(
            node_id=remote_node_id,
            send_key=send_key,
            recv_key=recv_key,
            is_initiator=False,
        )

        # Clean up pending handshake.
        with self._lock:
            self._pending.pop(remote_node_id, None)

        return HandshakeResult(
            session=session,
            remote_enr=handshake.record,
        )

    def get_pending(self, remote_node_id: bytes) -> PendingHandshake | None:
        """Get pending handshake for a node."""
        with self._lock:
            pending = self._pending.get(remote_node_id)
            if pending is not None and pending.is_expired(self._timeout_secs):
                del self._pending[remote_node_id]
                return None
            return pending

    def cancel_handshake(self, remote_node_id: bytes) -> bool:
        """Cancel a pending handshake."""
        with self._lock:
            if remote_node_id in self._pending:
                del self._pending[remote_node_id]
                return True
            return False

    def cleanup_expired(self) -> int:
        """Remove expired pending handshakes."""
        with self._lock:
            expired = [
                node_id
                for node_id, pending in self._pending.items()
                if pending.is_expired(self._timeout_secs)
            ]
            for node_id in expired:
                del self._pending[node_id]
            return len(expired)

    def _get_remote_pubkey(self, node_id: bytes, enr_record: bytes | None) -> bytes | None:
        """
        Retrieve the remote node's static public key for signature verification.

        The handshake completes with a signature check.
        We need the remote's public key to verify their id-nonce signature.
        This key may come from two sources:

        1. The handshake packet itself (if remote included their ENR)
        2. Our ENR cache (populated from prior NODES responses)

        Args:
            node_id: 32-byte remote node ID.
            enr_record: Optional RLP-encoded ENR from handshake.

        Returns:
            33-byte compressed secp256k1 public key, or None if unavailable.
        """
        # Prefer the ENR from the handshake packet.
        #
        # The remote may include their ENR when responding to our challenge.
        # This is the freshest source and takes precedence.
        if enr_record is not None:
            try:
                enr = self._parse_enr_rlp(enr_record)
                if enr is not None and enr.public_key is not None:
                    # Verify ENR ownership matches the claimed node ID.
                    #
                    # The node ID is keccak256(pubkey), so we recompute it
                    # to ensure the ENR belongs to who we think sent it.
                    computed_id = enr.compute_node_id()
                    if computed_id is not None and bytes(computed_id) == node_id:
                        return bytes(enr.public_key)
            except Exception:
                pass

        # Fall back to our ENR cache.
        #
        # We may have received this node's ENR earlier via NODES responses.
        # Use it if the handshake packet did not include an ENR.
        cached_enr = self._enr_cache.get(node_id)
        if cached_enr is not None and cached_enr.public_key is not None:
            return bytes(cached_enr.public_key)

        return None

    def _parse_enr_rlp(self, enr_rlp: bytes) -> "ENR | None":
        """
        Decode an RLP-encoded ENR into a structured record.

        ENR (Ethereum Node Record) is the standard format for node identity.
        Handshake packets may include the sender's ENR so we can verify
        their identity without prior knowledge of the node.

        Args:
            enr_rlp: RLP-encoded ENR bytes.

        Returns:
            Parsed ENR with computed node ID, or None if malformed.
        """
        from lean_spec.subspecs.networking.enr import ENR
        from lean_spec.types import Bytes64, Uint64, rlp

        try:
            # Decode the RLP list structure.
            #
            # ENR format: [signature, seq, key1, val1, key2, val2, ...]
            # Minimum: signature + seq = 2 items.
            # Key-value pairs must come in pairs, so total is always even.
            items = rlp.decode_rlp_list(enr_rlp)
            if len(items) < 2 or len(items) % 2 != 0:
                return None

            # Extract signature (always 64 bytes for secp256k1).
            signature_raw = items[0]
            if len(signature_raw) != 64:
                return None

            # Extract sequence number (big-endian encoded).
            #
            # Sequence increments with each ENR update.
            # Higher sequence means newer record.
            seq_bytes = items[1]
            seq = int.from_bytes(seq_bytes, "big") if seq_bytes else 0

            # Extract key-value pairs.
            #
            # Common keys: "id", "secp256k1", "ip", "udp", "tcp".
            # Keys are UTF-8 strings; values are raw bytes.
            pairs: dict[str, bytes] = {}
            for i in range(2, len(items), 2):
                key = items[i].decode("utf-8")
                value = items[i + 1]
                pairs[key] = value

            enr = ENR(
                signature=Bytes64(signature_raw),
                seq=Uint64(seq),
                pairs=pairs,
            )

            # Compute and attach the node ID.
            #
            # Node ID = keccak256(public_key).
            # Pre-computing avoids repeated hashing during lookups.
            node_id = enr.compute_node_id()
            if node_id is not None:
                return enr.model_copy(update={"node_id": node_id})

            return enr
        except Exception:
            return None

    def register_enr(self, node_id: bytes, enr: "ENR") -> None:
        """
        Cache an ENR for future handshake verification.

        When we learn about a node (via NODES responses or other means),
        we cache its ENR here. Later, if that node initiates a handshake,
        we can verify their identity without requiring them to include
        their ENR in the handshake packet.

        Args:
            node_id: 32-byte node ID (keccak256 of public key).
            enr: The node's ENR containing their public key.
        """
        self._enr_cache[node_id] = enr

    def get_cached_enr(self, node_id: bytes) -> "ENR | None":
        """
        Retrieve a previously cached ENR.

        Args:
            node_id: 32-byte node ID to look up.

        Returns:
            The cached ENR, or None if not in cache.
        """
        return self._enr_cache.get(node_id)
