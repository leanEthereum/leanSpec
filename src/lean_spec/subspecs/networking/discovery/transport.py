"""
UDP transport for Discovery v5.

Provides async UDP send/receive with packet encoding/decoding.

Transport Responsibilities:
- Bind to UDP socket
- Send/receive raw packets
- Route incoming packets to appropriate handlers
- Manage pending requests and timeouts

References:
- https://github.com/ethereum/devp2p/blob/master/discv5/discv5-wire.md
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from lean_spec.types import Uint64

from .codec import (
    DiscoveryMessage,
    decode_message,
    encode_message,
    generate_request_id,
)
from .config import DiscoveryConfig
from .handshake import HandshakeManager
from .messages import FindNode, Nonce, PacketFlag, Ping, Pong, TalkReq
from .packet import (
    decode_handshake_authdata,
    decode_message_authdata,
    decode_packet_header,
    decode_whoareyou_authdata,
    decrypt_message,
    encode_message_authdata,
    encode_packet,
    generate_nonce,
)
from .session import SessionCache

if TYPE_CHECKING:
    from lean_spec.subspecs.networking.enr import ENR

logger = logging.getLogger(__name__)


@dataclass
class PendingRequest:
    """Tracks a pending request awaiting response."""

    request_id: bytes
    """Request ID for matching responses."""

    dest_node_id: bytes
    """Destination node ID."""

    sent_at: float
    """Timestamp when request was sent."""

    nonce: bytes
    """Packet nonce (needed for WHOAREYOU handling)."""

    message: DiscoveryMessage
    """Original message (for retransmission after handshake)."""

    future: asyncio.Future
    """Future to complete when response arrives."""


@dataclass
class PendingMultiRequest:
    """Tracks a pending request that may receive multiple responses.

    Used for FINDNODE which can return multiple NODES messages split
    across UDP packets when results exceed MTU.
    """

    request_id: bytes
    """Request ID for matching responses."""

    dest_node_id: bytes
    """Destination node ID."""

    sent_at: float
    """Timestamp when request was sent."""

    nonce: bytes
    """Packet nonce (needed for WHOAREYOU handling)."""

    message: DiscoveryMessage
    """Original message (for retransmission after handshake)."""

    response_queue: asyncio.Queue
    """Queue to collect multiple responses."""

    expected_total: int | None
    """Expected number of responses (from first NODES.total field)."""

    received_count: int
    """Number of responses received so far."""


class DiscoveryProtocol(asyncio.DatagramProtocol):
    """Async UDP protocol handler for Discovery v5."""

    def __init__(self, transport_handler: DiscoveryTransport):
        """
        Initialize the protocol handler.

        Args:
            transport_handler: Parent transport for packet handling.
        """
        self._handler = transport_handler
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.transports.BaseTransport) -> None:
        """Called when UDP socket is ready."""
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called when a UDP packet is received."""
        asyncio.create_task(self._handler._handle_packet(data, addr))

    def error_received(self, exc: Exception) -> None:
        """Called when a send/receive error occurs."""
        logger.warning("UDP error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when the socket is closed."""
        if exc is not None:
            logger.warning("UDP connection lost: %s", exc)


class DiscoveryTransport:
    """
    UDP transport for Discovery v5.

    Handles all wire protocol operations:
    - Packet encoding/decoding
    - Session management
    - Handshake orchestration
    - Request/response matching
    """

    def __init__(
        self,
        local_node_id: bytes,
        local_private_key: bytes,
        local_enr: ENR,
        config: DiscoveryConfig | None = None,
    ):
        """
        Initialize the transport.

        Args:
            local_node_id: Our 32-byte node ID.
            local_private_key: Our 32-byte secp256k1 private key.
            local_enr: Our ENR.
            config: Optional protocol configuration.
        """
        self._local_node_id = local_node_id
        self._local_private_key = local_private_key
        self._local_enr = local_enr
        self._config = config or DiscoveryConfig()

        self._session_cache = SessionCache()
        self._handshake_manager = HandshakeManager(
            local_node_id=local_node_id,
            local_private_key=local_private_key,
            local_enr_rlp=local_enr.to_rlp(),
            local_enr_seq=int(local_enr.seq),
            session_cache=self._session_cache,
        )

        self._protocol: DiscoveryProtocol | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self._pending_requests: dict[bytes, PendingRequest] = {}
        self._pending_multi_requests: dict[bytes, PendingMultiRequest] = {}
        self._node_addresses: dict[bytes, tuple[str, int]] = {}

        # ENR cache for handshake verification.
        #
        # When receiving WHOAREYOU, we must prove our identity by signing
        # with our private key. When sending HANDSHAKE, we need the remote's
        # public key to derive session keys via ECDH.
        #
        # This cache stores ENRs learned from NODES responses.
        # It mirrors the handshake manager's cache but provides transport-level access.
        self._enr_cache: dict[bytes, ENR] = {}

        self._message_handler: Callable[[bytes, DiscoveryMessage, tuple[str, int]], None] | None = (
            None
        )

        self._running = False

    async def start(self, host: str = "0.0.0.0", port: int = 9000) -> None:
        """
        Start listening for UDP packets.

        Args:
            host: IP address to bind to.
            port: UDP port to bind to.
        """
        if self._running:
            return

        loop = asyncio.get_running_loop()

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: DiscoveryProtocol(self),
            local_addr=(host, port),
        )
        self._transport = transport  # type: ignore[assignment]
        self._protocol = protocol  # type: ignore[assignment]

        self._running = True
        logger.info("Discovery transport started on %s:%d", host, port)

    async def stop(self) -> None:
        """Stop the transport."""
        if not self._running:
            return

        self._running = False

        if self._transport is not None:
            self._transport.close()
            self._transport = None

        # Cancel pending requests.
        for pending in self._pending_requests.values():
            if not pending.future.done():
                pending.future.cancel()
        self._pending_requests.clear()

        logger.info("Discovery transport stopped")

    def set_message_handler(
        self,
        handler: Callable[[bytes, DiscoveryMessage, tuple[str, int]], None],
    ) -> None:
        """Set handler for incoming messages."""
        self._message_handler = handler

    def register_node_address(self, node_id: bytes, address: tuple[str, int]) -> None:
        """Register a node's UDP address."""
        self._node_addresses[node_id] = address

    def get_node_address(self, node_id: bytes) -> tuple[str, int] | None:
        """Get a node's registered UDP address."""
        return self._node_addresses.get(node_id)

    def register_enr(self, node_id: bytes, enr: ENR) -> None:
        """
        Cache an ENR for future handshake completion.

        The ENR contains the node's public key, which is essential for:

        - ECDH key derivation during session establishment
        - Verifying id-nonce signatures in handshake responses

        Caches in both the transport and handshake manager to ensure
        availability regardless of which component needs it first.

        Args:
            node_id: 32-byte node ID (keccak256 of public key).
            enr: The node's ENR.
        """
        self._enr_cache[node_id] = enr
        self._handshake_manager.register_enr(node_id, enr)

    def get_enr(self, node_id: bytes) -> ENR | None:
        """
        Retrieve a cached ENR by node ID.

        Args:
            node_id: 32-byte node ID to look up.

        Returns:
            The cached ENR, or None if unknown.
        """
        return self._enr_cache.get(node_id)

    async def send_ping(self, dest_node_id: bytes, dest_addr: tuple[str, int]) -> Pong | None:
        """
        Send a PING and wait for PONG.

        Args:
            dest_node_id: 32-byte destination node ID.
            dest_addr: (ip, port) tuple.

        Returns:
            PONG response or None on timeout.
        """
        request_id = generate_request_id()
        ping = Ping(
            request_id=request_id,
            enr_seq=Uint64(self._local_enr.seq),
        )

        response = await self._send_request(dest_node_id, dest_addr, ping)
        if isinstance(response, Pong):
            return response
        return None

    async def send_findnode(
        self,
        dest_node_id: bytes,
        dest_addr: tuple[str, int],
        distances: list[int],
    ) -> list[bytes]:
        """
        Send FINDNODE and collect all NODES responses.

        Per spec, FINDNODE responses may be split across multiple NODES messages
        when results exceed UDP MTU. The `total` field indicates how many messages
        to expect. We collect all messages until `total` is reached or timeout.

        Args:
            dest_node_id: 32-byte destination node ID.
            dest_addr: (ip, port) tuple.
            distances: List of log2 distances to query.

        Returns:
            List of RLP-encoded ENRs from all NODES responses.
        """
        from .messages import Distance, Nodes

        request_id = generate_request_id()
        findnode = FindNode(
            request_id=request_id,
            distances=[Distance(d) for d in distances],
        )

        # Use multi-response collection for FINDNODE.
        responses = await self._send_multi_response_request(dest_node_id, dest_addr, findnode)

        # Collect all ENRs from all NODES responses.
        all_enrs: list[bytes] = []
        for response in responses:
            if isinstance(response, Nodes):
                all_enrs.extend(response.enrs)

        return all_enrs

    async def _send_multi_response_request(
        self,
        dest_node_id: bytes,
        dest_addr: tuple[str, int],
        message: DiscoveryMessage,
    ) -> list[DiscoveryMessage]:
        """
        Send a request that may receive multiple responses.

        Used for FINDNODE which can return multiple NODES messages.
        Collects responses until the expected total is reached or timeout.

        Args:
            dest_node_id: 32-byte destination node ID.
            dest_addr: (ip, port) tuple.
            message: Request message to send.

        Returns:
            List of response messages (may be empty on timeout/error).
        """
        from .messages import Nodes

        if self._transport is None:
            raise RuntimeError("Transport not started")

        # Register address for responses.
        self._node_addresses[dest_node_id] = dest_addr

        # Get or create session.
        session = self._session_cache.get(dest_node_id)
        nonce = generate_nonce()

        # Encode message.
        message_bytes = encode_message(message)

        if session is not None:
            authdata = encode_message_authdata(self._local_node_id)
            packet = encode_packet(
                dest_node_id=dest_node_id,
                src_node_id=self._local_node_id,
                flag=PacketFlag.MESSAGE,
                nonce=bytes(nonce),
                authdata=authdata,
                message=message_bytes,
                encryption_key=session.send_key,
            )
        else:
            # Trigger handshake via deliberate decryption failure.
            self._handshake_manager.start_handshake(dest_node_id)
            authdata = encode_message_authdata(self._local_node_id)

            import os

            dummy_key = os.urandom(16)
            packet = encode_packet(
                dest_node_id=dest_node_id,
                src_node_id=self._local_node_id,
                flag=PacketFlag.MESSAGE,
                nonce=bytes(nonce),
                authdata=authdata,
                message=message_bytes,
                encryption_key=dummy_key,
            )

        # Create collector for multiple responses.
        loop = asyncio.get_running_loop()
        request_id_bytes = bytes(message.request_id)

        # Use a queue to collect multiple responses.
        response_queue: asyncio.Queue[DiscoveryMessage] = asyncio.Queue()
        pending = PendingMultiRequest(
            request_id=request_id_bytes,
            dest_node_id=dest_node_id,
            sent_at=loop.time(),
            nonce=bytes(nonce),
            message=message,
            response_queue=response_queue,
            expected_total=None,
            received_count=0,
        )
        self._pending_multi_requests[request_id_bytes] = pending

        # Send packet.
        self._transport.sendto(packet, dest_addr)

        # Collect responses until total reached or timeout.
        responses: list[DiscoveryMessage] = []
        deadline = loop.time() + self._config.request_timeout_secs

        try:
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break

                try:
                    response = await asyncio.wait_for(response_queue.get(), timeout=remaining)
                    responses.append(response)

                    # Update expected total from first NODES response.
                    if isinstance(response, Nodes):
                        if pending.expected_total is None:
                            pending.expected_total = int(response.total)
                        pending.received_count += 1

                        # Check if we've received all expected messages.
                        if (
                            pending.expected_total is not None
                            and pending.received_count >= pending.expected_total
                        ):
                            break

                except asyncio.TimeoutError:
                    break

        finally:
            self._pending_multi_requests.pop(request_id_bytes, None)

        return responses

    async def send_talkreq(
        self,
        dest_node_id: bytes,
        dest_addr: tuple[str, int],
        protocol: bytes,
        request: bytes,
    ) -> bytes | None:
        """
        Send TALKREQ and wait for TALKRESP.

        Args:
            dest_node_id: 32-byte destination node ID.
            dest_addr: (ip, port) tuple.
            protocol: Protocol identifier.
            request: Protocol-specific request payload.

        Returns:
            Response payload or None on timeout/error.
        """
        from .messages import TalkResp

        request_id = generate_request_id()
        talkreq = TalkReq(
            request_id=request_id,
            protocol=protocol,
            request=request,
        )

        response = await self._send_request(dest_node_id, dest_addr, talkreq)
        if isinstance(response, TalkResp):
            return response.response
        return None

    async def _send_request(
        self,
        dest_node_id: bytes,
        dest_addr: tuple[str, int],
        message: DiscoveryMessage,
    ) -> DiscoveryMessage | None:
        """
        Send a request and wait for response.

        Handles session establishment if needed.
        """
        if self._transport is None:
            raise RuntimeError("Transport not started")

        # Register address for responses.
        self._node_addresses[dest_node_id] = dest_addr

        # Get or create session.
        session = self._session_cache.get(dest_node_id)
        nonce = generate_nonce()

        # Encode message.
        message_bytes = encode_message(message)

        if session is not None:
            # Have session, send encrypted message.
            authdata = encode_message_authdata(self._local_node_id)
            packet = encode_packet(
                dest_node_id=dest_node_id,
                src_node_id=self._local_node_id,
                flag=PacketFlag.MESSAGE,
                nonce=bytes(nonce),
                authdata=authdata,
                message=message_bytes,
                encryption_key=session.send_key,
            )
        else:
            # Deliberate decryption failure triggers handshake.
            #
            # Discovery v5's handshake is initiated by failure:
            #
            # 1. We send a MESSAGE with random encryption key
            # 2. Recipient cannot decrypt (they don't have the key)
            # 3. Recipient responds with WHOAREYOU challenge
            # 4. We complete handshake with HANDSHAKE packet
            #
            # This approach avoids the need for session negotiation
            # before sending the first message.
            self._handshake_manager.start_handshake(dest_node_id)

            authdata = encode_message_authdata(self._local_node_id)

            import os

            dummy_key = os.urandom(16)
            packet = encode_packet(
                dest_node_id=dest_node_id,
                src_node_id=self._local_node_id,
                flag=PacketFlag.MESSAGE,
                nonce=bytes(nonce),
                authdata=authdata,
                message=message_bytes,
                encryption_key=dummy_key,
            )

        # Create pending request.
        loop = asyncio.get_running_loop()
        future: asyncio.Future[DiscoveryMessage | None] = loop.create_future()

        request_id_bytes = bytes(message.request_id)
        pending = PendingRequest(
            request_id=request_id_bytes,
            dest_node_id=dest_node_id,
            sent_at=loop.time(),
            nonce=bytes(nonce),
            message=message,
            future=future,
        )
        self._pending_requests[request_id_bytes] = pending

        # Send packet.
        self._transport.sendto(packet, dest_addr)

        # Wait for response with timeout.
        try:
            return await asyncio.wait_for(
                future,
                timeout=self._config.request_timeout_secs,
            )
        except asyncio.TimeoutError:
            return None
        finally:
            self._pending_requests.pop(request_id_bytes, None)

    async def _handle_packet(self, data: bytes, addr: tuple[str, int]) -> None:
        """Handle a received UDP packet."""
        try:
            # Decode packet header.
            header, message_bytes = decode_packet_header(self._local_node_id, data)

            if header.flag == PacketFlag.WHOAREYOU:
                await self._handle_whoareyou(header, message_bytes, addr, data)
            elif header.flag == PacketFlag.HANDSHAKE:
                await self._handle_handshake(header, message_bytes, addr, data)
            else:
                await self._handle_message(header, message_bytes, addr, data)

        except Exception as e:
            logger.debug("Error handling packet from %s: %s", addr, e)

    async def _handle_whoareyou(
        self,
        header,
        message_bytes: bytes,
        addr: tuple[str, int],
        raw_packet: bytes,
    ) -> None:
        """
        Respond to a WHOAREYOU challenge with a HANDSHAKE packet.

        WHOAREYOU is the recipient's way of saying "I cannot decrypt your message."
        We must prove our identity and establish session keys before communication.

        The response flow:

        1. Find which pending request triggered this challenge
        2. Extract challenge_data from the WHOAREYOU for key derivation
        3. Look up the remote's public key from our ENR cache
        4. Generate ephemeral keypair for ECDH
        5. Sign the challenge nonce to prove identity
        6. Derive session keys and send HANDSHAKE with original message
        """
        whoareyou = decode_whoareyou_authdata(header.authdata)

        # Match WHOAREYOU to our pending request via nonce.
        #
        # The WHOAREYOU contains our original packet's nonce.
        # This links the challenge to the specific request that failed.
        pending = None
        for p in self._pending_requests.values():
            if p.nonce == bytes(header.nonce):
                pending = p
                break

        if pending is None:
            logger.debug("No pending request for WHOAREYOU nonce")
            return

        remote_node_id = pending.dest_node_id

        # Extract challenge_data for key derivation.
        #
        # Per spec: challenge_data = masking-iv || static-header || authdata
        # This is the first 63 bytes of the WHOAREYOU packet:
        # - masking-iv: 16 bytes
        # - static-header: 23 bytes (protocol-id + version + flag + nonce + authdata-size)
        # - authdata: 24 bytes (id-nonce 16 + enr-seq 8)
        #
        # We use the unmasked header, which we can reconstruct from the decoded values.
        import struct

        from .messages import PROTOCOL_ID, PROTOCOL_VERSION

        masking_iv = raw_packet[:16]
        static_header = (
            PROTOCOL_ID
            + struct.pack(">H", PROTOCOL_VERSION)
            + bytes([PacketFlag.WHOAREYOU])
            + bytes(header.nonce)
            + struct.pack(">H", len(header.authdata))
        )
        challenge_data = masking_iv + static_header + header.authdata

        # Retrieve the remote's public key for ECDH.
        #
        # Session key derivation requires ECDH between our ephemeral private key
        # and the remote's static public key. Without their ENR, we cannot proceed.
        remote_enr = self._enr_cache.get(remote_node_id)
        if remote_enr is None or remote_enr.public_key is None:
            logger.debug("No ENR for %s, cannot complete handshake", remote_node_id.hex()[:16])
            return

        remote_pubkey = bytes(remote_enr.public_key)

        # Build and send the HANDSHAKE response.
        try:
            authdata, send_key, recv_key = self._handshake_manager.create_handshake_response(
                remote_node_id=remote_node_id,
                whoareyou=whoareyou,
                remote_pubkey=remote_pubkey,
                challenge_data=challenge_data,
            )

            # Re-send the original message, now encrypted with the new session key.
            #
            # The HANDSHAKE packet includes both the authentication data
            # and our original message (encrypted). This completes the
            # handshake and delivers the message in one round trip.
            message_bytes = encode_message(pending.message)
            nonce = generate_nonce()

            packet = encode_packet(
                dest_node_id=remote_node_id,
                src_node_id=self._local_node_id,
                flag=PacketFlag.HANDSHAKE,
                nonce=bytes(nonce),
                authdata=authdata,
                message=message_bytes,
                encryption_key=send_key,
            )

            if self._transport is not None:
                self._transport.sendto(packet, addr)
                logger.debug("Sent HANDSHAKE to %s", remote_node_id.hex()[:16])

        except Exception as e:
            logger.debug("Failed to create handshake response: %s", e)

    async def _handle_handshake(
        self,
        header,
        message_bytes: bytes,
        addr: tuple[str, int],
        raw_packet: bytes,
    ) -> None:
        """Handle a HANDSHAKE packet."""
        handshake_authdata = decode_handshake_authdata(header.authdata)
        remote_node_id = handshake_authdata.src_id

        try:
            result = self._handshake_manager.handle_handshake(remote_node_id, handshake_authdata)
            logger.debug("Handshake completed with %s", remote_node_id.hex()[:16])

            # Decrypt the included message.
            if len(message_bytes) > 0:
                # Extract masked header for AAD.
                masked_header = raw_packet[16 : 16 + 23 + len(header.authdata)]

                plaintext = decrypt_message(
                    encryption_key=result.session.recv_key,
                    nonce=bytes(header.nonce),
                    ciphertext=message_bytes,
                    masked_header=masked_header,
                )

                message = decode_message(plaintext)
                await self._handle_decoded_message(remote_node_id, message, addr)

        except Exception as e:
            logger.debug("Handshake failed: %s", e)

    async def _handle_message(
        self,
        header,
        message_bytes: bytes,
        addr: tuple[str, int],
        raw_packet: bytes,
    ) -> None:
        """Handle an ordinary MESSAGE packet."""
        message_authdata = decode_message_authdata(header.authdata)
        remote_node_id = message_authdata.src_id

        # Get session.
        session = self._session_cache.get(remote_node_id)
        if session is None:
            # Can't decrypt - send WHOAREYOU.
            await self._send_whoareyou(remote_node_id, header.nonce, addr)
            return

        try:
            # Extract masked header for AAD.
            masked_header = raw_packet[16 : 16 + 23 + len(header.authdata)]

            plaintext = decrypt_message(
                encryption_key=session.recv_key,
                nonce=bytes(header.nonce),
                ciphertext=message_bytes,
                masked_header=masked_header,
            )

            message = decode_message(plaintext)
            await self._handle_decoded_message(remote_node_id, message, addr)

        except Exception as e:
            # Decryption failed - send WHOAREYOU.
            logger.debug("Decryption failed, sending WHOAREYOU: %s", e)
            await self._send_whoareyou(remote_node_id, header.nonce, addr)

    async def _handle_decoded_message(
        self,
        remote_node_id: bytes,
        message: DiscoveryMessage,
        addr: tuple[str, int],
    ) -> None:
        """Process a successfully decoded message."""
        # Update session activity.
        self._session_cache.touch(remote_node_id)

        # Check if this is a response to a pending request.
        request_id = bytes(message.request_id)

        # Check for multi-response requests first (e.g., FINDNODE -> NODES).
        multi_pending = self._pending_multi_requests.get(request_id)
        if multi_pending is not None:
            await multi_pending.response_queue.put(message)
            return

        # Check for single-response requests.
        pending = self._pending_requests.get(request_id)
        if pending is not None and not pending.future.done():
            pending.future.set_result(message)
            return

        # Otherwise, pass to message handler.
        if self._message_handler is not None:
            self._message_handler(remote_node_id, message, addr)

    async def _send_whoareyou(
        self,
        remote_node_id: bytes,
        request_nonce: Nonce,
        addr: tuple[str, int],
    ) -> None:
        """Send a WHOAREYOU packet."""
        import os

        if self._transport is None:
            return

        # Get last known ENR seq for this node (0 if unknown).
        remote_enr_seq = 0

        # Generate masking IV for the WHOAREYOU packet.
        #
        # This IV is part of the challenge_data used for key derivation.
        # Both sides must use identical challenge_data to derive matching keys.
        masking_iv = os.urandom(16)

        id_nonce, authdata, nonce, challenge_data = self._handshake_manager.create_whoareyou(
            remote_node_id=remote_node_id,
            request_nonce=bytes(request_nonce),
            remote_enr_seq=remote_enr_seq,
            masking_iv=masking_iv,
        )

        packet = encode_packet(
            dest_node_id=remote_node_id,
            src_node_id=self._local_node_id,
            flag=PacketFlag.WHOAREYOU,
            nonce=nonce,
            authdata=authdata,
            message=b"",
            encryption_key=None,
        )

        self._transport.sendto(packet, addr)
        logger.debug("Sent WHOAREYOU to %s", remote_node_id.hex()[:16])

    async def send_response(
        self,
        dest_node_id: bytes,
        dest_addr: tuple[str, int],
        message: DiscoveryMessage,
    ) -> bool:
        """
        Send a response message using an existing session.

        Response messages (PONG, NODES, TALKRESP) reply to incoming requests.
        Unlike requests, responses do not trigger handshakes if no session exists.
        The session must have been established by the original request flow.

        Args:
            dest_node_id: 32-byte destination node ID.
            dest_addr: (ip, port) tuple.
            message: Response message to send.

        Returns:
            True if sent successfully.
            False if transport not running or no session exists.
        """
        if self._transport is None:
            return False

        # Responses require an existing session.
        #
        # The requester initiated the handshake.
        # By the time we respond, session keys must exist.
        session = self._session_cache.get(dest_node_id)
        if session is None:
            logger.debug("No session for response to %s", dest_node_id.hex()[:16])
            return False

        # Encode and encrypt the response.
        nonce = generate_nonce()
        message_bytes = encode_message(message)
        authdata = encode_message_authdata(self._local_node_id)

        packet = encode_packet(
            dest_node_id=dest_node_id,
            src_node_id=self._local_node_id,
            flag=PacketFlag.MESSAGE,
            nonce=bytes(nonce),
            authdata=authdata,
            message=message_bytes,
            encryption_key=session.send_key,
        )

        self._transport.sendto(packet, dest_addr)
        return True
