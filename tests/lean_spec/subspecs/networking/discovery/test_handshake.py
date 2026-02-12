"""Tests for Discovery v5 handshake state machine."""

import time

import pytest

from lean_spec.subspecs.networking.discovery.crypto import (
    generate_secp256k1_keypair,
    sign_id_nonce,
)
from lean_spec.subspecs.networking.discovery.handshake import (
    HandshakeError,
    HandshakeManager,
    HandshakeResult,
    HandshakeState,
    PendingHandshake,
)
from lean_spec.subspecs.networking.discovery.keys import compute_node_id
from lean_spec.subspecs.networking.discovery.messages import IdNonce
from lean_spec.subspecs.networking.discovery.packet import (
    HandshakeAuthdata,
    WhoAreYouAuthdata,
    decode_handshake_authdata,
    decode_whoareyou_authdata,
    encode_handshake_authdata,
)
from lean_spec.subspecs.networking.discovery.session import SessionCache
from lean_spec.subspecs.networking.enr import ENR
from lean_spec.subspecs.networking.types import NodeId
from lean_spec.types import Bytes32, Bytes33, Bytes64, Uint64
from tests.lean_spec.subspecs.networking.discovery.conftest import NODE_B_PUBKEY


@pytest.fixture
def local_keypair():
    """Generate a local keypair for testing."""
    priv, pub = generate_secp256k1_keypair()
    node_id = compute_node_id(pub)
    return priv, pub, node_id


@pytest.fixture
def remote_keypair():
    """Generate a remote keypair for testing."""
    priv, pub = generate_secp256k1_keypair()
    node_id = compute_node_id(pub)
    return priv, pub, node_id


@pytest.fixture
def session_cache():
    """Create a session cache."""
    return SessionCache()


@pytest.fixture
def manager(local_keypair, session_cache):
    """Create a handshake manager."""
    priv, pub, node_id = local_keypair

    return HandshakeManager(
        local_node_id=node_id,
        local_private_key=priv,
        local_enr_rlp=b"mock_enr",
        local_enr_seq=1,
        session_cache=session_cache,
    )


class TestPendingHandshake:
    """Tests for PendingHandshake dataclass."""

    def test_create_pending_handshake(self):
        """Test creating a pending handshake."""
        pending = PendingHandshake(
            state=HandshakeState.IDLE,
            remote_node_id=NodeId(bytes(32)),
        )

        assert pending.state == HandshakeState.IDLE
        assert pending.id_nonce is None
        assert pending.ephemeral_privkey is None

    def test_is_expired_false_for_new(self):
        """Test that new handshake is not expired."""
        pending = PendingHandshake(
            state=HandshakeState.IDLE,
            remote_node_id=NodeId(bytes(32)),
        )

        assert not pending.is_expired(timeout_secs=1.0)

    def test_is_expired_true_for_old(self):
        """Test that old handshake is expired."""
        pending = PendingHandshake(
            state=HandshakeState.IDLE,
            remote_node_id=NodeId(bytes(32)),
            started_at=time.time() - 10,
        )

        assert pending.is_expired(timeout_secs=1.0)


class TestHandshakeManager:
    """Tests for HandshakeManager."""

    def test_start_handshake(self, manager):
        """Test starting a handshake as initiator."""
        remote_node_id = bytes(32)

        pending = manager.start_handshake(remote_node_id)

        assert pending.state == HandshakeState.SENT_ORDINARY
        assert pending.remote_node_id == remote_node_id

    def test_get_pending(self, manager):
        """Test getting a pending handshake."""
        remote_node_id = bytes(32)

        manager.start_handshake(remote_node_id)
        pending = manager.get_pending(remote_node_id)

        assert pending is not None
        assert pending.remote_node_id == remote_node_id

    def test_get_pending_nonexistent(self, manager):
        """Test getting nonexistent pending handshake."""
        pending = manager.get_pending(bytes(32))
        assert pending is None

    def test_cancel_handshake(self, manager):
        """Test canceling a handshake."""
        remote_node_id = bytes(32)

        manager.start_handshake(remote_node_id)
        assert manager.cancel_handshake(remote_node_id)
        assert manager.get_pending(remote_node_id) is None

    def test_cancel_nonexistent_returns_false(self, manager):
        """Test that canceling nonexistent handshake returns False."""
        assert not manager.cancel_handshake(bytes(32))

    def test_create_whoareyou(self, manager):
        """Test creating a WHOAREYOU challenge."""
        remote_node_id = bytes(32)
        request_nonce = bytes(12)
        remote_enr_seq = 0
        masking_iv = bytes(16)

        id_nonce, authdata, nonce, challenge_data = manager.create_whoareyou(
            remote_node_id, request_nonce, remote_enr_seq, masking_iv
        )

        assert len(id_nonce) == 16
        assert nonce == request_nonce

        # Verify authdata decodes correctly
        decoded = decode_whoareyou_authdata(authdata)
        assert bytes(decoded.id_nonce) == id_nonce
        assert int(decoded.enr_seq) == remote_enr_seq

        # Verify challenge_data structure: masking-iv || static-header || authdata
        # masking-iv (16) + static-header (23) + authdata (24) = 63 bytes
        assert len(challenge_data) == 63
        assert challenge_data[:16] == masking_iv
        assert challenge_data[39:] == authdata  # 16 + 23 = 39

        # Check pending state
        pending = manager.get_pending(remote_node_id)
        assert pending is not None
        assert pending.state == HandshakeState.SENT_WHOAREYOU
        assert pending.id_nonce == id_nonce
        assert pending.challenge_data == challenge_data

    def test_cleanup_expired(self, manager):
        """Test cleanup of expired handshakes."""
        remote1 = bytes.fromhex("01" + "00" * 31)
        remote2 = bytes.fromhex("02" + "00" * 31)

        # Create handshakes with short timeout
        manager._timeout_secs = 0.001
        manager.start_handshake(remote1)
        manager.start_handshake(remote2)

        time.sleep(0.01)
        removed = manager.cleanup_expired()

        assert removed == 2
        assert manager.get_pending(remote1) is None
        assert manager.get_pending(remote2) is None

    def test_invalid_local_node_id_raises(self):
        """Test that invalid local node ID raises ValueError."""
        with pytest.raises(ValueError, match="Local node ID must be 32 bytes"):
            HandshakeManager(
                local_node_id=bytes(31),  # type: ignore[arg-type]
                local_private_key=bytes(32),
                local_enr_rlp=b"enr",
                local_enr_seq=1,
                session_cache=SessionCache(),
            )

    def test_invalid_local_private_key_raises(self):
        """Test that invalid local private key raises ValueError."""
        with pytest.raises(ValueError, match="Local private key must be 32 bytes"):
            HandshakeManager(
                local_node_id=NodeId(bytes(32)),
                local_private_key=bytes(31),
                local_enr_rlp=b"enr",
                local_enr_seq=1,
                session_cache=SessionCache(),
            )


class TestHandshakeState:
    """Tests for HandshakeState enum."""

    def test_states_exist(self):
        """Test that all expected states exist."""
        assert HandshakeState.IDLE
        assert HandshakeState.SENT_ORDINARY
        assert HandshakeState.SENT_WHOAREYOU
        assert HandshakeState.COMPLETED

    def test_states_are_distinct(self):
        """Test that states are distinct."""
        states = [
            HandshakeState.IDLE,
            HandshakeState.SENT_ORDINARY,
            HandshakeState.SENT_WHOAREYOU,
            HandshakeState.COMPLETED,
        ]

        assert len(set(states)) == 4


class TestHandshakeStateTransitions:
    """Verify all state machine transitions."""

    def test_idle_to_sent_ordinary_on_start_handshake(self, manager):
        """Starting a handshake transitions to SENT_ORDINARY state.

        When initiating contact with a node that has no session,
        we send a MESSAGE that will trigger WHOAREYOU.
        """
        remote_node_id = bytes(32)

        pending = manager.start_handshake(remote_node_id)

        assert pending.state == HandshakeState.SENT_ORDINARY
        assert pending.remote_node_id == remote_node_id

    def test_sent_ordinary_state_has_no_challenge_data(self, manager):
        """In SENT_ORDINARY state, challenge data is not yet available.

        Challenge data only becomes available after receiving WHOAREYOU.
        """
        remote_node_id = bytes(32)

        pending = manager.start_handshake(remote_node_id)

        assert pending.state == HandshakeState.SENT_ORDINARY
        assert pending.id_nonce is None
        assert pending.challenge_data is None
        assert pending.ephemeral_privkey is None

    def test_create_whoareyou_transitions_to_sent_whoareyou(self, manager):
        """Creating WHOAREYOU transitions to SENT_WHOAREYOU state.

        When we receive an undecryptable MESSAGE, we respond with WHOAREYOU.
        """
        remote_node_id = bytes(32)
        request_nonce = bytes(12)
        remote_enr_seq = 0
        masking_iv = bytes(16)

        id_nonce, authdata, nonce, challenge_data = manager.create_whoareyou(
            remote_node_id, request_nonce, remote_enr_seq, masking_iv
        )

        pending = manager.get_pending(remote_node_id)

        assert pending is not None
        assert pending.state == HandshakeState.SENT_WHOAREYOU
        assert pending.id_nonce == id_nonce
        assert pending.challenge_data == challenge_data

    def test_sent_whoareyou_state_has_challenge_data(self, manager):
        """In SENT_WHOAREYOU state, all challenge data is stored."""
        remote_node_id = bytes(32)
        request_nonce = bytes(12)
        remote_enr_seq = 5
        masking_iv = bytes(16)

        manager.create_whoareyou(remote_node_id, request_nonce, remote_enr_seq, masking_iv)

        pending = manager.get_pending(remote_node_id)

        assert pending.id_nonce is not None
        assert pending.challenge_data is not None
        assert pending.challenge_nonce == request_nonce
        assert pending.remote_enr_seq == remote_enr_seq

    def test_handshake_overwrites_previous_pending(self, manager):
        """Starting new handshake overwrites any previous pending state."""
        remote_node_id = bytes(32)

        # Start first handshake.
        pending1 = manager.start_handshake(remote_node_id)
        timestamp1 = pending1.started_at

        # Wait a bit and start another.
        time.sleep(0.01)
        pending2 = manager.start_handshake(remote_node_id)

        # Should have new pending with later timestamp.
        assert pending2.started_at > timestamp1
        assert manager.get_pending(remote_node_id) is pending2


class TestHandshakeValidation:
    """Handshake security validation tests."""

    def test_handle_handshake_requires_pending_state(self, manager, remote_keypair):
        """Handshake fails if no pending state exists for the remote."""
        remote_priv, remote_pub, remote_node_id = remote_keypair

        # Create fake handshake authdata.
        fake_authdata = HandshakeAuthdata(
            src_id=NodeId(remote_node_id),
            sig_size=64,
            eph_key_size=33,
            id_signature=bytes(64),
            eph_pubkey=bytes(33),
            record=None,
        )

        # Should fail because no WHOAREYOU was sent.
        with pytest.raises(HandshakeError, match="No pending handshake"):
            manager.handle_handshake(NodeId(remote_node_id), fake_authdata)

    def test_handle_handshake_requires_sent_whoareyou_state(self, manager, remote_keypair):
        """Handshake fails if not in SENT_WHOAREYOU state."""
        remote_priv, remote_pub, remote_node_id = remote_keypair

        # Start handshake (puts in SENT_ORDINARY state).
        manager.start_handshake(NodeId(remote_node_id))

        fake_authdata = HandshakeAuthdata(
            src_id=NodeId(remote_node_id),
            sig_size=64,
            eph_key_size=33,
            id_signature=bytes(64),
            eph_pubkey=bytes(33),
            record=None,
        )

        # Should fail because we're in SENT_ORDINARY, not SENT_WHOAREYOU.
        with pytest.raises(HandshakeError, match="Unexpected handshake state"):
            manager.handle_handshake(NodeId(remote_node_id), fake_authdata)

    def test_handle_handshake_rejects_src_id_mismatch(self, manager, remote_keypair):
        """Handshake fails if src_id doesn't match expected remote."""
        remote_priv, remote_pub, remote_node_id = remote_keypair

        # Set up WHOAREYOU state.
        manager.create_whoareyou(
            NodeId(remote_node_id),
            bytes(12),
            0,
            bytes(16),
        )

        # Create authdata with different src_id.
        wrong_src_id = NodeId(bytes([0xFF] * 32))
        fake_authdata = HandshakeAuthdata(
            src_id=wrong_src_id,
            sig_size=64,
            eph_key_size=33,
            id_signature=bytes(64),
            eph_pubkey=bytes(33),
            record=None,
        )

        # Should fail due to source ID mismatch.
        with pytest.raises(HandshakeError, match="Source ID mismatch"):
            manager.handle_handshake(NodeId(remote_node_id), fake_authdata)

    def test_handle_handshake_requires_enr_when_seq_zero(self, manager, remote_keypair):
        """Handshake fails if enr_seq=0 and no ENR included.

        When we don't know the remote's ENR (signaled by enr_seq=0 in WHOAREYOU),
        the remote MUST include their ENR in the HANDSHAKE response.
        """
        remote_priv, remote_pub, remote_node_id = remote_keypair

        # Set up WHOAREYOU with enr_seq=0 (unknown).
        manager.create_whoareyou(
            NodeId(remote_node_id),
            bytes(12),
            0,  # enr_seq = 0 means we don't know remote's ENR
            bytes(16),
        )

        # Create authdata without ENR record.
        fake_authdata = HandshakeAuthdata(
            src_id=NodeId(remote_node_id),
            sig_size=64,
            eph_key_size=33,
            id_signature=bytes(64),
            eph_pubkey=bytes(33),
            record=None,  # No ENR included.
        )

        # Should fail because ENR is required.
        with pytest.raises(HandshakeError, match="ENR required"):
            manager.handle_handshake(NodeId(remote_node_id), fake_authdata)

    def test_successful_handshake_with_signature_verification(
        self, manager, remote_keypair, session_cache
    ):
        """Full handshake succeeds when signature is valid.

        Exercises the complete WHOAREYOU -> HANDSHAKE -> session flow.
        """
        remote_priv, remote_pub, remote_node_id = remote_keypair

        # Node A (manager) creates WHOAREYOU for remote.
        masking_iv = bytes(16)
        id_nonce, authdata, nonce, challenge_data = manager.create_whoareyou(
            NodeId(remote_node_id), bytes(12), 0, masking_iv
        )

        # Remote creates handshake response.
        eph_priv, eph_pub = generate_secp256k1_keypair()
        local_node_id = manager._local_node_id

        # Remote signs the id_nonce proving ownership.
        id_signature = sign_id_nonce(
            Bytes32(remote_priv),
            challenge_data,
            Bytes33(eph_pub),
            Bytes32(local_node_id),
        )

        # Remote includes their ENR since enr_seq=0.
        remote_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"id": b"v4", "secp256k1": bytes(remote_pub)},
        )

        authdata_bytes = encode_handshake_authdata(
            src_id=NodeId(remote_node_id),
            id_signature=id_signature,
            eph_pubkey=eph_pub,
            record=remote_enr.to_rlp(),
        )

        handshake = decode_handshake_authdata(authdata_bytes)

        # Manager processes handshake - should succeed.
        result = manager.handle_handshake(NodeId(remote_node_id), handshake)

        assert result is not None
        assert isinstance(result, HandshakeResult)
        assert result.session is not None
        assert len(result.session.send_key) == 16
        assert len(result.session.recv_key) == 16

    def test_handle_handshake_rejects_invalid_signature(
        self, manager, remote_keypair, session_cache
    ):
        """Handshake fails when signature is invalid."""
        remote_priv, remote_pub, remote_node_id = remote_keypair

        # Set up WHOAREYOU state.
        masking_iv = bytes(16)
        manager.create_whoareyou(NodeId(remote_node_id), bytes(12), 0, masking_iv)

        # Generate ephemeral key.
        _eph_priv, eph_pub = generate_secp256k1_keypair()

        # Create authdata with INVALID signature (all-zero 64 bytes).
        remote_enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={"id": b"v4", "secp256k1": bytes(remote_pub)},
        )

        authdata_bytes = encode_handshake_authdata(
            src_id=NodeId(remote_node_id),
            id_signature=bytes(64),  # Wrong signature.
            eph_pubkey=eph_pub,
            record=remote_enr.to_rlp(),
        )

        handshake = decode_handshake_authdata(authdata_bytes)

        with pytest.raises(HandshakeError, match="Invalid ID signature"):
            manager.handle_handshake(NodeId(remote_node_id), handshake)


class TestHandshakeConcurrency:
    """Concurrent handshake handling tests."""

    def test_multiple_handshakes_independent(self, manager):
        """Handshakes to different peers don't interfere."""
        remote1 = bytes.fromhex("01" + "00" * 31)
        remote2 = bytes.fromhex("02" + "00" * 31)
        remote3 = bytes.fromhex("03" + "00" * 31)

        # Start handshakes with different remotes.
        manager.start_handshake(remote1)
        manager.start_handshake(remote2)

        # Create WHOAREYOU for third remote.
        manager.create_whoareyou(remote3, bytes(12), 0, bytes(16))

        # All should have independent state.
        assert manager.get_pending(remote1).state == HandshakeState.SENT_ORDINARY
        assert manager.get_pending(remote2).state == HandshakeState.SENT_ORDINARY
        assert manager.get_pending(remote3).state == HandshakeState.SENT_WHOAREYOU

    def test_cancel_one_handshake_preserves_others(self, manager):
        """Canceling one handshake doesn't affect others."""
        remote1 = bytes.fromhex("01" + "00" * 31)
        remote2 = bytes.fromhex("02" + "00" * 31)

        manager.start_handshake(remote1)
        manager.start_handshake(remote2)

        # Cancel first.
        result = manager.cancel_handshake(remote1)
        assert result is True

        # First should be gone, second should remain.
        assert manager.get_pending(remote1) is None
        assert manager.get_pending(remote2) is not None
        assert manager.get_pending(remote2).state == HandshakeState.SENT_ORDINARY

    def test_expired_handshake_cleanup_selective(self, manager):
        """Cleanup only removes expired handshakes."""
        remote1 = bytes.fromhex("01" + "00" * 31)
        remote2 = bytes.fromhex("02" + "00" * 31)

        # Set short timeout.
        manager._timeout_secs = 0.01

        # Start first handshake.
        manager.start_handshake(remote1)

        # Wait for expiry.
        time.sleep(0.02)

        # Start second handshake (not expired yet).
        manager.start_handshake(remote2)

        # Cleanup should remove only expired.
        removed = manager.cleanup_expired()
        assert removed == 1

        assert manager.get_pending(remote1) is None
        assert manager.get_pending(remote2) is not None

    def test_get_pending_returns_none_for_expired(self, manager):
        """Getting an expired pending handshake returns None and cleans up."""
        remote = bytes.fromhex("01" + "00" * 31)

        manager._timeout_secs = 0.01
        manager.start_handshake(remote)

        time.sleep(0.02)

        # Should return None because expired.
        pending = manager.get_pending(remote)
        assert pending is None

    def test_id_nonce_uniqueness_across_challenges(self, manager):
        """Each WHOAREYOU challenge has a unique id_nonce."""
        remote1 = bytes.fromhex("01" + "00" * 31)
        remote2 = bytes.fromhex("02" + "00" * 31)

        id_nonce1, _, _, _ = manager.create_whoareyou(remote1, bytes(12), 0, bytes(16))
        id_nonce2, _, _, _ = manager.create_whoareyou(remote2, bytes(12), 0, bytes(16))

        # Each challenge should have unique id_nonce.
        assert id_nonce1 != id_nonce2


class TestHandshakeEnrInclusion:
    """Tests for ENR inclusion/exclusion in HANDSHAKE responses."""

    def test_enr_included_when_remote_seq_is_stale(self, local_keypair, remote_keypair):
        """HANDSHAKE includes our ENR when remote's known seq is lower than ours.

        When the WHOAREYOU's enr_seq < our local_enr_seq, the remote has a
        stale copy of our ENR. We include our current ENR so they can update.
        """
        local_priv, local_pub, local_node_id = local_keypair
        remote_priv, remote_pub, remote_node_id = remote_keypair

        session_cache = SessionCache()
        manager = HandshakeManager(
            local_node_id=local_node_id,
            local_private_key=local_priv,
            local_enr_rlp=b"mock_enr_data",
            local_enr_seq=5,
            session_cache=session_cache,
        )

        # Remote creates WHOAREYOU with enr_seq=0 (stale).
        whoareyou = WhoAreYouAuthdata(
            id_nonce=IdNonce(bytes(16)),
            enr_seq=Uint64(0),
        )

        challenge_data = bytes(63)
        authdata, _, _ = manager.create_handshake_response(
            remote_node_id=NodeId(remote_node_id),
            whoareyou=whoareyou,
            remote_pubkey=bytes(remote_pub),
            challenge_data=challenge_data,
        )

        # Decode authdata and verify ENR is present.
        decoded = decode_handshake_authdata(authdata)
        assert decoded.record is not None

    def test_enr_excluded_when_remote_seq_is_current(self, local_keypair, remote_keypair):
        """HANDSHAKE excludes our ENR when remote's known seq >= ours.

        When the remote already has our current ENR, sending it again
        wastes bandwidth. The handshake packet should omit the record.
        """
        local_priv, local_pub, local_node_id = local_keypair
        remote_priv, remote_pub, remote_node_id = remote_keypair

        session_cache = SessionCache()
        manager = HandshakeManager(
            local_node_id=local_node_id,
            local_private_key=local_priv,
            local_enr_rlp=b"mock_enr_data",
            local_enr_seq=5,
            session_cache=session_cache,
        )

        # Remote creates WHOAREYOU with enr_seq=5 (current).
        whoareyou = WhoAreYouAuthdata(
            id_nonce=IdNonce(bytes(16)),
            enr_seq=Uint64(5),
        )

        challenge_data = bytes(63)
        authdata, _, _ = manager.create_handshake_response(
            remote_node_id=NodeId(remote_node_id),
            whoareyou=whoareyou,
            remote_pubkey=bytes(remote_pub),
            challenge_data=challenge_data,
        )

        # Decode authdata and verify ENR is absent.
        decoded = decode_handshake_authdata(authdata)
        assert decoded.record is None


class TestHandshakeENRCache:
    """Tests for ENR caching in handshake manager."""

    def test_register_enr_stores_in_cache(self, manager):
        """Registered ENRs are retrievable from cache."""
        remote_node_id = compute_node_id(NODE_B_PUBKEY)

        enr = ENR(
            signature=Bytes64(bytes(64)),
            seq=Uint64(1),
            pairs={
                "id": b"v4",
                "secp256k1": NODE_B_PUBKEY,
            },
        )

        manager.register_enr(remote_node_id, enr)

        cached = manager.get_cached_enr(remote_node_id)
        assert cached is enr

    def test_get_cached_enr_returns_none_for_unknown(self, manager):
        """Getting uncached ENR returns None."""
        unknown_id = bytes(32)
        assert manager.get_cached_enr(unknown_id) is None
