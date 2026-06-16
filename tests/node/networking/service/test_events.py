"""Tests for the network event dataclasses."""

from __future__ import annotations

import dataclasses
from typing import get_args

import pytest

from consensus_testing import make_signed_block
from consensus_testing.keys import XmssKeyManager, create_dummy_signature
from lean_spec.node.networking import PeerId
from lean_spec.node.networking.gossipsub.topic import GossipTopic
from lean_spec.node.networking.reqresp.message import Status
from lean_spec.node.networking.service.events import (
    GossipAggregatedAttestationEvent,
    GossipAttestationEvent,
    GossipBlockEvent,
    NetworkEvent,
    PeerConnectedEvent,
    PeerDisconnectedEvent,
    PeerStatusEvent,
)
from lean_spec.spec.forks import Checkpoint, Slot, SubnetId, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AttestationData,
    SignedAggregatedAttestation,
    SignedAttestation,
)
from lean_spec.spec.ssz import Bytes32

FORK_DIGEST = "0x12345678"


def _sample_attestation_data() -> AttestationData:
    """Build slot-1 attestation data voting for the genesis source."""
    return AttestationData(
        slot=Slot(1),
        head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
        target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
        source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
    )


def _sample_signed_attestation() -> SignedAttestation:
    """Build a signed attestation from validator 1 over slot-1 data."""
    return SignedAttestation(
        validator_index=ValidatorIndex(1),
        data=_sample_attestation_data(),
        signature=create_dummy_signature(),
    )


def _sample_signed_aggregate() -> SignedAggregatedAttestation:
    """Build a signed aggregated attestation for validator 0 over slot-1 data."""
    attestation_data = _sample_attestation_data()
    return SignedAggregatedAttestation(
        data=attestation_data,
        proof=XmssKeyManager.shared().sign_and_aggregate([ValidatorIndex(0)], attestation_data),
    )


class TestGossipBlockEvent:
    """Tests for GossipBlockEvent."""

    def test_stores_all_fields(self, peer_id: PeerId) -> None:
        """The block, peer, and topic are stored exactly as passed."""
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        topic = GossipTopic.block(FORK_DIGEST)

        event = GossipBlockEvent(block=block, peer_id=peer_id, topic=topic)

        assert event == GossipBlockEvent(block=block, peer_id=peer_id, topic=topic)
        assert (event.block, event.peer_id, event.topic) == (block, peer_id, topic)

    def test_is_frozen(self, peer_id: PeerId) -> None:
        """Reassigning a field raises because the event is frozen."""
        block = make_signed_block(
            slot=Slot(1),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
        )
        event = GossipBlockEvent(block=block, peer_id=peer_id, topic=GossipTopic.block(FORK_DIGEST))

        with pytest.raises(dataclasses.FrozenInstanceError) as exception_info:
            event.peer_id = peer_id  # type: ignore[misc]
        assert str(exception_info.value) == "cannot assign to field 'peer_id'"


class TestGossipAttestationEvent:
    """Tests for GossipAttestationEvent."""

    def test_stores_all_fields(self, peer_id: PeerId) -> None:
        """The attestation, peer, and topic are stored exactly as passed."""
        attestation = _sample_signed_attestation()
        topic = GossipTopic.attestation_subnet(FORK_DIGEST, SubnetId(0))

        event = GossipAttestationEvent(attestation=attestation, peer_id=peer_id, topic=topic)

        assert event == GossipAttestationEvent(
            attestation=attestation, peer_id=peer_id, topic=topic
        )
        assert (event.attestation, event.peer_id, event.topic) == (attestation, peer_id, topic)

    def test_is_frozen(self, peer_id: PeerId) -> None:
        """Reassigning a field raises because the event is frozen."""
        event = GossipAttestationEvent(
            attestation=_sample_signed_attestation(),
            peer_id=peer_id,
            topic=GossipTopic.attestation_subnet(FORK_DIGEST, SubnetId(0)),
        )

        with pytest.raises(dataclasses.FrozenInstanceError) as exception_info:
            event.peer_id = peer_id  # type: ignore[misc]
        assert str(exception_info.value) == "cannot assign to field 'peer_id'"


class TestGossipAggregatedAttestationEvent:
    """Tests for GossipAggregatedAttestationEvent."""

    def test_stores_all_fields(self, peer_id: PeerId) -> None:
        """The aggregate, peer, and topic are stored exactly as passed."""
        signed_aggregate = _sample_signed_aggregate()
        topic = GossipTopic.committee_aggregation(FORK_DIGEST)

        event = GossipAggregatedAttestationEvent(
            signed_attestation=signed_aggregate, peer_id=peer_id, topic=topic
        )

        assert event == GossipAggregatedAttestationEvent(
            signed_attestation=signed_aggregate, peer_id=peer_id, topic=topic
        )
        assert (event.signed_attestation, event.peer_id, event.topic) == (
            signed_aggregate,
            peer_id,
            topic,
        )

    def test_is_frozen(self, peer_id: PeerId) -> None:
        """Reassigning a field raises because the event is frozen."""
        event = GossipAggregatedAttestationEvent(
            signed_attestation=_sample_signed_aggregate(),
            peer_id=peer_id,
            topic=GossipTopic.committee_aggregation(FORK_DIGEST),
        )

        with pytest.raises(dataclasses.FrozenInstanceError) as exception_info:
            event.peer_id = peer_id  # type: ignore[misc]
        assert str(exception_info.value) == "cannot assign to field 'peer_id'"


class TestPeerStatusEvent:
    """Tests for PeerStatusEvent."""

    def test_stores_all_fields(self, peer_id: PeerId) -> None:
        """The peer and reported status are stored exactly as passed."""
        status = Status(
            finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )

        event = PeerStatusEvent(peer_id=peer_id, status=status)

        assert event == PeerStatusEvent(peer_id=peer_id, status=status)
        assert (event.peer_id, event.status) == (peer_id, status)

    def test_is_frozen(self, peer_id: PeerId) -> None:
        """Reassigning a field raises because the event is frozen."""
        event = PeerStatusEvent(
            peer_id=peer_id,
            status=Status(
                finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
                head=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            ),
        )

        with pytest.raises(dataclasses.FrozenInstanceError) as exception_info:
            event.peer_id = peer_id  # type: ignore[misc]
        assert str(exception_info.value) == "cannot assign to field 'peer_id'"


class TestPeerConnectedEvent:
    """Tests for PeerConnectedEvent."""

    def test_stores_peer_and_compares_by_value(self, peer_id: PeerId, peer_id_2: PeerId) -> None:
        """Equality holds for the same peer and fails for a different peer."""
        event = PeerConnectedEvent(peer_id=peer_id)

        assert event == PeerConnectedEvent(peer_id=peer_id)
        assert event.peer_id == peer_id
        assert event != PeerConnectedEvent(peer_id=peer_id_2)

    def test_is_frozen(self, peer_id: PeerId, peer_id_2: PeerId) -> None:
        """Reassigning a field raises because the event is frozen."""
        event = PeerConnectedEvent(peer_id=peer_id)

        with pytest.raises(dataclasses.FrozenInstanceError) as exception_info:
            event.peer_id = peer_id_2  # type: ignore[misc]
        assert str(exception_info.value) == "cannot assign to field 'peer_id'"


class TestPeerDisconnectedEvent:
    """Tests for PeerDisconnectedEvent."""

    def test_stores_peer_and_compares_by_value(self, peer_id: PeerId, peer_id_2: PeerId) -> None:
        """Equality holds for the same peer and fails for a different peer."""
        event = PeerDisconnectedEvent(peer_id=peer_id)

        assert event == PeerDisconnectedEvent(peer_id=peer_id)
        assert event.peer_id == peer_id
        assert event != PeerDisconnectedEvent(peer_id=peer_id_2)

    def test_distinct_from_connected_event(self, peer_id: PeerId) -> None:
        """A disconnect event never equals a connect event for the same peer."""
        assert PeerDisconnectedEvent(peer_id=peer_id) != PeerConnectedEvent(peer_id=peer_id)

    def test_is_frozen(self, peer_id: PeerId, peer_id_2: PeerId) -> None:
        """Reassigning a field raises because the event is frozen."""
        event = PeerDisconnectedEvent(peer_id=peer_id)

        with pytest.raises(dataclasses.FrozenInstanceError) as exception_info:
            event.peer_id = peer_id_2  # type: ignore[misc]
        assert str(exception_info.value) == "cannot assign to field 'peer_id'"


class TestNetworkEventUnion:
    """Tests for the NetworkEvent union."""

    def test_union_members(self) -> None:
        """The union contains exactly the six concrete event types."""
        assert get_args(NetworkEvent.__value__) == (
            GossipBlockEvent,
            GossipAttestationEvent,
            GossipAggregatedAttestationEvent,
            PeerStatusEvent,
            PeerConnectedEvent,
            PeerDisconnectedEvent,
        )
