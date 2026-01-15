"""Shared test utilities and fixtures for sync service tests."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    BlockWithAttestation,
    Checkpoint,
    SignedBlockWithAttestation,
    State,
    Validator,
)
from lean_spec.subspecs.containers.block import BlockSignatures
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.peer.info import PeerInfo
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.types import ConnectionState
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.constants import PROD_CONFIG
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.types import HashDigestList, HashTreeOpening, Randomness
from lean_spec.types import Bytes32, Bytes52, Uint64


@pytest.fixture
def peer_id() -> PeerId:
    """Provide a sample peer ID for tests."""
    return PeerId.from_base58("16Uiu2HAmTestPeer123")


@pytest.fixture
def peer_id_2() -> PeerId:
    """Provide a second sample peer ID for tests."""
    return PeerId.from_base58("16Uiu2HAmTestPeer456")


@pytest.fixture
def peer_id_3() -> PeerId:
    """Provide a third sample peer ID for tests."""
    return PeerId.from_base58("16Uiu2HAmTestPeer789")


@pytest.fixture
def connected_peer_info(peer_id: PeerId) -> PeerInfo:
    """Provide a connected peer info for tests."""
    return PeerInfo(
        peer_id=peer_id,
        state=ConnectionState.CONNECTED,
        address="/ip4/192.168.1.1/tcp/9000",
    )


@pytest.fixture
def disconnected_peer_info(peer_id: PeerId) -> PeerInfo:
    """Provide a disconnected peer info for tests."""
    return PeerInfo(
        peer_id=peer_id,
        state=ConnectionState.DISCONNECTED,
        address="/ip4/192.168.1.2/tcp/9000",
    )


@pytest.fixture
def sample_checkpoint() -> Checkpoint:
    """Provide a sample checkpoint for tests."""
    return Checkpoint(root=Bytes32.zero(), slot=Slot(100))


@pytest.fixture
def sample_status(sample_checkpoint: Checkpoint) -> Status:
    """Provide a sample Status message for tests."""
    return Status(
        finalized=sample_checkpoint,
        head=Checkpoint(root=Bytes32.zero(), slot=Slot(150)),
    )


@pytest.fixture
def genesis_state() -> State:
    """Provide a genesis state for tests."""
    validators = Validators(
        data=[Validator(pubkey=Bytes52(b"\x00" * 52), index=Uint64(i)) for i in range(3)]
    )
    return State.generate_genesis(genesis_time=Uint64(0), validators=validators)


@pytest.fixture
def genesis_block(genesis_state: State) -> Block:
    """Provide a genesis block for tests."""
    return Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )


@pytest.fixture
def base_store(genesis_state: State, genesis_block: Block) -> Store:
    """Provide a base Store initialized with genesis for tests."""
    return Store.get_forkchoice_store(genesis_state, genesis_block)


def create_mock_signature() -> Signature:
    """Create a minimal mock signature for testing."""
    return Signature(
        path=HashTreeOpening(siblings=HashDigestList(data=[])),
        rho=Randomness(data=[Fp(0) for _ in range(PROD_CONFIG.RAND_LEN_FE)]),
        hashes=HashDigestList(data=[]),
    )


def create_signed_block(
    slot: Slot,
    proposer_index: Uint64,
    parent_root: Bytes32,
    state_root: Bytes32,
) -> SignedBlockWithAttestation:
    """Create a signed block with minimal valid structure for testing."""
    block = Block(
        slot=slot,
        proposer_index=proposer_index,
        parent_root=parent_root,
        state_root=state_root,
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    block_root = hash_tree_root(block)

    attestation = Attestation(
        validator_id=proposer_index,
        data=AttestationData(
            slot=slot,
            head=Checkpoint(root=block_root, slot=slot),
            target=Checkpoint(root=block_root, slot=slot),
            source=Checkpoint(root=parent_root, slot=Slot(0)),
        ),
    )

    return SignedBlockWithAttestation(
        message=BlockWithAttestation(
            block=block,
            proposer_attestation=attestation,
        ),
        signature=BlockSignatures(
            attestation_signatures=AttestationSignatures(data=[]),
            proposer_signature=create_mock_signature(),
        ),
    )


@pytest.fixture
def signed_block_factory() -> type:
    """Factory fixture for creating signed blocks."""

    class SignedBlockFactory:
        """Factory for creating signed blocks with different parameters."""

        @staticmethod
        def create(
            slot: int = 1,
            proposer_index: int = 0,
            parent_root: Bytes32 | None = None,
            state_root: Bytes32 | None = None,
        ) -> SignedBlockWithAttestation:
            """Create a signed block with the given parameters."""
            return create_signed_block(
                slot=Slot(slot),
                proposer_index=Uint64(proposer_index),
                parent_root=parent_root or Bytes32.zero(),
                state_root=state_root or Bytes32.zero(),
            )

    return SignedBlockFactory
