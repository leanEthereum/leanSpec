"""
Factory functions for constructing test fixtures.

Provides deterministic builders for all core container types.
Each function creates minimal valid instances suitable for unit tests.
"""

from __future__ import annotations

from typing import NamedTuple, cast

from consensus_testing.keys import XmssKeyManager, get_shared_key_manager

from lean_spec.subspecs.chain.clock import SlotClock
from lean_spec.subspecs.chain.config import SECONDS_PER_SLOT
from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    BlockWithAttestation,
    Checkpoint,
    SignedAttestation,
    SignedBlockWithAttestation,
    State,
    Validator,
)
from lean_spec.subspecs.containers.attestation import AggregatedAttestation, AggregationBits
from lean_spec.subspecs.containers.block import BlockSignatures
from lean_spec.subspecs.containers.block.types import AggregatedAttestations, AttestationSignatures
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.networking import PeerId
from lean_spec.subspecs.networking.peer.info import PeerInfo
from lean_spec.subspecs.networking.reqresp.message import Status
from lean_spec.subspecs.networking.types import ConnectionState
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.sync.block_cache import BlockCache
from lean_spec.subspecs.sync.peer_manager import PeerManager
from lean_spec.subspecs.sync.service import SyncService
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof, SignatureKey
from lean_spec.subspecs.xmss.constants import PROD_CONFIG
from lean_spec.subspecs.xmss.containers import PublicKey, Signature
from lean_spec.subspecs.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    Randomness,
)
from lean_spec.types import Bytes32, Bytes52, Uint64

from .mocks import MockForkchoiceStore, MockNetworkRequester


def make_bytes32(seed: int) -> Bytes32:
    """Create a deterministic 32-byte value from a seed."""
    return Bytes32(bytes([seed % 256]) * 32)


def make_public_key_bytes(seed: int) -> bytes:
    """
    Encode a deterministic XMSS public key.

    Constructs valid root and parameter vectors seeded by the input.
    """
    root = HashDigestVector(data=[Fp(seed + i) for i in range(HashDigestVector.LENGTH)])
    parameter = Parameter(data=[Fp(seed + 100 + i) for i in range(Parameter.LENGTH)])
    public_key = PublicKey(root=root, parameter=parameter)
    return public_key.encode_bytes()


def make_mock_signature() -> Signature:
    """
    Create a minimal mock XMSS signature.

    Suitable for tests that require signature structure but skip verification.
    """
    return Signature(
        path=HashTreeOpening(siblings=HashDigestList(data=[])),
        rho=Randomness(data=[Fp(0) for _ in range(PROD_CONFIG.RAND_LEN_FE)]),
        hashes=HashDigestList(data=[]),
    )


def make_signature(seed: int) -> Signature:
    """
    Create a deterministic XMSS signature from a seed.

    Produces unique randomness values based on the seed.
    """
    randomness = Randomness(data=[Fp(seed + 200 + i) for i in range(Randomness.LENGTH)])
    return Signature(
        path=HashTreeOpening(siblings=HashDigestList(data=[])),
        rho=randomness,
        hashes=HashDigestList(data=[]),
    )


def make_validators(count: int) -> Validators:
    """
    Build a validator registry with null public keys.

    Validators are indexed 0 through count-1.
    """
    validators = [
        Validator(pubkey=Bytes52(b"\x00" * 52), index=ValidatorIndex(i)) for i in range(count)
    ]
    return Validators(data=validators)


def make_validators_with_keys(count: int) -> Validators:
    """
    Build a validator registry with deterministic XMSS public keys.

    Each validator gets a unique key derived from their index.
    """
    validators = [
        Validator(pubkey=Bytes52(make_public_key_bytes(i)), index=ValidatorIndex(i))
        for i in range(count)
    ]
    return Validators(data=validators)


def make_validators_from_key_manager(key_manager: XmssKeyManager, count: int) -> Validators:
    """Build a validator registry with real XMSS keys from a key manager."""
    return Validators(
        data=[
            Validator(
                pubkey=Bytes52(key_manager[ValidatorIndex(i)].public.encode_bytes()),
                index=ValidatorIndex(i),
            )
            for i in range(count)
        ]
    )


def make_genesis_state(
    num_validators: int = 3,
    genesis_time: int = 0,
    validators: Validators | None = None,
) -> State:
    """
    Create a genesis state with the specified validator count.

    Uses null public keys by default for simplicity.
    If validators is provided, uses them directly.
    """
    if validators is None:
        validators = make_validators(num_validators)
    return State.generate_genesis(genesis_time=Uint64(genesis_time), validators=validators)


def make_empty_block_body() -> BlockBody:
    """Create an empty block body with no attestations."""
    return BlockBody(attestations=AggregatedAttestations(data=[]))


def make_checkpoint(root_seed: int = 0, slot: int = 0) -> Checkpoint:
    """Create a checkpoint from a seed integer and slot."""
    return Checkpoint(root=make_bytes32(root_seed), slot=Slot(slot))


def make_attestation_data(
    slot: Slot,
    target_slot: Slot,
    target_root: Bytes32,
    source_slot: Slot,
    source_root: Bytes32,
) -> AttestationData:
    """Create attestation data with specific target and source checkpoints."""
    return AttestationData(
        slot=slot,
        head=Checkpoint(root=target_root, slot=target_slot),
        target=Checkpoint(root=target_root, slot=target_slot),
        source=Checkpoint(root=source_root, slot=source_slot),
    )


def make_genesis_block(state: State) -> Block:
    """
    Create a genesis block matching the given state.

    The state root is computed from the provided state.
    """
    return Block(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )


def make_block(
    state: State,
    slot: Slot,
    attestations: list[AggregatedAttestation],
) -> Block:
    """
    Create a block at the given slot with attestations.

    Proposer index is derived from slot modulo validator count.
    Parent root is computed from the state's latest block header.
    """
    body = BlockBody(attestations=AggregatedAttestations(data=attestations))
    parent_root = hash_tree_root(state.latest_block_header)
    proposer_index = ValidatorIndex(int(slot) % len(state.validators))

    return Block(
        slot=slot,
        proposer_index=proposer_index,
        parent_root=parent_root,
        state_root=Bytes32.zero(),
        body=body,
    )


def make_signed_block(
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
) -> SignedBlockWithAttestation:
    """
    Create a signed block with minimal valid structure.

    Includes a proposer attestation pointing to the new block.
    """
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
            proposer_signature=make_mock_signature(),
        ),
    )


def make_aggregated_attestation(
    participant_ids: list[int],
    attestation_slot: Slot,
    source: Checkpoint,
    target: Checkpoint,
) -> AggregatedAttestation:
    """
    Create an aggregated attestation from participating validators.

    Head checkpoint uses the target's root and slot.
    """
    data = AttestationData(
        slot=attestation_slot,
        head=Checkpoint(root=target.root, slot=target.slot),
        target=target,
        source=source,
    )

    return AggregatedAttestation(
        aggregation_bits=AggregationBits.from_validator_indices(
            [ValidatorIndex(i) for i in participant_ids]
        ),
        data=data,
    )


def make_signed_attestation(
    validator: ValidatorIndex,
    target: Checkpoint,
    source: Checkpoint | None = None,
) -> SignedAttestation:
    """
    Construct a signed attestation for a single validator.

    Source defaults to a zero checkpoint if not provided.
    """
    source_checkpoint = source or Checkpoint(root=Bytes32.zero(), slot=Slot(0))
    attestation_data = AttestationData(
        slot=target.slot,
        head=target,
        target=target,
        source=source_checkpoint,
    )
    return SignedAttestation(
        validator_id=validator,
        message=attestation_data,
        signature=make_mock_signature(),
    )


def make_test_status() -> Status:
    """Create a valid Status message for testing."""
    return Status(
        finalized=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(100)),
        head=Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(200)),
    )


def make_test_block(slot: int = 1, seed: int = 0) -> SignedBlockWithAttestation:
    """Create a SignedBlockWithAttestation with convenient defaults for testing."""
    return make_signed_block(
        slot=Slot(slot),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32(bytes([seed]) * 32),
        state_root=Bytes32(bytes([seed + 1]) * 32),
    )


def make_challenge_data(id_nonce: bytes = bytes(16), *, nonce: bytes = bytes(12)) -> bytes:
    """Build mock Discovery v5 challenge_data for testing.

    Format: masking-iv (16) + static-header (23) + authdata (24) = 63 bytes.
    The authdata contains the id_nonce (16) + enr_seq (8).
    """
    masking_iv = bytes(16)
    # static-header: protocol-id (6) + version (2) + flag (1) + nonce (12) + authdata-size (2)
    static_header = b"discv5" + b"\x00\x01\x01" + nonce + b"\x00\x18"
    # authdata: id-nonce (16) + enr-seq (8)
    authdata = id_nonce + bytes(8)
    return masking_iv + static_header + authdata


_DEFAULT_VALIDATOR_ID = ValidatorIndex(0)
_DEFAULT_ATTESTATION_SLOT = Slot(1)


class GenesisData(NamedTuple):
    """All three genesis artifacts for tests that need more than just the store."""

    store: Store
    state: State
    block: Block


def make_genesis_data(
    num_validators: int = 3,
    genesis_time: int = 0,
    key_manager: XmssKeyManager | None = None,
    validator_id: ValidatorIndex | None = _DEFAULT_VALIDATOR_ID,
) -> GenesisData:
    """Create a forkchoice store with genesis state and block, returning all three."""
    if key_manager is not None:
        validators = make_validators_from_key_manager(key_manager, num_validators)
    else:
        validators = make_validators(num_validators)
    genesis_state = make_genesis_state(validators=validators, genesis_time=genesis_time)
    genesis_block = make_genesis_block(genesis_state)
    store = Store.get_forkchoice_store(genesis_state, genesis_block, validator_id=validator_id)
    return GenesisData(store, genesis_state, genesis_block)


def make_store(
    num_validators: int = 3,
    validator_id: ValidatorIndex | None = _DEFAULT_VALIDATOR_ID,
    genesis_time: int = 0,
    key_manager: XmssKeyManager | None = None,
) -> Store:
    """Create a forkchoice store initialized with genesis."""
    return make_genesis_data(
        num_validators=num_validators,
        genesis_time=genesis_time,
        key_manager=key_manager,
        validator_id=validator_id,
    ).store


def make_store_with_attestation_data(
    key_manager: XmssKeyManager,
    num_validators: int,
    validator_id: ValidatorIndex,
    attestation_slot: Slot = _DEFAULT_ATTESTATION_SLOT,
) -> tuple[Store, AttestationData]:
    """Create a store with validators and produce attestation data for testing."""
    store = make_store(
        num_validators=num_validators,
        validator_id=validator_id,
        key_manager=key_manager,
    )
    attestation_data = store.produce_attestation_data(attestation_slot)
    return store, attestation_data


def make_store_with_gossip_signatures(
    key_manager: XmssKeyManager,
    num_validators: int,
    validator_id: ValidatorIndex,
    attesting_validators: list[ValidatorIndex],
    attestation_slot: Slot = _DEFAULT_ATTESTATION_SLOT,
) -> tuple[Store, AttestationData]:
    """Create a store pre-populated with gossip signatures for testing aggregation."""
    store, attestation_data = make_store_with_attestation_data(
        key_manager,
        num_validators,
        validator_id,
        attestation_slot,
    )
    data_root = attestation_data.data_root_bytes()
    gossip_signatures = {
        SignatureKey(vid, data_root): key_manager.sign_attestation_data(vid, attestation_data)
        for vid in attesting_validators
    }
    store = store.model_copy(
        update={
            "gossip_signatures": gossip_signatures,
            "attestation_data_by_root": {data_root: attestation_data},
        }
    )
    return store, attestation_data


def make_attestation_data_simple(
    slot: int,
    head_root: Bytes32,
    target_root: Bytes32,
    source: Checkpoint,
) -> AttestationData:
    """Create attestation data with head/target roots and a source checkpoint."""
    return AttestationData(
        slot=Slot(slot),
        head=Checkpoint(root=head_root, slot=Slot(slot)),
        target=Checkpoint(root=target_root, slot=Slot(slot)),
        source=source,
    )


def make_keyed_genesis_state(
    num_validators: int,
    key_manager: XmssKeyManager | None = None,
) -> State:
    """Create a genesis state with real XMSS keys from the shared key manager."""
    if key_manager is None:
        key_manager = get_shared_key_manager()
    validators = make_validators_from_key_manager(key_manager, num_validators)
    return make_genesis_state(validators=validators)


def make_aggregated_proof(
    key_manager: XmssKeyManager,
    participants: list[ValidatorIndex],
    attestation_data: AttestationData,
) -> AggregatedSignatureProof:
    """Create a valid aggregated signature proof for the given participants."""
    data_root = attestation_data.data_root_bytes()
    return AggregatedSignatureProof.aggregate(
        participants=AggregationBits.from_validator_indices(participants),
        public_keys=[key_manager.get_public_key(vid) for vid in participants],
        signatures=[
            key_manager.sign_attestation_data(vid, attestation_data) for vid in participants
        ],
        message=data_root,
        epoch=attestation_data.slot,
    )


def make_signed_block_from_store(
    store: Store,
    key_manager: XmssKeyManager,
    slot: Slot,
    proposer_index: ValidatorIndex,
) -> tuple[Store, SignedBlockWithAttestation]:
    """Produce a signed block and advance the consumer store to accept it.

    Returns the updated store (with time advanced) and the signed block.
    """
    _, block, _ = store.produce_block_with_signatures(slot, proposer_index)
    block_root = hash_tree_root(block)
    parent_state = store.states[block.parent_root]

    proposer_attestation = Attestation(
        validator_id=proposer_index,
        data=AttestationData(
            slot=slot,
            head=Checkpoint(root=block_root, slot=slot),
            target=Checkpoint(root=block_root, slot=slot),
            source=Checkpoint(
                root=block.parent_root,
                slot=parent_state.latest_block_header.slot,
            ),
        ),
    )
    proposer_signature = key_manager.sign_attestation_data(
        proposer_index, proposer_attestation.data
    )
    attestation_signatures = key_manager.build_attestation_signatures(block.body.attestations)

    signed_block = SignedBlockWithAttestation(
        message=BlockWithAttestation(
            block=block,
            proposer_attestation=proposer_attestation,
        ),
        signature=BlockSignatures(
            attestation_signatures=attestation_signatures,
            proposer_signature=proposer_signature,
        ),
    )

    slot_duration = block.slot * SECONDS_PER_SLOT
    block_time = store.config.genesis_time + slot_duration
    advanced_store, _ = store.on_tick(block_time, has_proposal=True)

    return advanced_store, signed_block


def create_mock_sync_service(peer_id: PeerId) -> SyncService:
    """Create a SyncService with mock dependencies for integration testing."""
    mock_store = MockForkchoiceStore(head_slot=0)
    peer_manager = PeerManager()
    peer_manager.add_peer(PeerInfo(peer_id=peer_id, state=ConnectionState.CONNECTED))

    return SyncService(
        store=cast(Store, mock_store),
        peer_manager=peer_manager,
        block_cache=BlockCache(),
        clock=SlotClock(genesis_time=Uint64(0), time_fn=lambda: 1000.0),
        network=MockNetworkRequester(),
        process_block=lambda s, b: s.on_block(b),
    )
