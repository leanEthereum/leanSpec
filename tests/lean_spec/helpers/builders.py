"""
Factory functions for constructing test fixtures.

Provides deterministic builders for all core container types.
Each function creates minimal valid instances suitable for unit tests.
"""

from __future__ import annotations

from typing import NamedTuple, cast

from consensus_testing.keys import XmssKeyManager

from lean_spec.node.chain.clock import Interval, SlotClock
from lean_spec.node.networking import PeerId
from lean_spec.node.networking.peer import PeerInfo
from lean_spec.node.networking.reqresp.message import Status
from lean_spec.node.networking.types import ConnectionState
from lean_spec.node.storage import Database
from lean_spec.node.sync.block_cache import BlockCache
from lean_spec.node.sync.peer_manager import PeerManager
from lean_spec.node.sync.service import SyncService
from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.aggregation import TypeOneMultiSignature, TypeTwoMultiSignature
from lean_spec.spec.crypto.xmss.constants import TARGET_CONFIG
from lean_spec.spec.crypto.xmss.containers import Signature
from lean_spec.spec.crypto.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Randomness,
)
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex, ValidatorIndices
from lean_spec.spec.forks.lstar import AttestationSignatureEntry, State, Store
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    Validator,
    Validators,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import ByteList512KiB, Bytes32, Bytes52, Uint64

from .mocks import MockForkchoiceStore, MockNetworkRequester, StoreInterceptingSpec


def make_bytes32(seed: int) -> Bytes32:
    """Create a deterministic 32-byte value from a seed."""
    return Bytes32(bytes([seed % 256]) * 32)


def _zero_digest() -> HashDigestVector:
    """Create a zero-filled hash digest vector."""
    return HashDigestVector(data=[Fp(0)] * TARGET_CONFIG.HASH_LEN_FE)


def make_mock_signature() -> Signature:
    """
    Create a mock XMSS signature with correctly-sized fields.

    Fills path, rho, and hashes with zeros at the exact dimensions
    required by the active scheme. This ensures the signature serializes
    to exactly SIGNATURE_LEN_BYTES, matching the fixed-size SSZ encoding.
    """
    return Signature(
        path=HashTreeOpening(
            siblings=HashDigestList(
                data=[_zero_digest() for _ in range(TARGET_CONFIG.LOG_LIFETIME)]
            )
        ),
        rho=Randomness(data=[Fp(0)] * TARGET_CONFIG.RAND_LEN_FE),
        hashes=HashDigestList(data=[_zero_digest() for _ in range(TARGET_CONFIG.DIMENSION)]),
    )


def make_validators(count: int) -> Validators:
    """
    Build a validator registry with null public keys.

    Validators are indexed 0 through count-1.
    """
    validators = [
        Validator(
            attestation_pubkey=Bytes52(b"\x00" * 52),
            proposal_pubkey=Bytes52(b"\x00" * 52),
            index=ValidatorIndex(i),
        )
        for i in range(count)
    ]
    return Validators(data=validators)


def make_validators_from_key_manager(key_manager: XmssKeyManager, count: int) -> Validators:
    """Build a validator registry with real XMSS keys from a key manager."""
    validators = []
    for i in range(count):
        idx = ValidatorIndex(i)
        att_pk, prop_pk = key_manager.get_public_keys(idx)
        validators.append(
            Validator(
                attestation_pubkey=Bytes52(att_pk.encode_bytes()),
                proposal_pubkey=Bytes52(prop_pk.encode_bytes()),
                index=idx,
            )
        )
    return Validators(data=validators)


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
    return LstarSpec().generate_genesis(genesis_time=Uint64(genesis_time), validators=validators)


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
) -> SignedBlock:
    """Create a signed block with minimal valid structure."""
    block = Block(
        slot=slot,
        proposer_index=proposer_index,
        parent_root=parent_root,
        state_root=state_root,
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    return SignedBlock(block=block, proof=ByteList512KiB(data=b""))


def make_aggregated_attestation(
    participant_ids: list[ValidatorIndex],
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
        aggregation_bits=ValidatorIndices(data=participant_ids).to_aggregation_bits(),
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
        data=attestation_data,
        signature=make_mock_signature(),
    )


def make_test_status() -> Status:
    """Create a valid Status message for testing."""
    return Status(
        finalized=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(100)),
        head=Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(200)),
    )


def make_test_block(slot: int = 1, seed: int = 0) -> SignedBlock:
    """Create a SignedBlock with convenient defaults for testing."""
    return make_signed_block(
        slot=Slot(slot),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32(bytes([seed]) * 32),
        state_root=Bytes32(bytes([seed + 1]) * 32),
    )


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
    store = LstarSpec().create_store(genesis_state, genesis_block, validator_id=validator_id)
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
    store.time = Interval.from_slot(attestation_slot)
    attestation_data = LstarSpec().produce_attestation_data(store, attestation_slot)
    return store, attestation_data


def make_store_with_attestation_signatures(
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
    store.attestation_signatures = {
        attestation_data: {
            AttestationSignatureEntry(vid, key_manager.sign_attestation_data(vid, attestation_data))
            for vid in attesting_validators
        },
    }
    return store, attestation_data


def make_attestation_data_simple(
    slot: Slot,
    head_root: Bytes32,
    target_root: Bytes32,
    source: Checkpoint,
) -> AttestationData:
    """Create attestation data with head/target roots and a source checkpoint."""
    return AttestationData(
        slot=slot,
        head=Checkpoint(root=head_root, slot=slot),
        target=Checkpoint(root=target_root, slot=slot),
        source=source,
    )


def make_keyed_genesis_state(
    num_validators: int,
    key_manager: XmssKeyManager | None = None,
) -> State:
    """Create a genesis state with real XMSS keys from the shared key manager."""
    if key_manager is None:
        key_manager = XmssKeyManager.shared()
    validators = make_validators_from_key_manager(key_manager, num_validators)
    return make_genesis_state(validators=validators)


def make_aggregated_proof(
    key_manager: XmssKeyManager,
    participants: list[ValidatorIndex],
    attestation_data: AttestationData,
) -> TypeOneMultiSignature:
    """Create a valid Type-1 aggregated proof for the given participants."""
    data_root = hash_tree_root(attestation_data)
    raw_xmss = [
        (
            vid,
            key_manager.get_public_keys(vid)[0],
            key_manager.sign_attestation_data(vid, attestation_data),
        )
        for vid in participants
    ]
    return TypeOneMultiSignature.aggregate(
        children=[],
        raw_xmss=raw_xmss,
        message=data_root,
        slot=attestation_data.slot,
    )


def make_signed_aggregated_attestation(
    key_manager: XmssKeyManager | None = None,
    participants: list[ValidatorIndex] | None = None,
    attestation_data: AttestationData | None = None,
) -> "SignedAggregatedAttestation":
    """Create a valid signed aggregated attestation with real XMSS keys."""
    if key_manager is None:
        key_manager = XmssKeyManager.shared()
    if participants is None:
        participants = [ValidatorIndex(0)]
    if attestation_data is None:
        attestation_data = AttestationData(
            slot=Slot(1),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        )
    proof = make_aggregated_proof(key_manager, participants, attestation_data)
    return SignedAggregatedAttestation(data=attestation_data, proof=proof)


def make_signed_block_from_store(
    store: Store,
    key_manager: XmssKeyManager,
    slot: Slot,
    proposer_index: ValidatorIndex,
) -> tuple[Store, SignedBlock]:
    """Produce a signed block and advance the consumer store to accept it.

    Returns the updated store (with time advanced) and the signed block.
    The merged Type-2 proof is built honestly because callers usually
    feed the result through spec.on_block, which decodes and verifies
    the proof.
    """
    new_store, block, attestation_proofs = LstarSpec().produce_block_with_signatures(
        store, slot, proposer_index
    )
    block_root = hash_tree_root(block)

    head_state = new_store.states[new_store.head]
    public_keys_per_part: list[list] = [
        [
            head_state.validators[vid].get_attestation_pubkey()
            for vid in proof.participants.to_validator_indices()
        ]
        for proof in attestation_proofs
    ]
    proposer_pubkey = head_state.validators[proposer_index].get_proposal_pubkey()
    public_keys_per_part.append([proposer_pubkey])

    proposer_signature = key_manager.sign_block_root(proposer_index, slot, block_root)
    proposer_type_1 = TypeOneMultiSignature.aggregate(
        children=[],
        raw_xmss=[(proposer_index, proposer_pubkey, proposer_signature)],
        message=block_root,
        slot=slot,
    )

    merged = TypeTwoMultiSignature.aggregate(
        [*attestation_proofs, proposer_type_1],
        public_keys_per_part=public_keys_per_part,
    )

    signed_block = SignedBlock(
        block=block,
        proof=ByteList512KiB(data=merged.encode_bytes()),
    )

    target_interval = Interval.from_slot(block.slot)
    advanced_store, _ = LstarSpec().on_tick(store, target_interval, has_proposal=True)

    return advanced_store, signed_block


def create_mock_sync_service(
    peer_id: PeerId,
    *,
    database: Database | None = None,
    genesis_start: bool = False,
) -> SyncService:
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
        spec=StoreInterceptingSpec(),
        database=database,
        genesis_start=genesis_start,
    )
