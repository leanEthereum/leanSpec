"""Tests for Store attestation handling."""

from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.chain.config import SECONDS_PER_SLOT
from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
    SignedAttestation,
)
from lean_spec.subspecs.containers.block import (
    Block,
    BlockBody,
    BlockSignatures,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Bytes52, Uint64


def test_on_block_processes_multi_validator_aggregations() -> None:
    """Ensure Store.on_block handles aggregated attestations with many validators."""
    key_manager = XmssKeyManager(max_slot=Slot(10))
    validators = Validators(
        data=[
            Validator(pubkey=Bytes52(key_manager[Uint64(i)].public.encode_bytes()), index=Uint64(i))
            for i in range(3)
        ]
    )
    genesis_state = State.generate_genesis(genesis_time=Uint64(0), validators=validators)
    genesis_block = Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    base_store = Store.get_forkchoice_store(genesis_state, genesis_block)
    consumer_store = base_store

    # Producer view knows about attestations from validators 1 and 2
    attestation_slot = Slot(1)
    attestation_data = base_store.produce_attestation_data(attestation_slot)

    # Store attestation data in latest_known_attestations
    attestation_data_map = {
        validator_id: attestation_data
        for validator_id in (Uint64(1), Uint64(2))
    }

    # Store signatures in gossip_attestation_signatures
    data_root = attestation_data.data_root_bytes()
    gossip_sigs = {
        (validator_id, data_root): key_manager.sign_attestation_data(validator_id, attestation_data)
        for validator_id in (Uint64(1), Uint64(2))
    }

    producer_store = base_store.model_copy(
        update={
            "latest_known_attestations": attestation_data_map,
            "gossip_attestation_signatures": gossip_sigs,
        }
    )

    # For slot 1 with 3 validators: 1 % 3 == 1, so validator 1 is the proposer
    proposer_index = Uint64(1)
    _, block, _ = producer_store.produce_block_with_signatures(
        attestation_slot,
        proposer_index,
    )

    block_root = hash_tree_root(block)
    parent_state = producer_store.states[block.parent_root]
    proposer_attestation = Attestation(
        validator_id=proposer_index,
        data=AttestationData(
            slot=attestation_slot,
            head=Checkpoint(root=block_root, slot=attestation_slot),
            target=Checkpoint(root=block_root, slot=attestation_slot),
            source=Checkpoint(root=block.parent_root, slot=parent_state.latest_block_header.slot),
        ),
    )
    proposer_signature = key_manager.sign_attestation_data(
        proposer_attestation.validator_id,
        proposer_attestation.data,
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

    # Advance consumer store time to block's slot before processing
    block_time = consumer_store.config.genesis_time + block.slot * Uint64(SECONDS_PER_SLOT)
    consumer_store = consumer_store.on_tick(block_time, has_proposal=True)

    updated_store = consumer_store.on_block(signed_block)

    assert Uint64(1) in updated_store.latest_known_attestations
    assert Uint64(2) in updated_store.latest_known_attestations
    assert updated_store.latest_known_attestations[Uint64(1)] == attestation_data
    assert updated_store.latest_known_attestations[Uint64(2)] == attestation_data
