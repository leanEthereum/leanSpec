"""
Factory functions for constructing test fixtures.

Provides deterministic builders for all core container types.
Each function creates minimal valid instances suitable for unit tests.
"""

from __future__ import annotations

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
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.ssz.hash import hash_tree_root
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

# -----------------------------------------------------------------------------
# Primitive Builders
# -----------------------------------------------------------------------------


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


# -----------------------------------------------------------------------------
# Signature Builders
# -----------------------------------------------------------------------------


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


# -----------------------------------------------------------------------------
# Validator Builders
# -----------------------------------------------------------------------------


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


# -----------------------------------------------------------------------------
# State Builders
# -----------------------------------------------------------------------------


def make_genesis_state(num_validators: int = 3, genesis_time: int = 0) -> State:
    """
    Create a genesis state with the specified validator count.

    Uses null public keys by default for simplicity.
    """
    validators = make_validators(num_validators)
    return State.generate_genesis(genesis_time=Uint64(genesis_time), validators=validators)


# -----------------------------------------------------------------------------
# Block Builders
# -----------------------------------------------------------------------------


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


# -----------------------------------------------------------------------------
# Attestation Builders
# -----------------------------------------------------------------------------


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
