"""Deterministic constructors for primitive test values, built from a seed or explicit fields."""

from __future__ import annotations

from typing import Callable

from consensus_testing.keys import create_dummy_signature
from lean_spec.node.networking.reqresp.message import Status
from lean_spec.spec.forks import Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import Store
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    MultiMessageAggregate,
    SignedAttestation,
    SignedBlock,
)
from lean_spec.spec.ssz_types import ByteList512KiB, Bytes32

TEST_VALIDATOR_INDEX = ValidatorIndex(0)
"""Validator index a node owns by default in unit tests."""


def signed_block_with_empty_proof(block: Block) -> SignedBlock:
    """Wrap an unsigned block in an empty proof, as a genesis or anchor block carries."""
    return SignedBlock(
        block=block,
        proof=MultiMessageAggregate(proof=ByteList512KiB(data=b"")),
    )


def store_backed_signed_block_getter(
    store: Store,
) -> Callable[[Bytes32], SignedBlock | None]:
    """Build a signed-block lookup over a store's unsigned blocks."""

    def signed_block_for(root: Bytes32) -> SignedBlock | None:
        block = store.blocks.get(root)
        if block is None:
            return None
        return signed_block_with_empty_proof(block)

    return signed_block_for


def make_signed_block(
    slot: Slot,
    proposer_index: ValidatorIndex,
    parent_root: Bytes32,
    state_root: Bytes32,
) -> SignedBlock:
    """Build a signed block with an empty proof for structural tests."""
    return signed_block_with_empty_proof(
        Block(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=state_root,
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )
    )


def make_test_block(slot: int = 1, seed: int = 0) -> SignedBlock:
    """Build a placeholder signed block with seeded parent and state roots."""
    return make_signed_block(
        slot=Slot(slot),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32(bytes([seed % 256]) * 32),
        state_root=Bytes32(bytes([(seed + 1) % 256]) * 32),
    )


def make_signed_attestation(
    validator: ValidatorIndex,
    target: Checkpoint,
    source: Checkpoint | None = None,
) -> SignedAttestation:
    """Build a single-validator signed attestation that is structurally valid but chain-agnostic."""
    return SignedAttestation(
        validator_index=validator,
        data=AttestationData(
            slot=target.slot,
            head=target,
            target=target,
            source=source or Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        ),
        signature=create_dummy_signature(),
    )


def make_test_status() -> Status:
    """Build a status message with fixed finalized and head checkpoints."""
    return Status(
        finalized=Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(100)),
        head=Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(200)),
    )
