"""Test signed block with attestation signature correctness."""

import pytest
from consensus_testing import (
    SignedBlockWithAttestationTestFiller,
    generate_pre_state,
)

from lean_spec.subspecs.containers import Signature
from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
)
from lean_spec.subspecs.containers.block.block import (
    Block,
    BlockBody,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import Attestations, BlockSignatures
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.types import Bytes32, Bytes52, Uint64, ValidatorIndex

pytestmark = pytest.mark.valid_until("Devnet")


def test_signed_block_no_attestations(
    signed_block_with_attestation_test: SignedBlockWithAttestationTestFiller,
) -> None:
    """
    Test a signed block with no attestations, only proposer attestation.

    This test verifies that:
    1. A block with empty attestations can be properly signed
    2. The proposer attestation signature is correctly generated
    3. The signature verifies against the proposer's public key
    """
    # Create a block with no attestations
    block = Block(
        slot=Slot(1),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=Attestations(data=[])),
    )

    # Create proposer attestation
    proposer_attestation = Attestation(
        validator_id=Uint64(0),
        data=AttestationData(
            slot=Slot(1),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        ),
    )

    # Create signed block (signatures will be filled by fixture)
    signed_block_with_attestation = SignedBlockWithAttestation(
        message=BlockWithAttestation(
            block=block,
            proposer_attestation=proposer_attestation,
        ),
        signature=BlockSignatures(data=[Signature.zero()]),
    )

    signed_block_with_attestation_test(
        anchor_state=generate_pre_state(
            validators=Validators(data=[Validator(pubkey=Bytes52.zero())])
        ),
        signed_block_with_attestation=signed_block_with_attestation,
        valid=True,
    )


def test_signed_block_with_single_attestation(
    signed_block_with_attestation_test: SignedBlockWithAttestationTestFiller,
) -> None:
    """
    Test a signed block containing one attestation plus proposer attestation.

    This test verifies that:
    1. Block attestations are correctly signed
    2. Proposer attestation is correctly signed
    3. Both signatures verify independently
    4. Signature aggregation in BlockSignatures is correct
    """
    # Create an attestation to include in the block
    included_attestation = Attestation(
        validator_id=Uint64(1),
        data=AttestationData(
            slot=Slot(1),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
        ),
    )

    # Create a block with one attestation
    block = Block(
        slot=Slot(2),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=Attestations(data=[included_attestation])),
    )

    # Create proposer attestation
    proposer_attestation = Attestation(
        validator_id=Uint64(2),
        data=AttestationData(
            slot=Slot(2),
            head=Checkpoint(root=Bytes32.zero(), slot=Slot(2)),
            target=Checkpoint(root=Bytes32.zero(), slot=Slot(2)),
            source=Checkpoint(root=Bytes32.zero(), slot=Slot(1)),
        ),
    )

    # Create signed block (2 signatures: one for included attestation, one for proposer)
    signed_block_with_attestation = SignedBlockWithAttestation(
        message=BlockWithAttestation(
            block=block,
            proposer_attestation=proposer_attestation,
        ),
        signature=BlockSignatures(data=[Signature.zero(), Signature.zero()]),
    )

    signed_block_with_attestation_test(
        anchor_state=generate_pre_state(
            validators=Validators(data=[Validator(pubkey=Bytes52.zero()) for _ in range(3)])
        ),
        signed_block_with_attestation=signed_block_with_attestation,
        valid=True,
    )
