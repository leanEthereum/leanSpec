"""SSZ conformance tests for consensus containers."""

import pytest
from consensus_testing import SSZTestFiller

from lean_spec.subspecs.containers import (
    AggregatedAttestation,
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    BlockHeader,
    BlockWithAttestation,
    Checkpoint,
    Config,
    SignedAttestation,
    SignedBlockWithAttestation,
    Slot,
    State,
    Validator,
    ValidatorIndex,
)
from lean_spec.subspecs.containers.attestation import AggregationBits
from lean_spec.subspecs.containers.block import BlockSignatures
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    Validators,
)
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.xmss import Signature
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.types import (
    HashDigestList,
    HashTreeOpening,
    Randomness,
)
from lean_spec.types import Boolean, Bytes32, Bytes52, Uint64
from lean_spec.types.byte_arrays import ByteListMiB

pytestmark = pytest.mark.valid_until("Devnet")


# --- Helper functions ---


def _zero_checkpoint() -> Checkpoint:
    return Checkpoint(root=Bytes32.zero(), slot=Slot(0))


def _zero_attestation_data() -> AttestationData:
    zero_cp = _zero_checkpoint()
    return AttestationData(slot=Slot(0), head=zero_cp, target=zero_cp, source=zero_cp)


def _typical_attestation_data() -> AttestationData:
    head = Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(100))
    target = Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(99))
    source = Checkpoint(root=Bytes32(b"\x03" * 32), slot=Slot(50))
    return AttestationData(slot=Slot(100), head=head, target=target, source=source)


def _zero_signature() -> Signature:
    return Signature(
        path=HashTreeOpening(siblings=HashDigestList(data=[])),
        rho=Randomness(data=[Fp(0) for _ in range(Randomness.LENGTH)]),
        hashes=HashDigestList(data=[]),
    )


# --- Checkpoint ---


def test_checkpoint_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Checkpoint with zero values."""
    ssz(type_name="Checkpoint", value=_zero_checkpoint())


def test_checkpoint_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Checkpoint with typical values."""
    ssz(
        type_name="Checkpoint",
        value=Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(12345)),
    )


# --- AttestationData ---


def test_attestation_data_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for AttestationData with zero values."""
    ssz(type_name="AttestationData", value=_zero_attestation_data())


def test_attestation_data_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for AttestationData with typical values."""
    ssz(type_name="AttestationData", value=_typical_attestation_data())


# --- Attestation ---


def test_attestation_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Attestation with zero values."""
    ssz(
        type_name="Attestation",
        value=Attestation(validator_id=ValidatorIndex(0), data=_zero_attestation_data()),
    )


def test_attestation_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Attestation with typical values."""
    ssz(
        type_name="Attestation",
        value=Attestation(validator_id=ValidatorIndex(42), data=_typical_attestation_data()),
    )


# --- SignedAttestation ---


def test_signed_attestation_minimal(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for SignedAttestation with minimal values."""
    ssz(
        type_name="SignedAttestation",
        value=SignedAttestation(
            validator_id=ValidatorIndex(0),
            message=_zero_attestation_data(),
            signature=_zero_signature(),
        ),
    )


# --- AggregatedAttestation ---


def test_aggregated_attestation_single(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for AggregatedAttestation with single validator."""
    ssz(
        type_name="AggregatedAttestation",
        value=AggregatedAttestation(
            aggregation_bits=AggregationBits(data=[Boolean(True)]),
            data=_zero_attestation_data(),
        ),
    )


def test_aggregated_attestation_multiple(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for AggregatedAttestation with multiple validators."""
    ssz(
        type_name="AggregatedAttestation",
        value=AggregatedAttestation(
            aggregation_bits=AggregationBits(
                data=[Boolean(True), Boolean(False), Boolean(True), Boolean(True)]
            ),
            data=_typical_attestation_data(),
        ),
    )


# --- BlockBody ---


def test_block_body_empty(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for BlockBody with no attestations."""
    ssz(
        type_name="BlockBody",
        value=BlockBody(attestations=AggregatedAttestations(data=[])),
    )


def test_block_body_with_attestation(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for BlockBody with attestations."""
    ssz(
        type_name="BlockBody",
        value=BlockBody(
            attestations=AggregatedAttestations(
                data=[
                    AggregatedAttestation(
                        aggregation_bits=AggregationBits(data=[Boolean(True)]),
                        data=_zero_attestation_data(),
                    )
                ]
            )
        ),
    )


# --- BlockHeader ---


def test_block_header_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for BlockHeader with zero values."""
    ssz(
        type_name="BlockHeader",
        value=BlockHeader(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=Bytes32.zero(),
        ),
    )


def test_block_header_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for BlockHeader with typical values."""
    ssz(
        type_name="BlockHeader",
        value=BlockHeader(
            slot=Slot(100),
            proposer_index=ValidatorIndex(3),
            parent_root=Bytes32(b"\x01" * 32),
            state_root=Bytes32(b"\x02" * 32),
            body_root=Bytes32(b"\x03" * 32),
        ),
    )


# --- Block ---


def test_block_empty_body(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Block with empty body."""
    ssz(
        type_name="Block",
        value=Block(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        ),
    )


def test_block_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Block with attestations."""
    ssz(
        type_name="Block",
        value=Block(
            slot=Slot(100),
            proposer_index=ValidatorIndex(3),
            parent_root=Bytes32(b"\x01" * 32),
            state_root=Bytes32(b"\x02" * 32),
            body=BlockBody(
                attestations=AggregatedAttestations(
                    data=[
                        AggregatedAttestation(
                            aggregation_bits=AggregationBits(data=[Boolean(True)]),
                            data=_typical_attestation_data(),
                        )
                    ]
                )
            ),
        ),
    )


# --- BlockWithAttestation ---


def test_block_with_attestation_minimal(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for BlockWithAttestation with minimal values."""
    block = Block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    attestation = Attestation(validator_id=ValidatorIndex(0), data=_zero_attestation_data())
    ssz(
        type_name="BlockWithAttestation",
        value=BlockWithAttestation(block=block, proposer_attestation=attestation),
    )


# --- BlockSignatures ---


def test_block_signatures_empty(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for BlockSignatures with no attestation signatures."""
    ssz(
        type_name="BlockSignatures",
        value=BlockSignatures(
            attestation_signatures=AttestationSignatures(data=[]),
            proposer_signature=_zero_signature(),
        ),
    )


def test_block_signatures_with_attestation(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for BlockSignatures with attestation signatures."""
    ssz(
        type_name="BlockSignatures",
        value=BlockSignatures(
            attestation_signatures=AttestationSignatures(
                data=[
                    AggregatedSignatureProof(
                        participants=AggregationBits(data=[Boolean(True)]),
                        proof_data=ByteListMiB(data=b""),
                    )
                ]
            ),
            proposer_signature=_zero_signature(),
        ),
    )


# --- SignedBlockWithAttestation ---


def test_signed_block_with_attestation_minimal(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for SignedBlockWithAttestation with minimal values."""
    block = Block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    attestation = Attestation(validator_id=ValidatorIndex(0), data=_zero_attestation_data())
    message = BlockWithAttestation(block=block, proposer_attestation=attestation)
    signature = BlockSignatures(
        attestation_signatures=AttestationSignatures(data=[]),
        proposer_signature=_zero_signature(),
    )
    ssz(
        type_name="SignedBlockWithAttestation",
        value=SignedBlockWithAttestation(message=message, signature=signature),
    )


# --- Config ---


def test_config_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Config with zero genesis time."""
    ssz(type_name="Config", value=Config(genesis_time=Uint64(0)))


def test_config_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Config with typical genesis time."""
    ssz(type_name="Config", value=Config(genesis_time=Uint64(1609459200)))


# --- Validator ---


def test_validator_zero(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Validator with zero values."""
    ssz(
        type_name="Validator",
        value=Validator(pubkey=Bytes52.zero(), index=ValidatorIndex(0)),
    )


def test_validator_typical(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for Validator with typical values."""
    ssz(
        type_name="Validator",
        value=Validator(pubkey=Bytes52(b"\xab" * 52), index=ValidatorIndex(42)),
    )


# --- State ---


def test_state_minimal(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for State with minimal values."""
    zero_cp = _zero_checkpoint()
    zero_header = BlockHeader(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body_root=Bytes32.zero(),
    )
    ssz(
        type_name="State",
        value=State(
            config=Config(genesis_time=Uint64(0)),
            slot=Slot(0),
            latest_block_header=zero_header,
            latest_justified=zero_cp,
            latest_finalized=zero_cp,
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            validators=Validators(data=[Validator(pubkey=Bytes52.zero(), index=ValidatorIndex(0))]),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_state_with_validators(ssz: SSZTestFiller) -> None:
    """SSZ roundtrip for State with multiple validators and history."""
    ssz(
        type_name="State",
        value=State(
            config=Config(genesis_time=Uint64(1609459200)),
            slot=Slot(100),
            latest_block_header=BlockHeader(
                slot=Slot(99),
                proposer_index=ValidatorIndex(2),
                parent_root=Bytes32(b"\x01" * 32),
                state_root=Bytes32(b"\x02" * 32),
                body_root=Bytes32(b"\x03" * 32),
            ),
            latest_justified=Checkpoint(root=Bytes32(b"\x04" * 32), slot=Slot(64)),
            latest_finalized=Checkpoint(root=Bytes32(b"\x05" * 32), slot=Slot(32)),
            historical_block_hashes=HistoricalBlockHashes(
                data=[Bytes32(b"\x10" * 32), Bytes32(b"\x11" * 32)]
            ),
            justified_slots=JustifiedSlots(data=[Boolean(True), Boolean(False), Boolean(True)]),
            validators=Validators(
                data=[
                    Validator(pubkey=Bytes52(b"\x01" * 52), index=ValidatorIndex(0)),
                    Validator(pubkey=Bytes52(b"\x02" * 52), index=ValidatorIndex(1)),
                    Validator(pubkey=Bytes52(b"\x03" * 52), index=ValidatorIndex(2)),
                    Validator(pubkey=Bytes52(b"\x04" * 52), index=ValidatorIndex(3)),
                ]
            ),
            justifications_roots=JustificationRoots(data=[Bytes32(b"\x20" * 32)]),
            justifications_validators=JustificationValidators(
                data=[Boolean(True), Boolean(True), Boolean(False), Boolean(True)]
            ),
        ),
    )
