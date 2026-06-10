"""SSZ conformance tests for consensus containers."""

import pytest

from consensus_testing import SSZTestFiller
from consensus_testing.keys import create_dummy_signature
from lean_spec.spec.forks import AggregationBits, Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar import State
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    BlockHeader,
    GenesisConfig,
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    MultiMessageAggregate,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    SingleMessageAggregate,
    Validator,
    Validators,
)
from lean_spec.spec.ssz import Boolean, ByteList512KiB, Bytes32, Bytes52, Uint64

pytestmark = pytest.mark.valid_until("Lstar")


def _zero_checkpoint() -> Checkpoint:
    """Build a checkpoint with all-zero root and slot zero."""
    return Checkpoint(root=Bytes32.zero(), slot=Slot(0))


def _zero_attestation_data() -> AttestationData:
    """Build attestation data with all checkpoints and slot at zero."""
    zero_cp = _zero_checkpoint()
    return AttestationData(slot=Slot(0), head=zero_cp, target=zero_cp, source=zero_cp)


def _typical_attestation_data() -> AttestationData:
    """Build attestation data with distinct non-zero checkpoints at realistic slots."""
    head = Checkpoint(root=Bytes32(b"\x01" * 32), slot=Slot(100))
    target = Checkpoint(root=Bytes32(b"\x02" * 32), slot=Slot(99))
    source = Checkpoint(root=Bytes32(b"\x03" * 32), slot=Slot(50))
    return AttestationData(slot=Slot(100), head=head, target=target, source=source)


def test_checkpoint_zero(ssz_test: SSZTestFiller) -> None:
    """
    A checkpoint with zero values round-trips unchanged.

    Given
    -----
    - a checkpoint with an all-zero root at slot zero.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Checkpoint", value=_zero_checkpoint())


def test_checkpoint_typical(ssz_test: SSZTestFiller) -> None:
    """
    A checkpoint with non-zero values round-trips unchanged.

    Given
    -----
    - a checkpoint with a non-zero root at slot 12345.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="Checkpoint",
        value=Checkpoint(root=Bytes32(b"\xab" * 32), slot=Slot(12345)),
    )


def test_attestation_data_zero(ssz_test: SSZTestFiller) -> None:
    """
    Attestation data with zero values round-trips unchanged.

    Given
    -----
    - attestation data with all checkpoints and slot at zero.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="AttestationData", value=_zero_attestation_data())


def test_attestation_data_typical(ssz_test: SSZTestFiller) -> None:
    """
    Attestation data with distinct checkpoints round-trips unchanged.

    Given
    -----
    - attestation data with distinct head, target, and source checkpoints.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="AttestationData", value=_typical_attestation_data())


def test_attestation_zero(ssz_test: SSZTestFiller) -> None:
    """
    An attestation with zero values round-trips unchanged.

    Given
    -----
    - an attestation from validator index 0 with zero attestation data.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="Attestation",
        value=Attestation(validator_index=ValidatorIndex(0), data=_zero_attestation_data()),
    )


def test_attestation_typical(ssz_test: SSZTestFiller) -> None:
    """
    An attestation with non-zero values round-trips unchanged.

    Given
    -----
    - an attestation from validator index 42 with distinct attestation data.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="Attestation",
        value=Attestation(validator_index=ValidatorIndex(42), data=_typical_attestation_data()),
    )


def test_signed_attestation_minimal(ssz_test: SSZTestFiller) -> None:
    """
    A signed attestation with minimal values round-trips unchanged.

    Given
    -----
    - a signed attestation from validator index 0 with zero attestation data.
    - a placeholder signature.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="SignedAttestation",
        value=SignedAttestation(
            validator_index=ValidatorIndex(0),
            data=_zero_attestation_data(),
            signature=create_dummy_signature(),
        ),
    )


def test_aggregated_attestation_single(ssz_test: SSZTestFiller) -> None:
    """
    An aggregated attestation with one participant round-trips unchanged.

    Given
    -----
    - an aggregated attestation with a single set participation bit.
    - zero attestation data.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="AggregatedAttestation",
        value=AggregatedAttestation(
            aggregation_bits=AggregationBits(data=[Boolean(True)]),
            data=_zero_attestation_data(),
        ),
    )


def test_aggregated_attestation_multiple(ssz_test: SSZTestFiller) -> None:
    """
    An aggregated attestation with several participants round-trips unchanged.

    Given
    -----
    - an aggregated attestation with four mixed participation bits.
    - distinct attestation data.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="AggregatedAttestation",
        value=AggregatedAttestation(
            aggregation_bits=AggregationBits(
                data=[Boolean(True), Boolean(False), Boolean(True), Boolean(True)]
            ),
            data=_typical_attestation_data(),
        ),
    )


def test_block_body_empty(ssz_test: SSZTestFiller) -> None:
    """
    A block body with no attestations round-trips unchanged.

    Given
    -----
    - a block body whose attestation list is empty.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="BlockBody",
        value=BlockBody(attestations=AggregatedAttestations(data=[])),
    )


def test_block_body_with_attestation(ssz_test: SSZTestFiller) -> None:
    """
    A block body carrying one attestation round-trips unchanged.

    Given
    -----
    - a block body with a single aggregated attestation.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
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


def test_block_header_zero(ssz_test: SSZTestFiller) -> None:
    """
    A block header with zero values round-trips unchanged.

    Given
    -----
    - a block header at slot zero with proposer index 0 and all-zero roots.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="BlockHeader",
        value=BlockHeader(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=Bytes32.zero(),
        ),
    )


def test_block_header_typical(ssz_test: SSZTestFiller) -> None:
    """
    A block header with non-zero values round-trips unchanged.

    Given
    -----
    - a block header at slot 100 with proposer index 3 and distinct roots.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="BlockHeader",
        value=BlockHeader(
            slot=Slot(100),
            proposer_index=ValidatorIndex(3),
            parent_root=Bytes32(b"\x01" * 32),
            state_root=Bytes32(b"\x02" * 32),
            body_root=Bytes32(b"\x03" * 32),
        ),
    )


def test_block_empty_body(ssz_test: SSZTestFiller) -> None:
    """
    A block with an empty body round-trips unchanged.

    Given
    -----
    - a block at slot zero whose body holds no attestations.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="Block",
        value=Block(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        ),
    )


def test_block_typical(ssz_test: SSZTestFiller) -> None:
    """
    A block carrying one attestation round-trips unchanged.

    Given
    -----
    - a block at slot 100 with distinct roots.
    - a body holding a single aggregated attestation.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
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


def test_signed_block_minimal(ssz_test: SSZTestFiller) -> None:
    """
    A signed block with empty proof bytes round-trips unchanged.

    Given
    -----
    - a block at slot 1 with an empty body.
    - a multi-message aggregate with empty proof bytes.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    block = Block(
        slot=Slot(1),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    ssz_test(
        type_name="SignedBlock",
        value=SignedBlock(
            block=block,
            proof=MultiMessageAggregate(proof=ByteList512KiB(data=b"")),
        ),
    )


def test_signed_block_with_proof_bytes(ssz_test: SSZTestFiller) -> None:
    """
    A signed block with proof bytes round-trips unchanged.

    Given
    -----
    - a block at slot 2 with distinct roots and an empty body.
    - a multi-message aggregate carrying four bytes of proof content.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    block = Block(
        slot=Slot(2),
        proposer_index=ValidatorIndex(1),
        parent_root=Bytes32(b"\x01" * 32),
        state_root=Bytes32(b"\x02" * 32),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )
    ssz_test(
        type_name="SignedBlock",
        value=SignedBlock(
            block=block,
            proof=MultiMessageAggregate(proof=ByteList512KiB(data=b"\xde\xad\xbe\xef")),
        ),
    )


def test_config_zero(ssz_test: SSZTestFiller) -> None:
    """
    A config with zero genesis time round-trips unchanged.

    Given
    -----
    - a config whose genesis time is zero.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Config", value=GenesisConfig(genesis_time=Uint64(0)))


def test_config_typical(ssz_test: SSZTestFiller) -> None:
    """
    A config with a non-zero genesis time round-trips unchanged.

    Given
    -----
    - a config whose genesis time is 1609459200.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Config", value=GenesisConfig(genesis_time=Uint64(1609459200)))


def test_validator_zero(ssz_test: SSZTestFiller) -> None:
    """
    A validator with zero values round-trips unchanged.

    Given
    -----
    - a validator at index 0 with all-zero public keys.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="Validator",
        value=Validator(
            attestation_public_key=Bytes52.zero(),
            proposal_public_key=Bytes52.zero(),
            index=ValidatorIndex(0),
        ),
    )


def test_validator_typical(ssz_test: SSZTestFiller) -> None:
    """
    A validator with non-zero values round-trips unchanged.

    Given
    -----
    - a validator at index 42 with non-zero public keys.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="Validator",
        value=Validator(
            attestation_public_key=Bytes52(b"\xab" * 52),
            proposal_public_key=Bytes52(b"\xab" * 52),
            index=ValidatorIndex(42),
        ),
    )


def test_state_minimal(ssz_test: SSZTestFiller) -> None:
    """
    A state with minimal values round-trips unchanged.

    Given
    -----
    - a state at slot zero with a zero block header and zero checkpoints.
    - a single validator and empty history lists.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    zero_cp = _zero_checkpoint()
    zero_header = BlockHeader(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body_root=Bytes32.zero(),
    )
    ssz_test(
        type_name="State",
        value=State(
            config=GenesisConfig(genesis_time=Uint64(0)),
            slot=Slot(0),
            latest_block_header=zero_header,
            latest_justified=zero_cp,
            latest_finalized=zero_cp,
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            validators=Validators(
                data=[
                    Validator(
                        attestation_public_key=Bytes52.zero(),
                        proposal_public_key=Bytes52.zero(),
                        index=ValidatorIndex(0),
                    )
                ]
            ),
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        ),
    )


def test_state_with_validators(ssz_test: SSZTestFiller) -> None:
    """
    A state with several validators and history round-trips unchanged.

    Given
    -----
    - a state at slot 100 with non-zero checkpoints and block header.
    - four validators, two historical block hashes, and justification data.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="State",
        value=State(
            config=GenesisConfig(genesis_time=Uint64(1609459200)),
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
                    Validator(
                        attestation_public_key=Bytes52(b"\x01" * 52),
                        proposal_public_key=Bytes52(b"\x01" * 52),
                        index=ValidatorIndex(0),
                    ),
                    Validator(
                        attestation_public_key=Bytes52(b"\x02" * 52),
                        proposal_public_key=Bytes52(b"\x02" * 52),
                        index=ValidatorIndex(1),
                    ),
                    Validator(
                        attestation_public_key=Bytes52(b"\x03" * 52),
                        proposal_public_key=Bytes52(b"\x03" * 52),
                        index=ValidatorIndex(2),
                    ),
                    Validator(
                        attestation_public_key=Bytes52(b"\x04" * 52),
                        proposal_public_key=Bytes52(b"\x04" * 52),
                        index=ValidatorIndex(3),
                    ),
                ]
            ),
            justifications_roots=JustificationRoots(data=[Bytes32(b"\x20" * 32)]),
            justifications_validators=JustificationValidators(
                data=[Boolean(True), Boolean(True), Boolean(False), Boolean(True)]
            ),
        ),
    )


def test_signed_aggregated_attestation_minimal(ssz_test: SSZTestFiller) -> None:
    """
    A signed aggregated attestation with one participant round-trips unchanged.

    Given
    -----
    - a signed aggregated attestation over zero attestation data.
    - a proof with one participant and empty proof bytes.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    data = _zero_attestation_data()
    ssz_test(
        type_name="SignedAggregatedAttestation",
        value=SignedAggregatedAttestation(
            data=data,
            proof=SingleMessageAggregate(
                participants=AggregationBits(data=[Boolean(True)]),
                proof=ByteList512KiB(data=b""),
            ),
        ),
    )


def test_signed_aggregated_attestation_typical(ssz_test: SSZTestFiller) -> None:
    """
    A signed aggregated attestation with mixed participation round-trips unchanged.

    Given
    -----
    - a signed aggregated attestation over distinct attestation data.
    - a proof with four mixed participation bits and six bytes of proof content.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    data = _typical_attestation_data()
    wire = b"\xca\xfe\xba\xbe\xde\xad"
    ssz_test(
        type_name="SignedAggregatedAttestation",
        value=SignedAggregatedAttestation(
            data=data,
            proof=SingleMessageAggregate(
                participants=AggregationBits(
                    data=[Boolean(True), Boolean(False), Boolean(True), Boolean(True)]
                ),
                proof=ByteList512KiB(data=wire),
            ),
        ),
    )


def test_checkpoint_max_slot(ssz_test: SSZTestFiller) -> None:
    """
    A checkpoint at the maximum slot round-trips unchanged.

    Given
    -----
    - a checkpoint with an all-0xff root.
    - the maximum 64-bit slot value.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="Checkpoint",
        value=Checkpoint(root=Bytes32(b"\xff" * 32), slot=Slot(2**64 - 1)),
    )


def test_block_body_max_attestations(ssz_test: SSZTestFiller) -> None:
    """
    A block body with four attestations round-trips unchanged.

    Given
    -----
    - a block body holding four aggregated attestations.
    - participation bitfields of varying sizes across the attestations.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="BlockBody",
        value=BlockBody(
            attestations=AggregatedAttestations(
                data=[
                    AggregatedAttestation(
                        aggregation_bits=AggregationBits(data=[Boolean(True)]),
                        data=_zero_attestation_data(),
                    ),
                    AggregatedAttestation(
                        aggregation_bits=AggregationBits(data=[Boolean(True), Boolean(True)]),
                        data=_typical_attestation_data(),
                    ),
                    AggregatedAttestation(
                        aggregation_bits=AggregationBits(
                            data=[Boolean(False), Boolean(True), Boolean(True)]
                        ),
                        data=_zero_attestation_data(),
                    ),
                    AggregatedAttestation(
                        aggregation_bits=AggregationBits(
                            data=[
                                Boolean(True),
                                Boolean(False),
                                Boolean(True),
                                Boolean(False),
                            ]
                        ),
                        data=_typical_attestation_data(),
                    ),
                ]
            )
        ),
    )


def test_validator_max_index(ssz_test: SSZTestFiller) -> None:
    """
    A validator at the maximum index round-trips unchanged.

    Given
    -----
    - a validator with all-0xff public keys.
    - the maximum 64-bit index value.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="Validator",
        value=Validator(
            attestation_public_key=Bytes52(b"\xff" * 52),
            proposal_public_key=Bytes52(b"\xff" * 52),
            index=ValidatorIndex(2**64 - 1),
        ),
    )


def test_state_with_full_history(ssz_test: SSZTestFiller) -> None:
    """
    A state with full history round-trips unchanged.

    Given
    -----
    - a state at slot 500 with five historical block hashes.
    - eight justification bits and three justification roots.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="State",
        value=State(
            config=GenesisConfig(genesis_time=Uint64(1700000000)),
            slot=Slot(500),
            latest_block_header=BlockHeader(
                slot=Slot(499),
                proposer_index=ValidatorIndex(7),
                parent_root=Bytes32(b"\xaa" * 32),
                state_root=Bytes32(b"\xbb" * 32),
                body_root=Bytes32(b"\xcc" * 32),
            ),
            latest_justified=Checkpoint(root=Bytes32(b"\xdd" * 32), slot=Slot(480)),
            latest_finalized=Checkpoint(root=Bytes32(b"\xee" * 32), slot=Slot(450)),
            historical_block_hashes=HistoricalBlockHashes(
                data=[
                    Bytes32(b"\x10" * 32),
                    Bytes32(b"\x11" * 32),
                    Bytes32(b"\x12" * 32),
                    Bytes32(b"\x13" * 32),
                    Bytes32(b"\x14" * 32),
                ]
            ),
            justified_slots=JustifiedSlots(
                data=[
                    Boolean(True),
                    Boolean(True),
                    Boolean(False),
                    Boolean(True),
                    Boolean(False),
                    Boolean(True),
                    Boolean(True),
                    Boolean(True),
                ]
            ),
            validators=Validators(
                data=[
                    Validator(
                        attestation_public_key=Bytes52(b"\x01" * 52),
                        proposal_public_key=Bytes52(b"\x01" * 52),
                        index=ValidatorIndex(0),
                    ),
                    Validator(
                        attestation_public_key=Bytes52(b"\x02" * 52),
                        proposal_public_key=Bytes52(b"\x02" * 52),
                        index=ValidatorIndex(1),
                    ),
                ]
            ),
            justifications_roots=JustificationRoots(
                data=[
                    Bytes32(b"\x20" * 32),
                    Bytes32(b"\x21" * 32),
                    Bytes32(b"\x22" * 32),
                ]
            ),
            justifications_validators=JustificationValidators(
                data=[
                    Boolean(True),
                    Boolean(True),
                    Boolean(False),
                    Boolean(True),
                    Boolean(True),
                    Boolean(False),
                    Boolean(True),
                    Boolean(False),
                ]
            ),
        ),
    )
