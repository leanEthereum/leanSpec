"""Reaggregation test fixture format."""

from __future__ import annotations

from typing import ClassVar

from consensus_testing.keys import XmssKeyManager
from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import AggregationBits, Checkpoint, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    AttestationData,
    Block,
    BlockBody,
    MultiMessageAggregate,
    SingleMessageAggregate,
)
from lean_spec.spec.ssz import Bytes32

ATTESTATION_SLOT: Slot = Slot(1)
"""Attestation slot, one before the block that carries it."""

BLOCK_SLOT: Slot = Slot(2)
"""Block slot, one after the attestation it carries."""

PROPOSER_INDEX: ValidatorIndex = ValidatorIndex(0)
"""Validator index that signs the block."""

CHAIN_ROOT: Bytes32 = Bytes32(b"\x11" * 32)
"""Head and target root the attestation votes for."""

GENESIS_ROOT: Bytes32 = Bytes32(b"\x33" * 32)
"""Source root anchoring the attestation."""

PARENT_ROOT: Bytes32 = Bytes32(b"\xaa" * 32)
"""Parent root of the synthetic block."""


class ReaggregationFixture(BaseConsensusFixture):
    """Emitted vector for proof re-aggregation."""

    block_proof: str
    """The block's multi-message proof that gets split, as hex."""

    public_keys_per_message: list[list[str]]
    """Per-message public key layout the original proof was built with, as hex."""

    attestation_message: str
    """Hash tree root of the split attestation, as hex."""

    attestation_slot: int
    """Slot of the split attestation."""

    block_attesters: list[int]
    """Validator indices whose signed attestations came in the block."""

    local_attesters: list[int]
    """Validator indices whose signed attestations are in the node's local pool."""

    combined_attesters: list[int]
    """Validator indices covered by the re-aggregated proof, the block and local union."""

    reaggregated_proof: str
    """The re-aggregated single-message proof bytes, as hex."""


class ReaggregationTest(BaseTestSpec):
    """
    Split one attestation's proof out of a block, then merge it with the local partial.

    The reference proof bytes are not deterministic.
    Each vector is checked by verifying against the expected attesters' keys, not by byte match.
    """

    format_name: ClassVar[str] = "reaggregation_test"
    description: ClassVar[str] = "Tests aggregate proof split and merge clients must reproduce"

    block_attesters: list[ValidatorIndex]
    """Validator indices whose signed attestations were aggregated into the block."""

    local_attesters: list[ValidatorIndex] = []
    """Validator indices whose signed attestations are in the node's local pool."""

    def generate(self) -> ReaggregationFixture:
        """Build the merged proof, split the attestation out, merge it, and verify."""
        key_manager = XmssKeyManager.shared()

        attestation_data = AttestationData(
            slot=ATTESTATION_SLOT,
            head=Checkpoint(root=CHAIN_ROOT, slot=ATTESTATION_SLOT),
            target=Checkpoint(root=CHAIN_ROOT, slot=ATTESTATION_SLOT),
            source=Checkpoint(root=GENESIS_ROOT, slot=Slot(0)),
        )
        attestation_message = hash_tree_root(attestation_data)

        signing_validators = list(dict.fromkeys([*self.block_attesters, *self.local_attesters]))
        shared_signatures = {
            validator_index: key_manager.sign_attestation_data(validator_index, attestation_data)
            for validator_index in signing_validators
        }

        # Phase 1: the block's attestation component, then the proposal component.
        attestation_component = key_manager.sign_and_aggregate(
            self.block_attesters,
            attestation_data,
            precomputed_signatures=shared_signatures,
        )
        attestation_keys = [
            key_manager.get_public_keys(validator_index)[0]
            for validator_index in self.block_attesters
        ]
        block = Block(
            slot=BLOCK_SLOT,
            proposer_index=PROPOSER_INDEX,
            parent_root=PARENT_ROOT,
            state_root=Bytes32.zero(),
            body=BlockBody(
                attestations=AggregatedAttestations(
                    data=[
                        AggregatedAttestation(
                            aggregation_bits=AggregationBits.from_indices(self.block_attesters),
                            data=attestation_data,
                        )
                    ]
                )
            ),
        )
        block_root = hash_tree_root(block)
        proposal_key = key_manager.get_public_keys(PROPOSER_INDEX)[1]
        proposal_signature = key_manager.sign_block_root(PROPOSER_INDEX, BLOCK_SLOT, block_root)
        proposal_component = SingleMessageAggregate.aggregate(
            children=[],
            raw_xmss=[(PROPOSER_INDEX, proposal_key, proposal_signature)],
            message=block_root,
            slot=BLOCK_SLOT,
        )
        public_keys_per_message = [attestation_keys, [proposal_key]]

        # Phase 2: merge the two components into a single, multi-message block proof.
        block_proof = MultiMessageAggregate.aggregate(
            [attestation_component, proposal_component],
            public_keys_per_aggregate=public_keys_per_message,
        )

        # Phase 3: split the attestation's component back out by its message.
        block_bits = AggregationBits.from_indices(self.block_attesters)
        recovered_proof = block_proof.split_by_message(
            message=attestation_message,
            public_keys_per_message=public_keys_per_message,
            participants=block_bits,
        )

        # The split output must verify on its own against the block attesters' keys.
        # A later merge could otherwise mask a malformed recovered component.
        recovered_proof.verify(attestation_keys, attestation_message, attestation_data.slot)

        # Phase 4: merge the recovered proof with the local partial.
        if self.local_attesters:
            local_partial = key_manager.sign_and_aggregate(
                self.local_attesters,
                attestation_data,
                precomputed_signatures=shared_signatures,
            )
            local_keys = [
                key_manager.get_public_keys(validator_index)[0]
                for validator_index in self.local_attesters
            ]
            reaggregated_proof = SingleMessageAggregate.aggregate(
                children=[
                    (recovered_proof, attestation_keys),
                    (local_partial, local_keys),
                ],
                raw_xmss=[],
                message=attestation_message,
                slot=attestation_data.slot,
            )
        else:
            reaggregated_proof = recovered_proof

        # Phase 5: the merged proof must cover exactly the union of block and local attesters.
        combined_attester_indices = list(reaggregated_proof.participants.to_validator_indices())
        expected_attester_indices = sorted({*self.block_attesters, *self.local_attesters})
        assert combined_attester_indices == expected_attester_indices, (
            f"re-aggregated proof covers {combined_attester_indices}, "
            f"expected the union {expected_attester_indices}"
        )

        # The merged proof must verify against the union attesters' keys.
        reaggregated_proof.verify(
            [
                key_manager.get_public_keys(validator_index)[0]
                for validator_index in combined_attester_indices
            ],
            attestation_message,
            attestation_data.slot,
        )

        return ReaggregationFixture(
            block_proof="0x" + bytes(block_proof.proof.data).hex(),
            public_keys_per_message=[
                ["0x" + public_key.encode_bytes().hex() for public_key in component_keys]
                for component_keys in public_keys_per_message
            ],
            attestation_message="0x" + bytes(attestation_message).hex(),
            attestation_slot=int(attestation_data.slot),
            block_attesters=[int(validator_index) for validator_index in self.block_attesters],
            local_attesters=[int(validator_index) for validator_index in self.local_attesters],
            combined_attesters=[
                int(validator_index) for validator_index in combined_attester_indices
            ],
            reaggregated_proof="0x" + bytes(reaggregated_proof.proof.data).hex(),
        )
