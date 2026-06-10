"""Lstar fork — block signature verification."""

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.forks.lstar._base import LstarSpecBase
from lean_spec.spec.forks.lstar.containers import (
    AggregationError,
    SignedBlock,
    Slot,
    Validators,
)
from lean_spec.spec.forks.lstar.errors import RejectionReason, SpecRejectionError
from lean_spec.spec.ssz import Bytes32, Uint64


class SignatureMixin(LstarSpecBase):
    """Block signature verification for the lstar fork."""

    def verify_signatures(
        self,
        signed_block: SignedBlock,
        validators: Validators,
    ) -> bool:
        """
        Verify the merged aggregate proof carried by a signed block.

        A block carries one proof.
        It binds every body attestation plus the proposer's endorsement.

        The proof itself holds neither public keys nor messages.
        It only proves: these keys, signing these messages, produced this aggregate.
        So the caller must reconstruct both lists and the verifier checks them.

        Two parallel lists drive the check.
        Entry i pairs the public keys of one component with the message it signed.

        Args:
            signed_block: Block whose merged proof is verified.
            validators: Registry that maps each index to its public keys.

        Returns:
            True when the proof is valid.

        Raises:
            SpecRejectionError: Carrying one of three reasons.
                - VALIDATOR_INDEX_OUT_OF_RANGE when an attester index exceeds the registry.
                - PROPOSER_INDEX_OUT_OF_RANGE when the proposer index exceeds the registry.
                - INVALID_BLOCK_PROOF when the cryptographic check fails.
        """
        block = signed_block.block
        num_validators = Uint64(len(validators))

        # Public keys of each signing component, one entry per signed message.
        public_keys_per_message: list[list[PublicKey]] = []

        # The message each component signed, paired index-for-index with the keys above.
        #
        # The binding pins each key set to the exact data it signed.
        # Without it a proposer could reuse honest signatures over forged data.
        message_bindings: list[tuple[Bytes32, Slot]] = []

        # Each attestation names the validators that voted for its data.
        #
        # Invariant: this list stays parallel to the proof's components.
        # The producer builds attestations first, in body order, so we match that.
        for aggregated_attestation in block.body.attestations:
            voter_indices = aggregated_attestation.aggregation_bits.to_validator_indices()

            # The bitfield is attacker-controlled so every index is bounds-checked
            # against the active set before it indexes the registry below.
            for voter_index in voter_indices:
                if not voter_index.is_within_registry(num_validators):
                    raise SpecRejectionError(
                        RejectionReason.VALIDATOR_INDEX_OUT_OF_RANGE,
                        "Validator index out of range",
                    )

            # Resolve each voter to the attestation key it signs with.
            public_keys_per_message.append(
                [
                    PublicKey.decode_bytes(validators[voter_index].attestation_public_key)
                    for voter_index in voter_indices
                ]
            )

            # Bind that key set to the attestation data root and its slot.
            message_bindings.append(
                (
                    hash_tree_root(aggregated_attestation.data),
                    aggregated_attestation.data.slot,
                )
            )

        # The proposer's endorsement is the final component, appended last.
        #
        # It is the only thing tying the proof to this specific block.
        # It signs the block root with the proposal key, not the attestation key.
        # So it stands as a single-participant entry distinct from the votes above.
        #
        # The proposer index is attacker-controlled, so bound it before indexing.
        if not block.proposer_index.is_within_registry(num_validators):
            raise SpecRejectionError(
                RejectionReason.PROPOSER_INDEX_OUT_OF_RANGE, "Proposer index out of range"
            )

        # Resolve the proposal key, the lone signer of this component.
        public_keys_per_message.append(
            [PublicKey.decode_bytes(validators[block.proposer_index].proposal_public_key)]
        )

        # Bind it to the block root and the block's own slot.
        message_bindings.append((hash_tree_root(block), block.slot))

        # Check the proof against the reconstructed keys and messages.
        # A failure here means the aggregate does not match what the block claims.
        try:
            signed_block.proof.verify(
                public_keys_per_message=public_keys_per_message,
                messages=message_bindings,
            )
        except AggregationError as exception:
            raise SpecRejectionError(
                RejectionReason.INVALID_BLOCK_PROOF,
                f"Block proof verification failed: {exception}",
            ) from exception

        return True
