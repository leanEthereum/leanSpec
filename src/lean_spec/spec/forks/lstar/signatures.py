"""Lstar fork — block signature verification."""

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.forks.lstar.containers import (
    AggregationError,
    SignedBlock,
    Slot,
    Validators,
)
from lean_spec.spec.ssz import Bytes32, Uint64

from ._contract import LstarSpecContract


class SignatureMixin(LstarSpecContract):
    """Block signature verification for the lstar fork."""

    def verify_signatures(
        self,
        signed_block: SignedBlock,
        validators: Validators,
    ) -> bool:
        """
        Verify the merged multi-message aggregate proof carried by a signed block.

        The block envelope holds one multi-message aggregate proof binding
        every body attestation plus the proposer's signature over the
        block root.

        Args:
            signed_block: The signed block whose merged proof is checked.
            validators: Validator registry providing public keys for verification.

        Returns:
            True if the merged proof is valid.

        Raises:
            AssertionError: On any structural or cryptographic mismatch.
        """
        block = signed_block.block
        aggregated_attestations = block.body.attestations

        num_validators = Uint64(len(validators))
        public_keys_per_message: list[list[PublicKey]] = []

        # Each component is bound to the message and slot it signed.
        #
        # Without this binding a proposer could pair honest signatures
        # with attacker-chosen attestation data that resolves to the same
        # public_keys, crediting validators for votes they never cast.
        message_bindings: list[tuple[Bytes32, Slot]] = []

        # One public_key set per attestation, in body order.
        #
        # The attestation list and the proof component list are parallel.
        # Each attestation names the validators that voted for its data.
        # Its matching proof component proves those validators signed.
        for aggregated_attestation in aggregated_attestations:
            validator_indices = aggregated_attestation.aggregation_bits.to_validator_indices()
            for validator_index in validator_indices:
                assert validator_index.is_valid(num_validators), "Validator index out of range"

            public_keys_per_message.append(
                [
                    validators[validator_index].get_attestation_public_key()
                    for validator_index in validator_indices
                ]
            )
            message_bindings.append(
                (
                    hash_tree_root(aggregated_attestation.data),
                    aggregated_attestation.data.slot,
                )
            )

        # Final component: the proposer's signature over the block root.
        #
        # The proposer signs the block root with their proposal key.
        # This proves the proposer endorsed this specific block.
        # It is a single-participant entry, distinct from the vote entries.
        proposer_index = block.proposer_index
        assert proposer_index.is_valid(num_validators), "Proposer index out of range"

        public_keys_per_message.append([validators[proposer_index].get_proposal_public_key()])
        message_bindings.append((hash_tree_root(block), block.slot))

        try:
            signed_block.proof.verify(
                public_keys_per_message=public_keys_per_message,
                messages=message_bindings,
            )
        except AggregationError as exception:
            raise AssertionError(f"Block proof verification failed: {exception}") from exception

        return True
