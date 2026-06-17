"""
Post-quantum signature aggregation proofs wrapping the Rust prover.

- Single-message proofs aggregate many validators signing the same message.
- Multi-message proofs merge components over distinct messages into one blob.
"""

from lean_multisig_py import (
    aggregate_single_message,
    merge_many_single_message_proof,
    split_multi_message_proof_by_message,
    verify_multi_message_proof_with_messages,
    verify_single_message_proof,
)

from lean_spec.config import LEAN_ENV
from lean_spec.spec.crypto.xmss.containers import PublicKey, Signature
from lean_spec.spec.forks.lstar.containers.identifiers import ValidatorIndex
from lean_spec.spec.forks.lstar.containers.participation import AggregationBits
from lean_spec.spec.forks.lstar.slot import Slot
from lean_spec.spec.ssz import ByteList512KiB, Bytes32, Container

LOG_INVERSE_RATE: int = 1 if LEAN_ENV == "test" else 2
"""
Inverse-rate exponent forwarded to the SNARK backend.

A smaller rate trades verifier cost for prover speed.
Test mode favors prover speed.
"""


class AggregationError(Exception):
    """Raised when aggregation, merging, splitting, or verification fails."""


class SingleMessageAggregate(Container):
    """
    Single-message proof aggregating signatures from many validators.

    Every validator signs the same message for the same slot.

    The message and slot stay outside the proof.
    The verifier rederives them from the block body it already trusts.
    """

    participants: AggregationBits
    """Bitfield indicating which validators contributed signatures."""

    proof: ByteList512KiB
    """Aggregated proof bytes in compact public-key-free representation."""

    @classmethod
    def aggregate(
        cls,
        children: list[tuple["SingleMessageAggregate", list[PublicKey]]],
        raw_xmss: list[tuple[ValidatorIndex, PublicKey, Signature]],
        message: Bytes32,
        slot: Slot,
    ) -> "SingleMessageAggregate":
        """
        Fold fresh signatures and child proofs into one single-message proof.

        Two kinds of contribution merge into one proof.

        - A fresh signer contributes a single raw signature.
        - A child proof contributes an already-aggregated bundle of signers.

        The result names the union of every contributing validator.
        The prover compresses all contributions into one proof over the shared message.

        Each fresh entry carries its own validator index.
        A public key carries no validator index on its own.
        Pairing the index with each fresh entry lets the bitfield be derived, not passed in.
        An empty list of fresh signers simply contributes no indices.

        Args:
            children: Child proofs, each paired with the public keys it names.
            raw_xmss: Fresh entries, each carrying its validator index, public key, and signature.
            message: The 32-byte message every signer signed.
            slot: The slot every signer signed for.

        Returns:
            A single-message proof covering the union of all participants.

        Raises:
            AggregationError: When the prover rejects the inputs.
        """
        # Phase 1: union every contributing validator index.
        #
        # Fresh signers bring their own index.
        # Child proofs expose theirs through the participant bitfield.
        all_indices = {validator_index for validator_index, _, _ in raw_xmss}.union(
            *(child.participants.to_validator_indices() for child, _ in children)
        )
        participants = AggregationBits.from_indices(all_indices)

        # Phase 2: serialize inputs to the prover's wire format.
        raw_public_keys_ssz = [public_key.encode_bytes() for _, public_key, _ in raw_xmss]
        raw_signatures_ssz = [signature.encode_bytes() for _, _, signature in raw_xmss]
        children_bytes = [
            ([public_key.encode_bytes() for public_key in public_keys], bytes(child.proof.data))
            for child, public_keys in children
        ]

        # Phase 3: hand off to the Rust prover.
        # The mode argument routes the call to the matching backend bytecode.
        try:
            _, single_message_aggregate_wire = aggregate_single_message(
                raw_public_keys_ssz,
                raw_signatures_ssz,
                bytes(message),
                int(slot),
                LOG_INVERSE_RATE,
                children_bytes or None,
                mode=LEAN_ENV,
            )
        except Exception as exception:
            raise AggregationError(str(exception)) from exception

        return cls(
            participants=participants,
            proof=ByteList512KiB(data=single_message_aggregate_wire),
        )

    def verify(
        self,
        public_keys: list[PublicKey],
        message: Bytes32,
        slot: Slot,
    ) -> None:
        """
        Verify this single-message aggregate proof against a set of public keys.

        Args:
            public_keys: PublicKeys for the validators named by participants.
            message: Message bound by the proof.
            slot: Slot bound by the proof.

        Raises:
            AggregationError: When the public_key count does not match the bitfield
                or the Rust verifier rejects the proof.
        """
        # The bitfield names one validator per set bit.
        # The caller must supply exactly that many keys, in the same order.
        # A miscount would otherwise fail deep in the verifier with an opaque error.
        expected_public_key_count = len(self.participants.to_validator_indices())
        if len(public_keys) != expected_public_key_count:
            raise AggregationError(
                f"single-message aggregate verify expected {expected_public_key_count} pubkeys "
                f"for participants, got {len(public_keys)}"
            )

        # Hand the resolved keys, message, and slot to the Rust verifier.
        # The mode argument selects the matching backend bytecode.
        try:
            verify_single_message_proof(
                [public_key.encode_bytes() for public_key in public_keys],
                bytes(message),
                int(slot),
                bytes(self.proof.data),
                mode=LEAN_ENV,
            )
        except Exception as exception:
            raise AggregationError(
                f"single-message aggregate verification failed: {exception}"
            ) from exception

    def __hash__(self) -> int:
        """Content-deterministic hash via SSZ encoding."""
        return hash(self.encode_bytes())


class MultiMessageAggregate(Container):
    """
    Merged proof covering many distinct messages.

    Each component is a single-message proof over its own message.
    Merging binds the components into one proof the block can carry whole.
    """

    proof: ByteList512KiB
    """Compact public-key-free serialized multi-message aggregate proof bytes."""

    @classmethod
    def aggregate(
        cls,
        single_message_aggregates: list[SingleMessageAggregate],
        public_keys_per_aggregate: list[list[PublicKey]],
    ) -> "MultiMessageAggregate":
        """
        Merge several single-message proofs over distinct messages into one.

        A merged proof stores no public keys.
        The prover needs them as external context to fold the components together.
        They cannot be recovered from the proofs, so the caller supplies them.

        Args:
            single_message_aggregates: The single-message proofs to merge,
                one per distinct message.
            public_keys_per_aggregate: Public keys for each component,
                in the same order as the proofs.

        Returns:
            A merged proof binding every component to its own message.

        Raises:
            AggregationError: When no proofs are given, a public_key list disagrees
                with its participant count, or the prover rejects the inputs.
        """
        if not single_message_aggregates:
            raise AggregationError(
                "multi-message aggregate requires at least one single-message aggregate input"
            )

        # Each component carries the public keys named by its bitfield, in the same order.
        #
        # A miscount would otherwise fail deep in the prover with an opaque error.
        single_message_aggregate_entries: list[tuple[list[bytes], bytes]] = []
        for aggregate_index, (single_message_aggregate, public_keys) in enumerate(
            zip(single_message_aggregates, public_keys_per_aggregate, strict=True)
        ):
            expected_public_key_count = len(
                single_message_aggregate.participants.to_validator_indices()
            )
            if len(public_keys) != expected_public_key_count:
                raise AggregationError(
                    f"multi-message aggregate entry {aggregate_index} "
                    f"expected {expected_public_key_count} pubkeys, got {len(public_keys)}"
                )
            single_message_aggregate_entries.append(
                (
                    [public_key.encode_bytes() for public_key in public_keys],
                    bytes(single_message_aggregate.proof.data),
                )
            )

        # Hand the per-component keys and proof bytes to the Rust prover.
        #
        # The mode argument selects the matching backend bytecode.
        try:
            _, multi_message_aggregate_wire = merge_many_single_message_proof(
                single_message_aggregate_entries,
                LOG_INVERSE_RATE,
                mode=LEAN_ENV,
            )
        except Exception as exception:
            raise AggregationError(str(exception)) from exception

        return cls(proof=ByteList512KiB(data=multi_message_aggregate_wire))

    def split_by_message(
        self,
        message: Bytes32,
        public_keys_per_message: list[list[PublicKey]],
        participants: AggregationBits,
    ) -> SingleMessageAggregate:
        """
        Recover the single-message aggregate proof bound to one message.

        Splits this multi-message aggregate to extract the component
        bound to the given message.

        A merged proof stores neither the public keys nor the participant bitfields.
        The prover needs the original key layout to isolate one component.
        The caller supplies both, drawn from the block attestation this component binds.

        Args:
            message: Message that selects the single-message aggregate component.
            public_keys_per_message: PublicKey layout this multi-message aggregate was built with.
            participants: Bitfield naming the validators of the recovered component.

        Returns:
            The single-message aggregate proof bound to the message.

        Raises:
            AggregationError: When the Rust binding rejects the split.
        """
        # Each component carries the public keys named by its bitfield, in the same order.
        public_keys_per_component_ssz: list[list[bytes]] = [
            [public_key.encode_bytes() for public_key in public_keys]
            for public_keys in public_keys_per_message
        ]

        # Hand the key layout, merged proof, and selector message to the Rust prover.
        #
        # The mode argument selects the matching backend bytecode.
        try:
            _, single_message_aggregate_wire = split_multi_message_proof_by_message(
                public_keys_per_component_ssz,
                bytes(self.proof.data),
                bytes(message),
                LOG_INVERSE_RATE,
                mode=LEAN_ENV,
            )
        except Exception as exception:
            raise AggregationError(
                f"multi-message aggregate split failed: {exception}"
            ) from exception

        return SingleMessageAggregate(
            participants=participants,
            proof=ByteList512KiB(data=single_message_aggregate_wire),
        )

    def verify(
        self,
        public_keys_per_message: list[list[PublicKey]],
        messages: list[tuple[Bytes32, Slot]],
    ) -> None:
        """
        Verify this multi-message proof against its per-component bindings.

        Each component is checked against one message and slot supplied by the caller.
        Without that binding the proof would accept attacker-chosen data.
        That data could resolve to the same keys.
        The parallel lists pin every component to the message it actually signed.

        Args:
            public_keys_per_message: Public keys for each component, in component order.
            messages: Message-slot pair each component is bound to, parallel to the keys.

        Raises:
            AggregationError: When the two lists disagree in length, or the verifier rejects.
        """
        # Each component needs exactly one message-slot binding.
        #
        # A length mismatch would leave components unbound or misaligned.
        if len(messages) != len(public_keys_per_message):
            raise AggregationError(
                f"multi-message aggregate verify expected "
                f"{len(public_keys_per_message)} message bindings, "
                f"got {len(messages)}"
            )

        # Serialize the key layout and the per-component message bindings.
        public_keys_per_component_ssz: list[list[bytes]] = [
            [public_key.encode_bytes() for public_key in public_keys]
            for public_keys in public_keys_per_message
        ]
        expected_messages = [(bytes(message), int(slot)) for message, slot in messages]

        # Hand the layout, bindings, and merged proof to the Rust verifier.
        #
        # The mode argument selects the matching backend bytecode.
        try:
            verify_multi_message_proof_with_messages(
                public_keys_per_component_ssz,
                expected_messages,
                bytes(self.proof.data),
                mode=LEAN_ENV,
            )
        except Exception as exception:
            raise AggregationError(
                f"multi-message aggregate verification failed: {exception}"
            ) from exception

    def __hash__(self) -> int:
        """Content-deterministic hash via SSZ encoding."""
        return hash(self.encode_bytes())
