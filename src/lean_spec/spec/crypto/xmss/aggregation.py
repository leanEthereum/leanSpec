"""Multi-signature aggregation over Generalized XMSS.

Two proof shapes:

- Type-1: many validators on a single message (one attestation, or one block root).
- Type-2: a merge of several Type-1 proofs over distinct messages.

The Rust binding owns proof construction and cryptographic checks.
"""

from lean_multisig_py import (
    aggregate_type_1,
    merge_many_type_1,
    setup_prover,
    split_type_2_by_msg,
    verify_type_1,
    verify_type_2_with_messages,
)

from lean_spec.config import LEAN_ENV
from lean_spec.spec.forks.lstar.containers import (
    AggregationBits,
    Slot,
    ValidatorIndex,
    ValidatorIndices,
)
from lean_spec.spec.ssz import ByteList512KiB, Bytes32, Container

from .containers import PublicKey, Signature

LOG_INV_RATE: int = 1 if LEAN_ENV == "test" else 2
"""Inverse-rate exponent forwarded to the SNARK backend.

- A smaller rate trades verifier cost for prover speed.
- Test mode favors prover speed.
"""

# The environment is fixed for the lifetime of the process.
#
# One setup call covers every aggregation, verification, split, and merge below.
#
# Per-call invocations then default to the mode established here.
setup_prover(mode=LEAN_ENV)


class AggregationError(Exception):
    """Raised when aggregation, merging, splitting, or verification fails."""


class TypeOneMultiSignature(Container):
    """Single-message proof aggregating signatures from many validators.

    Every validator signs the same message for the same slot.

    The message and slot stay outside the proof.
    The verifier rederives them from the block body it already trusts.
    """

    model_config = Container.model_config | {"frozen": True}

    participants: AggregationBits
    """Bitfield indicating which validators contributed signatures."""

    proof: ByteList512KiB
    """Aggregated proof bytes in compact no-pubkeys representation."""

    @classmethod
    def aggregate(
        cls,
        children: list[tuple["TypeOneMultiSignature", list[PublicKey]]],
        raw_xmss: list[tuple[ValidatorIndex, PublicKey, Signature]],
        message: Bytes32,
        slot: Slot,
    ) -> "TypeOneMultiSignature":
        """Fold fresh signatures and child proofs into one single-message proof.

        # Overview

        Two kinds of contribution merge into one proof.

        - A fresh signer contributes a single raw signature.
        - A child proof contributes an already-aggregated bundle of signers.

        The result names the union of every contributing validator.
        The prover compresses all contributions into one proof over the shared message.

        # Why the index travels with each fresh signer

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
        all_indices = {vid for vid, _, _ in raw_xmss}.union(
            *(child.participants.to_validator_indices() for child, _ in children)
        )
        participants = ValidatorIndices(data=sorted(all_indices)).to_aggregation_bits()

        # Phase 2: serialize inputs to the prover's wire format.
        raw_pubkeys_ssz = [pk.encode_bytes() for _, pk, _ in raw_xmss]
        raw_signatures_ssz = [sig.encode_bytes() for _, _, sig in raw_xmss]
        children_bytes = [
            ([pk.encode_bytes() for pk in pubkeys], bytes(child.proof.data))
            for child, pubkeys in children
        ]

        # Phase 3: hand off to the Rust prover.
        # The mode argument routes the call to the matching backend bytecode.
        try:
            _, type1_wire = aggregate_type_1(
                raw_pubkeys_ssz,
                raw_signatures_ssz,
                bytes(message),
                int(slot),
                LOG_INV_RATE,
                children_bytes or None,
                mode=LEAN_ENV,
            )
        except Exception as exc:
            raise AggregationError(str(exc)) from exc

        return cls(participants=participants, proof=ByteList512KiB(data=type1_wire))

    def verify(
        self,
        public_keys: list[PublicKey],
        message: Bytes32,
        slot: Slot,
    ) -> None:
        """Verify this single-message Type-1 proof against a pubkey set.

        Args:
            public_keys: Pubkeys for the validators named by participants.
            message: Message bound by the proof.
            slot: Slot bound by the proof.

        Raises:
            AggregationError: When the pubkey count does not match the bitfield
                or the Rust verifier rejects the proof.
        """
        # The bitfield names one validator per set bit.
        # The caller must supply exactly that many keys, in the same order.
        # A miscount would otherwise fail deep in the verifier with an opaque error.
        expected = len(self.participants.to_validator_indices())
        if len(public_keys) != expected:
            raise AggregationError(
                f"Type-1 verify expected {expected} pubkeys for participants, "
                f"got {len(public_keys)}"
            )

        # Hand the resolved keys, message, and slot to the Rust verifier.
        # The mode argument selects the matching backend bytecode.
        try:
            verify_type_1(
                [pk.encode_bytes() for pk in public_keys],
                bytes(message),
                int(slot),
                bytes(self.proof.data),
                mode=LEAN_ENV,
            )
        except Exception as exc:
            raise AggregationError(f"Type-1 verification failed: {exc}") from exc

    def __hash__(self) -> int:
        """Content-deterministic hash via SSZ encoding."""
        return hash(self.encode_bytes())


class TypeTwoMultiSignature(Container):
    """Merged proof covering many distinct messages.

    Each component is a single-message proof over its own message.
    Merging binds the components into one proof the block can carry whole.

    A signed block stores this proof as a single serialized blob.
    """

    model_config = Container.model_config | {"frozen": True}

    proof: ByteList512KiB
    """Compact no-pubkeys serialized Type-2 proof bytes."""

    @classmethod
    def aggregate(
        cls,
        parts: list[TypeOneMultiSignature],
        public_keys_per_part: list[list[PublicKey]],
    ) -> "TypeTwoMultiSignature":
        """Merge several single-message proofs over distinct messages into one.

        # Why the public keys are passed in

        - A merged proof stores no public keys.
        - The prover needs them as external context to fold the components together.
        - They cannot be recovered from the proofs, so the caller supplies them.

        Args:
            parts: The single-message proofs to merge, one per distinct message.
            public_keys_per_part: Public keys for each component, in the same order as the proofs.

        Returns:
            A merged proof binding every component to its own message.

        Raises:
            AggregationError: When no proofs are given, a pubkey list disagrees
                with its participant count, or the prover rejects the inputs.
        """
        if not parts:
            raise AggregationError("Type-2 aggregate requires at least one Type-1 input")

        # Each component carries the public keys named by its bitfield, in the same order.
        #
        # A miscount would otherwise fail deep in the prover with an opaque error.
        type1_entries: list[tuple[list[bytes], bytes]] = []
        for idx, (part, pubkeys) in enumerate(zip(parts, public_keys_per_part, strict=True)):
            expected = len(part.participants.to_validator_indices())
            if len(pubkeys) != expected:
                raise AggregationError(
                    f"Type-2 aggregate entry {idx} expected {expected} pubkeys, got {len(pubkeys)}"
                )
            type1_entries.append(([pk.encode_bytes() for pk in pubkeys], bytes(part.proof.data)))

        # Hand the per-component keys and proof bytes to the Rust prover.
        #
        # The mode argument selects the matching backend bytecode.
        try:
            _, type2_wire = merge_many_type_1(type1_entries, LOG_INV_RATE, mode=LEAN_ENV)
        except Exception as exc:
            raise AggregationError(str(exc)) from exc

        return cls(proof=ByteList512KiB(data=type2_wire))

    def split_by_msg(
        self,
        message: Bytes32,
        public_keys_per_message: list[list[PublicKey]],
        participants: AggregationBits,
    ) -> TypeOneMultiSignature:
        """Recover the Type-1 proof bound to one message from this Type-2 merge.

        # Why the layout and participants are passed in

        - A merged proof stores neither the public keys nor the participant bitfields.
        - The prover needs the original key layout to isolate one component.
        - The caller supplies both, drawn from the block attestation this component binds.

        Args:
            message: Message that selects the Type-1 component.
            public_keys_per_message: Pubkey layout this Type-2 was built with.
            participants: Bitfield naming the validators of the recovered component.

        Returns:
            The Type-1 proof bound to the message.

        Raises:
            AggregationError: When the Rust binding rejects the split.
        """
        # Each component carries the public keys named by its bitfield, in the same order.
        pub_keys_per_component_ssz: list[list[bytes]] = [
            [pk.encode_bytes() for pk in pks] for pks in public_keys_per_message
        ]

        # Hand the key layout, merged proof, and selector message to the Rust prover.
        #
        # The mode argument selects the matching backend bytecode.
        try:
            _, type1_wire = split_type_2_by_msg(
                pub_keys_per_component_ssz,
                bytes(self.proof.data),
                bytes(message),
                LOG_INV_RATE,
                mode=LEAN_ENV,
            )
        except Exception as exc:
            raise AggregationError(f"Type-2 split failed: {exc}") from exc

        return TypeOneMultiSignature(
            participants=participants,
            proof=ByteList512KiB(data=type1_wire),
        )

    def verify(
        self,
        public_keys_per_message: list[list[PublicKey]],
        messages: list[tuple[Bytes32, Slot]],
    ) -> None:
        """Verify this multi-message proof against its per-component bindings.

        # The message bindings

        Each component is checked against one message and slot supplied by the caller.
        Without that binding the proof would accept attacker-chosen data resolving to the same keys.
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
                f"Type-2 verify expected {len(public_keys_per_message)} message bindings, "
                f"got {len(messages)}"
            )

        # Serialize the key layout and the per-component message bindings.
        pub_keys_per_component_ssz: list[list[bytes]] = [
            [pk.encode_bytes() for pk in pks] for pks in public_keys_per_message
        ]
        expected_messages = [(bytes(msg), int(slot)) for msg, slot in messages]

        # Hand the layout, bindings, and merged proof to the Rust verifier.
        #
        # The mode argument selects the matching backend bytecode.
        try:
            verify_type_2_with_messages(
                pub_keys_per_component_ssz,
                expected_messages,
                bytes(self.proof.data),
                mode=LEAN_ENV,
            )
        except Exception as exc:
            raise AggregationError(f"Type-2 verification failed: {exc}") from exc

    def __hash__(self) -> int:
        """Content-deterministic hash via SSZ encoding."""
        return hash(self.encode_bytes())
