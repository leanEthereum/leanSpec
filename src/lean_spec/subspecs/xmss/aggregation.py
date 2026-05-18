"""
Multi-signature aggregation for the Lean Ethereum consensus spec.

Two proof shapes:

- Type-1: many validators on one message (one AttestationData, or one block root).
- Type-2: a merge of N Type-1 proofs over distinct messages.
"""

from __future__ import annotations

from collections.abc import Sequence

from lean_multisig_py import (
    aggregate_type_1,
    merge_many_type_1,
    setup_prover,
    split_type_2_by_msg,
    verify_type_1,
    verify_type_2_with_messages,
)

from lean_spec.config import LEAN_ENV, LeanEnvMode
from lean_spec.types import (
    AggregationBits,
    ByteList512KiB,
    Bytes32,
    Container,
    Slot,
    ValidatorIndex,
    ValidatorIndices,
)
from lean_spec.types.boolean import Boolean

from .containers import PublicKey, Signature

LOG_INV_RATE_TEST = 1
"""
Inverse rate exponent for test mode (fastest, biggest proofs).

This parameter is forwarded to `lean_multisig_py` prover and controls a performance/size trade-off:

- Lower values generate proofs faster but increase proof size.
- Higher values reduce proof size but increase prover work.
"""

LOG_INV_RATE_PROD = 2
"""Inverse rate exponent for production mode (balanced speed vs proof size)."""


class AggregationError(Exception):
    """Raised when signature aggregation, merging, splitting, or verification fails."""


class TypeOneMultiSignature(Container):
    """A single-message proof aggregating signatures from many validators.

    The signed message and slot are rederived by the verifier from the
    block body it already trusts, so they live outside the proof envelope.
    """

    participants: AggregationBits
    """Bitfield indicating which validators contributed signatures."""

    proof: ByteList512KiB
    """Aggregated proof bytes in compact no-pubkeys representation."""

    @staticmethod
    def select_greedily(
        *proof_sets: set[TypeOneMultiSignature] | None,
    ) -> tuple[list[TypeOneMultiSignature], set[ValidatorIndex]]:
        """Greedy set-cover over Type-1 proofs to maximise validator coverage.

        Repeatedly selects the proof covering the most uncovered validators
        until no proof adds new coverage. Earlier proof sets are
        prioritised: gossip-fresh proofs win over already-known ones.
        """
        selected: list[TypeOneMultiSignature] = []
        covered: set[ValidatorIndex] = set()

        for proofs in proof_sets:
            if not proofs:
                continue

            remaining = list(proofs)

            while remaining:
                best = max(
                    remaining,
                    key=lambda p: len(set(p.participants.to_validator_indices()) - covered),
                )
                new_coverage = set(best.participants.to_validator_indices()) - covered

                if not new_coverage:
                    break

                selected.append(best)
                covered |= new_coverage
                remaining.remove(best)

        return selected, covered

    @staticmethod
    def aggregate(
        children: Sequence[tuple[TypeOneMultiSignature, Sequence[PublicKey]]],
        raw_xmss: Sequence[tuple[PublicKey, Signature]],
        xmss_participants: AggregationBits | None,
        message: Bytes32,
        slot: Slot,
        mode: LeanEnvMode | None = None,
    ) -> TypeOneMultiSignature:
        """Aggregate raw XMSS signatures and child Type-1 proofs into one Type-1 proof.

        Proof bytes are stored in compact no-pubkeys form. Participant identity is
        tracked separately in participants (attestation bits on the wire).
        """
        if not raw_xmss and not children:
            raise AggregationError("At least one raw signature or child proof is required")

        if raw_xmss and xmss_participants is None:
            raise AggregationError("xmss_participants is required when raw_xmss is provided")

        if not raw_xmss and len(children) < 2:
            raise AggregationError(
                "At least two child proofs are required when no raw signatures are provided"
            )

        aggregated_validator_ids: set[ValidatorIndex] = set()
        if xmss_participants is not None:
            aggregated_validator_ids.update(xmss_participants.to_validator_indices())

        if len(aggregated_validator_ids) != len(raw_xmss):
            raise AggregationError("Raw signature count does not match XMSS participant count")

        # Include child participants in the aggregated participants
        for child, _ in children:
            aggregated_validator_ids.update(child.participants.to_validator_indices())
        participants = ValidatorIndices(data=sorted(aggregated_validator_ids)).to_aggregation_bits()

        mode = mode or LEAN_ENV
        setup_prover(mode=mode)
        log_inv_rate = LOG_INV_RATE_TEST if mode == "test" else LOG_INV_RATE_PROD

        raw_pubkeys_ssz = [pk.encode_bytes() for pk, _ in raw_xmss]
        raw_signatures_ssz = [sig.encode_bytes() for _, sig in raw_xmss]

        children_bytes: list[tuple[list[bytes], bytes]] = []
        for idx, (child, child_public_keys_raw) in enumerate(children):
            child_public_keys = list(child_public_keys_raw)
            expected = child.participants.data.count(Boolean(1))
            if len(child_public_keys) != expected:
                raise AggregationError(
                    f"Type-1 aggregate child {idx} expected {expected} pubkeys, "
                    f"got {len(child_public_keys)}"
                )

            child_pks_ssz = [pk.encode_bytes() for pk in child_public_keys]
            child_wire = bytes(child.proof.data)
            if not child_wire:
                raise AggregationError(f"Child proof {idx} has empty proof bytes")
            children_bytes.append((child_pks_ssz, child_wire))

        try:
            _, type1_wire = aggregate_type_1(
                raw_pubkeys_ssz,
                raw_signatures_ssz,
                bytes(message),
                int(slot),
                log_inv_rate,
                children_bytes if children_bytes else None,
                mode=mode,
            )
        except Exception as exc:
            raise AggregationError(f"Type-1 aggregation failed: {exc}") from exc

        return TypeOneMultiSignature(
            participants=participants,
            proof=ByteList512KiB(data=type1_wire),
        )

    def verify(
        self,
        public_keys: Sequence[PublicKey],
        message: Bytes32,
        slot: Slot,
        mode: LeanEnvMode | None = None,
    ) -> None:
        """Verify this single-message Type-1 proof against a resolved set of pubkeys."""
        mode = mode or LEAN_ENV
        setup_prover(mode=mode)

        expected = self.participants.data.count(Boolean(1))
        if len(public_keys) != expected:
            raise AggregationError(
                f"Type-1 verify expected {expected} pubkeys for participants, "
                f"got {len(public_keys)}"
            )

        pks_ssz = [pk.encode_bytes() for pk in public_keys]
        try:
            verify_type_1(
                pks_ssz,
                bytes(message),
                int(slot),
                bytes(self.proof.data),
                mode=mode,
            )
        except Exception as exc:
            raise AggregationError(f"Type-1 verification failed: {exc}") from exc


class TypeTwoMultiSignature(Container):
    """A merged proof covering many distinct messages.

    On the wire a SignedBlock carries the SSZ-serialised form of this
    container as its single proof blob.
    """

    proof: ByteList512KiB
    """Compact no-pubkeys serialized Type-2 proof bytes."""

    @staticmethod
    def aggregate(
        parts: Sequence[TypeOneMultiSignature],
        public_keys_per_part: Sequence[Sequence[PublicKey]] | None = None,
        mode: LeanEnvMode | None = None,
    ) -> TypeTwoMultiSignature:
        """Merge several Type-1 proofs (each over a distinct message) into one Type-2 proof.

        The returned Type-2 proof bytes are stored in compact no-pubkeys form.
        """
        if not parts:
            raise AggregationError("Type-2 aggregate requires at least one Type-1 input")

        mode = mode or LEAN_ENV
        setup_prover(mode=mode)
        log_inv_rate = LOG_INV_RATE_TEST if mode == "test" else LOG_INV_RATE_PROD

        if public_keys_per_part is not None and len(public_keys_per_part) != len(parts):
            raise AggregationError(
                f"Type-2 aggregate expected pubkeys for {len(parts)} parts, "
                f"got {len(public_keys_per_part)}"
            )

        type1_entries: list[tuple[list[bytes], bytes]] = []
        for idx, part in enumerate(parts):
            expected = part.participants.data.count(Boolean(1))
            if public_keys_per_part is None:
                raise AggregationError(
                    "public_keys_per_part is required when Type-1 proofs are stored without pubkeys"
                )
            pubkeys = list(public_keys_per_part[idx])
            if len(pubkeys) != expected:
                raise AggregationError(
                    f"Type-2 aggregate entry {idx} expected {expected} pubkeys, got {len(pubkeys)}"
                )
            pks_ssz = [pk.encode_bytes() for pk in pubkeys]
            type1_entries.append((pks_ssz, bytes(part.proof.data)))

        try:
            _, type2_wire = merge_many_type_1(type1_entries, log_inv_rate, mode=mode)
        except Exception as exc:
            raise AggregationError(f"Type-2 aggregation failed: {exc}") from exc

        return TypeTwoMultiSignature(proof=ByteList512KiB(data=type2_wire))

    def split_by_msg(
        self,
        message: Bytes32,
        public_keys_per_message: Sequence[Sequence[PublicKey]],
        mode: LeanEnvMode | None = None,
    ) -> TypeOneMultiSignature:
        """Recover the Type-1 proof bound to a specific message from this Type-2 merge.

        public_keys_per_message defines the per-component pubkey layout the
        Type-2 was built with.
        """
        mode = mode or LEAN_ENV
        setup_prover(mode=mode)
        log_inv_rate = LOG_INV_RATE_TEST if mode == "test" else LOG_INV_RATE_PROD

        pub_keys_per_component_ssz: list[list[bytes]] = [
            [pk.encode_bytes() for pk in pks] for pks in public_keys_per_message
        ]

        try:
            _, type1_wire = split_type_2_by_msg(
                pub_keys_per_component_ssz,
                bytes(self.proof.data),
                bytes(message),
                log_inv_rate,
                mode=mode,
            )
        except Exception as exc:
            raise AggregationError(f"Type-2 split-by-message failed: {exc}") from exc

        return TypeOneMultiSignature(
            participants=AggregationBits(data=[]),
            proof=ByteList512KiB(data=type1_wire),
        )

    def verify(
        self,
        public_keys_per_message: Sequence[Sequence[PublicKey]],
        messages: Sequence[tuple[Bytes32, Slot]],
        mode: LeanEnvMode | None = None,
    ) -> None:
        """Verify this multi-message Type-2 proof.

        Each entry of public_keys_per_message corresponds to one Type-1
        component merged into this Type-2.
        The parallel messages entry binds that component to a specific
        message hash and slot.
        Without this binding the proof would verify against any attacker
        chosen attestation data that resolves to the same pubkeys.
        """
        mode = mode or LEAN_ENV
        setup_prover(mode=mode)

        if len(messages) != len(public_keys_per_message):
            raise AggregationError(
                f"Type-2 verify expected {len(public_keys_per_message)} message bindings, "
                f"got {len(messages)}"
            )

        pub_keys_per_component_ssz: list[list[bytes]] = [
            [pk.encode_bytes() for pk in pks] for pks in public_keys_per_message
        ]
        expected_messages = [(bytes(msg), int(slot)) for msg, slot in messages]

        try:
            verify_type_2_with_messages(
                pub_keys_per_component_ssz,
                expected_messages,
                bytes(self.proof.data),
                mode=mode,
            )
        except Exception as exc:
            raise AggregationError(f"Type-2 verification failed: {exc}") from exc
