"""
Signature aggregation for the Lean Ethereum consensus specification.
Multi-signature aggregation containers and helpers.

Two proof shapes:

- Type-1: many validators, one message (one AttestationData, or one block root).
- Type-2: a merge of N Type-1 proofs, each over a distinct message.
"""

from __future__ import annotations

from collections.abc import Sequence

from lean_multisig_py import (
    aggregate_type_1,
    merge_many_type_1,
    setup_prover,
    split_type_2_by_msg,
    type1_compress_with_pubkeys,
    type1_compress_without_pubkeys,
    type1_decompress_with_pubkeys,
    type2_compress_with_pubkeys,
    type2_compress_without_pubkeys,
    type2_decompress_with_pubkeys,
    verify_type_1,
    verify_type_2,
)

from lean_spec.config import LEAN_ENV, LeanEnvMode
from lean_spec.subspecs.chain.config import MAX_ATTESTATIONS_DATA
from lean_spec.types import (
    AggregationBits,
    ByteListMiB,
    Bytes32,
    Container,
    Slot,
    SSZList,
    ValidatorIndex,
    ValidatorIndices,
)

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


class TypeOneInfo(Container):
    """Per-component metadata for a single-message multi-signer proof.

    Carries only the participant bitfield. The signed message and slot are
    rederived by the verifier from the block body it already trusts, so
    they live outside the proof envelope.
    """

    participants: AggregationBits
    """Bitfield indicating which validators contributed signatures."""

    proof: ByteListMiB
    """Compact no-pubkeys serialized Type-1 proof bytes."""


class TypeOneInfos(SSZList[TypeOneInfo]):
    """List of per-message info entries inside a Type-2 proof.

    A valid block carries at most MAX_ATTESTATIONS_DATA total entries + 1,
    one is reserved for the proposer's own signature.
    """

    LIMIT = int(MAX_ATTESTATIONS_DATA) + 1


class TypeOneMultiSignature(Container):
    """A single-message proof aggregating signatures from many validators."""

    info: TypeOneInfo
    """Participant bitfield for this proof."""

    proof: ByteListMiB
    """Aggregated proof bytes in compact no-pubkeys representation."""

    def with_public_keys(
        self,
        public_keys: Sequence[PublicKey],
    ) -> tuple[TypeOneMultiSignature, list[PublicKey]]:
        """Bind this proof with its participant-ordered public keys for parent merges."""
        keys = list(public_keys)
        expected = sum(1 for bit in self.info.participants.data if bool(bit))
        if len(keys) != expected:
            raise AggregationError(
                f"Type-1 child expected {expected} pubkeys for participants, got {len(keys)}"
            )
        return self, keys

    @staticmethod
    def select_greedily(
        *proof_sets: set[TypeOneMultiSignature] | None,
    ) -> tuple[list[TypeOneMultiSignature], set[ValidatorIndex]]:
        """Greedy set-cover over Type-1 proofs to maximise validator coverage.

        Repeatedly selects the proof covering the most uncovered validators
        until no proof adds new coverage. Earlier proof sets are
        prioritised: gossip-fresh proofs win over already-known ones.

        TODO: a more principled home for this once the proof pool layer
        firms up.
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
                    key=lambda p: len(set(p.info.participants.to_validator_indices()) - covered),
                )
                new_coverage = set(best.info.participants.to_validator_indices()) - covered

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
        tracked separately in info.participants (attestation bits on the wire).
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
            aggregated_validator_ids.update(child.info.participants.to_validator_indices())
        participants = ValidatorIndices(data=sorted(aggregated_validator_ids)).to_aggregation_bits()

        mode = mode or LEAN_ENV
        setup_prover(mode=mode)
        log_inv_rate = LOG_INV_RATE_TEST if mode == "test" else LOG_INV_RATE_PROD

        raw_pubkeys_ssz = [pk.encode_bytes() for pk, _ in raw_xmss]
        raw_signatures_ssz = [sig.encode_bytes() for _, sig in raw_xmss]

        children_bytes: list[tuple[list[bytes], bytes]] = []
        for idx, (child, child_public_keys_raw) in enumerate(children):
            child_public_keys = list(child_public_keys_raw)
            expected = sum(1 for bit in child.info.participants.data if bool(bit))
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
            sorted_pks_ssz, type1_wire = aggregate_type_1(
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

        # Canonicalise to the compact no-pubkeys form the verifier expects.
        type1_wire = _coerce_type1_wire(type1_wire, sorted_pks_ssz, mode)

        return TypeOneMultiSignature(
            info=TypeOneInfo(
                participants=participants,
                proof=ByteListMiB(data=type1_wire),
            ),
            proof=ByteListMiB(data=type1_wire),
        )

    def verify(
        self,
        public_keys: Sequence[PublicKey],
        message: Bytes32,
        slot: Slot,
        mode: LeanEnvMode | None = None,
    ) -> None:
        """Verify this single-message Type-1 proof against a resolved set of pubkeys.

        The pubkey list must be parallel to info.participants (one entry per
        set bit, in the same order). The message and slot are supplied by
        the caller — they are not stored on the proof. Raises
        AggregationError on any binding rejection or structural mismatch.
        """
        mode = mode or LEAN_ENV
        setup_prover(mode=mode)

        expected = sum(1 for bit in self.info.participants.data if bool(bit))
        if len(public_keys) != expected:
            raise AggregationError(
                f"Type-1 verify expected {expected} pubkeys for participants, "
                f"got {len(public_keys)}"
            )

        pks_ssz = [pk.encode_bytes() for pk in public_keys]
        proof_wire = _coerce_type1_wire(bytes(self.proof.data), pks_ssz, mode)
        try:
            verify_type_1(
                pks_ssz,
                bytes(message),
                int(slot),
                bytes(proof_wire),
                mode=mode,
            )
        except Exception as exc:
            raise AggregationError(f"Type-1 verification failed: {exc}") from exc


class TypeTwoMultiSignature(Container):
    """A merged proof covering many distinct messages.

    On the wire a SignedBlock carries the SSZ-serialised form of this
    container as its single proof blob. The block-level info list
    enumerates the participant bitfield for every merged Type-1
    component. Messages and slots are rederived by the verifier from
    the block body, not duplicated in the proof.
    """

    info: TypeOneInfos
    """Per-message metadata, one entry per merged Type-1 proof."""

    proof: ByteListMiB
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
            expected = sum(1 for bit in part.info.participants.data if bool(bit))
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
            pks_per_component_ssz, type2_wire = merge_many_type_1(
                type1_entries, log_inv_rate, mode=mode
            )
        except Exception as exc:
            raise AggregationError(f"Type-2 aggregation failed: {exc}") from exc

        # Canonicalise to the compact no-pubkeys form the verifier expects.
        type2_wire = _coerce_type2_wire(type2_wire, pks_per_component_ssz, mode)

        return TypeTwoMultiSignature(
            info=TypeOneInfos(data=[part.info for part in parts]),
            proof=ByteListMiB(data=type2_wire),
        )

    def split_by_msg(
        self,
        entry_index: int,
        message: Bytes32,
        public_keys_per_message: Sequence[Sequence[PublicKey]],
        mode: LeanEnvMode | None = None,
    ) -> TypeOneMultiSignature:
        """Recover the Type-1 proof bound to a specific message from this Type-2 merge.

        The caller is responsible for knowing which entry index of self.info
        corresponds to the message being split out — the proof envelope no
        longer stores per-entry messages.
        """
        mode = mode or LEAN_ENV
        setup_prover(mode=mode)
        log_inv_rate = LOG_INV_RATE_TEST if mode == "test" else LOG_INV_RATE_PROD

        if not 0 <= entry_index < len(self.info):
            raise AggregationError(
                f"Type-2 split entry_index {entry_index} out of range for {len(self.info)} entries"
            )

        entry = self.info[entry_index]

        if len(public_keys_per_message) != len(self.info):
            raise AggregationError(
                f"Type-2 split expected pubkey lists for {len(self.info)} messages, "
                f"got {len(public_keys_per_message)}"
            )

        pub_keys_per_component_ssz: list[list[bytes]] = []
        for idx, (info, pks) in enumerate(zip(self.info, public_keys_per_message, strict=True)):
            expected = sum(1 for bit in info.participants.data if bool(bit))
            if len(pks) != expected:
                raise AggregationError(
                    f"Type-2 split entry {idx} expected {expected} pubkeys, got {len(pks)}"
                )
            pub_keys_per_component_ssz.append([pk.encode_bytes() for pk in pks])

        type2_wire = _coerce_type2_wire(bytes(self.proof.data), pub_keys_per_component_ssz, mode)
        try:
            pks_ssz, type1_wire = split_type_2_by_msg(
                pub_keys_per_component_ssz,
                bytes(type2_wire),
                bytes(message),
                log_inv_rate,
                mode=mode,
            )
        except Exception as exc:
            raise AggregationError(f"Type-2 split-by-message failed: {exc}") from exc

        type1_wire = _coerce_type1_wire(type1_wire, pks_ssz, mode)

        return TypeOneMultiSignature(
            info=entry,
            proof=ByteListMiB(data=type1_wire),
        )

    def verify(
        self,
        public_keys_per_message: Sequence[Sequence[PublicKey]],
        mode: LeanEnvMode | None = None,
    ) -> None:
        """Verify this multi-message Type-2 proof against per-entry resolved pubkeys.

        public_keys_per_message must be parallel to self.info: one pubkey
        list per Type-1 info entry, ordered by that entry's participants
        bitfield.
        """
        mode = mode or LEAN_ENV
        setup_prover(mode=mode)

        if len(public_keys_per_message) != len(self.info):
            raise AggregationError(
                f"Type-2 verify expected pubkey lists for {len(self.info)} messages, "
                f"got {len(public_keys_per_message)}"
            )

        pub_keys_per_component_ssz: list[list[bytes]] = []
        for idx, (info, pks) in enumerate(zip(self.info, public_keys_per_message, strict=True)):
            expected = sum(1 for bit in info.participants.data if bool(bit))
            if len(pks) != expected:
                raise AggregationError(
                    f"Type-2 verify entry {idx} expected {expected} pubkeys, got {len(pks)}"
                )
            pub_keys_per_component_ssz.append([pk.encode_bytes() for pk in pks])

        type2_wire = _coerce_type2_wire(bytes(self.proof.data), pub_keys_per_component_ssz, mode)
        try:
            verify_type_2(pub_keys_per_component_ssz, type2_wire, mode=mode)
        except Exception as exc:
            raise AggregationError(f"Type-2 verification failed: {exc}") from exc


def _coerce_type1_wire(sig_bytes: bytes, pub_keys_ssz: list[bytes], mode: LeanEnvMode) -> bytes:
    """Normalise Type-1 bytes to the compact no-pubkeys form.

    The lean_multisig_py binding emits proofs in different layouts depending
    on which entry point produced them (aggregate, split, merge). This helper
    funnels every shape into the canonical no-pubkeys form expected by
    verify_type_1 and re-aggregation flows.
    """
    try:
        return type1_compress_without_pubkeys(sig_bytes, mode=mode)
    except Exception:
        pass

    try:
        bundled = type1_compress_with_pubkeys(pub_keys_ssz, sig_bytes, mode=mode)
        return type1_compress_without_pubkeys(bundled, mode=mode)
    except Exception:
        pass

    try:
        _, no_pubkeys = type1_decompress_with_pubkeys(sig_bytes, mode=mode)
        return no_pubkeys
    except Exception:
        return sig_bytes


def _coerce_type2_wire(
    sig_bytes: bytes,
    pub_keys_per_component: list[list[bytes]],
    mode: LeanEnvMode,
) -> bytes:
    """Normalise Type-2 bytes to the compact no-pubkeys form."""
    try:
        return type2_compress_without_pubkeys(sig_bytes, mode=mode)
    except Exception:
        pass

    try:
        bundled = type2_compress_with_pubkeys(pub_keys_per_component, sig_bytes, mode=mode)
        return type2_compress_without_pubkeys(bundled, mode=mode)
    except Exception:
        pass

    try:
        _, no_pubkeys = type2_decompress_with_pubkeys(sig_bytes, mode=mode)
        return no_pubkeys
    except Exception:
        return sig_bytes
