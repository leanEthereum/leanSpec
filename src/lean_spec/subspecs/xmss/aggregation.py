"""Signature aggregation for the Lean Ethereum consensus specification.
Multi-signature aggregation containers and helpers.

Two proof shapes:

- Type-1: many validators, one message (one AttestationData, or one block root).
- Type-2: a merge of N Type-1 proofs, each over a distinct message.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypeAlias

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


BytecodeClaim: TypeAlias = Bytes32
"""Placeholder alias for the trusted Evaluation<EF> field on TypeOneInfo / TypeTwoMultiSignature.

The Rust type is an extension-field evaluation. Its concrete SSZ
serialisation will land with the lean_multisig_py bindings.
"""


class AggregationError(Exception):
    """Raised when signature aggregation, merging, splitting, or verification fails."""


class TypeOneInfo(Container):
    """Per-message metadata for a single-message multi-signer proof.

    Carries everything a verifier needs to recompute the proof's binding
    inputs without re-deriving from block content. Participants stay in
    bitfield form for wire compactness; pubkeys are resolved at the
    binding boundary from the validator registry.
    """

    message: Bytes32
    """The 32-byte message that was signed (e.g. hash_tree_root of attestation data or block)."""

    slot: Slot
    """The slot in which the signatures were created."""

    participants: AggregationBits
    """Bitfield indicating which validators contributed signatures."""

    bytecode_claim: BytecodeClaim
    """Trusted evaluation tied to the proof. Recomputed by the verifier when received externally."""


class TypeOneInfos(SSZList[TypeOneInfo]):
    """List of per-message info entries inside a Type-2 proof.

    A valid block carries at most MAX_ATTESTATIONS_DATA distinct entries
    plus one for the proposer's own signature. 
    """

    LIMIT = int(MAX_ATTESTATIONS_DATA) + 1


class TypeOneMultiSignature(Container):
    """A single-message proof aggregating signatures from many validators."""

    info: TypeOneInfo
    """Message, slot, participants, and trusted bytecode claim."""

    proof: ByteListMiB
    """Raw aggregated proof bytes (ExecutionProof on the Rust side)."""

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


class TypeTwoMultiSignature(Container):
    """A merged proof covering many distinct messages.

    On the wire a SignedBlock carries the SSZ-serialised form of this
    container as its single proof blob. The block-level info list
    enumerates every (message, slot, participants) tuple the proof
    binds to.
    """

    info: TypeOneInfos
    """Per-message metadata, one entry per merged Type-1 proof."""

    bytecode_claim: BytecodeClaim
    """Aggregation-level trusted evaluation. Recomputed on receive."""

    proof: ByteListMiB
    """Raw merged proof bytes (ExecutionProof on the Rust side)."""


def _placeholder_proof_bytes() -> ByteListMiB:
    """Empty proof blob for stub returns. Real bytes land with the bindings."""
    return ByteListMiB(data=b"")


def _placeholder_bytecode_claim() -> BytecodeClaim:
    """Zero-filled placeholder. Real evaluation lands with the bindings."""
    return Bytes32(b"\x00" * 32)


def aggregate_type_1(
    children: Sequence[TypeOneMultiSignature],
    raw_xmss: Sequence[tuple[PublicKey, Signature]],
    xmss_participants: AggregationBits | None,
    message: Bytes32,
    slot: Slot,
    mode: LeanEnvMode | None = None,
) -> TypeOneMultiSignature:
    """Aggregate raw XMSS signatures and child Type-1 proofs into one Type-1 proof.

    All inputs must bind to the same (message, slot). The resulting proof
    covers the union of every child's participants plus the validators
    described by xmss_participants.

    Stub: returns a placeholder proof with empty bytes and a zero
    bytecode_claim until the binding lands. The participant union is
    computed honestly so callers reading the participants bitfield
    observe correct coverage.
    """
    _ = mode or LEAN_ENV

    if not raw_xmss and not children:
        raise AggregationError("At least one raw signature or child proof is required")

    if raw_xmss and xmss_participants is None:
        raise AggregationError("xmss_participants is required when raw_xmss is provided")

    if not raw_xmss and len(children) < 2:
        raise AggregationError(
            "At least two child proofs are required when no raw signatures are provided"
        )

    aggregated: set[ValidatorIndex] = set()
    if xmss_participants is not None:
        aggregated.update(xmss_participants.to_validator_indices())

    if len(aggregated) != len(raw_xmss):
        raise AggregationError("Raw signature count does not match XMSS participant count")

    for child in children:
        aggregated.update(child.info.participants.to_validator_indices())

    participants = ValidatorIndices(data=sorted(aggregated)).to_aggregation_bits()

    return TypeOneMultiSignature(
        info=TypeOneInfo(
            message=message,
            slot=slot,
            participants=participants,
            bytecode_claim=_placeholder_bytecode_claim(),
        ),
        proof=_placeholder_proof_bytes(),
    )


def verify_type_1(
    sig: TypeOneMultiSignature,
    public_keys: Sequence[PublicKey],
    mode: LeanEnvMode | None = None,
) -> None:
    """Verify a single-message Type-1 proof against a resolved set of pubkeys.

    Structural checks always run; cryptographic verification arrives with
    the bindings. The structural side enforces:

    - The pubkey list is parallel to the participants bitfield.

    Stub crypto path silently accepts; once bindings ship the call
    delegates to the multi-signature library and raises AggregationError
    on cryptographic failure.
    """
    _ = mode or LEAN_ENV

    expected = sum(1 for bit in sig.info.participants.data if bool(bit))
    if len(public_keys) != expected:
        raise AggregationError(
            f"Type-1 verify expected {expected} pubkeys for participants, "
            f"got {len(public_keys)}"
        )


def aggregate_type_2(
    parts: Sequence[TypeOneMultiSignature],
    mode: LeanEnvMode | None = None,
) -> TypeTwoMultiSignature:
    """Merge several Type-1 proofs (each over a distinct message) into one Type-2 proof.

    Stub: returns a shape-correct TypeTwoMultiSignature with the supplied
    info entries, empty proof bytes, and a zero bytecode_claim.
    """
    _ = mode or LEAN_ENV

    if not parts:
        raise AggregationError("aggregate_type_2 requires at least one Type-1 input")

    return TypeTwoMultiSignature(
        info=TypeOneInfos(data=[part.info for part in parts]),
        bytecode_claim=_placeholder_bytecode_claim(),
        proof=_placeholder_proof_bytes(),
    )


def split_type_2_by_msg(
    sig: TypeTwoMultiSignature,
    message: Bytes32,
    mode: LeanEnvMode | None = None,
) -> TypeOneMultiSignature:
    """Recover the Type-1 proof bound to a specific message from a Type-2 merge.

    Stub: locates the matching info entry and returns a Type-1 wrapping it
    with empty proof bytes. Real implementation runs the binding's split.
    """
    _ = mode or LEAN_ENV

    for entry in sig.info:
        if entry.message == message:
            return TypeOneMultiSignature(
                info=entry,
                proof=_placeholder_proof_bytes(),
            )

    raise AggregationError(f"Type-2 proof has no entry for message {message.hex()}")


def verify_type_2(
    sig: TypeTwoMultiSignature,
    public_keys_per_message: Sequence[Sequence[PublicKey]],
    mode: LeanEnvMode | None = None,
) -> None:
    """Verify a multi-message Type-2 proof against the resolved pubkeys for each entry.

    public_keys_per_message must be parallel to sig.info: one pubkey list
    per Type-1 info entry, ordered by the participants bitfield of that
    entry.

    Structural checks always run; cryptographic verification arrives with
    the bindings. The structural side enforces:

    - The pubkey lists are parallel to the info list.
    - Each pubkey list has the same length as its info entry's
      participant bitfield popcount.

    Stub crypto path silently accepts; once bindings ship the call
    delegates to the multi-signature library and raises AggregationError
    on cryptographic failure.
    """
    _ = mode or LEAN_ENV

    if len(public_keys_per_message) != len(sig.info):
        raise AggregationError(
            f"Type-2 verify expected pubkey lists for {len(sig.info)} messages, "
            f"got {len(public_keys_per_message)}"
        )

    for idx, (info, pks) in enumerate(zip(sig.info, public_keys_per_message, strict=True)):
        expected = sum(1 for bit in info.participants.data if bool(bit))
        if len(pks) != expected:
            raise AggregationError(
                f"Type-2 verify entry {idx} expected {expected} pubkeys, got {len(pks)}"
            )
