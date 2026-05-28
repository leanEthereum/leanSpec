"""Lightweight block specification for test definitions."""

from __future__ import annotations

from collections import defaultdict

from lean_spec.base import CamelModel
from lean_spec.node.chain.clock import Interval
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.aggregation import (
    TypeOneMultiSignature,
    TypeTwoMultiSignature,
)
from lean_spec.spec.crypto.xmss.containers import Signature
from lean_spec.spec.forks import Slot, ValidatorIndex, ValidatorIndices
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AggregatedAttestations,
    Attestation,
    AttestationData,
    Block,
    BlockBody,
    SignedAttestation,
    SignedBlock,
    State,
)
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.forks.lstar.store import Store
from lean_spec.spec.ssz import ByteList512KiB, Bytes32

from ..keys import XmssKeyManager, create_dummy_signature
from .aggregated_attestation_spec import AggregatedAttestationSpec


class BlockSpec(CamelModel):
    """
    Block specification for test definitions.

    Contains the same fields as Block, but all optional except slot.
    The framework fills in any missing fields automatically.
    """

    slot: Slot
    """The slot for this block (required)."""

    proposer_index: ValidatorIndex | None = None
    """
    The proposer index for this block.

    If None, framework selects using round-robin based on slot and num_validators.
    """

    parent_root: Bytes32 | None = None
    """
    The root of the parent block.

    If None, framework computes from state.latest_block_header.
    """

    state_root: Bytes32 | None = None
    """
    The state root after applying this block.

    If None, framework computes via state_transition dry-run.
    """

    body: BlockBody | None = None
    """
    The block body containing attestations.

    If None, framework creates body from the attestations field.
    If both body and attestations are None, framework creates body with empty attestations.
    Note: If body is provided, attestations field is ignored.
    """

    attestations: list[AggregatedAttestationSpec] | None = None
    """
    List of aggregated attestations to include in this block's body.

    Each entry specifies multiple validators attesting to the same data.
    The framework generates signatures and aggregates them.

    If None, framework uses default behavior (empty body).
    If body is provided, this field is ignored.
    """

    forced_attestations: list[AggregatedAttestationSpec] | None = None
    """
    Raw aggregated attestations appended directly to the final block body.

    Unlike attestations, these entries bypass the block builder's filtering.
    Use this only for STF coverage when the builder would pre-filter the
    attestation before state processing (e.g., unjustified source).
    """

    label: str | None = None
    """
    Optional label to tag this block for later reference.

    Enables fork creation by referencing labeled ancestors.
    Labels must be unique within a test.
    """

    parent_label: str | None = None
    """
    Optional label referencing a previously created block as parent.

    If None, parent is determined by the current canonical head.
    If specified, parent_root is computed from the labeled block.
    """

    valid_signature: bool = True
    """
    Flag whether the proposer's signature in generated block should be valid.

    Used for testing that verification properly rejects invalid block signatures.
    When False, a structurally valid but cryptographically invalid signature
    (all zeros) will be generated for the proposer attestation instead of a
    proper XMSS signature.

    Defaults to True (valid signature).
    If False, the proposer attestation will be given a dummy/invalid signature.
    """

    skip_slot_processing: bool = False
    """
    If True, the state transition fixture skips automatic slot advancement
    before processing this block.

    Useful for tests that intentionally exercise slot mismatch failures.
    """

    def resolve_proposer_index(self, num_validators: int) -> ValidatorIndex:
        """Return the proposer index, falling back to round-robin by slot."""
        return self.proposer_index or ValidatorIndex(int(self.slot) % num_validators)

    def resolve_parent_root(
        self,
        block_registry: dict[str, Block],
        default_root: Bytes32,
    ) -> Bytes32:
        """
        Resolve the parent block root with a three-level fallback:

        1. Explicit parent_root on the spec (for direct override)
        2. parent_label lookup in the block registry (for fork building)
        3. default_root provided by the caller (typically the current head
           or the state's latest block header root)

        Args:
            block_registry: Map of labels to previously built blocks.
            default_root: Root to use when neither parent_root nor parent_label is set.

        Returns:
            Root hash of the parent block.

        Raises:
            ValueError: If parent_label is set but not found in registry.
        """
        # Explicit override takes highest priority.
        if self.parent_root is not None:
            return self.parent_root

        # Label-based resolution for fork building.
        if self.parent_label is not None:
            if not (parent_block := block_registry.get(self.parent_label)):
                raise ValueError(
                    f"Parent label '{self.parent_label}' not found. "
                    f"Available: {list(block_registry)}"
                )
            return hash_tree_root(parent_block)

        # No explicit parent: use the caller-provided default.
        return default_root

    def build_attestations(
        self,
        state: State,
        block_registry: dict[str, Block],
        key_manager: XmssKeyManager,
    ) -> tuple[
        list[Attestation],
        dict[AttestationData, dict[ValidatorIndex, Signature]],
        set[Attestation],
    ]:
        """
        Build attestations and signatures from this block's attestation specs.

        Args:
            state: Parent state for source checkpoint resolution.
            block_registry: Labeled blocks for target checkpoint resolution.
            key_manager: XMSS key manager for signing attestation data.

        Returns:
            Tuple of:
                - All built attestations (one per validator per spec)
                - Signature lookup keyed by (attestation_data, validator_id)
                - Subset of attestations that have valid (non-dummy) signatures
        """
        if self.attestations is None:
            return [], {}, set()

        attestations: list[Attestation] = []
        signature_lookup: dict[AttestationData, dict[ValidatorIndex, Signature]] = {}
        valid_attestations: set[Attestation] = set()

        for aggregated_spec in self.attestations:
            # Build attestation data once.
            # All validators in this aggregation vote for the same target.
            attestation_data = aggregated_spec.build_attestation_data(block_registry, state)

            # Create one attestation per validator.
            # Each validator signs independently; signatures aggregate later.
            for validator_id in aggregated_spec.validator_ids:
                attestation = Attestation(
                    validator_id=validator_id,
                    data=attestation_data,
                )
                attestations.append(attestation)

                # Generate signature or use invalid placeholder.
                # Invalid signatures test rejection paths.
                if aggregated_spec.valid_signature:
                    signature = key_manager.sign_attestation_data(
                        validator_id,
                        attestation_data,
                    )
                    valid_attestations.add(attestation)
                else:
                    signature = create_dummy_signature()

                # Index signature by attestation data and validator ID.
                signature_lookup.setdefault(attestation_data, {}).setdefault(
                    validator_id,
                    signature,
                )

        return attestations, signature_lookup, valid_attestations

    def _sign_block(
        self,
        final_block: Block,
        attestation_proofs: list[TypeOneMultiSignature],
        proposer_index: ValidatorIndex,
        key_manager: XmssKeyManager,
        state: State,
    ) -> SignedBlock:
        """Sign a block and assemble the final SignedBlock with the merged proof.

        Builds a Type-1 wrapping the proposer's XMSS signature, then merges
        that with the per-attestation Type-1 proofs into a single Type-2 proof
        and SSZ-encodes it onto the envelope. Consumers of this filler feed
        the block through spec.on_block / verify_signatures, which decodes
        the proof and verifies it, so an honest merged proof is required.

        When valid_signature is False, the proposer signature is a dummy
        XMSS one and the binding-driven aggregation would reject it before
        verify_signatures ever runs. The Type-2 envelope is then assembled
        directly from the info entries with empty proof bytes — that
        decodes structurally and lets verify_signatures reach (and reject
        at) the verify_type_2 call, which is the contract the test exercises.

        Args:
            final_block: The unsigned block.
            attestation_proofs: Per-attestation Type-1 proofs (parallel to
                final_block.body.attestations).
            proposer_index: Which validator proposes this block.
            key_manager: XMSS key manager for signing.
            state: State providing the validator registry used to resolve
                participant pubkeys for the merge.

        Returns:
            Complete signed block.
        """
        block_root = hash_tree_root(final_block)
        proposer_pubkey = key_manager.get_public_keys(proposer_index)[1]

        # The binding rejects placeholder bytes; if anything in the merged
        # input is a dummy (invalid proposer sig or a build_invalid_proof
        # attestation), bypass aggregate_type_2 entirely and assemble the
        # Type-2 envelope by hand. The result still SSZ-decodes so
        # verify_signatures reaches verify_type_2 for the rejection.
        any_placeholder_attestation = any(not proof.proof.data for proof in attestation_proofs)
        use_placeholder = not self.valid_signature or any_placeholder_attestation

        if not use_placeholder:
            proposer_signature = key_manager.sign_block_root(
                proposer_index,
                self.slot,
                block_root,
            )
            proposer_type_1 = TypeOneMultiSignature.aggregate(
                children=[],
                raw_xmss=[(proposer_index, proposer_pubkey, proposer_signature)],
                message=block_root,
                slot=self.slot,
            )

            public_keys_per_part: list[list] = [
                [
                    state.validators[vid].get_attestation_pubkey()
                    for vid in proof.participants.to_validator_indices()
                ]
                for proof in attestation_proofs
            ]
            public_keys_per_part.append([proposer_pubkey])

            merged = TypeTwoMultiSignature.aggregate(
                [*attestation_proofs, proposer_type_1],
                public_keys_per_part=public_keys_per_part,
            )
            proof_bytes = merged.encode_bytes()
        else:
            placeholder = ByteList512KiB(data=b"")
            envelope = TypeTwoMultiSignature(proof=placeholder)
            proof_bytes = envelope.encode_bytes()

        return SignedBlock(
            block=final_block,
            proof=ByteList512KiB(data=proof_bytes),
        )

    def build_signed_block(
        self,
        state: State,
        key_manager: XmssKeyManager,
    ) -> SignedBlock:
        """
        Build a complete SignedBlock from this specification without a Store.

        Used by signature verification tests where no fork choice is involved.

        Args:
            state: The anchor state to build against.
            key_manager: XMSS key manager for signing.

        Returns:
            Complete signed block with all attestation and proposer signatures.
        """
        spec = LstarSpec()
        proposer_index = self.resolve_proposer_index(len(state.validators))

        # Build a genesis block registry so attestation specs can resolve labels.
        anchor_block = Block(
            slot=state.latest_block_header.slot,
            proposer_index=state.latest_block_header.proposer_index,
            parent_root=state.latest_block_header.parent_root,
            state_root=hash_tree_root(state),
            body=BlockBody(attestations=AggregatedAttestations(data=[])),
        )
        block_registry: dict[str, Block] = {"genesis": anchor_block}

        # Resolve the parent root.
        # The default is the latest block header from the slot-advanced state.
        parent_state = spec.process_slots(state, self.slot)
        parent_root = self.resolve_parent_root(
            block_registry,
            default_root=hash_tree_root(parent_state.latest_block_header),
        )

        # Separate valid and invalid attestation specs.
        # Valid specs go through normal aggregation; invalid specs get special proofs.
        invalid_specs = [
            att_spec
            for att_spec in (self.attestations or [])
            if not att_spec.valid_signature
            or (att_spec.signer_ids is not None and att_spec.signer_ids != att_spec.validator_ids)
        ]

        # Build a valid-only copy for normal attestation construction.
        valid_only = self.model_copy(
            update={
                "attestations": [
                    att_spec
                    for att_spec in (self.attestations or [])
                    if att_spec not in invalid_specs
                ]
            }
        )

        # Build valid attestations and their signatures.
        valid_attestations, signature_lookup, _ = valid_only.build_attestations(
            state, block_registry, key_manager
        )

        # Group attestations that share the same AttestationData.
        # Validators seeing the same head/source/target produce identical data,
        # so they can be merged into a single aggregated attestation.
        data_to_validator_ids: dict[AttestationData, list[ValidatorIndex]] = defaultdict(list)
        for attestation in valid_attestations:
            data_to_validator_ids[attestation.data].append(attestation.validator_id)

        # Build one AggregatedAttestation per unique data.
        # Each carries a bitfield marking which validators participated.
        aggregated_attestations = [
            AggregatedAttestation(
                aggregation_bits=ValidatorIndices(data=validator_ids).to_aggregation_bits(),
                data=data,
            )
            for data, validator_ids in data_to_validator_ids.items()
        ]
        attestation_sigs = key_manager.build_attestation_proofs(
            AggregatedAttestations(data=aggregated_attestations),
            signature_lookup=signature_lookup,
        )
        aggregated_payloads = {
            agg_att.data: {proof}
            for agg_att, proof in zip(aggregated_attestations, attestation_sigs, strict=True)
        }

        final_block, _, _, aggregated_signatures = spec.build_block(
            state,
            slot=self.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots={parent_root},
            aggregated_payloads=aggregated_payloads,
        )

        # Append proofs for invalid attestation specs.
        # These exercise signature verification rejection paths.
        for invalid_spec in invalid_specs:
            final_block, invalid_proof = invalid_spec.build_invalid_proof(
                block_registry, state, key_manager, final_block
            )
            aggregated_signatures.append(invalid_proof)

        return self._sign_block(
            final_block, aggregated_signatures, proposer_index, key_manager, state
        )

    def build_signed_block_with_store(
        self,
        store: Store,
        block_registry: dict[str, Block],
        key_manager: XmssKeyManager,
        lean_env: str,
    ) -> tuple[SignedBlock, Store]:
        """
        Build a complete signed block through the Store's attestation pipeline.

        Simulates what a real node does when proposing a block.
        Replays the gossip, aggregation, and proposal pipeline through the Store.

        Returns a Store enriched with the aggregated Type-1 payloads built
        during the simulated pipeline. The caller can persist these so future
        block builds can re-aggregate the same attestations rather than
        reconstructing them from on-chain block bodies (which would require
        splitting the block-level Type-2 proof — a heavy and, in the test
        recursive-aggregation mode, unreliable operation). Other fields of
        the original Store (gossip signatures, time, head, etc.) are
        preserved so the simulated build does not consume state the caller
        is tracking separately.

        Args:
            store: Fork choice store for head state lookup and gossip processing.
            block_registry: Labeled blocks for fork creation.
            key_manager: Key manager for signing.
            lean_env: Signature scheme environment name ("test" or "prod").

        Returns:
            The signed block and the Store with new known payloads merged in.
        """
        spec = LstarSpec()
        proposer_index = self.resolve_proposer_index(len(store.states[store.head].validators))

        # Resolve parent block.
        # Parent can be specified by label (for forks) or defaults to head.
        parent_root = self.resolve_parent_root(block_registry, default_root=store.head)

        # Verify the parent's state exists in the store.
        if parent_root not in store.states:
            raise ValueError(
                f"Parent (root=0x{parent_root.hex()}) "
                "has no state in store - cannot build on this fork"
            )

        # Preserve the caller's Store so unrelated fields (gossip signatures,
        # head, finalization checkpoints, time) survive the simulated pipeline.
        # Only the freshly aggregated Type-1 payloads merge back at the end.
        caller_store = store

        # Build attestations from this spec's attestation fields.
        parent_state = store.states[parent_root]
        _, attestation_signatures, valid_attestations = self.build_attestations(
            parent_state, block_registry, key_manager
        )

        # Advance the local store clock to the block's slot before gossiping.
        # In-body attestations carry data.slot = self.slot; the Store's time
        # check rejects votes whose slot has not yet started locally.
        block_slot_interval = Interval.from_slot(self.slot)
        if store.time < block_slot_interval:
            store, _ = spec.on_tick(
                store, block_slot_interval, has_proposal=True, is_aggregator=True
            )

        # Gossip valid attestation signatures into the Store.
        # This runs signature verification through the spec's validation path.
        for attestation in valid_attestations:
            sigs_for_data = attestation_signatures.get(attestation.data)
            if (
                sigs_for_data is None
                or (signature := sigs_for_data.get(attestation.validator_id)) is None
            ):
                continue
            store = spec.on_gossip_attestation(
                store,
                SignedAttestation(
                    validator_id=attestation.validator_id,
                    data=attestation.data,
                    signature=signature,
                ),
                is_aggregator=True,
            )

        # Trigger Store aggregation to merge gossip signatures into known payloads.
        # Aggregation runs on a local clone: gossip pools mutate here, but the
        # caller's gossip-signature view must not be consumed by this simulated
        # build. Only the freshly aggregated Type-1 payloads propagate back.
        aggregation_store, _ = spec.aggregate(store)
        merged_store = spec.accept_new_attestations(aggregation_store)

        # Build the block through the spec's State.build_block().
        final_block, _, _, block_proofs = spec.build_block(
            parent_state,
            slot=self.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots=set(store.blocks.keys()),
            aggregated_payloads=merged_store.latest_known_aggregated_payloads,
        )

        # Merge new known payloads (built locally) back into the caller's
        # store while leaving every other field untouched.
        merged_known = {k: set(v) for k, v in caller_store.latest_known_aggregated_payloads.items()}
        for data, proofs in merged_store.latest_known_aggregated_payloads.items():
            merged_known.setdefault(data, set()).update(proofs)
        store = caller_store.model_copy(update={"latest_known_aggregated_payloads": merged_known})

        # Append forced attestations that bypass the builder's MAX cap.
        # Each entry is signed and aggregated so the block carries valid proofs.
        if self.forced_attestations:
            for att_spec in self.forced_attestations:
                att_data = att_spec.build_attestation_data(block_registry, parent_state)
                proof = key_manager.sign_and_aggregate(att_spec.validator_ids, att_data)
                block_proofs.append(proof)
                final_block = final_block.model_copy(
                    update={
                        "body": final_block.body.model_copy(
                            update={
                                "attestations": AggregatedAttestations(
                                    data=[
                                        *final_block.body.attestations.data,
                                        AggregatedAttestation(
                                            aggregation_bits=ValidatorIndices(
                                                data=att_spec.validator_ids,
                                            ).to_aggregation_bits(),
                                            data=att_data,
                                        ),
                                    ]
                                )
                            }
                        )
                    }
                )

            # Recompute state root with the modified body.
            post_state = spec.process_slots(parent_state, self.slot)
            post_state = spec.process_block(post_state, final_block)
            final_block = final_block.model_copy(update={"state_root": hash_tree_root(post_state)})

        signed_block = self._sign_block(
            final_block, block_proofs, proposer_index, key_manager, parent_state
        )
        return signed_block, store
