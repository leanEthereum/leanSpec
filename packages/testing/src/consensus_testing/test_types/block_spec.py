"""Lightweight block specification for test definitions."""

from __future__ import annotations

from collections import defaultdict

from lean_spec.forks.lstar.containers.attestation import (
    AggregatedAttestation,
    Attestation,
    AttestationData,
    SignedAttestation,
)
from lean_spec.forks.lstar.containers.block import (
    Block,
    BlockBody,
    BlockSignatures,
    SignedBlock,
)
from lean_spec.forks.lstar.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.state import State
from lean_spec.forks.lstar.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.forks.lstar.store import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.types import Bytes32, CamelModel

from ..keys import LEAN_ENV_TO_SCHEMES, XmssKeyManager, create_dummy_signature
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
        attestation_proofs: list[AggregatedSignatureProof],
        proposer_index: ValidatorIndex,
        key_manager: XmssKeyManager,
    ) -> SignedBlock:
        """
        Sign a block and assemble the final SignedBlock.

        Args:
            final_block: The unsigned block.
            attestation_proofs: Aggregated signature proofs for attestations.
            proposer_index: Which validator proposes this block.
            key_manager: XMSS key manager for signing.

        Returns:
            Complete signed block.
        """
        if self.valid_signature:
            proposer_signature = key_manager.sign_block_root(
                proposer_index,
                self.slot,
                hash_tree_root(final_block),
            )
        else:
            proposer_signature = create_dummy_signature()

        return SignedBlock(
            block=final_block,
            signature=BlockSignatures(
                attestation_signatures=AttestationSignatures(data=attestation_proofs),
                proposer_signature=proposer_signature,
            ),
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
        parent_state = state.process_slots(self.slot)
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
        attestation_sigs = key_manager.build_attestation_signatures(
            AggregatedAttestations(data=aggregated_attestations),
            signature_lookup=signature_lookup,
        )
        aggregated_payloads = {
            agg_att.data: {proof}
            for agg_att, proof in zip(aggregated_attestations, attestation_sigs.data, strict=True)
        }

        final_block, _, _, aggregated_signatures = state.build_block(
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

        return self._sign_block(final_block, aggregated_signatures, proposer_index, key_manager)

    def build_signed_block_with_store(
        self,
        store: Store,
        block_registry: dict[str, Block],
        key_manager: XmssKeyManager,
        lean_env: str,
    ) -> SignedBlock:
        """
        Build a complete signed block through the Store's attestation pipeline.

        Simulates what a real node does when proposing a block.
        Replays the gossip, aggregation, and proposal pipeline through the Store.

        Args:
            store: Fork choice store for head state lookup and gossip processing.
            block_registry: Labeled blocks for fork creation.
            key_manager: Key manager for signing.
            lean_env: Signature scheme environment name ("test" or "prod").

        Returns:
            Complete signed block ready for Store processing.
        """
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

        # Build attestations from this spec's attestation fields.
        parent_state = store.states[parent_root]
        _, attestation_signatures, valid_attestations = self.build_attestations(
            parent_state, block_registry, key_manager
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
            store = store.on_gossip_attestation(
                SignedAttestation(
                    validator_id=attestation.validator_id,
                    data=attestation.data,
                    signature=signature,
                ),
                scheme=LEAN_ENV_TO_SCHEMES[lean_env],
                is_aggregator=True,
            )

        # Trigger Store aggregation to merge gossip signatures into known payloads.
        aggregation_store, _ = store.aggregate()
        merged_store = aggregation_store.accept_new_attestations()

        # Build the block through the spec's State.build_block().
        final_block, _, _, block_proofs = parent_state.build_block(
            slot=self.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots=set(store.blocks.keys()),
            aggregated_payloads=merged_store.latest_known_aggregated_payloads,
        )

        # Append forced attestations that bypass the builder's MAX cap.
        # Each entry is signed and aggregated so the block carries valid proofs.
        if self.forced_attestations:
            for spec in self.forced_attestations:
                att_data = spec.build_attestation_data(block_registry, parent_state)
                proof = key_manager.sign_and_aggregate(spec.validator_ids, att_data)
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
                                                data=spec.validator_ids,
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
            post_state = parent_state.process_slots(self.slot).process_block(final_block)
            final_block = final_block.model_copy(update={"state_root": hash_tree_root(post_state)})

        return self._sign_block(final_block, block_proofs, proposer_index, key_manager)
