"""Lstar fork — proposer-side block building."""

from collections import defaultdict
from collections.abc import Set as AbstractSet

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.forks.lstar._base import LstarSpecBase
from lean_spec.spec.forks.lstar.aggregation import select_proofs_for_coverage
from lean_spec.spec.forks.lstar.config import (
    MAX_ATTESTATIONS_DATA,
)
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    AttestationData,
    Block,
    Checkpoint,
    SingleMessageAggregate,
    Slot,
    State,
    ValidatorIndex,
)
from lean_spec.spec.ssz import ZERO_HASH, Bytes32


class BlockProductionMixin(LstarSpecBase):
    """Proposer-side block building for the lstar fork."""

    def build_block(
        self,
        state: State,
        slot: Slot,
        proposer_index: ValidatorIndex,
        parent_root: Bytes32,
        known_block_roots: AbstractSet[Bytes32],
        aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]] | None = None,
    ) -> tuple[Block, State, list[AggregatedAttestation], list[SingleMessageAggregate]]:
        """
        Build a valid block on top of the given pre-state.

        # Overview

        A proposer fills a block with attestation votes, then records the post-state root.

        Selection is circular:

        - A vote may only build from an already-justified source.
        - Yet including votes is the act that justifies those sources.

        So the eligible set grows as votes are added, and the proposer selects in rounds.

        # Algorithm

        Each round repeats these steps:

        1. Pick the eligible proofs covering the most uncounted validators.
        2. Apply the state transition.
        3. Re-anchor on any newly justified checkpoint.

        The rounds stop once a pass adds nothing.

        # Why it terminates

        Justification and finalization only move forward, and the chosen set only grows.
        Both are bounded, so the rounds must end.

        Args:
            state: Pre-state the block builds on.
            slot: Slot the new block occupies.
            proposer_index: Validator proposing the block.
            parent_root: Root of the parent block.
            known_block_roots: Block roots the proposer has seen and may vote on.
            aggregated_payloads: Candidate proofs grouped by the data they attest to.

        Returns:
            The final block, its post-state, the included attestations,
            and the merged proof backing each one.
        """
        aggregated_attestations: list[AggregatedAttestation] = []
        aggregated_signatures: list[SingleMessageAggregate] = []

        # Advance the pre-state to this block's slot once.
        advanced_state = self.process_slots(state, slot)

        if aggregated_payloads:
            # Anchor on the checkpoint this chain treats as justified.
            #
            # On genesis the parent is justified at slot 0 by header processing.
            # Anchor there so eligible sources match.
            current_justified_checkpoint = (
                Checkpoint(slot=Slot(0), root=parent_root)
                if state.latest_block_header.slot == Slot(0)
                else state.latest_justified
            )

            # Track which slots are already justified.
            #
            # Extend the window so every slot the loop may query is covered.
            # It spans the finalized boundary up to the slot before this block.
            current_finalized_slot = state.latest_finalized.slot
            current_justified_slots = state.justified_slots.extend_to_slot(
                current_finalized_slot, slot - Slot(1)
            )

            # Assemble the chain as it will look once this block is applied.
            #
            # 1. History up to the parent.
            # 2. The parent root at its own slot.
            # 3. A zero hash for each slot skipped before this block.
            #
            # Source and target roots are validated against this view.
            num_empty_slots = int(slot - state.latest_block_header.slot - Slot(1))
            extended_historical_block_hashes: list[Bytes32] = (
                list(state.historical_block_hashes) + [parent_root] + [ZERO_HASH] * num_empty_slots
            )

            processed_attestation_data: set[AttestationData] = set()

            # Order candidates by target slot, once.
            candidates_in_target_slot_order = sorted(
                aggregated_payloads.items(), key=lambda item: item[0].target.slot
            )

            # Fixed-point selection.
            #
            # - Each pass scans every candidate once, in target-slot order.
            # - Accepting an entry may advance justification and unlock more.
            # - Re-scan until a pass finds nothing new.
            while True:
                found_new_entries = False

                for attestation_data, proofs in candidates_in_target_slot_order:
                    if attestation_data in processed_attestation_data:
                        continue

                    # Stop once the block holds the maximum distinct data entries.
                    # This cap is a proposer-side budget, not a consensus rule.
                    if len(processed_attestation_data) >= int(MAX_ATTESTATIONS_DATA):
                        break

                    # Skip votes whose head block the proposer has not seen.
                    if attestation_data.head.root not in known_block_roots:
                        continue

                    # Reject votes that do not match this chain.
                    #
                    # This also rejects any checkpoint past the chain view.
                    # That keeps the bounded lookups below in range.
                    if not attestation_data.lies_on_chain(extended_historical_block_hashes):
                        continue

                    # A vote may only build from an already-justified source.
                    if not current_justified_slots.is_slot_justified(
                        current_finalized_slot, attestation_data.source.slot
                    ):
                        continue

                    # Genesis self-votes have source and target both at slot 0.
                    #
                    # - The state transition drops them: they justify nothing.
                    # - They still carry head weight for fork choice.
                    # - Including them propagates them to peers.
                    # - Slot 0 counts as justified, so the next check would drop them.
                    # - This flag lets them through.
                    source_at_genesis = attestation_data.source.slot == Slot(0)
                    target_at_genesis = attestation_data.target.slot == Slot(0)
                    is_genesis_self_vote = source_at_genesis and target_at_genesis

                    # Skip votes whose target slot is already justified.
                    #
                    # - A justified target gains nothing from more votes.
                    # - Genesis self-votes are exempt, kept for their head weight.
                    if not is_genesis_self_vote and current_justified_slots.is_slot_justified(
                        current_finalized_slot, attestation_data.target.slot
                    ):
                        continue

                    processed_attestation_data.add(attestation_data)
                    found_new_entries = True

                    # Choose proofs covering the most validators.
                    # Emit one attestation per chosen proof.
                    selected_proofs, _ = select_proofs_for_coverage(proofs)
                    aggregated_signatures.extend(selected_proofs)
                    for proof in selected_proofs:
                        aggregated_attestations.append(
                            self.aggregated_attestation_class(
                                aggregation_bits=proof.participants,
                                data=attestation_data,
                            )
                        )

                if not found_new_entries:
                    break

                # Apply the state transition to a trial block.
                # Its post-state reveals whether this pass advanced justification.
                candidate_block = self.block_class(
                    slot=slot,
                    proposer_index=proposer_index,
                    parent_root=parent_root,
                    state_root=Bytes32.zero(),
                    body=self.block_body_class(
                        attestations=self.aggregated_attestations_class(
                            data=aggregated_attestations
                        )
                    ),
                )
                post_state = self.process_block(advanced_state, candidate_block)

                # Repeat only if justification or finalization moved.
                #
                # - Both advance monotonically, so the loop is bounded.
                # - A finalization step slides the justified window forward.
                # - That can make previously out-of-range targets eligible.
                if (
                    post_state.latest_justified != current_justified_checkpoint
                    or post_state.latest_finalized.slot != current_finalized_slot
                ):
                    current_justified_checkpoint = post_state.latest_justified
                    current_justified_slots = post_state.justified_slots
                    current_finalized_slot = post_state.latest_finalized.slot

                    # Re-anchoring needs no other rebuilds.
                    # The justified window still covers every slot the loop queries.
                    # The chain view is fixed once written, never recomputed.
                    continue

                break

            # Collapse each attestation data down to a single proof.
            #
            # - The coverage picker may emit several proofs for one data in a pass.
            # - A block must carry one attestation per data, over the union of voters.

            # Group every proof under the data it attests to.
            # Strict pairing guards against the two lists drifting out of sync.
            signatures_by_attestation_data: defaultdict[
                AttestationData, list[SingleMessageAggregate]
            ] = defaultdict(list)
            for attestation, signature in zip(
                aggregated_attestations, aggregated_signatures, strict=True
            ):
                signatures_by_attestation_data[attestation.data].append(signature)

            # Rebuild the output lists, one entry per distinct data.
            aggregated_attestations = []
            aggregated_signatures = []
            for attestation_data, grouped_signatures in signatures_by_attestation_data.items():
                if len(grouped_signatures) == 1:
                    # One proof already covers this data, so use it as-is.
                    signature = grouped_signatures[0]
                else:
                    # Fold the proofs into one, each kept as a child.
                    # Verifying a child needs the public keys of the voters it covers.
                    children = [
                        (
                            proof,
                            [
                                PublicKey.decode_bytes(
                                    state.validators[validator_index].attestation_public_key
                                )
                                for validator_index in proof.participants.to_validator_indices()
                            ],
                        )
                        for proof in grouped_signatures
                    ]
                    # Merge over the union of voters; no new raw signatures are added.
                    signature = SingleMessageAggregate.aggregate(
                        children=children,
                        raw_xmss=[],
                        message=hash_tree_root(attestation_data),
                        slot=attestation_data.slot,
                    )

                aggregated_signatures.append(signature)
                aggregated_attestations.append(
                    self.aggregated_attestation_class(
                        aggregation_bits=signature.participants, data=attestation_data
                    )
                )

        # Assemble the block carrying the chosen attestations.
        final_block = self.block_class(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=Bytes32.zero(),
            body=self.block_body_class(
                attestations=self.aggregated_attestations_class(data=aggregated_attestations),
            ),
        )

        # Recompute the post-state to obtain the state root.
        #
        # Merging proofs keeps the same voters, so the post-state is unchanged.
        # Only the body's shape differs, so just the root is needed.
        post_state = self.process_block(advanced_state, final_block)
        final_block = final_block.model_copy(update={"state_root": hash_tree_root(post_state)})

        return final_block, post_state, aggregated_attestations, aggregated_signatures
