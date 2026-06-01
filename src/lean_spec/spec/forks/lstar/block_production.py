"""Lstar fork — proposer-side block building."""

from collections.abc import Set as AbstractSet

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.lstar.aggregation_select import select_greedily
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
from lean_spec.spec.ssz import ZERO_HASH, Bytes32, Uint8

from ._contract import LstarSpecContract
from .state_transition import attestation_data_matches_chain


class BlockProductionMixin(LstarSpecContract):
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

        Computes the post-state and creates a block with the correct state root.

        Uses a fixed-point algorithm: finds attestation_data entries whose source
        matches the current justified checkpoint, greedily selects proofs maximizing
        new validator coverage, then applies the STF. If justification advances,
        repeats with the new checkpoint.
        """
        aggregated_attestations: list[AggregatedAttestation] = []
        aggregated_signatures: list[SingleMessageAggregate] = []

        if aggregated_payloads:
            # Fixed-point loop: find attestation_data entries matching the current
            # justified checkpoint and greedily select proofs. Processing attestations
            # may advance justification, unlocking more entries.
            # When building on top of genesis (slot 0), process_block_header
            # updates the justified root to parent_root. Apply the same
            # derivation here so attestation sources match.
            if state.latest_block_header.slot == Slot(0):
                current_justified = Checkpoint(slot=Slot(0), root=parent_root)
            else:
                current_justified = state.latest_justified

            # Track the justified-slot bitfield to skip already-justified targets.
            #
            # Extend the bitfield to cover every slot we might query.
            # The range runs from the finalized boundary up to slot - 1 inclusive.
            current_finalized_slot = state.latest_finalized.slot
            current_justified_slots = state.justified_slots.extend_to_slot(
                current_finalized_slot, slot - Slot(1)
            )

            # Build the chain view as it will appear on the candidate block.
            #
            # The view is the recorded history up to the parent.
            # Then comes the parent root at the parent's slot.
            # Then zero-hash entries for any skipped slots up to the new block.
            # The chain-match helper uses this view to validate source and target roots.
            num_empty_slots = int(slot - state.latest_block_header.slot - Slot(1))
            extended_historical_block_hashes: list[Bytes32] = (
                list(state.historical_block_hashes) + [parent_root] + [ZERO_HASH] * num_empty_slots
            )

            processed_attestation_data: set[AttestationData] = set()

            while True:
                found_entries = False

                for attestation_data, proofs in sorted(
                    aggregated_payloads.items(), key=lambda item: item[0].target.slot
                ):
                    if attestation_data in processed_attestation_data:
                        continue

                    if Uint8(len(processed_attestation_data)) >= MAX_ATTESTATIONS_DATA:
                        break

                    if attestation_data.head.root not in known_block_roots:
                        continue

                    # Chain-match runs first.
                    #
                    # It rejects checkpoints whose slot is past the chain view.
                    # That prevents the bounded queries below from indexing out of range.
                    if not attestation_data_matches_chain(
                        attestation_data, extended_historical_block_hashes
                    ):
                        continue

                    # The source slot must already be justified on this chain.
                    if not current_justified_slots.is_slot_justified(
                        current_finalized_slot, attestation_data.source.slot
                    ):
                        continue

                    # Genesis-anchored votes have source.slot = target.slot = 0.
                    #
                    # They cannot advance justification: the state transition drops them.
                    # They still carry head-vote weight for fork choice.
                    # Including them in the body propagates them into peers' payload pool.
                    # The bypass below keeps them past the target-already-justified check,
                    # since slot 0 is implicitly justified and would otherwise filter them.
                    is_genesis_self_vote = attestation_data.source.slot == Slot(0) and (
                        attestation_data.target.slot == Slot(0)
                    )

                    # Skip attestations whose target slot is already justified.
                    #
                    # Justification adds nothing for them.
                    # Entries the state transition will later drop are still kept here.
                    # They carry head-vote weight for fork choice.
                    if not is_genesis_self_vote and current_justified_slots.is_slot_justified(
                        current_finalized_slot, attestation_data.target.slot
                    ):
                        continue

                    processed_attestation_data.add(attestation_data)

                    found_entries = True

                    selected, _ = select_greedily(proofs)
                    aggregated_signatures.extend(selected)
                    for proof in selected:
                        aggregated_attestations.append(
                            self.aggregated_attestation_class(
                                aggregation_bits=proof.participants,
                                data=attestation_data,
                            )
                        )

                if not found_entries:
                    break

                # Build candidate block and check if justification changed.
                candidate_block = self.block_class(
                    slot=slot,
                    proposer_index=proposer_index,
                    parent_root=parent_root,
                    state_root=Bytes32.zero(),
                    body=self.block_body_class(
                        attestations=self.aggregated_attestations_class(
                            data=list(aggregated_attestations)
                        )
                    ),
                )
                post_state = self.process_block(self.process_slots(state, slot), candidate_block)

                # Re-run the filter when justification or finalization advanced.
                #
                # Both quantities are monotonic in 3SF-mini, so the loop is bounded.
                # Finalization advancement shifts the justified window forward.
                # That can unlock attestations whose target slot was outside it before.
                if (
                    post_state.latest_justified != current_justified
                    or post_state.latest_finalized.slot != current_finalized_slot
                ):
                    current_justified = post_state.latest_justified
                    current_justified_slots = post_state.justified_slots
                    current_finalized_slot = post_state.latest_finalized.slot
                    continue

                break

            # Compact: merge all proofs sharing the same AttestationData into one
            # using recursive children aggregation.
            #
            # During the fixed-point loop above, multiple proofs may have been
            # selected for the same AttestationData across iterations. Group them
            # and merge each group into a single recursive proof.
            proof_groups: dict[AttestationData, list[SingleMessageAggregate]] = {}
            for attestation, signature in zip(
                aggregated_attestations, aggregated_signatures, strict=True
            ):
                proof_groups.setdefault(attestation.data, []).append(signature)

            aggregated_attestations = []
            aggregated_signatures = []
            for attestation_data, proofs in proof_groups.items():
                if len(proofs) == 1:
                    signature = proofs[0]
                else:
                    # Multiple proofs for the same data were aggregated separately.
                    # Merge them into one recursive proof using children-only
                    # aggregation (no new raw signatures).
                    children = [
                        (
                            proof,
                            [
                                state.validators[validator_index].get_attestation_public_key()
                                for validator_index in proof.participants.to_validator_indices()
                            ],
                        )
                        for proof in proofs
                    ]
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

        # Create the final block with selected attestations.
        final_block = self.block_class(
            slot=slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=Bytes32.zero(),
            body=self.block_body_class(
                attestations=self.aggregated_attestations_class(data=aggregated_attestations),
            ),
        )

        # Recompute state from the final block.
        post_state = self.process_block(self.process_slots(state, slot), final_block)
        final_block.state_root = hash_tree_root(post_state)

        return final_block, post_state, aggregated_attestations, aggregated_signatures
