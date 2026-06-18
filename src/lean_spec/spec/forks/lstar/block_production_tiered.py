"""
Lstar fork — proposer-side block building, tiered greedy strategy.

This is an alternative to the round-based fixed-point strategy.
Exactly one block-production mixin is composed into the fork at a time.
The two are interchangeable: same contract, different selection policy.
"""

from collections import defaultdict
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from enum import IntEnum

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
    JustifiedSlots,
    SingleMessageAggregate,
    Slot,
    State,
    ValidatorIndex,
)
from lean_spec.spec.ssz import ZERO_HASH, Boolean, Bytes32


class _Tier(IntEnum):
    """
    Selection tier for a candidate attestation data entry.

    Declared in priority order: a lower value wins.
    """

    FINALIZE = 1
    """Applying the entry crosses two-thirds on target and finalizes the source."""
    JUSTIFY = 2
    """Applying the entry crosses two-thirds on target but does not finalize."""
    BUILD = 3
    """Adds marginal new voters toward target's two-thirds supermajority."""


@dataclass(frozen=True)
class _EntryScore:
    """
    Tiered score for a candidate attestation data entry during block building.

    Lower tier wins.
    The remaining order depends on the tier.

    The finalize and justify tiers already cross the threshold on their target.
    So they rank a larger target slot first, then a larger attestation slot,
    then more new voters, then the entry's data root for determinism.
    Pushing the justified slot as far forward as possible shortens recovery
    from a justification or finalization stall.

    The build tier only adds marginal voters toward the threshold.
    So coverage matters more than reaching for a distant slot.
    It ranks more new voters first, then a larger target slot, then a larger
    attestation slot, then the entry's data root for determinism.
    """

    tier: _Tier
    new_voter_count: int
    target_slot: Slot
    attestation_slot: Slot

    def ordering_key(self, data_root: Bytes32) -> tuple[int, int, int, int, bytes]:
        """Sort key where the smallest tuple is the best candidate."""
        larger_target_slot = -int(self.target_slot)
        larger_attestation_slot = -int(self.attestation_slot)
        more_new_voters = -self.new_voter_count
        if self.tier is _Tier.BUILD:
            return (
                int(self.tier),
                more_new_voters,
                larger_target_slot,
                larger_attestation_slot,
                bytes(data_root),
            )
        return (
            int(self.tier),
            larger_target_slot,
            larger_attestation_slot,
            more_new_voters,
            bytes(data_root),
        )


class TieredBlockProductionMixin(LstarSpecBase):
    """Proposer-side block building for the lstar fork, tiered greedy strategy."""

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

        1. Score every remaining candidate against the projected post-state.
        2. Pick the best one: finalize beats justify beats build.
        3. Project justification and finalization forward, unlocking dependents.

        The rounds stop at the data-entry cap or once nothing scores.
        Projection replaces trial state transitions, so the real transition
        runs only once at the end to seal the state root.

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
            # Tiered greedy selection.
            #
            # Each round scores remaining candidates against a projected post-state
            # and picks the best: finalize beats justify beats build.
            # Justification and finalization are projected incrementally so dependent
            # attestations become eligible on the next round without re-running the
            # state transition.
            # Selection stops at the data-entry cap or when no remaining candidate scores.
            selected_attestations_with_proofs: list[
                tuple[AggregatedAttestation, SingleMessageAggregate]
            ] = []

            # Assemble the chain as it will look once this block is applied.
            #
            # 1. History up to the parent.
            # 2. The parent root at its own slot.
            # 3. A zero hash for each slot skipped before this block.
            #
            # Precondition: the new slot must lie strictly after the parent slot.
            # Without the guard, unsigned subtraction underflows and the empty-slot
            # padding allocates an astronomically large list.
            parent_slot = state.latest_block_header.slot
            assert slot > parent_slot, (
                f"Cannot build block at slot {slot} <= parent slot {parent_slot}"
            )
            num_empty_slots = int(slot - parent_slot - Slot(1))
            extended_historical_block_hashes: list[Bytes32] = (
                list(state.historical_block_hashes) + [parent_root] + [ZERO_HASH] * num_empty_slots
            )
            validator_count = len(state.validators)

            # Projected post-state, updated incrementally as entries are selected.
            finalized_slot = state.latest_finalized.slot
            justified_slots = state.justified_slots.extend_to_slot(finalized_slot, slot - Slot(1))

            # Seed the running voter map from the on-chain justification bitlist.
            #
            # The state stores one bit per tracked-root and validator pair.
            # The bit at index (root_index * N + validator_index) means that
            # validator voted for that tracked root, where N is the validator count.
            # Seeding from these bits lets scoring count on-chain voters toward the
            # two-thirds threshold.
            votes_by_target_root: dict[Bytes32, set[ValidatorIndex]] = {}
            for root_index, on_chain_target_root in enumerate(state.justifications_roots):
                votes_by_target_root[on_chain_target_root] = {
                    ValidatorIndex(validator_index)
                    for validator_index in range(validator_count)
                    if state.justifications_validators[
                        root_index * validator_count + validator_index
                    ]
                }
            processed_attestation_data: set[AttestationData] = set()

            for _ in range(int(MAX_ATTESTATIONS_DATA)):
                # Scan every remaining candidate and keep the best ordering key.
                #
                # Skips entries already processed, those failing the projected-chain
                # filters, and those with zero new voters.
                # A smaller ordering key wins.
                best_candidate: tuple[AttestationData, _EntryScore, set[ValidatorIndex]] | None = (
                    None
                )
                best_candidate_key: tuple[int, int, int, int, bytes] | None = None
                for candidate_data, proofs in aggregated_payloads.items():
                    if candidate_data in processed_attestation_data:
                        continue

                    # Validate the candidate against the projected chain view.
                    #
                    # Mirrors the vote-validity rules: head must be known, source must be
                    # justified, source and target must match the candidate-block chain view,
                    # target must be after source, target must not already be justified, and
                    # target must be justifiable relative to the projected finalized slot.
                    #
                    # Chain-match runs before the justified-slot queries: it rejects
                    # checkpoints whose slot is past the chain view, which keeps the bounded
                    # justification queries from raising IndexError.
                    if candidate_data.head.root not in known_block_roots:
                        continue
                    if not candidate_data.lies_on_chain(extended_historical_block_hashes):
                        continue
                    if not justified_slots.is_slot_justified(
                        finalized_slot, candidate_data.source.slot
                    ):
                        continue

                    # A genesis self-vote anchors both source and target at slot 0.
                    # It cannot justify or finalize, but it carries fork-choice signal,
                    # so selection treats it specially.
                    is_genesis_self_vote = candidate_data.source.slot == Slot(
                        0
                    ) and candidate_data.target.slot == Slot(0)

                    # Genesis self-votes are exempt from the target-after-source and
                    # target-already-justified checks.
                    # The state transition drops them, but they carry fork-choice signal.
                    if not is_genesis_self_vote:
                        if candidate_data.target.slot <= candidate_data.source.slot:
                            continue
                        if justified_slots.is_slot_justified(
                            finalized_slot, candidate_data.target.slot
                        ):
                            continue
                        if not candidate_data.target.slot.is_justifiable_after(finalized_slot):
                            continue

                    # New voters: participants across all proofs not already recorded
                    # for the target.
                    prior_voters = votes_by_target_root.get(candidate_data.target.root, set())
                    new_voters: set[ValidatorIndex] = set()
                    for proof in proofs:
                        for validator_index in proof.participants.to_validator_indices():
                            if validator_index not in prior_voters:
                                new_voters.add(validator_index)

                    # An entry adding no validators cannot improve the target, so skip it.
                    if not new_voters:
                        continue

                    # Threshold: total voters (prior plus new) crossing two-thirds.
                    total_voters = len(prior_voters) + len(new_voters)
                    crosses_two_thirds = 3 * total_voters >= 2 * validator_count

                    # 3SF-mini finalization requires no slot strictly between source and
                    # target to still be justifiable.
                    # Source and target must be consecutive justified checkpoints in the
                    # projected post-state.
                    #
                    # The source must lie strictly past the projected finalized boundary.
                    # A source at or behind the boundary is already final.
                    # It may still justify a newer target, but it must not re-finalize.
                    # This mirrors the state transition, which advances finalization only
                    # when the source slot is strictly greater than the finalized slot.
                    # Scanning from one past the source also keeps every queried slot
                    # strictly above the boundary, where justifiability is defined.
                    finalizes_source = (
                        crosses_two_thirds
                        and candidate_data.source.slot > finalized_slot
                        and all(
                            not Slot(intermediate_slot).is_justifiable_after(finalized_slot)
                            for intermediate_slot in range(
                                int(candidate_data.source.slot) + 1,
                                int(candidate_data.target.slot),
                            )
                        )
                    )

                    # A genesis self-vote cannot justify or finalize and is always BUILD tier.
                    if is_genesis_self_vote or not crosses_two_thirds:
                        tier = _Tier.BUILD
                    elif finalizes_source:
                        tier = _Tier.FINALIZE
                    else:
                        tier = _Tier.JUSTIFY

                    candidate_score = _EntryScore(
                        tier=tier,
                        new_voter_count=len(new_voters),
                        target_slot=candidate_data.target.slot,
                        attestation_slot=candidate_data.slot,
                    )
                    candidate_key = candidate_score.ordering_key(hash_tree_root(candidate_data))
                    if best_candidate_key is None or candidate_key < best_candidate_key:
                        best_candidate = (candidate_data, candidate_score, new_voters)
                        best_candidate_key = candidate_key

                if best_candidate is None:
                    break
                attestation_data, entry_score, selected_new_voters = best_candidate
                processed_attestation_data.add(attestation_data)

                # Pack proofs that maximize new validator coverage for this entry.
                selected_proofs, _ = select_proofs_for_coverage(
                    aggregated_payloads[attestation_data]
                )
                for proof in selected_proofs:
                    selected_attestations_with_proofs.append(
                        (
                            self.aggregated_attestation_class(
                                aggregation_bits=proof.participants,
                                data=attestation_data,
                            ),
                            proof,
                        )
                    )

                target_root = attestation_data.target.root

                # Project justification and finalization. Finalize implies justify.
                if entry_score.tier <= _Tier.JUSTIFY:
                    justified_slots = justified_slots.extend_to_slot(
                        finalized_slot, attestation_data.target.slot
                    )

                    # The justifiable filter and the extension above guarantee an
                    # in-range index, so mark the target justified directly.
                    target_justified_index = attestation_data.target.slot.justified_index_after(
                        finalized_slot
                    )
                    assert target_justified_index is not None
                    updated_justified_bits = list(justified_slots.data)
                    updated_justified_bits[target_justified_index] = Boolean(True)
                    justified_slots = JustifiedSlots(data=updated_justified_bits)

                    # A justified target can no longer be a candidate target, so its
                    # voter bucket is irrelevant for further scoring.
                    votes_by_target_root.pop(target_root, None)
                else:
                    # BUILD tier: the target stays a candidate, so record its new
                    # voters to push it toward the threshold on a later round.
                    votes_by_target_root.setdefault(target_root, set()).update(selected_new_voters)
                if entry_score.tier == _Tier.FINALIZE:
                    # The finalize tier requires a source strictly past the boundary,
                    # so the window always advances by at least one slot.
                    # Drop the leading bits that fell behind the new finalized boundary.
                    new_finalized_slot = attestation_data.source.slot
                    finalized_slot_advance = int(new_finalized_slot) - int(finalized_slot)
                    justified_slots = JustifiedSlots(
                        data=justified_slots.data[finalized_slot_advance:]
                    )
                    finalized_slot = new_finalized_slot

            for attestation, proof in selected_attestations_with_proofs:
                aggregated_attestations.append(attestation)
                aggregated_signatures.append(proof)

            # Collapse each attestation data down to a single proof.
            #
            # - The coverage picker may emit several proofs for one data entry.
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

        # Compute the post-state to obtain the state root.
        post_state = self.process_block(advanced_state, final_block)
        final_block = final_block.model_copy(update={"state_root": hash_tree_root(post_state)})

        return final_block, post_state, aggregated_attestations, aggregated_signatures
