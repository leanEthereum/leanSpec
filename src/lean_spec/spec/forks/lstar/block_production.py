"""Lstar fork — proposer-side block building."""

from collections.abc import Sequence, Set as AbstractSet
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
from lean_spec.spec.forks.lstar.state_transition import attestation_data_matches_chain
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
    Within a tier, more new voters wins, then a smaller target slot, then a
    smaller attestation slot, then the entry's data root for determinism.
    """

    tier: _Tier
    new_voter_count: int
    target_slot: Slot
    attestation_slot: Slot

    def ordering_key(self, data_root: Bytes32) -> tuple[int, int, int, int, bytes]:
        """Sort key where the smallest tuple is the best candidate."""
        return (
            int(self.tier),
            -self.new_voter_count,
            int(self.target_slot),
            int(self.attestation_slot),
            bytes(data_root),
        )


def _build_votes_by_target_root(state: State) -> dict[Bytes32, set[ValidatorIndex]]:
    """
    Deserialize the flat justification bitlist into a per-target-root voter map.

    The state stores one bit per tracked-root and validator pair.
    The bit at index (i * N + j) means validator j voted for tracked root i,
    where N is the validator count.
    Seeding the running voter map from these bits lets scoring count on-chain
    voters toward the two-thirds threshold.
    """
    num_validators = len(state.validators)
    votes_by_target_root: dict[Bytes32, set[ValidatorIndex]] = {}
    for root_index, target_root in enumerate(state.justifications_roots):
        voters = {
            ValidatorIndex(validator_index)
            for validator_index in range(num_validators)
            if state.justifications_validators[root_index * num_validators + validator_index]
        }
        votes_by_target_root[target_root] = voters
    return votes_by_target_root


def _is_genesis_self_vote(attestation_data: AttestationData) -> bool:
    """
    Whether the vote anchors both source and target at slot 0.

    Genesis self-votes cannot justify or finalize, but they carry
    fork-choice signal, so selection treats them specially.
    """
    return attestation_data.source.slot == Slot(0) and attestation_data.target.slot == Slot(0)


def _score_entry(
    attestation_data: AttestationData,
    proofs: AbstractSet[SingleMessageAggregate],
    votes_by_target_root: dict[Bytes32, set[ValidatorIndex]],
    projected_finalized_slot: Slot,
    validator_count: int,
) -> tuple[_EntryScore, set[ValidatorIndex]] | None:
    """
    Score a single candidate entry under the current projected state.

    Returns None if the entry adds zero validators relative to the running
    voter set for its target root.
    Otherwise returns the score and the new voters this entry contributes.
    A genesis self-vote cannot justify or finalize and is always BUILD tier.
    """
    prior_voters = votes_by_target_root.get(attestation_data.target.root, set())

    # New voters: participants across all proofs not already recorded for the target.
    new_voters: set[ValidatorIndex] = set()
    for proof in proofs:
        for validator_index in proof.participants.to_validator_indices():
            if validator_index not in prior_voters:
                new_voters.add(validator_index)
    if not new_voters:
        return None

    # Threshold: total voters (prior plus new) crossing two-thirds.
    total_voters = len(prior_voters) + len(new_voters)
    crosses_two_thirds = 3 * total_voters >= 2 * validator_count

    is_genesis_self_vote = _is_genesis_self_vote(attestation_data)

    # 3SF-mini finalization requires no slot strictly between source and target
    # to still be justifiable.
    # Source and target must be consecutive justified checkpoints in the
    # projected post-state.
    #
    # The source must lie strictly past the projected finalized boundary.
    # A source at or behind the boundary is already final.
    # It may still justify a newer target, but it must not re-finalize.
    # This mirrors the state transition, which advances finalization only when
    # the source slot is strictly greater than the finalized slot.
    # Scanning from one past the source also keeps every queried slot strictly
    # above the boundary, where justifiability is defined.
    finalizes_source = (
        crosses_two_thirds
        and attestation_data.source.slot > projected_finalized_slot
        and all(
            not Slot(intermediate_slot).is_justifiable_after(projected_finalized_slot)
            for intermediate_slot in range(
                int(attestation_data.source.slot) + 1, int(attestation_data.target.slot)
            )
        )
    )

    if is_genesis_self_vote or not crosses_two_thirds:
        tier = _Tier.BUILD
    elif finalizes_source:
        tier = _Tier.FINALIZE
    else:
        tier = _Tier.JUSTIFY

    return (
        _EntryScore(
            tier=tier,
            new_voter_count=len(new_voters),
            target_slot=attestation_data.target.slot,
            attestation_slot=attestation_data.slot,
        ),
        new_voters,
    )


def _entry_passes_filters(
    attestation_data: AttestationData,
    known_block_roots: AbstractSet[Bytes32],
    extended_historical_block_hashes: Sequence[Bytes32],
    projected_justified_slots: JustifiedSlots,
    projected_finalized_slot: Slot,
) -> bool:
    """
    Validate a candidate entry against the projected chain view.

    Mirrors the vote-validity rules: head must be known, source must be
    justified, source and target must match the candidate-block chain view,
    target must be after source, target must not already be justified, and
    target must be justifiable relative to the projected finalized slot.

    The genesis self-vote (source and target both at slot 0) is exempt from
    the target-after-source and target-already-justified checks.
    The state transition drops it, but it carries fork-choice signal.

    Chain-match runs before the justified-slot queries: it rejects checkpoints
    whose slot is past the chain view, which keeps the bounded justification
    queries from raising IndexError.
    """
    if attestation_data.head.root not in known_block_roots:
        return False
    if not attestation_data_matches_chain(attestation_data, extended_historical_block_hashes):
        return False
    if not projected_justified_slots.is_slot_justified(
        projected_finalized_slot, attestation_data.source.slot
    ):
        return False

    # Genesis self-votes are exempt from the remaining checks.
    # The state transition drops them, but they carry fork-choice signal.
    if not _is_genesis_self_vote(attestation_data):
        if attestation_data.target.slot <= attestation_data.source.slot:
            return False
        if projected_justified_slots.is_slot_justified(
            projected_finalized_slot, attestation_data.target.slot
        ):
            return False
        if not attestation_data.target.slot.is_justifiable_after(projected_finalized_slot):
            return False
    return True


def _pick_best_candidate(
    aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]],
    known_block_roots: AbstractSet[Bytes32],
    extended_historical_block_hashes: Sequence[Bytes32],
    processed_attestation_data: AbstractSet[AttestationData],
    projected_justified_slots: JustifiedSlots,
    projected_finalized_slot: Slot,
    votes_by_target_root: dict[Bytes32, set[ValidatorIndex]],
    validator_count: int,
) -> tuple[AttestationData, _EntryScore, set[ValidatorIndex]] | None:
    """
    Scan candidate entries and return the highest-scoring one.

    Skips entries already processed, those failing the projected-chain
    filters, and those with zero new voters.
    Returns the entry with the best ordering key (smaller is better),
    or None when nothing scores.
    """
    best_candidate: tuple[AttestationData, _EntryScore, set[ValidatorIndex]] | None = None
    best_candidate_key: tuple[int, int, int, int, bytes] | None = None

    for attestation_data, proofs in aggregated_payloads.items():
        if attestation_data in processed_attestation_data:
            continue
        if not _entry_passes_filters(
            attestation_data,
            known_block_roots,
            extended_historical_block_hashes,
            projected_justified_slots,
            projected_finalized_slot,
        ):
            continue
        scored = _score_entry(
            attestation_data,
            proofs,
            votes_by_target_root,
            projected_finalized_slot,
            validator_count,
        )
        if scored is None:
            continue
        entry_score, new_voters = scored

        candidate_key = entry_score.ordering_key(hash_tree_root(attestation_data))
        if best_candidate_key is None or candidate_key < best_candidate_key:
            best_candidate = (attestation_data, entry_score, new_voters)
            best_candidate_key = candidate_key

    return best_candidate


class BlockProductionMixin(LstarSpecBase):
    """Proposer-side block building for the lstar fork."""

    def _select_attestations(
        self,
        head_state: State,
        slot: Slot,
        parent_root: Bytes32,
        known_block_roots: AbstractSet[Bytes32],
        aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]],
    ) -> list[tuple[AggregatedAttestation, SingleMessageAggregate]]:
        """
        Tiered greedy attestation selection for block proposal.

        Each round scores remaining candidates against a projected post-state
        and picks the best: finalize beats justify beats build.
        Justification and finalization are projected incrementally so dependent
        attestations become eligible on the next round without re-running the
        state transition.
        Stops at the data-entry cap or when no remaining candidate scores.
        """
        selected_attestations_with_proofs: list[
            tuple[AggregatedAttestation, SingleMessageAggregate]
        ] = []
        if not aggregated_payloads:
            return selected_attestations_with_proofs

        # Assemble the chain as it will look once this block is applied.
        #
        # 1. History up to the parent.
        # 2. The parent root at its own slot.
        # 3. A zero hash for each slot skipped before this block.
        #
        # Precondition: the new slot must lie strictly after the parent slot.
        # Without the guard, unsigned subtraction underflows and the empty-slot
        # padding allocates an astronomically large list.
        parent_slot = head_state.latest_block_header.slot
        assert slot > parent_slot, f"Cannot build block at slot {slot} <= parent slot {parent_slot}"
        num_empty_slots = int(slot - parent_slot - Slot(1))
        extended_historical_block_hashes: list[Bytes32] = (
            list(head_state.historical_block_hashes) + [parent_root] + [ZERO_HASH] * num_empty_slots
        )
        validator_count = len(head_state.validators)

        # Projected post-state, updated incrementally as entries are selected.
        finalized_slot = head_state.latest_finalized.slot
        justified_slots = head_state.justified_slots.extend_to_slot(finalized_slot, slot - Slot(1))
        votes_by_target_root = _build_votes_by_target_root(head_state)
        processed_attestation_data: set[AttestationData] = set()

        for _ in range(int(MAX_ATTESTATIONS_DATA)):
            best_candidate = _pick_best_candidate(
                aggregated_payloads,
                known_block_roots,
                extended_historical_block_hashes,
                processed_attestation_data,
                justified_slots,
                finalized_slot,
                votes_by_target_root,
                validator_count,
            )
            if best_candidate is None:
                break
            attestation_data, entry_score, new_voters = best_candidate
            processed_attestation_data.add(attestation_data)

            # Pack proofs that maximize new validator coverage for this entry.
            selected_proofs, _ = select_proofs_for_coverage(aggregated_payloads[attestation_data])
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
                justified_slots = justified_slots.with_justified(
                    finalized_slot, attestation_data.target.slot, Boolean(True)
                )
                # A justified target can no longer be a candidate target, so its
                # voter bucket is irrelevant for further scoring.
                votes_by_target_root.pop(target_root, None)
            else:
                # BUILD tier: the target stays a candidate, so record its new
                # voters to push it toward the threshold on a later round.
                votes_by_target_root.setdefault(target_root, set()).update(new_voters)
            if entry_score.tier == _Tier.FINALIZE:
                new_finalized_slot = attestation_data.source.slot
                finalized_slot_advance = int(new_finalized_slot) - int(finalized_slot)
                justified_slots = justified_slots.shift_window(finalized_slot_advance)
                finalized_slot = new_finalized_slot

        return selected_attestations_with_proofs

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
            selected_attestations_with_proofs = self._select_attestations(
                state,
                slot,
                parent_root,
                known_block_roots,
                aggregated_payloads,
            )
            for attestation, proof in selected_attestations_with_proofs:
                aggregated_attestations.append(attestation)
                aggregated_signatures.append(proof)

            # Collapse each attestation data down to a single proof.
            #
            # - The coverage picker may emit several proofs for one data entry.
            # - A block must carry one attestation per data, over the union of voters.

            # Group every proof under the data it attests to.
            # Strict pairing guards against the two lists drifting out of sync.
            signatures_by_attestation_data: dict[AttestationData, list[SingleMessageAggregate]] = {}
            for attestation, signature in zip(
                aggregated_attestations, aggregated_signatures, strict=True
            ):
                signatures_by_attestation_data.setdefault(attestation.data, []).append(signature)

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
