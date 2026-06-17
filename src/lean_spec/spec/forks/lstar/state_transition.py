"""Lstar fork — state transition."""

from collections.abc import Iterable
from itertools import batched

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks.lstar._base import LstarSpecBase
from lean_spec.spec.forks.lstar.config import MAX_ATTESTATIONS_DATA
from lean_spec.spec.forks.lstar.containers import (
    AggregatedAttestation,
    Block,
    Checkpoint,
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    Slot,
    State,
    ValidatorIndex,
    Validators,
)
from lean_spec.spec.forks.lstar.errors import RejectionReason, SpecRejectionError
from lean_spec.spec.observability import (
    observe_state_transition,
)
from lean_spec.spec.ssz import ZERO_HASH, Boolean, Bytes32, Uint64


class StateTransitionMixin(LstarSpecBase):
    """State transition function for the lstar fork."""

    def generate_genesis(self, genesis_time: Uint64, validators: Validators) -> State:
        """Generate a genesis state with empty history and proper initial values."""
        genesis_config = self.genesis_config_class(
            genesis_time=genesis_time,
        )

        genesis_header = self.block_header_class(
            slot=Slot(0),
            proposer_index=ValidatorIndex(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32.zero(),
            body_root=hash_tree_root(
                self.block_body_class(attestations=self.aggregated_attestations_class(data=[]))
            ),
        )

        return self.state_class(
            config=genesis_config,
            slot=Slot(0),
            latest_block_header=genesis_header,
            latest_justified=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            latest_finalized=Checkpoint(root=Bytes32.zero(), slot=Slot(0)),
            historical_block_hashes=HistoricalBlockHashes(data=[]),
            justified_slots=JustifiedSlots(data=[]),
            validators=validators,
            justifications_roots=JustificationRoots(data=[]),
            justifications_validators=JustificationValidators(data=[]),
        )

    def process_slots(self, state: State, target_slot: Slot) -> State:
        """
        Advance the state through empty slots up to, but not including, target_slot.

        The pre-block state root is cached at most once per block.
        Only the first empty slot after a block finds an empty root to fill.

        Raises:
            SpecRejectionError: BLOCK_SLOT_NOT_IN_FUTURE if target_slot is not in the future.
        """
        if state.slot >= target_slot:
            raise SpecRejectionError(
                RejectionReason.BLOCK_SLOT_NOT_IN_FUTURE, "Target slot must be in the future"
            )

        while state.slot < target_slot:
            # Cache the pre-block state root into the latest header, then advance the slot.
            #
            # Invariant: the header's state root is empty only on the first empty slot
            # after a block, so this fills it at most once per block.
            # Later empty slots reuse the populated root.
            needs_state_root = state.latest_block_header.state_root == Bytes32.zero()
            cached_state_root = (
                hash_tree_root(state) if needs_state_root else state.latest_block_header.state_root
            )

            state = state.model_copy(
                update={
                    "latest_block_header": state.latest_block_header.model_copy(
                        update={"state_root": cached_state_root}
                    ),
                    "slot": state.slot + Slot(1),
                }
            )

        return state

    def process_block_header(self, state: State, block: Block) -> State:
        """
        Validate the block header and update header-linked state.

        Raises:
            SpecRejectionError: If any header check fails (slot mismatch, block older
                than the latest header, wrong proposer, or parent root mismatch).
        """
        parent_header = state.latest_block_header
        parent_root = hash_tree_root(parent_header)

        # The block must sit at the slot the state was advanced to.
        if block.slot != state.slot:
            raise SpecRejectionError(RejectionReason.BLOCK_SLOT_MISMATCH, "Block slot mismatch")

        # The block must be newer than the latest header.
        if block.slot <= parent_header.slot:
            raise SpecRejectionError(
                RejectionReason.BLOCK_OLDER_THAN_LATEST_HEADER, "Block is older than latest header"
            )

        # The block must come from the validator assigned to this slot.
        if block.proposer_index != ValidatorIndex.proposer_for_slot(
            slot=state.slot,
            num_validators=Uint64(len(state.validators)),
        ):
            raise SpecRejectionError(RejectionReason.WRONG_PROPOSER, "Incorrect block proposer")

        # The block must point at the known parent.
        if block.parent_root != parent_root:
            raise SpecRejectionError(
                RejectionReason.PARENT_ROOT_MISMATCH, "Block parent root mismatch"
            )

        # Genesis is the chain's anchor, justified and finalized by definition.
        # So the first block forces its parent to both.
        # Every later block keeps its checkpoints, which only attestations move.
        if parent_header.slot == Slot(0):
            new_latest_justified = Checkpoint(slot=Slot(0), root=parent_root)
            new_latest_finalized = Checkpoint(slot=Slot(0), root=parent_root)
        else:
            new_latest_justified = state.latest_justified
            new_latest_finalized = state.latest_finalized

        # Slots skipped since the parent from missed proposals.
        # Adjacent blocks skip none, giving zero.
        num_empty_slots = int(block.slot - parent_header.slot - Slot(1))

        # Record the parent root, then a zero hash for each skipped slot.
        new_historical_block_hashes = (
            state.historical_block_hashes + [parent_root] + [ZERO_HASH] * num_empty_slots
        )

        # The justified-slot flags are stored relative to the finalized boundary.
        # The current slot is not materialized until its header finishes, so stop one short.
        last_materialized_slot = block.slot - Slot(1)
        new_justified_slots = state.justified_slots.extend_to_slot(
            new_latest_finalized.slot,
            last_materialized_slot,
        )

        # Build the new tip header.
        # Leave its state root empty until the body is processed or the next slot begins.
        new_latest_block_header = self.block_header_class(
            slot=block.slot,
            proposer_index=block.proposer_index,
            parent_root=block.parent_root,
            body_root=hash_tree_root(block.body),
            state_root=Bytes32.zero(),
        )

        return state.model_copy(
            update={
                "latest_justified": new_latest_justified,
                "latest_finalized": new_latest_finalized,
                "historical_block_hashes": new_historical_block_hashes,
                "justified_slots": new_justified_slots,
                "latest_block_header": new_latest_block_header,
            }
        )

    def process_block(self, state: State, block: Block) -> State:
        """
        Apply full block processing including header and body.

        Raises:
            SpecRejectionError: If header validation fails.
        """
        state = self.process_block_header(state, block)
        return self.process_attestations(state, block.body.attestations)

    def process_attestations(
        self,
        state: State,
        attestations: Iterable[AggregatedAttestation],
    ) -> State:
        """
        Apply attestations and update justification and finalization under 3SF-mini rules.

        Raises:
            SpecRejectionError: TOO_MANY_ATTESTATION_DATA if the distinct data
                count exceeds the per-block cap.
            SpecRejectionError: EMPTY_AGGREGATION_BITS if an attestation that passes
                the vote filters has no set bits.
            SpecRejectionError: VALIDATOR_INDEX_OUT_OF_RANGE if a set bit points
                outside the validator registry.
        """
        # Cap the distinct attestation data a block may carry.
        # Each distinct data builds a tally sized to the validator set, so the count drives work.
        # Only distinct data is bounded, not total attestations.
        # Split aggregates for one target share their data and count once.
        aggregated_attestations = tuple(attestations)
        distinct_attestation_data = {attestation.data for attestation in aggregated_attestations}
        if len(distinct_attestation_data) > int(MAX_ATTESTATIONS_DATA):
            raise SpecRejectionError(
                RejectionReason.TOO_MANY_ATTESTATION_DATA,
                f"Block contains {len(distinct_attestation_data)} distinct AttestationData "
                f"entries; maximum is {MAX_ATTESTATIONS_DATA}",
            )

        # Unpack the SSZ vote tracking into a root -> per-validator vote map.
        # The state holds one flat vote list segmented by tracked root, each segment N flags long:
        #
        #     roots:  [root_0,  root_1,  ...]
        #     votes:  [<--N-->][<--N-->] ...
        #
        # Slicing per segment recovers a vote list per root.
        assert not any(root == ZERO_HASH for root in state.justifications_roots), (
            "zero hash is not allowed in justifications roots"
        )
        validator_count = len(state.validators)
        justifications = {
            root: list(validator_votes)
            for root, validator_votes in zip(
                state.justifications_roots,
                batched(state.justifications_validators.data, validator_count),
                strict=True,
            )
        }

        # Accumulate changes locally, then apply them in one copy at the end.
        latest_justified = state.latest_justified
        latest_finalized = state.latest_finalized
        finalized_slot = latest_finalized.slot
        justified_slots = state.justified_slots

        # Map each unfinalized root to its slot, used later to prune finalized roots.
        start_slot = int(finalized_slot) + 1
        root_to_slot: dict[Bytes32, Slot] = {
            root: Slot(i)
            for i, root in enumerate(state.historical_block_hashes[start_slot:], start=start_slot)
        }

        # Each attestation votes to extend the chain from a source to a target.
        # The filters below drop invalid or irrelevant votes.
        for attestation in aggregated_attestations:
            source = attestation.data.source
            target = attestation.data.target

            # A vote may only anchor on an already-justified source.
            if not justified_slots.is_slot_justified(finalized_slot, source.slot):
                continue

            # An already-justified target gains nothing from more votes.
            if justified_slots.is_slot_justified(finalized_slot, target.slot):
                continue

            # Both roots must match the canonical chain.
            # This also rejects zero-hash source or target roots.
            if not attestation.data.lies_on_chain(state.historical_block_hashes.data):
                continue

            # The target must lie strictly after the source.
            if target.slot <= source.slot:
                continue

            # The target slot must be justifiable after the finalized slot.
            # 3SF-mini admits only a structured set of distances; see the justifiable-slot rule.
            if not target.slot.is_justifiable_after(finalized_slot):
                continue

            voting_validator_indices = attestation.aggregation_bits.to_validator_indices()

            # A bit outside the registry has no flag in the tally, so reject the block.
            # This guards the unsigned path, where no signature stage catches it first.
            for validator_index in voting_validator_indices:
                if not validator_index.is_within_registry(Uint64(validator_count)):
                    raise SpecRejectionError(
                        RejectionReason.VALIDATOR_INDEX_OUT_OF_RANGE,
                        "Attestation aggregation bits reference a validator outside the registry",
                    )

            # Start a fresh all-False tally on the first vote for this target.
            if target.root not in justifications:
                justifications[target.root] = [Boolean(False)] * validator_count

            # Mark each voter; re-marking is idempotent, so no guard is needed.
            for validator_index in voting_validator_indices:
                justifications[target.root][validator_index] = Boolean(True)

            # Threshold: justified once two-thirds of validators vote for the target.
            # Compare as integers to avoid floating-point division: 3 * votes >= 2 * total.
            count = sum(bool(justified) for justified in justifications[target.root])

            if 3 * count >= (2 * validator_count):
                # Only advance the justified checkpoint forward.
                # Targets within a block can resolve out of order, so an earlier
                # target seen after a later one must not drag the checkpoint back.
                if target.slot > latest_justified.slot:
                    latest_justified = target

                # The justifiable filter above guarantees an in-range index.
                justified_index = target.slot.justified_index_after(finalized_slot)
                assert justified_index is not None

                # Rebind to a copy so the pre-state bitfield is never mutated.
                updated_justified_bits = list(justified_slots.data)
                updated_justified_bits[justified_index] = Boolean(True)
                justified_slots = JustifiedSlots(data=updated_justified_bits)

                # The target is justified; its individual votes no longer matter.
                del justifications[target.root]

                # Finalize the source when no justifiable slot sits between it and the target.
                # The source must also lie past the old finalized slot, or it is already final.
                if source.slot > finalized_slot and not any(
                    Slot(slot).is_justifiable_after(finalized_slot)
                    for slot in range(source.slot + Slot(1), target.slot)
                ):
                    old_finalized_slot = finalized_slot
                    latest_finalized = source
                    finalized_slot = latest_finalized.slot

                    # Rebase tracking onto the new finalized boundary.
                    # The flags start at one past the finalized slot, so drop the first delta bits.
                    # Also drop any pending justifications now at or below the finalized slot.
                    delta = int(finalized_slot - old_finalized_slot)
                    if delta > 0:
                        justified_slots = JustifiedSlots(data=justified_slots.data[delta:])
                        assert all(root in root_to_slot for root in justifications), (
                            "Justification root missing from root_to_slot"
                        )
                        justifications = {
                            root: votes
                            for root, votes in justifications.items()
                            if root_to_slot[root] > finalized_slot
                        }

        # Re-pack the vote map into the flat SSZ layout, roots first.
        # Sorting the roots makes the state representation deterministic across nodes.
        sorted_roots = sorted(justifications.keys())

        return state.model_copy(
            update={
                "justifications_roots": JustificationRoots(data=sorted_roots),
                "justifications_validators": JustificationValidators(
                    data=[vote for root in sorted_roots for vote in justifications[root]]
                ),
                "justified_slots": justified_slots,
                "latest_justified": latest_justified,
                "latest_finalized": latest_finalized,
            }
        )

    def state_transition(
        self,
        state: State,
        block: Block,
    ) -> State:
        """
        Apply the complete state transition function for a block.

        Signatures are verified outside this function, before it is called.

        Raises:
            SpecRejectionError: If slot or header validation fails, or STATE_ROOT_MISMATCH
                if the block's state root does not match the computed post-state root.
        """
        with observe_state_transition():
            advanced = self.process_slots(state, block.slot)
            new_state = self.process_block(advanced, block)

            # The block must commit to the post-state it actually produces.
            computed_state_root = hash_tree_root(new_state)
            if block.state_root != computed_state_root:
                raise SpecRejectionError(
                    RejectionReason.STATE_ROOT_MISMATCH, "Invalid block state root"
                )

        return new_state
