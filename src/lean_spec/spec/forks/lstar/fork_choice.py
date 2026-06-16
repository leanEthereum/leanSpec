"""Lstar fork — fork choice: store, LMD-GHOST, attestation handling."""

import math
from collections import defaultdict

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.containers import PublicKey
from lean_spec.spec.crypto.xmss.interface import TARGET_SIGNATURE_SCHEME
from lean_spec.spec.forks.lstar._base import LstarSpecBase, LstarStore
from lean_spec.spec.forks.lstar.config import (
    GOSSIP_DISPARITY_INTERVALS,
    INTERVALS_PER_SLOT,
)
from lean_spec.spec.forks.lstar.containers import (
    AggregationError,
    AttestationData,
    AttestationSignatureEntry,
    Block,
    Checkpoint,
    Interval,
    SignedAggregatedAttestation,
    SignedAttestation,
    SignedBlock,
    SingleMessageAggregate,
    Slot,
    State,
    ValidatorIndex,
)
from lean_spec.spec.forks.lstar.errors import RejectionReason, SpecRejectionError
from lean_spec.spec.forks.protocol import SpecBlockType, SpecStateType
from lean_spec.spec.observability import (
    observe_on_attestation,
    observe_on_block,
)
from lean_spec.spec.ssz import Bytes32, Uint64


class ForkChoiceMixin(LstarSpecBase):
    """Fork choice and store maintenance for the lstar fork."""

    def _checkpoint_is_ancestor(
        self,
        store: LstarStore,
        ancestor: Checkpoint,
        descendant: Checkpoint,
    ) -> bool:
        """
        Decide whether one checkpoint lies on the other's chain of ancestors.

        Args:
            store: Fork-choice store holding the known block tree.
            ancestor: Candidate ancestor checkpoint, expected at or below the descendant's slot.
            descendant: Checkpoint whose parent chain is searched.

        Returns:
            True when the ancestor block lies on the descendant's parent chain.
        """
        # An ancestor can never sit later in time than its descendant.
        if ancestor.slot > descendant.slot:
            return False

        # Climb parent links from the descendant toward genesis.
        #
        # The walk stops the moment a root is absent from the local view.
        current_root = descendant.root
        while current_root in store.blocks:
            current_block = store.blocks[current_root]

            # Landed on the ancestor's slot.
            # - It lies on the chain only when the roots also match.
            # - A different root here means the checkpoints are on forked branches.
            if current_block.slot == ancestor.slot:
                return current_root == ancestor.root

            # Climbed past the ancestor's slot without landing on it.
            # That slot held no block on this chain, so the ancestor is off it.
            if current_block.slot < ancestor.slot:
                return False

            # Still above the ancestor's slot.
            # Step to the parent and keep climbing.
            current_root = current_block.parent_root

        # The chain left the known tree before reaching the ancestor's slot.
        return False

    def create_store(
        self,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_index: ValidatorIndex | None,
    ) -> LstarStore:
        """
        Initialize a forkchoice store from an anchor state and block.

        The anchor block and state form the starting point for fork choice.
        Both are treated as justified and finalized.

        Raises:
            SpecRejectionError: ANCHOR_STATE_ROOT_MISMATCH if the anchor block's
                state root does not match the hash of the state.
        """
        assert isinstance(state, State)
        assert isinstance(anchor_block, Block)

        # Compute the SSZ root of this state.
        #
        # This is the canonical hash that should appear in the block's state root.
        computed_state_root = hash_tree_root(state)

        # Check that the block actually points to this state.
        #
        # If this fails, the caller has supplied inconsistent inputs.
        if anchor_block.state_root != computed_state_root:
            raise SpecRejectionError(
                RejectionReason.ANCHOR_STATE_ROOT_MISMATCH,
                "Anchor block state root must match anchor state hash",
            )

        # Compute the SSZ root of the anchor block itself.
        #
        # This root will be used as:
        # - the key in the blocks/states maps,
        # - the initial head,
        # - the root of the initial checkpoints.
        anchor_root = hash_tree_root(anchor_block)

        return self.store_class(
            time=Interval.from_slot(anchor_block.slot),
            config=state.config,
            head=anchor_root,
            safe_target=anchor_root,
            latest_justified=Checkpoint(root=anchor_root, slot=anchor_block.slot),
            latest_finalized=Checkpoint(root=anchor_root, slot=anchor_block.slot),
            blocks={anchor_root: anchor_block},
            states={anchor_root: state},
            validator_index=validator_index,
        )

    def prune_stale_attestation_data(self, store: LstarStore) -> LstarStore:
        """
        Drop attestation data whose head can no longer influence fork choice.

        Fork choice only ever descends from the latest finalized block.
        A vote whose head sits at or below the finalized slot cannot name a descendant of it.
        Such a vote carries no fork-choice weight.
        Dropping it never changes the chosen chain.

        The same cutoff prunes all three attestation-keyed pools:

        - Per-validator attestation signatures.
        - Pending aggregated proofs not yet counted.
        - Aggregated proofs already counted toward fork choice.
        """
        # Keep only entries whose attested head sits strictly above the finalized slot.
        #
        # Every pool shares the same vote key, so one staleness test filters all three.
        return store.model_copy(
            update={
                "attestation_signatures": {
                    attestation_data: signatures
                    for attestation_data, signatures in store.attestation_signatures.items()
                    if attestation_data.head.slot > store.latest_finalized.slot
                },
                "latest_new_aggregated_payloads": {
                    attestation_data: proofs
                    for attestation_data, proofs in store.latest_new_aggregated_payloads.items()
                    if attestation_data.head.slot > store.latest_finalized.slot
                },
                "latest_known_aggregated_payloads": {
                    attestation_data: proofs
                    for attestation_data, proofs in store.latest_known_aggregated_payloads.items()
                    if attestation_data.head.slot > store.latest_finalized.slot
                },
            }
        )

    def validate_attestation(self, store: LstarStore, attestation_data: AttestationData) -> None:
        """
        Validate incoming attestation before processing.

        Ensures the vote respects the basic laws of time and topology:
            1. The blocks voted for must exist in our store.
            2. A vote cannot span backwards in time (source > target).
            3. The head must be at least as recent as source and target.
            4. Checkpoint slots must match the actual block slots.
            5. Source, target, and head must lie on one parent chain.
            6. The vote's slot cannot precede the slot of the head it claims to have seen.
            7. The vote's slot must have started locally (a small disparity margin is allowed).

        Raises:
            SpecRejectionError: If the attestation fails any of the validation checks above.
        """
        source_checkpoint = attestation_data.source
        target_checkpoint = attestation_data.target
        head_checkpoint = attestation_data.head

        # Availability Check
        #
        # We cannot count a vote if we haven't seen the blocks involved.
        if source_checkpoint.root not in store.blocks:
            raise SpecRejectionError(
                RejectionReason.UNKNOWN_SOURCE_BLOCK,
                f"Unknown source block: {source_checkpoint.root.hex()}",
            )
        if target_checkpoint.root not in store.blocks:
            raise SpecRejectionError(
                RejectionReason.UNKNOWN_TARGET_BLOCK,
                f"Unknown target block: {target_checkpoint.root.hex()}",
            )
        if head_checkpoint.root not in store.blocks:
            raise SpecRejectionError(
                RejectionReason.UNKNOWN_HEAD_BLOCK,
                f"Unknown head block: {head_checkpoint.root.hex()}",
            )

        # Topology Check
        #
        # History is linear and monotonic: source <= target <= head.
        # The second check implies head >= source by transitivity.
        if source_checkpoint.slot > target_checkpoint.slot:
            raise SpecRejectionError(
                RejectionReason.SOURCE_AFTER_TARGET,
                "Source checkpoint slot must not exceed target",
            )
        if head_checkpoint.slot < target_checkpoint.slot:
            raise SpecRejectionError(
                RejectionReason.HEAD_OLDER_THAN_TARGET,
                "Head checkpoint must not be older than target",
            )

        # Consistency Check
        #
        # Validate checkpoint slots match block slots.
        if store.blocks[source_checkpoint.root].slot != source_checkpoint.slot:
            raise SpecRejectionError(
                RejectionReason.SOURCE_SLOT_MISMATCH, "Source checkpoint slot mismatch"
            )
        if store.blocks[target_checkpoint.root].slot != target_checkpoint.slot:
            raise SpecRejectionError(
                RejectionReason.TARGET_SLOT_MISMATCH, "Target checkpoint slot mismatch"
            )
        if store.blocks[head_checkpoint.root].slot != head_checkpoint.slot:
            raise SpecRejectionError(
                RejectionReason.HEAD_SLOT_MISMATCH, "Head checkpoint slot mismatch"
            )

        # Ancestry Check
        #
        # Fork-choice weight accrues to every ancestor of the attested head.
        # A sibling head would steer that weight onto a non-canonical branch.
        if not self._checkpoint_is_ancestor(store, source_checkpoint, target_checkpoint):
            raise SpecRejectionError(
                RejectionReason.SOURCE_NOT_ANCESTOR_OF_TARGET,
                "Source checkpoint must be ancestor of target",
            )
        if not self._checkpoint_is_ancestor(store, target_checkpoint, head_checkpoint):
            raise SpecRejectionError(
                RejectionReason.TARGET_NOT_ANCESTOR_OF_HEAD,
                "Target checkpoint must be ancestor of head",
            )

        # Head Consistency Check
        #
        # A vote cannot have observed its head before that head existed.
        # This lower bound also keeps the wire slot clear of the 2**64 overflow edge.
        if attestation_data.slot < head_checkpoint.slot:
            raise SpecRejectionError(
                RejectionReason.ATTESTATION_SLOT_BEFORE_HEAD,
                "Attestation slot precedes head",
            )

        # Time Check
        #
        # Reject votes whose slot has not started, with a small clock-skew margin.
        # The margin is one interval, not a whole slot.
        #
        # With 5 intervals per slot, slot 10 begins at interval 50:
        #
        #     interval 49  ->  admitted by the one-interval margin (correct)
        #     interval 45  ->  admitted only by a whole-slot margin, a full slot early
        #
        # The early window lets an adversary pre-publish next-slot aggregates.
        #
        # Work in slot units, not intervals.
        # Multiplying a near-2**64 wire slot into intervals would overflow and crash first.
        admission_horizon_interval = int(store.time) + int(GOSSIP_DISPARITY_INTERVALS)
        max_admissible_slot = admission_horizon_interval // int(INTERVALS_PER_SLOT)
        if int(attestation_data.slot) > max_admissible_slot:
            raise SpecRejectionError(
                RejectionReason.ATTESTATION_TOO_FAR_IN_FUTURE, "Attestation too far in future"
            )

    def on_gossip_attestation(
        self,
        store: LstarStore,
        signed_attestation: SignedAttestation,
        is_aggregator: bool = False,
    ) -> LstarStore:
        """
        Verify a gossiped attestation and, for aggregators, record its signature.

        Steps:
            1. Validate the vote: known blocks, matching slots, ancestry, and timing.
            2. Verify the signature against the validator's key.
            3. Record the signature, but only when this node aggregates.

        Subnet filtering happens at the p2p subscription layer.
        Only attestations from subscribed subnets arrive here, so no subnet check is repeated.

        Args:
            store: Current fork-choice store.
            signed_attestation: The signed vote to process.
            is_aggregator: Whether this node aggregates signatures.

        Returns:
            A new store with the signature recorded when aggregating.
            The input store unchanged otherwise.

        Raises:
            SpecRejectionError: VALIDATOR_NOT_IN_STATE if the validator is not in the state.
            SpecRejectionError: INVALID_SIGNATURE if signature verification fails.
        """
        with observe_on_attestation():
            # Unpack the gossiped vote:
            # - the voter,
            # - the vote,
            # - the binding signature.
            validator_index = signed_attestation.validator_index
            attestation_data = signed_attestation.data
            signature = signed_attestation.signature

            # Validate the attestation data before verifying.
            #
            # It checks that:
            # - the source, target, and head blocks are all known in the store,
            # - their slots are ordered source <= target <= head,
            # - each checkpoint slot matches its block's actual slot from the store,
            # - source, target, and head lie on one parent chain,
            # - the vote's slot is not before the head block's slot,
            # - the vote's slot has already started locally with a small margin.
            self.validate_attestation(store, attestation_data)

            # Resolve the signer's public key from the target block's post-state:
            #
            #     target root -> post-state -> validators[voter index] -> public key
            #
            # The state always exists.
            #
            # Validation proved:
            # - the block is known,
            # - blocks are stored together with their post-state.
            key_state = store.states.get(attestation_data.target.root)
            assert key_state is not None, (
                f"No state available to verify attestation signature for target block "
                f"{attestation_data.target.root.hex()}"
            )

            # The validator index must fall inside that registry.
            # An out-of-range index names a validator the target state never knew.
            if not validator_index.is_within_registry(Uint64(len(key_state.validators))):
                raise SpecRejectionError(
                    RejectionReason.VALIDATOR_NOT_IN_STATE,
                    f"Validator {validator_index} not found in state "
                    f"{attestation_data.target.root.hex()}",
                )
            public_key = PublicKey.decode_bytes(
                key_state.validators[validator_index].attestation_public_key
            )

            # Verify the signature.
            #
            # The scheme binds the signature to the public key, the slot, and the vote hash.
            # None of those can be swapped out after signing.
            if not TARGET_SIGNATURE_SCHEME.verify(
                public_key, attestation_data.slot, hash_tree_root(attestation_data), signature
            ):
                raise SpecRejectionError(
                    RejectionReason.INVALID_SIGNATURE, "Signature verification failed"
                )

            # Non-aggregators stop here.
            # - They validate and relay the vote.
            # - They never keep its signature.
            if not is_aggregator:
                return store

            # Record the signature in the aggregator's pool.
            #
            # The pool groups signatures by the exact vote they sign:
            #
            #     vote A  ->  { (validator 3, signature), (validator 7, signature) }
            #     vote B  ->  { (validator 7, signature) }
            #
            # Add the entry to a fresh copy of this vote's set.
            # The union builds a new set, so the caller's set is never touched.
            signatures_for_vote = store.attestation_signatures.get(attestation_data, set()) | {
                AttestationSignatureEntry(validator_index, signature)
            }

            # Merge that one set back into a new map, sharing the other votes' sets.
            # Only the changed vote allocates; everything else stays immutable.
            new_attestation_signatures = store.attestation_signatures | {
                attestation_data: signatures_for_vote
            }

            return store.model_copy(update={"attestation_signatures": new_attestation_signatures})

    def on_gossip_aggregated_attestation(
        self,
        store: LstarStore,
        signed_attestation: SignedAggregatedAttestation,
    ) -> LstarStore:
        """
        Verify a gossiped aggregated attestation and record its proof.

        One aggregated attestation carries a single proof that stands in for many
        validators who all signed the same vote.

        Steps:
            1. Validate the vote: known blocks, matching slots, ancestry, and timing.
            2. Verify the aggregate proof against every participant's key.
            3. Record the proof in the pending pool.

        Args:
            store: Current fork-choice store.
            signed_attestation: The signed aggregated vote to process.

        Returns:
            A new store with the proof recorded in the pending pool.

        Raises:
            SpecRejectionError: VALIDATOR_NOT_IN_STATE if a participant is not in the state.
            SpecRejectionError: INVALID_SIGNATURE if aggregate verification fails.
        """
        # Unpack the aggregated vote: the vote, and the single proof covering its signers.
        attestation_data = signed_attestation.data
        aggregated_proof = signed_attestation.proof

        # Validate the attestation data before verifying.
        #
        # It checks that:
        # - the source, target, and head blocks are all known in the store,
        # - their slots are ordered source <= target <= head,
        # - each checkpoint slot matches its block's actual slot from the store,
        # - source, target, and head lie on one parent chain,
        # - the vote's slot is not before the head block's slot,
        # - the vote's slot has already started locally with a small margin.
        self.validate_attestation(store, attestation_data)

        # The proof names every validator that contributed to it.
        validator_indices = aggregated_proof.participants.to_validator_indices()

        # Resolve each participant's public key from the target block's post-state:
        #
        #     target root -> post-state -> validators[participant index] -> public key
        #
        # The state always exists.
        #
        # Validation proved:
        # - the block is known,
        # - blocks are stored together with their post-state.
        key_state = store.states.get(attestation_data.target.root)
        assert key_state is not None, (
            f"No state available to verify committee aggregation for target "
            f"{attestation_data.target.root.hex()}"
        )

        # Every participant must fall inside that registry.
        # An out-of-range index names a validator the target state never knew.
        validators = key_state.validators
        for validator_index in validator_indices:
            if not validator_index.is_within_registry(Uint64(len(validators))):
                raise SpecRejectionError(
                    RejectionReason.VALIDATOR_NOT_IN_STATE,
                    f"Validator {validator_index} not found in state "
                    f"{attestation_data.target.root.hex()}",
                )

        # Collect the participants' keys, in the order the proof expects them.
        public_keys = [
            PublicKey.decode_bytes(validators[validator_index].attestation_public_key)
            for validator_index in validator_indices
        ]

        # Verify the aggregate proof.
        #
        # The proof binds every participant key, the slot, and the vote hash together.
        # A failure rejects the whole aggregate, not one signer.
        try:
            aggregated_proof.verify(
                public_keys=public_keys,
                message=hash_tree_root(attestation_data),
                slot=attestation_data.slot,
            )
        except AggregationError as exception:
            raise SpecRejectionError(
                RejectionReason.INVALID_SIGNATURE,
                f"Committee aggregation signature verification failed: {exception}",
            ) from exception

        # Record the proof in the pending pool.
        #
        # The pool groups proofs by the exact vote they cover:
        #
        #     vote A  ->  { proof P, proof Q }
        #     vote B  ->  { proof P }
        #
        # Add the proof to a fresh copy of this vote's set.
        # The union builds a new set, so the caller's set is never touched.
        proofs_for_vote = store.latest_new_aggregated_payloads.get(attestation_data, set()) | {
            aggregated_proof
        }

        # Merge that one set back into a new map, sharing the other votes' sets.
        # Only the changed vote allocates; everything else stays immutable.
        new_aggregated_payloads = store.latest_new_aggregated_payloads | {
            attestation_data: proofs_for_vote
        }

        return store.model_copy(update={"latest_new_aggregated_payloads": new_aggregated_payloads})

    def on_block(
        self,
        store: LstarStore,
        signed_block: SignedBlock,
    ) -> LstarStore:
        """
        Process a new block and update the forkchoice state.

        This method integrates a block into the forkchoice store by:

        1. Validating the block's parent exists
        2. Computing the post-state via the state transition function
        3. Processing attestations included in the block body (on-chain)
        4. Updating the forkchoice head

        Raises:
            SpecRejectionError: UNKNOWN_PARENT_BLOCK if the parent state is not in the store.
            SpecRejectionError: DUPLICATE_ATTESTATION_DATA if the block repeats an AttestationData.
            SpecRejectionError: TOO_MANY_ATTESTATION_DATA if the block exceeds the data cap.
        """
        with observe_on_block():
            block = signed_block.block
            block_root = hash_tree_root(block)

            # Skip a block already in the store; re-importing it would change nothing.
            if block_root in store.blocks:
                return store

            # Snapshot the finalized slot before any update.
            # Comparing against it at the end tells us whether pruning is needed.
            previous_finalized_slot = store.latest_finalized.slot

            # Resolve the parent's post-state, where the state transition starts from.
            #
            # A missing parent state means a gap in the chain.
            # The node must sync the parent chain before this block can apply.
            parent_state = store.states.get(block.parent_root)
            if parent_state is None:
                raise SpecRejectionError(
                    RejectionReason.UNKNOWN_PARENT_BLOCK,
                    f"Parent state not found (root={block.parent_root.hex()}). "
                    f"Sync parent chain before processing block at slot {block.slot}.",
                )

            # Reject a block body that repeats the same vote data.
            #
            # Collapsing the votes to their distinct data exposes any repeat:
            #
            #     votes  ->  { vote A, vote B, vote B }  ->  distinct { vote A, vote B }
            #
            # A repeat (fewer distinct than total) is rejected as duplicate data.
            # The transition itself bounds the distinct-data count.
            # Only the wire-level duplicate prohibition lives here.
            aggregated_attestations = block.body.attestations
            attestation_data_set = {attestation.data for attestation in aggregated_attestations}
            if len(attestation_data_set) != len(aggregated_attestations):
                raise SpecRejectionError(
                    RejectionReason.DUPLICATE_ATTESTATION_DATA,
                    "Block contains duplicate AttestationData entries; "
                    "each AttestationData must appear at most once",
                )

            # Validate cryptographic signatures.
            #
            # This raises on any invalid signature, aborting the import.
            self.verify_signatures(signed_block, parent_state.validators)

            # Run the state transition from the parent state to this block's post-state.
            post_state = self.state_transition(parent_state, block)

            # Advance the justified checkpoint from the post-state.
            #
            # A candidate wins only when its slot is strictly higher than the store's.
            # On a slot tie the store keeps its checkpoint, avoiding a silent root swap:
            #
            #     store slot 5, candidate slot 7  ->  take candidate
            #     store slot 5, candidate slot 5  ->  keep store
            latest_justified = store.latest_justified.advance_to(post_state.latest_justified)

            # Seed each block-carried vote into the known pool with an empty proof set.
            #
            # A block's merged proof is never split here.
            # Per-vote proofs arrive later through the gossip path.
            # Until then a block's own votes add zero head weight, deferred by up to one slot.
            #
            # Existing entries win on collision, keeping their proofs:
            #
            #     pool { vote A -> {p} }  +  block votes A, B  ->  { vote A -> {p}, vote B -> {} }
            new_known_aggregated_payloads = {
                aggregated_attestation.data: set()
                for aggregated_attestation in aggregated_attestations
            } | store.latest_known_aggregated_payloads

            store = store.model_copy(
                update={
                    "blocks": store.blocks | {block_root: block},
                    "states": store.states | {block_root: post_state},
                    "latest_justified": latest_justified,
                    "latest_known_aggregated_payloads": new_known_aggregated_payloads,
                }
            )

            # Recompute the head now that the block and its votes are in the store.
            store = self.update_head(store)

            # Prune stale vote data, but only when finalization advanced past the snapshot.
            if store.latest_finalized.slot > previous_finalized_slot:
                store = self.prune_stale_attestation_data(store)

            return store

    def extract_attestations_from_aggregated_payloads(
        self,
        aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]],
        latest_finalized_slot: Slot,
    ) -> dict[ValidatorIndex, AttestationData]:
        """
        Map each participating validator to the latest vote it cast.

        This is the LMD view fork choice runs on.
        On equal slots the first vote seen wins, since the slot comparison is strict.

        A vote whose head sits at or below the finalized slot carries no fork-choice weight.
        Such stale votes are skipped here, so callers pass their pool without pre-filtering.

        Args:
            aggregated_payloads: Proof sets keyed by the vote they cover.
            latest_finalized_slot: Finalized cutoff; votes at or below it are skipped.

        Returns:
            Each validator mapped to its highest-slot vote.
        """
        latest_vote_by_validator: dict[ValidatorIndex, AttestationData] = {}

        # Walk every vote, every proof for it, and every validator the proof covers.
        for attestation_data, proofs in aggregated_payloads.items():
            # Skip votes whose head no longer outlives the finalized slot.
            if attestation_data.head.slot <= latest_finalized_slot:
                continue

            # Every proof here shares one attestation data, so they share one slot.
            # The strict slot comparison below never overwrites between them.
            # Set iteration order is therefore non-consensus and safe to leave native.
            for proof in proofs:
                for validator_index in proof.participants.to_validator_indices():
                    # Keep this vote only when it is newer than the one already stored.
                    previous_vote = latest_vote_by_validator.get(validator_index)
                    if previous_vote is None or previous_vote.slot < attestation_data.slot:
                        latest_vote_by_validator[validator_index] = attestation_data

        return latest_vote_by_validator

    def _accumulate_ancestor_weights(
        self,
        store: LstarStore,
        attestations: dict[ValidatorIndex, AttestationData],
        start_slot: Slot,
    ) -> dict[Bytes32, int]:
        """
        Tally how many latest votes credit each block.

        A vote credits its head block and every ancestor above the start slot.
        Climbing stops at the start slot, or where the chain leaves the known tree.

        Args:
            store: Fork-choice store holding the known block tree.
            attestations: Each validator mapped to its latest vote.
            start_slot: Anchor slot; ancestors at or below it are not counted.

        Returns:
            Each block root mapped to the number of votes crediting it.
        """
        weights: dict[Bytes32, int] = defaultdict(int)

        for attestation_data in attestations.values():
            # Climb from this vote's head toward genesis, crediting each block.
            current_root = attestation_data.head.root
            while current_root in store.blocks:
                current_block = store.blocks[current_root]

                # Stop at the anchor: the start slot and below are out of scope.
                if current_block.slot <= start_slot:
                    break

                weights[current_root] += 1
                current_root = current_block.parent_root

        return weights

    def compute_block_weights(self, store: LstarStore) -> dict[Bytes32, int]:
        """
        Weigh each block by the latest votes landing on it or its descendants.

        Only counted votes whose head outlives the finalized slot can move the head.

        Args:
            store: Fork-choice store holding the block tree and vote pools.

        Returns:
            Each block root mapped to its accumulated vote weight.
        """
        # Reduce the counted pool to each validator's latest still-relevant vote.
        latest_votes = self.extract_attestations_from_aggregated_payloads(
            store.latest_known_aggregated_payloads,
            store.latest_finalized.slot,
        )

        # Credit every block on those votes' ancestor chains above finalization.
        #
        # Return a plain dict so callers read missing blocks as absent, not zero.
        weights = self._accumulate_ancestor_weights(
            store, latest_votes, store.latest_finalized.slot
        )

        return dict(weights)

    def _compute_lmd_ghost_head(
        self,
        store: LstarStore,
        start_root: Bytes32,
        attestations: dict[ValidatorIndex, AttestationData],
        min_score: int = 0,
    ) -> Bytes32:
        """
        Walk the block tree according to the LMD GHOST rule.

        1. The walk starts from a chosen root.
        2. At each fork, the child subtree with the highest weight is taken.
        3. The process stops when a leaf is reached.
        4. That leaf is the chosen head.

        Weights are derived from votes as follows:
        - Each validator contributes its full weight to its most recent head vote.
        - The weight of that vote also flows to every ancestor of the voted block.
        - The weight of a subtree is the sum of all such contributions inside it.

        An optional threshold can be applied:
        - If a threshold is set, children below this threshold are ignored.

        When two branches have equal weight, the one with the lexicographically
        larger hash is chosen to break ties.
        """
        # Invariant: the anchor must be a block the store already knows.
        assert start_root in store.blocks, f"start_root {start_root.hex()} not in store.blocks"

        # Remember the slot of the anchor once and reuse it during the walk.
        #
        # This avoids repeated lookups inside the inner loop.
        start_slot = store.blocks[start_root].slot

        # Collect voting weight for every block above the anchor slot.
        weights = self._accumulate_ancestor_weights(store, attestations, start_slot)

        # Build the parent -> children adjacency.
        children_map: dict[Bytes32, list[Bytes32]] = defaultdict(list)

        for root, block in store.blocks.items():
            # Prune low-weight branches early when a threshold is set.
            if min_score > 0 and weights[root] < min_score:
                continue

            children_map[block.parent_root].append(root)

        # Now perform the greedy walk.
        #
        # At each step, pick the child with the highest weight among the candidates.
        head = start_root

        # Descend the tree, choosing the heaviest branch at every fork.
        while children := children_map.get(head):
            # Choose best child: most attestations, then lexicographically highest hash
            head = max(children, key=lambda child_root: (weights[child_root], child_root))

        return head

    def update_head(self, store: LstarStore) -> LstarStore:
        """
        Recompute the canonical head and return the store updated with it.

        Fork choice starts at the latest justified root and applies LMD-GHOST,
        descending to the heaviest subtree by attestation weight.

        Args:
            store: Fork-choice store holding the block tree and vote pools.

        Returns:
            The store with its head set to the chosen block.
        """
        # Reduce the counted pool to each validator's latest still-relevant vote.
        latest_votes = self.extract_attestations_from_aggregated_payloads(
            store.latest_known_aggregated_payloads,
            store.latest_finalized.slot,
        )

        # Descend from the justified root to the heaviest leaf.
        #
        # The result is always a descendant of that root, since the walk only follows children.
        new_head = self._compute_lmd_ghost_head(
            store,
            start_root=store.latest_justified.root,
            attestations=latest_votes,
        )
        # Invariant: the finalized checkpoint stays on the head's chain.
        # Climb from the head to its ancestor at the finalized slot.
        finalized_slot = store.states[new_head].latest_finalized.slot
        finalized_root = new_head
        while finalized_root in store.blocks and store.blocks[finalized_root].slot > finalized_slot:
            parent_root = store.blocks[finalized_root].parent_root
            if parent_root not in store.blocks:
                break
            finalized_root = parent_root

        # A fresh checkpoint-sync anchor stores no block at that slot.
        # Keep the trusted anchor there rather than emit an unresolved root.
        if store.blocks[finalized_root].slot == finalized_slot:
            latest_finalized = Checkpoint(root=finalized_root, slot=finalized_slot)
        else:
            latest_finalized = store.latest_finalized

        return store.model_copy(update={"head": new_head, "latest_finalized": latest_finalized})

    def accept_new_attestations(self, store: LstarStore) -> LstarStore:
        """
        Promote pending aggregate proofs into the counted pool, then recompute the head.

        Proofs gathered this slot sit in the pending pool and carry no fork-choice weight.
        This acceptance tick merges them into the counted pool, where they begin to count.
        The pending pool is then emptied.

        Args:
            store: Fork-choice store holding both aggregate pools.

        Returns:
            The store with proofs promoted and the head recomputed.
        """
        # Union each vote's pending proofs with its counted proofs.
        #
        # Each union builds a fresh set, so the caller's store stays untouched.
        known_payloads = store.latest_known_aggregated_payloads
        new_payloads = store.latest_new_aggregated_payloads
        merged_aggregated_payloads = {
            attestation_data: known_payloads.get(attestation_data, set())
            | new_payloads.get(attestation_data, set())
            for attestation_data in {**known_payloads, **new_payloads}
        }

        # Promote into the counted pool and clear the pending one.
        store = store.model_copy(
            update={
                "latest_known_aggregated_payloads": merged_aggregated_payloads,
                "latest_new_aggregated_payloads": {},
            }
        )

        # Recompute the head now that the promoted proofs count.
        return self.update_head(store)

    def update_safe_target(self, store: LstarStore) -> LstarStore:
        """
        Find the deepest block backed by two-thirds of this slot's voters.

        This is the block a validator is safe to attest to.

        Args:
            store: Fork-choice store holding the block tree and vote pools.

        Returns:
            The store with its safe target updated.
        """
        # Validator count from the head block's post-state sets the threshold.
        num_validators = len(store.states[store.head].validators)

        # Round up for a strict supermajority: 100 validators need 67, not 66.
        min_target_score = math.ceil(num_validators * 2 / 3)

        # Reduce the pending pool to each validator's latest still-relevant vote.
        latest_votes = self.extract_attestations_from_aggregated_payloads(
            store.latest_new_aggregated_payloads,
            store.latest_finalized.slot,
        )

        # Descend from the justified root, taking only children that clear the threshold.
        #
        # The walk stops where no child qualifies, so the target can sit shallower than the head.
        safe_target = self._compute_lmd_ghost_head(
            store,
            start_root=store.latest_justified.root,
            attestations=latest_votes,
            min_score=min_target_score,
        )

        return store.model_copy(update={"safe_target": safe_target})
