"""
Forkchoice store for tracking chain state and attestations.

The Store tracks all information required for the LMD GHOST forkchoice algorithm.
"""

__all__ = ["Store"]

import copy
from collections import defaultdict

from lean_spec.subspecs.chain.config import (
    ATTESTATION_COMMITTEE_COUNT,
    INTERVALS_PER_SLOT,
    JUSTIFICATION_LOOKBACK_SLOTS,
    MILLISECONDS_PER_INTERVAL,
    SECONDS_PER_SLOT,
)
from lean_spec.subspecs.containers import (
    Attestation,
    AttestationData,
    Block,
    Checkpoint,
    Config,
    SignedAttestation,
    SignedBlockWithAttestation,
    State,
    ValidatorIndex,
)
from lean_spec.subspecs.containers.attestation.attestation import SignedAggregatedAttestation
from lean_spec.subspecs.containers.block import BlockLookup
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import (
    AggregatedSignatureProof,
    AggregationError,
    SignatureKey,
)
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.interface import TARGET_SIGNATURE_SCHEME, GeneralizedXmssScheme
from lean_spec.types import (
    ZERO_HASH,
    Bytes32,
    Uint64,
)
from lean_spec.types.container import Container


class Store(Container):
    """
    Forkchoice store tracking chain state and validator attestations.

    This is the "local view" that a node uses to run LMD GHOST. It contains:

    - which blocks and states are known,
    - which checkpoints are justified and finalized,
    - which block is currently considered the head,
    - and, for each validator, their latest attestation that should influence fork choice.

    The `Store` is updated whenever:
    - a new block is processed,
    - an attestation is received (via a block or gossip),
    - an interval tick occurs (activating new attestations),
    - or when the head is recomputed.
    """

    time: Uint64
    """Current time in intervals since genesis."""

    config: Config
    """Chain configuration parameters."""

    head: Bytes32
    """
    Root of the current canonical chain head block.

    This is the result of running the fork choice algorithm on the current contents of the `Store`.
    """

    safe_target: Bytes32
    """
    Root of the current safe target for attestation.

    This can be used by higher-level logic to restrict which blocks are
    considered safe to attest to, based on additional safety conditions.
    """

    latest_justified: Checkpoint
    """
    Highest slot justified checkpoint known to the store.

    LMD GHOST starts from this checkpoint when computing the head.

    Only descendants of this checkpoint are considered viable.
    """

    latest_finalized: Checkpoint
    """
    Highest slot finalized checkpoint known to the store.

    Everything strictly before this checkpoint can be considered immutable.

    Fork choice will never revert finalized history.
    """

    blocks: BlockLookup = {}
    """
    Mapping from block root to Block objects.

    This is the set of blocks that the node currently knows about.

    Every block that might participate in fork choice must appear here.
    """

    states: dict[Bytes32, State] = {}
    """
    Mapping from block root to State objects.

    For each known block, we keep its post-state.

    These states carry justified and finalized checkpoints that we use to update the
    `Store`'s latest justified and latest finalized checkpoints.
    """

    validator_id: ValidatorIndex | None
    """Index of the validator running this store instance."""

    gossip_signatures: dict[SignatureKey, Signature] = {}
    """
    Per-validator XMSS signatures learned from committee attesters.

    Keyed by SignatureKey(validator_id, attestation_data_root).
    """

    attestation_data_by_root: dict[Bytes32, AttestationData] = {}
    """
    Mapping from attestation data root to full AttestationData.

    This allows reconstructing attestations from aggregated payloads.
    Entries are pruned once their target checkpoint falls at or before finalization.
    """

    latest_new_aggregated_payloads: dict[SignatureKey, list[AggregatedSignatureProof]] = {}
    """
    Aggregated signature proofs pending processing.

    These payloads are "new" and do not yet contribute to fork choice.
    They migrate to known payloads via interval ticks.
    Populated from blocks or gossip aggregated attestations.
    """

    latest_known_aggregated_payloads: dict[SignatureKey, list[AggregatedSignatureProof]] = {}
    """
    Aggregated signature proofs that have been processed.

    These payloads are "known" and contribute to fork choice weights.
    Used for recursive signature aggregation when building blocks.
    """

    @classmethod
    def get_forkchoice_store(
        cls,
        anchor_state: State,
        anchor_block: Block,
        validator_id: ValidatorIndex | None,
    ) -> "Store":
        """
        Initialize forkchoice store from an anchor state and block.

        The anchor block and its state form the starting point for fork choice.
        We treat this anchor as both justified and finalized.

        Args:
            anchor_state: The state corresponding to the anchor block.
            anchor_block: A trusted block (e.g. genesis or checkpoint).
            validator_id: Index of the validator running this store.

        Returns:
            A new Store instance, ready to accept blocks and attestations.

        Raises:
            AssertionError:
                If the anchor block's state root does not match the hash
                of the provided state.
        """
        # Compute the SSZ root of the given state.
        #
        # This is the canonical hash that should appear in the block's state root.
        computed_state_root = hash_tree_root(anchor_state)

        # Check that the block actually points to this state.
        #
        # If this fails, the caller has supplied inconsistent inputs.
        assert anchor_block.state_root == computed_state_root, (
            "Anchor block state root must match anchor state hash"
        )

        # Compute the SSZ root of the anchor block itself.
        #
        # This root will be used as:
        # - the key in the blocks/states maps,
        # - the initial head,
        # - the root of the initial checkpoints.
        anchor_root = hash_tree_root(anchor_block)

        # Read the slot at which the anchor block was proposed.
        anchor_slot = anchor_block.slot

        # Build an initial checkpoint using the anchor block.
        #
        # Both the root and the slot come directly from the anchor.
        # Initialize checkpoints from the anchor state
        #
        # We explicitly set the root to the anchor block root.
        # The anchor state internally might have zero-hash checkpoints (if genesis),
        # but the Store must treat the anchor block as the justified/finalized point.

        return cls(
            time=Uint64(anchor_slot * INTERVALS_PER_SLOT),
            config=anchor_state.config,
            head=anchor_root,
            safe_target=anchor_root,
            latest_justified=anchor_state.latest_justified.model_copy(update={"root": anchor_root}),
            latest_finalized=anchor_state.latest_finalized.model_copy(update={"root": anchor_root}),
            blocks={anchor_root: anchor_block},
            states={anchor_root: anchor_state},
            validator_id=validator_id,
        )

    def prune_stale_attestation_data(self) -> "Store":
        """
        Remove attestation data that can no longer influence fork choice.

        An attestation becomes stale when its target checkpoint falls at or before
        the finalized slot. Such attestations cannot affect chain selection since
        the target is already finalized.

        Pruning removes all attestation-related data:

        - Attestation data entries
        - Gossip signatures
        - Pending aggregated payloads
        - Processed aggregated payloads

        Returns:
            New Store with stale attestation data removed.
        """
        finalized_slot = self.latest_finalized.slot

        # Identify which attestations are stale.
        #
        # An attestation is stale if its target slot is at or before finalization.
        # We collect all such roots in one pass to avoid repeated lookups.
        stale_roots: set[Bytes32] = {
            data_root
            for data_root, data in self.attestation_data_by_root.items()
            if data.target.slot <= finalized_slot
        }

        # Early return if nothing to prune.
        #
        # Return the same instance to avoid unnecessary object creation.
        if not stale_roots:
            return self

        # Filter out stale entries from all attestation-related mappings.
        #
        # Each mapping is keyed by attestation data root, so we check membership
        # against the stale set we computed above.

        new_attestation_data = {
            root: data
            for root, data in self.attestation_data_by_root.items()
            if root not in stale_roots
        }

        new_gossip_sigs = {
            key: sig
            for key, sig in self.gossip_signatures.items()
            if key.data_root not in stale_roots
        }

        new_aggregated_new = {
            key: proofs
            for key, proofs in self.latest_new_aggregated_payloads.items()
            if key.data_root not in stale_roots
        }

        new_aggregated_known = {
            key: proofs
            for key, proofs in self.latest_known_aggregated_payloads.items()
            if key.data_root not in stale_roots
        }

        return self.model_copy(
            update={
                "attestation_data_by_root": new_attestation_data,
                "gossip_signatures": new_gossip_sigs,
                "latest_new_aggregated_payloads": new_aggregated_new,
                "latest_known_aggregated_payloads": new_aggregated_known,
            }
        )

    def validate_attestation(self, attestation: Attestation) -> None:
        """
        Validate incoming attestation before processing.

        Ensures the vote respects the basic laws of time and topology:
            1. The blocks voted for must exist in our store.
            2. A vote cannot span backwards in time (source > target).
            3. The head must be at least as recent as source and target.
            4. Checkpoint slots must match the actual block slots.
            5. A vote cannot be for a future slot.

        Args:
            attestation: Attestation to validate (unsigned).

        Raises:
            AssertionError: If attestation fails validation.
        """
        data = attestation.data

        # Availability Check
        #
        # We cannot count a vote if we haven't seen the blocks involved.
        assert data.source.root in self.blocks, f"Unknown source block: {data.source.root.hex()}"
        assert data.target.root in self.blocks, f"Unknown target block: {data.target.root.hex()}"
        assert data.head.root in self.blocks, f"Unknown head block: {data.head.root.hex()}"

        # Topology Check
        #
        # History is linear and monotonic: source <= target <= head.
        # The second check implies head >= source by transitivity.
        assert data.source.slot <= data.target.slot, "Source checkpoint slot must not exceed target"
        assert data.head.slot >= data.target.slot, "Head checkpoint must not be older than target"

        # Consistency Check
        #
        # Validate checkpoint slots match block slots.
        source_block = self.blocks[data.source.root]
        target_block = self.blocks[data.target.root]
        head_block = self.blocks[data.head.root]
        assert source_block.slot == data.source.slot, "Source checkpoint slot mismatch"
        assert target_block.slot == data.target.slot, "Target checkpoint slot mismatch"
        assert head_block.slot == data.head.slot, "Head checkpoint slot mismatch"

        # Time Check
        #
        # Validate attestation is not too far in the future
        # We allow a small margin for clock disparity (1 slot), but no further.
        current_slot = Slot(self.time // INTERVALS_PER_SLOT)
        assert data.slot <= current_slot + Slot(1), "Attestation too far in future"

    def on_gossip_attestation(
        self,
        signed_attestation: SignedAttestation,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
        is_aggregator: bool = False,
    ) -> "Store":
        """
        Process a signed attestation received via gossip network.

        This method:
        1. Verifies the XMSS signature
        2. If current node is aggregator, stores the signature in the gossip
           signature map if it belongs to the current validator's subnet
        3. Processes the attestation data via on_attestation

        Args:
            signed_attestation: The signed attestation from gossip.
            scheme: XMSS signature scheme for verification.
            is_aggregator: True if current validator holds aggregator role.

        Returns:
            New Store with attestation processed and signature stored.

        Raises:
            ValueError: If validator not found in state.
            AssertionError: If signature verification fails.
        """
        validator_id = signed_attestation.validator_id
        attestation_data = signed_attestation.message
        signature = signed_attestation.signature

        # Validate the attestation first so unknown blocks are rejected cleanly
        # (instead of raising a raw KeyError when state is missing).
        attestation = Attestation(validator_id=validator_id, data=attestation_data)
        self.validate_attestation(attestation)

        key_state = self.states.get(attestation_data.target.root)
        assert key_state is not None, (
            f"No state available to verify attestation signature for target block "
            f"{attestation_data.target.root.hex()}"
        )
        assert validator_id.is_valid(len(key_state.validators)), (
            f"Validator {validator_id} not found in state {attestation_data.target.root.hex()}"
        )
        public_key = key_state.validators[validator_id].get_pubkey()

        assert signature.verify(
            public_key, attestation_data.slot, attestation_data.data_root_bytes(), scheme
        ), "Signature verification failed"

        # Store signature and attestation data for later aggregation
        new_commitee_sigs = dict(self.gossip_signatures)
        new_attestation_data_by_root = dict(self.attestation_data_by_root)
        data_root = attestation_data.data_root_bytes()

        if is_aggregator:
            assert self.validator_id is not None, "Current validator ID must be set for aggregation"
            current_validator_subnet = self.validator_id.compute_subnet_id(
                ATTESTATION_COMMITTEE_COUNT
            )
            attester_subnet = validator_id.compute_subnet_id(ATTESTATION_COMMITTEE_COUNT)
            if current_validator_subnet != attester_subnet:
                # Not part of our committee; ignore for committee aggregation.
                pass
            else:
                sig_key = SignatureKey(validator_id, data_root)
                new_commitee_sigs[sig_key] = signature

        # Store attestation data for later extraction
        new_attestation_data_by_root[data_root] = attestation_data

        # Return store with updated signature map and attestation data
        return self.model_copy(
            update={
                "gossip_signatures": new_commitee_sigs,
                "attestation_data_by_root": new_attestation_data_by_root,
            }
        )

    def on_gossip_aggregated_attestation(
        self, signed_attestation: SignedAggregatedAttestation
    ) -> "Store":
        """
        Process a signed aggregated attestation received via aggregation topic

        This method:
        1. Verifies the aggregated attestation
        2. Stores the aggregation in aggregation_payloads map

        Args:
            signed_attestation: The signed aggregated attestation from committee aggregation.

        Returns:
            New Store with aggregation processed and stored.

        Raises:
            ValueError: If validator not found in state.
            AssertionError: If signature verification fails.
        """
        data = signed_attestation.data
        proof = signed_attestation.proof

        # Get validator IDs who participated in this aggregation
        validator_ids = proof.participants.to_validator_indices()

        # Retrieve the relevant state to look up public keys for verification.
        key_state = self.states.get(data.target.root)
        assert key_state is not None, (
            f"No state available to verify committee aggregation for target "
            f"{data.target.root.hex()}"
        )

        # Ensure all participants exist in the active set
        validators = key_state.validators
        for validator_id in validator_ids:
            assert validator_id < ValidatorIndex(len(validators)), (
                f"Validator {validator_id} not found in state {data.target.root.hex()}"
            )

        # Prepare public keys for verification
        public_keys = [validators[vid].get_pubkey() for vid in validator_ids]

        # Verify the leanVM aggregated proof
        try:
            proof.verify(
                public_keys=public_keys,
                message=data.data_root_bytes(),
                epoch=data.slot,
            )
        except AggregationError as exc:
            raise AssertionError(
                f"Committee aggregation signature verification failed: {exc}"
            ) from exc

        # Copy the aggregated proof map for updates
        # Must deep copy the lists to maintain immutability of previous store snapshots
        new_aggregated_payloads = copy.deepcopy(self.latest_new_aggregated_payloads)
        data_root = data.data_root_bytes()

        # Store attestation data by root for later retrieval
        new_attestation_data_by_root = dict(self.attestation_data_by_root)
        new_attestation_data_by_root[data_root] = data

        for vid in validator_ids:
            # Update Proof Map
            #
            # Store the proof so future block builders can reuse this aggregation
            key = SignatureKey(vid, data_root)
            new_aggregated_payloads.setdefault(key, []).append(proof)

        # Return store with updated aggregated payloads and attestation data
        return self.model_copy(
            update={
                "latest_new_aggregated_payloads": new_aggregated_payloads,
                "attestation_data_by_root": new_attestation_data_by_root,
            }
        )

    def on_block(
        self,
        signed_block_with_attestation: SignedBlockWithAttestation,
        scheme: GeneralizedXmssScheme = TARGET_SIGNATURE_SCHEME,
    ) -> "Store":
        """
        Process a new block and update the forkchoice state.

        This method integrates a block into the forkchoice store by:
        1. Validating the block's parent exists
        2. Computing the post-state via the state transition function
        3. Processing attestations included in the block body (on-chain)
        4. Updating the forkchoice head
        5. Processing the proposer's attestation (as if gossiped)

        Algorithm Overview
        ------------------
        The key insight is that blocks contain two types of attestations:

        **Block Body Attestations** (processed as on-chain):
            - These are attestations from other validators included by the proposer
            - They are historical and have already influenced prior fork choice
            - Processed immediately as "known" attestations

        **Proposer Attestation** (processed as gossip):
            - The proposer's attestation for their own block
            - Cast during interval 1 (after block proposal in interval 0)
            - Should NOT influence this block's fork choice position
            - Treated as pending until interval 3 (end of slot)
            - Will be included in a future block

        This separation ensures:
        - The proposer's attestation doesn't create circular weight
        - Fork choice head is computed before counting proposer attestation
        - The attestation is available for the next block producer

        Args:
            signed_block_with_attestation: Complete signed block with proposer attestation.
            scheme: XMSS signature scheme to use for signature verification.

        Returns:
            New Store with block integrated and head updated.

        Raises:
            AssertionError: If parent block/state not found in store.
        """
        # Unpack block components
        block = signed_block_with_attestation.message.block
        proposer_attestation = signed_block_with_attestation.message.proposer_attestation
        block_root = hash_tree_root(block)

        # Skip duplicate blocks (idempotent operation)
        if block_root in self.blocks:
            return self

        # Verify parent chain is available
        #
        # The parent state must exist before processing this block.
        # If missing, the node must sync the parent chain first.
        parent_state = self.states.get(block.parent_root)
        assert parent_state is not None, (
            f"Parent state not found (root={block.parent_root.hex()}). "
            f"Sync parent chain before processing block at slot {block.slot}."
        )

        # Validate cryptographic signatures
        valid_signatures = signed_block_with_attestation.verify_signatures(parent_state, scheme)

        # Execute state transition function to compute post-block state
        post_state = copy.deepcopy(parent_state).state_transition(block, valid_signatures)

        # If post-state has a higher justified checkpoint, update it to the store.
        latest_justified = (
            post_state.latest_justified
            if post_state.latest_justified.slot > self.latest_justified.slot
            else self.latest_justified
        )

        # If post-state has a higher finalized checkpoint, update it to the store.
        latest_finalized = (
            post_state.latest_finalized
            if post_state.latest_finalized.slot > self.latest_finalized.slot
            else self.latest_finalized
        )

        # Create new store with the computed data.
        store = self.model_copy(
            update={
                "blocks": self.blocks | {block_root: block},
                "states": self.states | {block_root: post_state},
                "latest_justified": latest_justified,
                "latest_finalized": latest_finalized,
            }
        )

        # Process block body attestations and their signatures
        aggregated_attestations = signed_block_with_attestation.message.block.body.attestations
        attestation_signatures = signed_block_with_attestation.signature.attestation_signatures

        assert len(aggregated_attestations) == len(attestation_signatures), (
            "Attestation signature groups must match aggregated attestations"
        )

        # Copy the aggregated proof map for updates
        # Must deep copy the lists to maintain immutability of previous store snapshots
        # Block attestations go directly to "known" payloads (like is_from_block=True)
        block_proofs: dict[SignatureKey, list[AggregatedSignatureProof]] = copy.deepcopy(
            store.latest_known_aggregated_payloads
        )

        # Store attestation data by root for later retrieval
        new_attestation_data_by_root = dict(store.attestation_data_by_root)

        for att, proof in zip(aggregated_attestations, attestation_signatures, strict=True):
            validator_ids = att.aggregation_bits.to_validator_indices()
            data_root = att.data.data_root_bytes()

            # Store the attestation data
            new_attestation_data_by_root[data_root] = att.data

            for vid in validator_ids:
                # Update Proof Map
                #
                # Store the proof so future block builders can reuse this aggregation
                key = SignatureKey(vid, data_root)
                block_proofs.setdefault(key, []).append(proof)

        # Store proposer attestation data as well
        proposer_data_root = proposer_attestation.data.data_root_bytes()
        new_attestation_data_by_root[proposer_data_root] = proposer_attestation.data

        # Update store with new aggregated proofs and attestation data
        store = store.model_copy(
            update={
                "latest_known_aggregated_payloads": block_proofs,
                "attestation_data_by_root": new_attestation_data_by_root,
            }
        )

        # Update forkchoice head based on new block and attestations
        #
        # IMPORTANT: This must happen BEFORE processing proposer attestation
        # to prevent the proposer from gaining circular weight advantage.
        store = store.update_head()

        # Process proposer signature for future aggregation
        #
        # The proposer casts their attestation in interval 1, after block
        # proposal. Store the signature so it can be aggregated later.

        new_gossip_sigs = dict(store.gossip_signatures)

        # Store proposer signature for future lookup if it belongs to the same committee
        # as the current validator.
        if self.validator_id is not None:
            proposer_validator_id = proposer_attestation.validator_id
            proposer_subnet_id = proposer_validator_id.compute_subnet_id(
                ATTESTATION_COMMITTEE_COUNT
            )
            current_validator_subnet_id = self.validator_id.compute_subnet_id(
                ATTESTATION_COMMITTEE_COUNT
            )
            if proposer_subnet_id == current_validator_subnet_id:
                proposer_sig_key = SignatureKey(
                    proposer_attestation.validator_id,
                    proposer_attestation.data.data_root_bytes(),
                )
                new_gossip_sigs[proposer_sig_key] = (
                    signed_block_with_attestation.signature.proposer_signature
                )

        # Update store with proposer signature
        store = store.model_copy(update={"gossip_signatures": new_gossip_sigs})

        # Prune stale attestation data when finalization advances
        if store.latest_finalized.slot > self.latest_finalized.slot:
            store = store.prune_stale_attestation_data()

        return store

    def _extract_attestations_from_aggregated_payloads(
        self, aggregated_payloads: dict[SignatureKey, list[AggregatedSignatureProof]]
    ) -> dict[ValidatorIndex, AttestationData]:
        """
        Extract attestations from aggregated payloads.

        Given a mapping of aggregated signature proofs, extract the attestation data
        for each validator that participated in the aggregation.

        Args:
            aggregated_payloads: Mapping from SignatureKey to list of aggregated proofs.

        Returns:
            Mapping from ValidatorIndex to AttestationData for each validator.
        """
        attestations: dict[ValidatorIndex, AttestationData] = {}

        for sig_key, proofs in aggregated_payloads.items():
            # Get the attestation data from the data root in the signature key
            data_root = sig_key.data_root
            attestation_data = self.attestation_data_by_root.get(data_root)

            if attestation_data is None:
                # Skip if we don't have the attestation data
                continue

            # Extract all validator IDs from all proofs for this signature key
            for proof in proofs:
                validator_ids = proof.participants.to_validator_indices()
                for vid in validator_ids:
                    # Store the attestation data for this validator
                    # If multiple attestations exist for same validator,
                    # keep the latest (highest slot)
                    existing = attestations.get(vid)
                    if existing is None or existing.slot < attestation_data.slot:
                        attestations[vid] = attestation_data

        return attestations

    def _compute_lmd_ghost_head(
        self,
        start_root: Bytes32,
        attestations: dict[ValidatorIndex, AttestationData],
        min_score: int = 0,
    ) -> Bytes32:
        """
        Walk the block tree according to the LMD GHOST rule.

        The walk starts from a chosen root.
        At each fork, the child subtree with the highest weight is taken.
        The process stops when a leaf is reached.
        That leaf is the chosen head.

        Weights are derived from votes as follows:
        - Each validator contributes its full weight to its most recent head vote.
        - The weight of that vote also flows to every ancestor of the voted block.
        - The weight of a subtree is the sum of all such contributions inside it.

        An optional threshold can be applied:
        - If a threshold is set, children below this threshold are ignored.

        When two branches have equal weight, the one with the lexicographically
        larger hash is chosen to break ties.

        Args:
            start_root: Starting point root (usually latest justified).
            attestations: Attestation data to consider for fork choice weights.
            min_score: Minimum attestation count for block inclusion.

        Returns:
            Hash of the chosen head block.
        """
        # If the starting point is not defined, choose the earliest known block.
        #
        # This ensures that the walk always has an anchor.
        if start_root == ZERO_HASH:
            start_root = min(
                self.blocks.keys(), key=lambda block_hash: self.blocks[block_hash].slot
            )

        # Remember the slot of the anchor once and reuse it during the walk.
        #
        # This avoids repeated lookups inside the inner loop.
        start_slot = self.blocks[start_root].slot

        # Prepare a table that will collect voting weight for each block.
        #
        # Each entry starts conceptually at zero and then accumulates contributions.
        weights: dict[Bytes32, int] = defaultdict(int)

        # For every vote, follow the chosen head upward through its ancestors.
        #
        # Each visited block accumulates one unit of weight from that validator.
        for attestation_data in attestations.values():
            current_root = attestation_data.head.root

            # Climb towards the anchor while staying inside the known tree.
            #
            # This naturally handles partial views and ongoing sync.
            while current_root in self.blocks and self.blocks[current_root].slot > start_slot:
                weights[current_root] += 1
                current_root = self.blocks[current_root].parent_root

        # Build the adjacency tree (parent -> children).
        #
        # We use a defaultdict to avoid checking if keys exist.
        children_map: dict[Bytes32, list[Bytes32]] = defaultdict(list)

        for root, block in self.blocks.items():
            # 1. Structural check: skip blocks without parents (e.g., purely genesis/orphans)
            if not block.parent_root:
                continue

            # 2. Heuristic check: prune branches early if they lack sufficient weight
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
            head = max(children, key=lambda x: (weights[x], x))

        return head

    def update_head(self) -> "Store":
        """
        Compute updated store with new canonical head.

        This method implements the core fork choice algorithm, selecting the canonical
        chain head based on:
        1. Latest justified checkpoint (from state analysis)
        2. LMD-GHOST fork choice rule (heaviest subtree)
        3. Finalization status (from head state)

        Algorithm
        ---------
        1. **Fork Choice**: Run LMD-GHOST from justified root using attestation weights
        2. **Return**: New Store instance with updated head

        Returns:
            New Store with updated head.

        """
        # Extract attestations from known aggregated payloads
        attestations = self._extract_attestations_from_aggregated_payloads(
            self.latest_known_aggregated_payloads
        )

        # Run LMD-GHOST fork choice algorithm
        #
        # Selects canonical head by walking the tree from the justified root,
        # choosing the heaviest child at each fork based on attestation weights.
        new_head = self._compute_lmd_ghost_head(
            start_root=self.latest_justified.root,
            attestations=attestations,
        )

        # Return new Store instance with updated values (immutable update)
        return self.model_copy(
            update={
                "head": new_head,
            }
        )

    def accept_new_attestations(self) -> "Store":
        """Process pending aggregated payloads and update forkchoice head."""
        # Merge new aggregated payloads into known aggregated payloads
        merged_aggregated_payloads = dict(self.latest_known_aggregated_payloads)
        for sig_key, proofs in self.latest_new_aggregated_payloads.items():
            if sig_key in merged_aggregated_payloads:
                # Merge proof lists for the same signature key
                merged_aggregated_payloads[sig_key] = merged_aggregated_payloads[sig_key] + proofs
            else:
                merged_aggregated_payloads[sig_key] = proofs

        # Create store with migrated aggregated payloads
        store = self.model_copy(
            update={
                "latest_known_aggregated_payloads": merged_aggregated_payloads,
                "latest_new_aggregated_payloads": {},
            }
        )

        # Update head with newly accepted aggregated payloads
        return store.update_head()

    def update_safe_target(self) -> "Store":
        """
        Update the safe target for attestations.

        Computes target that has sufficient (2/3+ majority) attestation support.
        The safe target represents a block with enough attestation weight to be
        considered "safe" for validators to attest to.

        Algorithm
        ---------
        1. Get validator count from head state
        2. Calculate 2/3 majority threshold (ceiling division)
        3. Run fork choice with minimum score requirement
        4. Return new Store with updated safe_target

        Returns:
            New Store with updated safe_target.
        """
        # Get validator count from head state
        head_state = self.states[self.head]
        num_validators = len(head_state.validators)

        # Calculate 2/3 majority threshold (ceiling division)
        min_target_score = -(-num_validators * 2 // 3)

        # Extract attestations from new aggregated payloads
        attestations = self._extract_attestations_from_aggregated_payloads(
            self.latest_new_aggregated_payloads
        )

        # Find head with minimum attestation threshold.
        safe_target = self._compute_lmd_ghost_head(
            start_root=self.latest_justified.root,
            attestations=attestations,
            min_score=min_target_score,
        )

        return self.model_copy(update={"safe_target": safe_target})

    def aggregate_committee_signatures(self) -> tuple["Store", list[SignedAggregatedAttestation]]:
        """
        Aggregate committee signatures for attestations in committee_signatures.

        This method aggregates signatures from the gossip_signatures map.
        Attestations are reconstructed from gossip_signatures using attestation_data_by_root.

        Returns:
            Tuple of (new Store with updated payloads, list of new SignedAggregatedAttestation).
        """
        new_aggregated_payloads = dict(self.latest_new_aggregated_payloads)

        # Extract attestations from gossip_signatures
        # Each SignatureKey contains (validator_id, data_root)
        # We look up the full AttestationData from attestation_data_by_root
        attestation_list: list[Attestation] = []
        for sig_key in self.gossip_signatures.keys():
            data_root = sig_key.data_root
            attestation_data = self.attestation_data_by_root.get(data_root)
            if attestation_data is not None:
                attestation_list.append(
                    Attestation(validator_id=sig_key.validator_id, data=attestation_data)
                )

        committee_signatures = self.gossip_signatures

        head_state = self.states[self.head]
        # Perform aggregation
        aggregated_results = head_state.aggregate_gossip_signatures(
            attestation_list,
            committee_signatures,
        )

        # Create list for broadcasting
        new_aggregates: list[SignedAggregatedAttestation] = []
        for aggregated_attestation, aggregated_signature in aggregated_results:
            agg = SignedAggregatedAttestation(
                data=aggregated_attestation.data,
                proof=aggregated_signature,
            )
            new_aggregates.append(agg)

        # Compute new aggregated payloads
        new_gossip_sigs = dict(self.gossip_signatures)
        for aggregated_attestation, aggregated_signature in aggregated_results:
            data_root = aggregated_attestation.data.data_root_bytes()
            validator_ids = aggregated_signature.participants.to_validator_indices()
            for vid in validator_ids:
                sig_key = SignatureKey(vid, data_root)
                if sig_key not in new_aggregated_payloads:
                    new_aggregated_payloads[sig_key] = []
                new_aggregated_payloads[sig_key].append(aggregated_signature)

                # Prune successfully aggregated signature from gossip map
                if sig_key in new_gossip_sigs:
                    del new_gossip_sigs[sig_key]

        return self.model_copy(
            update={
                "latest_new_aggregated_payloads": new_aggregated_payloads,
                "gossip_signatures": new_gossip_sigs,
            }
        ), new_aggregates

    def tick_interval(
        self, has_proposal: bool, is_aggregator: bool = False
    ) -> tuple["Store", list[SignedAggregatedAttestation]]:
        """
        Advance store time by one interval and perform interval-specific actions.

        Different actions are performed based on interval within slot:
        - Interval 0: Process attestations if proposal exists
        - Interval 1: Validator attesting period (no action)
        - Interval 2: Aggregators create proofs & broadcast
        - Interval 3: Update safe target (fast confirm)
        - Interval 4: Process accumulated attestations

        The Five-Interval System
        -------------------------
        Each slot is divided into 5 intervals:

        **Interval 0 (Block Proposal)**:
            - Block proposer publishes their block
            - If proposal exists, immediately accept new attestations
            - This ensures validators see the block before attesting

        **Interval 1 (Vote Propagation)**:
            - Validators vote & propagate to their attestation subnet topics
            - No store action required

        **Interval 2 (Aggregation)**:
            - Aggregators collect votes and create aggregated proofs
            - Broadcast proofs to the aggregation topic

        **Interval 3 (Safe Target Update)**:
            - Validators use received proofs to update safe target
            - Provides validators with a stable attestation target (fast confirm)

        **Interval 4 (Attestation Acceptance)**:
            - Accept accumulated attestations (new → known)
            - Update head based on new attestation weights
            - Prepare for next slot

        Args:
            has_proposal: Whether a proposal exists for this interval.
            is_aggregator: Whether the node is an aggregator.

        Returns:
            Tuple of (new store with advanced time, list of new signed aggregated attestation).
        """
        # Advance time by one interval
        store = self.model_copy(update={"time": self.time + Uint64(1)})
        current_interval = store.time % INTERVALS_PER_SLOT
        new_aggregates: list[SignedAggregatedAttestation] = []

        if current_interval == Uint64(0):
            # Start of slot - process attestations if proposal exists
            if has_proposal:
                store = store.accept_new_attestations()
        elif current_interval == Uint64(2):
            # Aggregation interval - aggregators create proofs
            if is_aggregator:
                store, new_aggregates = store.aggregate_committee_signatures()
        elif current_interval == Uint64(3):
            # Fast confirm - update safe target based on received proofs
            store = store.update_safe_target()
        elif current_interval == Uint64(4):
            # End of slot - accept accumulated attestations
            store = store.accept_new_attestations()

        return store, new_aggregates

    def on_tick(
        self, time: Uint64, has_proposal: bool, is_aggregator: bool = False
    ) -> tuple["Store", list[SignedAggregatedAttestation]]:
        """
        Advance forkchoice store time to given timestamp.

        Ticks store forward interval by interval, performing appropriate
        actions for each interval type. This method handles time progression
        incrementally to ensure all interval-specific actions are performed.

        Args:
            time: Target time as Unix timestamp in seconds.
            has_proposal: Whether node has proposal for current slot.
            is_aggregator: Whether the node is an aggregator.

        Returns:
            Tuple of (new store with time advanced,
            list of all produced signed aggregated attestation).
        """
        # Calculate target time in intervals
        time_delta_ms = (time - self.config.genesis_time) * Uint64(1000)
        tick_interval_time = time_delta_ms // MILLISECONDS_PER_INTERVAL

        # Tick forward one interval at a time
        store = self
        all_new_aggregates: list[SignedAggregatedAttestation] = []
        while store.time < tick_interval_time:
            # Check if proposal should be signaled for next interval
            should_signal_proposal = has_proposal and (store.time + Uint64(1)) == tick_interval_time

            # Advance by one interval with appropriate signaling
            store, new_aggregates = store.tick_interval(should_signal_proposal, is_aggregator)
            all_new_aggregates.extend(new_aggregates)

        return store, all_new_aggregates

    def get_proposal_head(self, slot: Slot) -> tuple["Store", Bytes32]:
        """
        Get the head for block proposal at given slot.

        Ensures store is up-to-date and processes any pending attestations
        before returning the canonical head. This guarantees the proposer
        builds on the most recent view of the chain.

        Algorithm
        ---------
        1. Calculate slot time from slot number
        2. Advance store time to current slot (ticking intervals)
        3. Accept any pending attestations
        4. Return updated store and head root

        Args:
            slot: Slot for which to get proposal head.

        Returns:
            Tuple of (new Store with updated time, head root for building).
        """
        # Calculate time corresponding to this slot
        slot_duration_seconds = slot * SECONDS_PER_SLOT
        slot_time = self.config.genesis_time + slot_duration_seconds

        # Advance time to current slot (ticking intervals)
        store, _ = self.on_tick(slot_time, True)

        # Process any pending attestations before proposal
        store = store.accept_new_attestations()

        return store, store.head

    def get_attestation_target(self) -> Checkpoint:
        """
        Calculate target checkpoint for validator attestations.

        Determines appropriate attestation target based on head, safe target,
        and finalization constraints. The target selection algorithm balances
        between advancing the chain head and maintaining safety guarantees.

        Attestation Target Algorithm
        -----------------------------
        The algorithm walks back from the current head toward the safe target,
        ensuring the target is in a justifiable slot range:

        1. **Start at Head**: Begin with the current head block
        2. **Walk Toward Safe**: Move backward (up to `JUSTIFICATION_LOOKBACK_SLOTS` steps)
           if safe target is newer
        3. **Ensure Justifiable**: Continue walking back until slot is justifiable
        4. **Return Checkpoint**: Create checkpoint from selected block

        Justifiability Rules (see Slot.is_justifiable_after)
        ------------------------------------------------------
        A slot is justifiable at distance delta from finalization if:
        1. delta ≤ 5 (first 5 slots always justifiable)
        2. delta is a perfect square (1, 4, 9, 16, 25, ...)
        3. delta is a pronic number (2, 6, 12, 20, 30, ...)

        These rules prevent long-range attacks by restricting which checkpoints
        validators can attest to relative to finalization.

        Returns:
            Target checkpoint for attestation.
        """
        # Start from current head
        target_block_root = self.head

        # Walk back toward safe target (up to `JUSTIFICATION_LOOKBACK_SLOTS` steps)
        #
        # This ensures the target doesn't advance too far ahead of safe target,
        # providing a balance between liveness and safety.
        #
        # We allow the target to be up to 1 slot ahead of the safe target
        # to ensure the chain can actually start advancing from genesis.
        for _ in range(JUSTIFICATION_LOOKBACK_SLOTS):
            if self.blocks[target_block_root].slot > self.blocks[self.safe_target].slot + Slot(1):
                target_block_root = self.blocks[target_block_root].parent_root
            else:
                break

        # Ensure target is in justifiable slot range
        #
        # Walk back until we find a slot that satisfies justifiability rules
        # relative to the latest finalized checkpoint.
        while not self.blocks[target_block_root].slot.is_justifiable_after(
            self.latest_finalized.slot
        ):
            target_block_root = self.blocks[target_block_root].parent_root

        # Create checkpoint from selected target block
        target_block = self.blocks[target_block_root]

        return Checkpoint(root=target_block_root, slot=target_block.slot)

    def produce_attestation_data(self, slot: Slot) -> AttestationData:
        """
        Produce attestation data for the given slot.

        This method constructs an AttestationData object according to the lean protocol
        specification. The attestation data represents the chain state view including
        head, target, and source checkpoints.

        The algorithm:
        1. Get the current head block
        2. Calculate the appropriate attestation target using current forkchoice state
        3. Use the store's latest justified checkpoint as the attestation source
        4. Construct and return the complete AttestationData object

        Args:
            slot: The slot for which to produce the attestation data.

        Returns:
            A fully constructed AttestationData object.
        """
        # Get the head block the validator sees for this slot
        head_checkpoint = Checkpoint(
            root=self.head,
            slot=self.blocks[self.head].slot,
        )

        # Calculate the target checkpoint for this attestation
        target_checkpoint = self.get_attestation_target()

        # Construct attestation data
        return AttestationData(
            slot=slot,
            head=head_checkpoint,
            target=target_checkpoint,
            source=self.latest_justified,
        )

    def produce_block_with_signatures(
        self,
        slot: Slot,
        validator_index: ValidatorIndex,
    ) -> tuple["Store", Block, list[AggregatedSignatureProof]]:
        """
        Produce a block and its aggregated signature proofs for the target slot.

        Block production proceeds in four stages:
        1. Retrieve the current chain head as the parent block
        2. Verify proposer authorization for the target slot
        3. Build the block with maximal valid attestations
        4. Store the block and update checkpoints

        The block builder uses a fixed-point algorithm to collect attestations.
        Each iteration may update the justified checkpoint.
        Some attestations only become valid after this update.
        The process repeats until no new attestations can be added.

        This maximizes consensus contribution from each block.

        Args:
            slot: Target slot for block production.
            validator_index: Proposer's validator index.

        Returns:
            Tuple containing:

            - Updated store with the new block
            - The produced block
            - Signature proofs aligned with block attestations

        Raises:
            AssertionError: If validator is not the proposer for this slot.
        """
        # Retrieve parent block.
        #
        # The proposal head reflects the latest chain view after processing
        # all pending attestations. Building on stale state would orphan the block.
        store, head_root = self.get_proposal_head(slot)
        head_state = store.states[head_root]

        # Verify proposer authorization.
        #
        # Only one validator may propose per slot.
        # Unauthorized proposals would be rejected by other nodes.
        num_validators = len(head_state.validators)
        assert validator_index.is_proposer_for(slot, num_validators), (
            f"Validator {validator_index} is not the proposer for slot {slot}"
        )

        # Gather attestations from the store.
        #
        # Extract attestations from known aggregated payloads.
        # These attestations have already influenced fork choice.
        # Including them in the block makes them permanent on-chain.
        attestation_data_map = store._extract_attestations_from_aggregated_payloads(
            store.latest_known_aggregated_payloads
        )
        available_attestations = [
            Attestation(validator_id=validator_id, data=attestation_data)
            for validator_id, attestation_data in attestation_data_map.items()
        ]

        # Build the block.
        #
        # The builder iteratively collects valid attestations.
        # It returns the final block, post-state, and signature proofs.
        final_block, final_post_state, collected_attestations, signatures = head_state.build_block(
            slot=slot,
            proposer_index=validator_index,
            parent_root=head_root,
            available_attestations=available_attestations,
            known_block_roots=set(store.blocks.keys()),
            aggregated_payloads=store.latest_known_aggregated_payloads,
        )

        # Compute block hash for storage.
        block_hash = hash_tree_root(final_block)

        # Update checkpoints from post-state.
        #
        # Locally produced blocks bypass normal block processing.
        # We must manually propagate any checkpoint advances.
        # Higher slots indicate more recent justified/finalized states.
        latest_justified = (
            final_post_state.latest_justified
            if final_post_state.latest_justified.slot > store.latest_justified.slot
            else store.latest_justified
        )
        latest_finalized = (
            final_post_state.latest_finalized
            if final_post_state.latest_finalized.slot > store.latest_finalized.slot
            else store.latest_finalized
        )

        # Persist block and state immutably.
        new_store = store.model_copy(
            update={
                "blocks": {**store.blocks, block_hash: final_block},
                "states": {**store.states, block_hash: final_post_state},
                "latest_justified": latest_justified,
                "latest_finalized": latest_finalized,
            }
        )

        # Prune stale attestation data when finalization advances
        if new_store.latest_finalized.slot > store.latest_finalized.slot:
            new_store = new_store.prune_stale_attestation_data()

        return new_store, final_block, signatures
