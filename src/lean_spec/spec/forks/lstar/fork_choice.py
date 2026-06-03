"""Lstar fork — fork choice: store, LMD-GHOST, attestation handling."""

import math
from collections import defaultdict

from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.crypto.xmss.interface import TARGET_SIGNATURE_SCHEME
from lean_spec.spec.forks.lstar._base import LstarSpecBase, LstarStore
from lean_spec.spec.forks.lstar.config import (
    GOSSIP_DISPARITY_INTERVALS,
    MAX_ATTESTATIONS_DATA,
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
from lean_spec.spec.forks.protocol import SpecBlockType, SpecStateType
from lean_spec.spec.observability import (
    observe_on_attestation,
    observe_on_block,
)
from lean_spec.spec.ssz import Bytes32, Uint64


class ForkChoiceMixin(LstarSpecBase):
    """Fork choice and store maintenance for the lstar fork."""

    def create_store(
        self,
        state: SpecStateType,
        anchor_block: SpecBlockType,
        validator_index: ValidatorIndex | None,
    ) -> LstarStore:
        """Initialize a forkchoice store from an anchor state and block.

        The anchor block and state form the starting point for fork choice.
        Both are treated as justified and finalized.

        Raises:
            AssertionError:
                If the anchor block's state root does not match the hash
                of the state.
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

        # Seed both checkpoints from the anchor block itself.
        #
        # The store treats the anchor as the new genesis for fork choice:
        # all history below it is pruned. The justified and finalized checkpoints
        # therefore point at the anchor block with the anchor's own slot,
        # regardless of what the anchor state's embedded checkpoints say.
        anchor_checkpoint = Checkpoint(root=anchor_root, slot=anchor_slot)

        return self.store_class(
            time=Interval.from_slot(anchor_slot),
            config=state.config,
            head=anchor_root,
            safe_target=anchor_root,
            latest_justified=anchor_checkpoint,
            latest_finalized=anchor_checkpoint,
            blocks={anchor_root: anchor_block},
            states={anchor_root: state},
            validator_index=validator_index,
        )

    def prune_stale_attestation_data(self, store: LstarStore) -> LstarStore:
        """Remove attestation data that can no longer influence fork choice.

        An attestation becomes stale when its target checkpoint falls at or before
        the finalized slot. Such attestations cannot affect chain selection since
        the target is already finalized.

        Pruning removes all attestation-related data:

        - Attestation signatures
        - Pending aggregated payloads
        - Processed aggregated payloads
        """
        # Filter out stale entries from all attestation-related mappings.
        #
        # Each mapping is keyed by attestation data, so we check membership by slot
        # against the finalized slot.
        store.attestation_signatures = {
            attestation_data: signatures
            for attestation_data, signatures in store.attestation_signatures.items()
            if attestation_data.target.slot > store.latest_finalized.slot
        }
        store.latest_new_aggregated_payloads = {
            attestation_data: proofs
            for attestation_data, proofs in store.latest_new_aggregated_payloads.items()
            if attestation_data.target.slot > store.latest_finalized.slot
        }
        store.latest_known_aggregated_payloads = {
            attestation_data: proofs
            for attestation_data, proofs in store.latest_known_aggregated_payloads.items()
            if attestation_data.target.slot > store.latest_finalized.slot
        }
        return store

    def validate_attestation(self, store: LstarStore, attestation_data: AttestationData) -> None:
        """Validate incoming attestation before processing.

        Ensures the vote respects the basic laws of time and topology:
            1. The blocks voted for must exist in our store.
            2. A vote cannot span backwards in time (source > target).
            3. The head must be at least as recent as source and target.
            4. Checkpoint slots must match the actual block slots.
            5. The vote's slot must have started locally (a small disparity margin is allowed).

        Raises:
            AssertionError: If attestation fails validation.
        """
        data = attestation_data

        # Availability Check
        #
        # We cannot count a vote if we haven't seen the blocks involved.
        assert data.source.root in store.blocks, f"Unknown source block: {data.source.root.hex()}"
        assert data.target.root in store.blocks, f"Unknown target block: {data.target.root.hex()}"
        assert data.head.root in store.blocks, f"Unknown head block: {data.head.root.hex()}"

        # Topology Check
        #
        # History is linear and monotonic: source <= target <= head.
        # The second check implies head >= source by transitivity.
        assert data.source.slot <= data.target.slot, "Source checkpoint slot must not exceed target"
        assert data.head.slot >= data.target.slot, "Head checkpoint must not be older than target"

        # Consistency Check
        #
        # Validate checkpoint slots match block slots.
        source_block = store.blocks[data.source.root]
        target_block = store.blocks[data.target.root]
        head_block = store.blocks[data.head.root]
        assert source_block.slot == data.source.slot, "Source checkpoint slot mismatch"
        assert target_block.slot == data.target.slot, "Target checkpoint slot mismatch"
        assert head_block.slot == data.head.slot, "Head checkpoint slot mismatch"

        # Time Check
        #
        # Honest validators emit votes only after their slot has begun.
        # Allow a small disparity margin for clock skew between peers.
        #
        # The bound is in intervals, not slots: a whole-slot margin would
        # let an adversary pre-publish next-slot aggregates ahead of any
        # honest validator.
        attestation_start_interval = Interval.from_slot(data.slot)
        gossip_disparity = Interval(int(GOSSIP_DISPARITY_INTERVALS))
        assert attestation_start_interval <= store.time + gossip_disparity, (
            "Attestation too far in future"
        )

    def on_gossip_attestation(
        self,
        store: LstarStore,
        signed_attestation: SignedAttestation,
        is_aggregator: bool = False,
    ) -> LstarStore:
        """Process a signed attestation received via gossip network.

        This method:

        1. Verifies the XMSS signature
        2. Stores the signature when the node is in aggregator mode

        Subnet filtering happens at the p2p subscription layer — only
        attestations from subscribed subnets reach this method. No
        additional subnet check is needed here.

        Args:
            store: The current forkchoice store.
            signed_attestation: The signed attestation to process.
            is_aggregator: True if the node is an aggregator.

        Returns:
            A new store with the attestation signature recorded when in
            aggregator mode, otherwise the input store unchanged.

        Raises:
            ValueError: If validator not found in state.
            AssertionError: If signature verification fails.
        """
        with observe_on_attestation():
            validator_index = signed_attestation.validator_index
            attestation_data = signed_attestation.data
            signature = signed_attestation.signature

            # Validate the attestation first so unknown blocks are rejected cleanly
            # (instead of raising a raw KeyError when state is missing).
            self.validate_attestation(store, attestation_data)

            key_state = store.states.get(attestation_data.target.root)
            assert key_state is not None, (
                f"No state available to verify attestation signature for target block "
                f"{attestation_data.target.root.hex()}"
            )
            assert validator_index.is_within_registry(Uint64(len(key_state.validators))), (
                f"Validator {validator_index} not found in state "
                f"{attestation_data.target.root.hex()}"
            )
            public_key = key_state.validators[validator_index].get_attestation_public_key()

            assert TARGET_SIGNATURE_SCHEME.verify(
                public_key, attestation_data.slot, hash_tree_root(attestation_data), signature
            ), "Signature verification failed"

            # Aggregators store all received gossip signatures.
            # The p2p layer only delivers attestations from subscribed subnets,
            # so subnet filtering happens at subscription time, not here.
            # Non-aggregator nodes validate and drop — they never store gossip signatures.
            if is_aggregator:
                store.attestation_signatures.setdefault(attestation_data, set()).add(
                    AttestationSignatureEntry(validator_index, signature)
                )

            return store

    def on_gossip_aggregated_attestation(
        self,
        store: LstarStore,
        signed_attestation: SignedAggregatedAttestation,
    ) -> LstarStore:
        """Process a signed aggregated attestation received via aggregation topic.

        This method:
        1. Verifies the aggregated attestation
        2. Stores the aggregation in aggregation_payloads map

        Raises:
            ValueError: If validator not found in state.
            AssertionError: If signature verification fails.
        """
        data = signed_attestation.data
        proof = signed_attestation.proof

        self.validate_attestation(store, data)

        # Get validator IDs who participated in this aggregation
        validator_indices = proof.participants.to_validator_indices()

        # Retrieve the relevant state to look up public keys for verification.
        key_state = store.states.get(data.target.root)
        assert key_state is not None, (
            f"No state available to verify committee aggregation for target "
            f"{data.target.root.hex()}"
        )

        # Ensure all participants exist in the active set
        validators = key_state.validators
        for validator_index in validator_indices:
            assert validator_index.is_within_registry(Uint64(len(validators))), (
                f"Validator {validator_index} not found in state {data.target.root.hex()}"
            )

        # Prepare public keys for verification
        public_keys = [
            validators[validator_index].get_attestation_public_key()
            for validator_index in validator_indices
        ]

        # Verify the single-message aggregate single-message aggregated proof.
        try:
            proof.verify(
                public_keys=public_keys,
                message=hash_tree_root(data),
                slot=data.slot,
            )
        except AggregationError as exception:
            raise AssertionError(
                f"Committee aggregation signature verification failed: {exception}"
            ) from exception

        store.latest_new_aggregated_payloads.setdefault(data, set()).add(proof)

        return store

    def on_block(
        self,
        store: LstarStore,
        signed_block: SignedBlock,
    ) -> LstarStore:
        """Process a new block and update the forkchoice state.

        This method integrates a block into the forkchoice store by:

        1. Validating the block's parent exists
        2. Computing the post-state via the state transition function
        3. Processing attestations included in the block body (on-chain)
        4. Updating the forkchoice head

        Raises:
            AssertionError: If parent block/state not found in store.
        """
        with observe_on_block():
            block = signed_block.block
            block_root = hash_tree_root(block)

            # Skip duplicate blocks (idempotent operation)
            if block_root in store.blocks:
                return store

            # Capture the finalized slot before any updates so we can decide
            # at the end whether finalization advanced and pruning is needed.
            previous_finalized_slot = store.latest_finalized.slot

            # Verify parent chain is available
            #
            # The parent state must exist before processing this block.
            # If missing, the node must sync the parent chain first.
            parent_state = store.states.get(block.parent_root)
            assert parent_state is not None, (
                f"Parent state not found (root={block.parent_root.hex()}). "
                f"Sync parent chain before processing block at slot {block.slot}."
            )

            # The block body constrains how many distinct AttestationData
            # entries it may carry.
            aggregated_attestations = block.body.attestations
            attestation_data_set = {attestation.data for attestation in aggregated_attestations}
            assert len(attestation_data_set) == len(aggregated_attestations), (
                "Block contains duplicate AttestationData entries; "
                "each AttestationData must appear at most once"
            )
            assert len(attestation_data_set) <= int(MAX_ATTESTATIONS_DATA), (
                f"Block contains {len(attestation_data_set)} distinct AttestationData entries; "
                f"maximum is {MAX_ATTESTATIONS_DATA}"
            )

            # Validate cryptographic signatures.
            #
            # This raises on any invalid signature, aborting the import.
            self.verify_signatures(signed_block, parent_state.validators)

            # Execute state transition function to compute post-block state
            post_state = self.state_transition(parent_state, block)

            # Propagate checkpoint advances from the post-state.
            #
            # A candidate replaces the store's checkpoint only when its slot is strictly higher.
            # On slot ties the store's view stays authoritative.
            #
            # Why: the store's checkpoint is pinned at init.
            # It advances only on real justification or finalization events.
            # An incoming tie must not silently swap roots.
            latest_justified = store.latest_justified.advance_to(post_state.latest_justified)
            latest_finalized = store.latest_finalized.advance_to(post_state.latest_finalized)

            store.blocks = store.blocks | {block_root: block}
            store.states = store.states | {block_root: post_state}
            store.latest_justified = latest_justified
            store.latest_finalized = latest_finalized

            # Register each block attestation's data in the known pool.
            #
            # Only the data key is recorded here, with an empty proof set.
            # The block carries one merged proof for all attestations.
            # That proof is verified as a whole and not decomposed at import.
            # Per-attestation proofs reach the pools through the
            # deconstruction and gossip path instead.
            #
            # Consequence: a block's own attestations contribute zero weight
            # to the head computation triggered by this import.
            # Recovered single-message aggregate proofs land in the new pool and migrate to
            # the known pool at the next acceptance tick.
            # Head weight from block-imported votes is therefore deferred
            # by up to one slot.
            for aggregated_attestation in aggregated_attestations:
                store.latest_known_aggregated_payloads.setdefault(
                    aggregated_attestation.data, set()
                )

            # Update forkchoice head based on new block and attestations.
            store = self.update_head(store)

            # Prune stale attestation data when finalization advances
            if store.latest_finalized.slot > previous_finalized_slot:
                store = self.prune_stale_attestation_data(store)

            return store

    def extract_attestations_from_aggregated_payloads(
        self,
        store: LstarStore,
        aggregated_payloads: dict[AttestationData, set[SingleMessageAggregate]],
    ) -> dict[ValidatorIndex, AttestationData]:
        """Extract attestations from aggregated payloads.

        Given a mapping of aggregated signature proofs, extract the attestation data
        for each validator that participated in the aggregation.
        """
        attestations: dict[ValidatorIndex, AttestationData] = {}

        for attestation_data, proofs in aggregated_payloads.items():
            for proof in proofs:
                for validator_index in proof.participants.to_validator_indices():
                    existing = attestations.get(validator_index)
                    if existing is None or existing.slot < attestation_data.slot:
                        attestations[validator_index] = attestation_data
        return attestations

    def _accumulate_ancestor_weights(
        self,
        store: LstarStore,
        attestations: dict[ValidatorIndex, AttestationData],
        start_slot: Slot,
    ) -> dict[Bytes32, int]:
        """Accumulate one unit of voting weight per ancestor of each head vote.

        For every vote, follow the chosen head upward through its ancestors.
        Each visited block above the start slot accumulates one unit of weight
        from that validator.

        Climbing stops at the start slot or as soon as the chain leaves the
        known tree, so partial views and ongoing sync are handled naturally.
        """
        weights: dict[Bytes32, int] = defaultdict(int)

        for attestation_data in attestations.values():
            current_root = attestation_data.head.root

            while current_root in store.blocks and store.blocks[current_root].slot > start_slot:
                weights[current_root] += 1
                current_root = store.blocks[current_root].parent_root

        return weights

    def compute_block_weights(self, store: LstarStore) -> dict[Bytes32, int]:
        """Compute attestation-based weight for each block above the finalized slot.

        Walks backward from each validator's latest head vote, incrementing weight
        for every ancestor above the finalized slot.
        """
        attestations = self.extract_attestations_from_aggregated_payloads(
            store, store.latest_known_aggregated_payloads
        )

        weights = self._accumulate_ancestor_weights(
            store, attestations, store.latest_finalized.slot
        )

        return dict(weights)

    def _compute_lmd_ghost_head(
        self,
        store: LstarStore,
        start_root: Bytes32,
        attestations: dict[ValidatorIndex, AttestationData],
        min_score: int = 0,
    ) -> Bytes32:
        """Walk the block tree according to the LMD GHOST rule.

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
        """
        # Invariant: the anchor must be a block the store already knows.
        # A loud failure here beats a cryptic missing-key error deep in the weight loop.
        assert start_root in store.blocks, f"start_root {start_root.hex()} not in store.blocks"

        # Remember the slot of the anchor once and reuse it during the walk.
        #
        # This avoids repeated lookups inside the inner loop.
        start_slot = store.blocks[start_root].slot

        # Collect voting weight for every block above the anchor slot.
        weights = self._accumulate_ancestor_weights(store, attestations, start_slot)

        # Build the parent -> children adjacency.
        #
        # Genesis blocks land in the bucket keyed by the zero hash.
        # That bucket is never consulted.
        # The walk anchors at the latest justified root and only descends.
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
            head = max(children, key=lambda x: (weights[x], x))

        return head

    def update_head(self, store: LstarStore) -> LstarStore:
        """Compute updated store with new canonical head.

        Selects the canonical chain head using:

        1. Latest justified checkpoint as the starting root
        2. LMD-GHOST fork choice rule (heaviest subtree by attestation weight)
        """
        # Extract attestations from known aggregated payloads
        attestations = self.extract_attestations_from_aggregated_payloads(
            store, store.latest_known_aggregated_payloads
        )

        # Run LMD-GHOST fork choice algorithm.
        #
        # Starts from the justified root and greedily descends to the heaviest
        # leaf. The result is always a descendant of the justified root by
        # construction: the walk only follows child edges within the subtree.
        store.head = self._compute_lmd_ghost_head(
            store,
            start_root=store.latest_justified.root,
            attestations=attestations,
        )
        return store

    def accept_new_attestations(self, store: LstarStore) -> LstarStore:
        """Process pending aggregated payloads and update forkchoice head.

        Moves aggregated payloads from latest_new_aggregated_payloads to
        latest_known_aggregated_payloads, making them eligible to contribute to
        fork choice weights. This migration happens at specific interval ticks.

        The Interval Tick System
        -------------------------
        Aggregated payloads progress through intervals:
        - Interval 0: Block proposal
        - Interval 1: Validators cast attestations (enter "new")
        - Interval 2: Aggregators create proofs & broadcast
        - Interval 3: Safe target update
        - Interval 4: Process accumulated attestations

        This staged progression ensures proper timing and prevents premature
        influence on fork choice decisions.
        """
        # Merge new aggregated payloads into known aggregated payloads
        for attestation_data, proofs in store.latest_new_aggregated_payloads.items():
            store.latest_known_aggregated_payloads.setdefault(attestation_data, set()).update(
                proofs
            )
        store.latest_new_aggregated_payloads = {}

        # Update head with newly accepted aggregated payloads
        return self.update_head(store)

    def update_safe_target(self, store: LstarStore) -> LstarStore:
        """Compute the deepest block that has 2/3+ supermajority attestation weight.

        The safe target is the furthest-from-genesis block where enough validators
        agree. Validators use it to decide which block is safe to attest to.
        Only blocks meeting the supermajority threshold qualify.

        This runs at interval 3 of the slot cycle:

        - Interval 0: Block proposal
        - Interval 1: Validators cast attestation votes
        - Interval 2: Aggregators create proofs, broadcast via gossip
        - Interval 3: Safe target update (HERE)
        - Interval 4: New attestations migrate to "known" pool

        Only the "new" pool counts. Migration into "known" runs at interval 4,
        after this step, so safe target sees only votes received this slot.

        Safe target is an *availability* signal, not durable knowledge:

        - A block is safe when 2/3 of currently online validators vote for a descendant.
        - "Known" carries block-included, previously migrated, and self-attestations.
        - Those reflect historical knowledge, not current liveness.
        - Counting them would advance safe target on stale evidence after a participation collapse.
        """
        # Look up the post-state of the current head block.
        #
        # The validator registry in this state tells us how many active
        # validators exist. We need that count to compute the threshold.
        head_state = store.states[store.head]
        num_validators = Uint64(len(head_state.validators))

        # Compute the 2/3 supermajority threshold.
        #
        # A block needs at least this many attestation votes to be "safe".
        # The threshold is rounded UP so a strict majority is required.
        # For example, 100 validators => threshold is 67, not 66.
        min_target_score = math.ceil(int(num_validators) * 2 / 3)

        # Unpack "new" payloads into a flat validator -> vote mapping.
        # "Known" is excluded by design.
        attestations = self.extract_attestations_from_aggregated_payloads(
            store,
            store.latest_new_aggregated_payloads,
        )

        # Run LMD GHOST with the supermajority threshold.
        #
        # The walk starts from the latest justified checkpoint and descends
        # through the block tree. At each fork, only children with at least
        # `min_target_score` attestation weight are considered. The result
        # is the deepest block that clears the 2/3 bar.
        #
        # If no child meets the threshold at some fork, the walk stops
        # early. The safe target is then shallower than the actual head.
        safe_target = self._compute_lmd_ghost_head(
            store,
            start_root=store.latest_justified.root,
            attestations=attestations,
            min_score=min_target_score,
        )

        # Return a new Store with only the safe target updated.
        #
        # The head and attestation pools remain unchanged.
        store.safe_target = safe_target
        return store
