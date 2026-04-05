"""
Fork choice test fixture format.

Tests fork choice scenarios through time-ordered events.
Validates Store responses to blocks, attestations, and time progression.
"""

from __future__ import annotations

from typing import ClassVar, Self

from pydantic import model_validator

from lean_spec.subspecs.chain.clock import Interval
from lean_spec.subspecs.chain.config import (
    INTERVALS_PER_SLOT,
    MILLISECONDS_PER_INTERVAL,
)
from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
    SignedAttestation,
)
from lean_spec.subspecs.containers.attestation.aggregation_bits import AggregationBits
from lean_spec.subspecs.containers.attestation.attestation import (
    SignedAggregatedAttestation,
)
from lean_spec.subspecs.containers.block import (
    Block,
    BlockBody,
    BlockSignatures,
    SignedBlock,
)
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
    AttestationSignatures,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.types import ByteListMiB, Bytes32, Uint64

from ..keys import (
    LEAN_ENV_TO_SCHEMES,
    XmssKeyManager,
    create_dummy_signature,
)
from ..test_types import (
    AggregatedAttestationSpec,
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceStep,
    GossipAggregatedAttestationSpec,
    GossipAggregatedAttestationStep,
    GossipAttestationSpec,
    TickStep,
)
from .base import BaseConsensusFixture

DEFAULT_VALIDATOR_ID = ValidatorIndex(0)


class ForkChoiceTest(BaseConsensusFixture):
    """
    Test fixture for event-driven fork choice scenarios.

    Fork choice tests simulate a node processing events over time.
    The Store maintains all chain state needed to compute the head.

    Test structure:

    1. Initialize Store from anchor state and block
    2. Process steps in order (tick, block, attestation)
    3. Validate Store state against expected values

    Labels allow building forks.
    Give a block a label, then reference it as a parent in later blocks.
    """

    format_name: ClassVar[str] = "fork_choice_test"
    """Identifier used in fixture output paths and metadata."""

    description: ClassVar[str] = "Tests event-driven fork choice through Store operations"
    """Human-readable summary for fixture documentation."""

    anchor_state: State | None = None
    """
    Initial trusted consensus state.

    Most tests start from genesis.
    The pytest fixture provides this automatically.
    """

    anchor_block: Block | None = None
    """
    Initial trusted block (unsigned).

    Derived from anchor state if not provided.
    """

    steps: list[ForkChoiceStep]
    """
    Sequence of fork choice events to process.

    Events execute in order.
    Store state carries forward between steps.
    Each step can validate Store state via checks.
    """

    max_slot: Slot | None = None
    """
    Maximum slot for XMSS key validity.

    Calculated from steps if not provided.
    XMSS keys need precomputation up to this slot.
    """

    @model_validator(mode="after")
    def set_anchor_block_default(self) -> Self:
        """
        Auto-generate anchor block from anchor state if not provided.

        Most tests start from genesis.
        Deriving the anchor block from state reduces boilerplate.
        """
        if self.anchor_block is None and self.anchor_state is not None:
            # Build a minimal genesis block from the state's header fields.
            #
            # The state already contains the block header.
            # We extract its fields to create a matching Block.
            self.anchor_block = Block(
                slot=self.anchor_state.latest_block_header.slot,
                proposer_index=self.anchor_state.latest_block_header.proposer_index,
                parent_root=self.anchor_state.latest_block_header.parent_root,
                state_root=hash_tree_root(self.anchor_state),
                body=BlockBody(attestations=AggregatedAttestations(data=[])),
            )
        return self

    @model_validator(mode="after")
    def set_max_slot_default(self) -> Self:
        """
        Auto-calculate max slot from steps if not provided.

        XMSS keys require precomputation.
        We scan steps to find the highest slot needed.
        """
        if self.max_slot is None:
            max_slot_value = Slot(0)

            # Find the maximum slot across all block and attestation steps.
            #
            # XMSS signatures are slot-dependent.
            # Keys must be generated up to this slot before signing.
            for step in self.steps:
                if isinstance(step, BlockStep):
                    max_slot_value = max(max_slot_value, step.block.slot)
                elif isinstance(step, AttestationStep):
                    max_slot_value = max(max_slot_value, step.attestation.slot)
                elif isinstance(step, GossipAggregatedAttestationStep):
                    max_slot_value = max(max_slot_value, step.attestation.slot)

            self.max_slot = max_slot_value

        return self

    def make_fixture(self) -> Self:
        """
        Generate the fixture by running the spec's Store.

        Executes the test against the actual specification:

        1. Initialize Store from anchor state and block
        2. Process each step through Store
        3. Validate check assertions

        Returns:
            The validated fixture (self, since steps contain the test).

        Raises:
            AssertionError: If any step fails unexpectedly or checks mismatch.
        """
        # Precondition validation
        #
        # Pydantic validators should have populated these fields.
        # These assertions guard against misuse.
        assert self.anchor_state is not None, "anchor state must be set before making fixture"
        assert self.anchor_block is not None, "anchor block must be set before making fixture"
        assert self.max_slot is not None, "max slot must be set before making fixture"

        # Key manager setup
        #
        # XMSS keys are expensive to generate.
        # The shared key manager caches keys across tests.
        # Tests requiring higher max slot trigger key expansion.
        key_manager = XmssKeyManager.shared(max_slot=self.max_slot)

        # Validator pubkey synchronization
        #
        # Test states use placeholder pubkeys.
        # We must replace them with the key manager's actual keys.
        # Otherwise signature verification will fail.
        updated_validators = []
        for i, validator in enumerate(self.anchor_state.validators):
            idx = ValidatorIndex(i)
            attestation_pubkey, proposal_pubkey = key_manager.get_public_keys(idx)
            validator = validator.model_copy(
                update={
                    "attestation_pubkey": attestation_pubkey.encode_bytes(),
                    "proposal_pubkey": proposal_pubkey.encode_bytes(),
                }
            )
            updated_validators.append(validator)

        # Updating validators changes the state root.
        # We must also update the anchor block to match.
        self.anchor_state = self.anchor_state.model_copy(
            update={"validators": Validators(data=updated_validators)}
        )
        self.anchor_block = self.anchor_block.model_copy(
            update={"state_root": hash_tree_root(self.anchor_state)}
        )

        # Store initialization
        #
        # The Store is the node's local view of the chain.
        # It starts from a trusted anchor (usually genesis).
        store = Store.from_anchor(
            self.anchor_state,
            self.anchor_block,
            validator_id=DEFAULT_VALIDATOR_ID,
        )

        # Block registry for fork creation
        #
        # Labels let tests reference blocks by name.
        # This enables building forks: "build block B with parent A".
        # The "genesis" label is always available.
        self._block_registry: dict[str, Block] = {"genesis": self.anchor_block}

        # Step processing loop
        #
        # Process each step against the Store.
        # Store follows immutable pattern: each method returns a new Store.
        for i, step in enumerate(self.steps):
            try:
                match step:
                    case TickStep():
                        # Time advancement may trigger slot boundaries.
                        # At slot boundaries, pending attestations may become active.
                        # Always act as aggregator to ensure gossip signatures are aggregated
                        #
                        # TickStep.time is a Unix timestamp in seconds.
                        # Convert to intervals since genesis for the store.
                        delta_ms = (Uint64(step.time) - store.config.genesis_time) * Uint64(1000)
                        target_interval = Interval(delta_ms // MILLISECONDS_PER_INTERVAL)
                        store, _ = store.on_tick(
                            target_interval, has_proposal=False, is_aggregator=True
                        )

                    case BlockStep():
                        # Build a complete signed block from the lightweight spec.
                        # The spec contains minimal fields; we fill the rest.
                        signed_block = self._build_block_from_spec(
                            step.block, store, self._block_registry, key_manager
                        )

                        # Store the filled block for serialization.
                        block = signed_block.block
                        step._filled_block = block

                        # Register labeled blocks for fork building.
                        # Later blocks can reference this one as their parent.
                        if step.block.label is not None:
                            if step.block.label in self._block_registry:
                                raise ValueError(
                                    f"Step {i}: duplicate label '{step.block.label}' - "
                                    f"labels must be unique within a test"
                                )
                            self._block_registry[step.block.label] = block

                        # Advance time to the block's slot.
                        # Store rejects blocks from the future.
                        # This tick includes a block (has proposal).
                        # Always act as aggregator to ensure gossip signatures are aggregated
                        target_interval = Interval(block.slot * INTERVALS_PER_SLOT)
                        store, _ = store.on_tick(
                            target_interval, has_proposal=True, is_aggregator=True
                        )

                        # Process the block through Store.
                        # This validates, applies state transition, and updates the store's head.
                        store = store.on_block(
                            signed_block,
                            scheme=LEAN_ENV_TO_SCHEMES[self.lean_env],
                        )

                    case AttestationStep():
                        # Process a gossip attestation.
                        # Gossip attestations arrive outside of blocks.
                        # They influence the fork choice weight calculation.
                        signed_attestation = self._build_signed_attestation_from_spec(
                            step.attestation,
                            self._block_registry,
                            key_manager,
                            store,
                            step.valid,
                        )
                        step._filled_attestation = signed_attestation
                        store = store.on_gossip_attestation(
                            signed_attestation,
                            scheme=LEAN_ENV_TO_SCHEMES[self.lean_env],
                        )

                    case GossipAggregatedAttestationStep():
                        signed_aggregated = self._build_signed_aggregated_attestation_from_spec(
                            step.attestation,
                            store,
                            self._block_registry,
                            key_manager,
                        )
                        step._filled_attestation = signed_aggregated
                        store = store.on_gossip_aggregated_attestation(signed_aggregated)

                    case _:
                        raise ValueError(f"Step {i}: unknown step type {type(step).__name__}")

                # Validate Store state if checks are provided.
                # Labels in checks are resolved to actual block roots.
                if step.checks is not None:
                    step.checks.fill_hash_from_label(self._block_registry)
                    # Pass filled_block for BlockStep to enable block body attestation checks
                    filled_block = step._filled_block if isinstance(step, BlockStep) else None
                    step.checks.validate_against_store(
                        store,
                        step_index=i,
                        block_registry=self._block_registry,
                        filled_block=filled_block,
                    )

            except Exception as e:
                # Handle expected failures.
                # Steps marked valid=False should raise exceptions.
                if step.valid:
                    raise AssertionError(
                        f"Step {i} ({type(step).__name__}) failed unexpectedly: {e}"
                    ) from e

                # Verify the failure reason matches when specified.
                if step.expected_error is not None and step.expected_error not in str(e):
                    raise AssertionError(
                        f"Step {i} ({type(step).__name__}) failed with wrong error.\n"
                        f"  Expected error containing: {step.expected_error!r}\n"
                        f"  Actual error: {e!r}"
                    ) from e

                continue

            # Handle unexpected success.
            # If we expected failure but the step succeeded, that's a test bug.
            if not step.valid:
                raise AssertionError(
                    f"Step {i} ({type(step).__name__}) succeeded but expected failure"
                )

        # Return self (fixture is already complete)
        return self

    def _build_block_from_spec(
        self,
        spec: BlockSpec,
        store: Store,
        block_registry: dict[str, Block],
        key_manager: XmssKeyManager,
    ) -> SignedBlock:
        """
        Build a complete signed block from a lightweight specification.

        BlockSpec contains minimal fields (slot, parent label, attestations).
        This method fills in all remaining fields and signatures.

        The process:

        1. Resolve parent (from label or default to head)
        2. Build attestations from spec
        3. Delegate to State for core block construction
        4. Add proposer attestation and signatures

        Args:
            spec: Lightweight block specification.
            store: Fork choice store for head state lookup.
            block_registry: Labeled blocks for fork creation.
            key_manager: Key manager for signing.

        Returns:
            Complete signed block ready for Store processing.
        """
        # Determine the proposer
        #
        # If not specified, use round-robin based on slot.
        # Real proposer selection is more complex, but this suffices for tests.
        proposer_index = spec.proposer_index or ValidatorIndex(
            int(spec.slot) % len(store.states[store.head].validators)
        )

        # Resolve parent block
        #
        # Parent can be specified by label (for forks) or defaults to head.
        # This is how tests build competing chain branches.
        parent_root = self._resolve_parent_root(spec, store, block_registry)

        # Build attestations
        #
        # Attestations vote for blocks and influence fork choice weight.
        # The spec may include attestations to include in this block.
        (
            attestations,
            attestation_signatures,
            valid_attestations,
        ) = self._build_attestations_from_spec(
            spec, store, block_registry, parent_root, key_manager
        )

        # Merge valid attestation signatures into the Store's gossip cache.
        # Only attestations with valid (non-dummy) signatures are merged.
        working_store = store
        for attestation in valid_attestations:
            sigs_for_data = attestation_signatures.get(attestation.data)
            if (
                sigs_for_data is None
                or (signature := sigs_for_data.get(attestation.validator_id)) is None
            ):
                continue
            working_store = working_store.on_gossip_attestation(
                SignedAttestation(
                    validator_id=attestation.validator_id,
                    data=attestation.data,
                    signature=signature,
                ),
                scheme=LEAN_ENV_TO_SCHEMES[self.lean_env],
                is_aggregator=True,
            )

        # Aggregate gossip signatures and merge into known payloads.
        # This makes recently gossiped attestations available for block construction.
        aggregation_store, _ = working_store.aggregate()
        merged_store = aggregation_store.accept_new_attestations()

        # Build the block using the same path as regular proposal.
        #
        # block_payloads contains explicit spec attestations only.
        parent_state = store.states[parent_root]
        final_block, post_state, _, block_proofs = parent_state.build_block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots=set(store.blocks.keys()),
            aggregated_payloads=merged_store.latest_known_aggregated_payloads,
        )

        proposer_signature = key_manager.sign_block_root(
            proposer_index,
            spec.slot,
            hash_tree_root(final_block),
        )

        # Assemble the signed block.
        return SignedBlock(
            block=final_block,
            signature=BlockSignatures(
                attestation_signatures=AttestationSignatures(data=block_proofs),
                proposer_signature=proposer_signature,
            ),
        )

    def _resolve_parent_root(
        self,
        spec: BlockSpec,
        store: Store,
        block_registry: dict[str, Block],
    ) -> Bytes32:
        """
        Resolve parent root from block specification.

        Two resolution modes:

        - Label provided: Look up block by label (for building forks)
        - No label: Use current head (for extending canonical chain)

        Args:
            spec: Block specification with optional parent_label.
            store: Fork choice store containing block states.
            block_registry: Map of labels to blocks.

        Returns:
            Root hash of the parent block.

        Raises:
            ValueError: If label not found or parent state unavailable.
        """
        # Fast path: no label means build on current head.
        if not (label := spec.parent_label):
            return store.head

        # Label was provided: look up the block in the registry.
        if not (parent_block := block_registry.get(label)):
            raise ValueError(f"Parent label '{label}' not found. Available: {list(block_registry)}")

        # Compute the SSZ root of the parent block.
        #
        # This root serves as both:
        # - The key to look up the parent's post-state in the store
        # - The value to place in the new block's `parent_root` field
        parent_root = hash_tree_root(parent_block)

        # Verify the parent's state exists in the store.
        #
        # Building a block requires the parent's post-state to:
        # - Advance slots via `process_slots()`
        # - Apply the new block via `process_block()`
        #
        # If the state is missing, we cannot proceed.
        if parent_root not in store.states:
            raise ValueError(
                f"Parent '{label}' (root=0x{parent_root.hex()[:16]}...) "
                "has no state in store - cannot build on this fork"
            )

        return parent_root

    def _build_attestations_from_spec(
        self,
        spec: BlockSpec,
        store: Store,
        block_registry: dict[str, Block],
        parent_root: Bytes32,
        key_manager: XmssKeyManager,
    ) -> tuple[
        list[Attestation],
        dict[AttestationData, dict[ValidatorIndex, Signature]],
        set[Attestation],
    ]:
        """
        Build attestations and signatures from block specification.

        Each AggregatedAttestationSpec produces multiple attestations.
        All validators in a spec share the same attestation data.
        Signatures are collected for later aggregation.

        Args:
            spec: Block specification with attestation specs.
            store: Fork choice store for state lookup.
            block_registry: Labeled blocks for target resolution.
            parent_root: Root of the parent block.
            key_manager: Key manager for signing.

        Returns:
            Tuple of (attestations list, signature lookup by data, valid attestations).
        """
        # No attestations specified means empty block body.
        if spec.attestations is None:
            return [], {}, set()

        parent_state = store.states[parent_root]
        attestations = []
        signature_lookup: dict[AttestationData, dict[ValidatorIndex, Signature]] = {}
        valid_attestations: set[Attestation] = set()

        for aggregated_spec in spec.attestations:
            # Build attestation data once.
            # All validators in this aggregation vote for the same target.
            attestation_data = self._build_attestation_data_from_spec(
                aggregated_spec, block_registry, parent_state
            )

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
                    # Dummy signature for testing invalid signature handling.
                    # The Store should reject attestations with bad signatures.
                    signature = create_dummy_signature()

                # Index signature by attestation data and validator ID.
                signature_lookup.setdefault(attestation_data, {}).setdefault(
                    validator_id,
                    signature,
                )

        return attestations, signature_lookup, valid_attestations

    def _resolve_checkpoint(
        self,
        label: str,
        slot_override: Slot | None,
        block_registry: dict[str, Block],
    ) -> Checkpoint:
        """
        Resolve a block label and optional slot override into a Checkpoint.

        Args:
            label: Block label in the registry.
            slot_override: When set, overrides the block's actual slot.
            block_registry: Labeled blocks for lookup.

        Returns:
            Checkpoint with the block's root and resolved slot.

        Raises:
            ValueError: If label not found in registry.
        """
        if (block := block_registry.get(label)) is None:
            raise ValueError(
                f"label '{label}' not found - available: {list(block_registry.keys())}"
            )
        return Checkpoint(
            root=hash_tree_root(block),
            slot=block.slot if slot_override is None else slot_override,
        )

    def _build_attestation_data_from_spec(
        self,
        spec: AggregatedAttestationSpec,
        block_registry: dict[str, Block],
        state: State,
    ) -> AttestationData:
        """
        Build attestation data from a specification.

        Attestation data contains the validator's vote:

        - slot: When the attestation was made
        - head: What block the validator sees as head
        - target: Checkpoint being voted for (epoch boundary)
        - source: Previously justified checkpoint (link source)

        Target is resolved from label.
        Source comes from the parent state's justified checkpoint.

        Args:
            spec: Aggregated attestation specification.
            block_registry: Labeled blocks for target resolution.
            state: State for source checkpoint lookup.

        Returns:
            Attestation data shared by all validators in the aggregation.

        Raises:
            ValueError: If target label not found in registry.
        """
        target = self._resolve_checkpoint(spec.target_root_label, spec.target_slot, block_registry)

        # In simplified tests, head equals target for convenience.
        #
        # Source is the state's last justified checkpoint (Casper FFG link).
        return AttestationData(
            slot=spec.slot,
            head=target,
            target=target,
            source=state.latest_justified,
        )

    def _build_signed_attestation_from_spec(
        self,
        spec: GossipAttestationSpec,
        block_registry: dict[str, Block],
        key_manager: XmssKeyManager,
        store: Store,
        expected_valid: bool,
    ) -> SignedAttestation:
        """
        Build a signed attestation from a gossip attestation specification.

        Two paths:

        - Valid with no overrides: delegates to the spec's own attestation data
          production. This ensures valid test vectors match what an honest validator
          would produce.
        - Invalid or with overrides: manually constructs checkpoints to create
          specific non-standard attestations for validation testing.

        Args:
            spec: Gossip attestation specification.
            block_registry: Labeled blocks for target resolution.
            key_manager: XMSS key manager for signing.
            store: Fork choice store for spec-based attestation data production.
            expected_valid: Whether the step expects this attestation to succeed.

        Returns:
            Signed attestation ready for gossip processing.

        Raises:
            ValueError: If target label not found in registry.
        """
        has_overrides = (
            spec.head_root_label is not None
            or spec.head_slot is not None
            or spec.source_root_label is not None
            or spec.source_slot is not None
            or spec.target_root_override is not None
            or spec.head_root_override is not None
            or spec.source_root_override is not None
        )

        if not expected_valid or has_overrides:
            attestation_data = self._build_overridden_attestation_data(spec, block_registry)
        else:
            # Reuse the spec for honest attestations.
            attestation_data = store.produce_attestation_data(spec.slot)

        signature = (
            key_manager.sign_attestation_data(spec.validator_id, attestation_data)
            if spec.valid_signature
            else create_dummy_signature()
        )

        return SignedAttestation(
            validator_id=spec.validator_id,
            data=attestation_data,
            signature=signature,
        )

    def _build_overridden_attestation_data(
        self,
        spec: GossipAttestationSpec,
        block_registry: dict[str, Block],
    ) -> AttestationData:
        """
        Build attestation data with explicit checkpoint overrides.

        Used for invalid or non-standard attestations where the test
        intentionally creates mismatches for validation testing.

        Args:
            spec: Gossip attestation specification with override fields.
            block_registry: Labeled blocks for target resolution.

        Returns:
            Attestation data with overridden checkpoints.
        """
        target = self._resolve_checkpoint(spec.target_root_label, spec.target_slot, block_registry)

        # Resolve head checkpoint.
        # Defaults to the target checkpoint when not overridden.
        if spec.head_root_label is not None:
            head = self._resolve_checkpoint(spec.head_root_label, spec.head_slot, block_registry)
        else:
            head = Checkpoint(
                root=target.root,
                slot=target.slot if spec.head_slot is None else spec.head_slot,
            )

        # Resolve source checkpoint.
        #
        # Defaults to the anchor (genesis) block when not overridden.
        assert self.anchor_block is not None, "anchor_block must be set before building attestation"
        if spec.source_root_label is not None:
            source = self._resolve_checkpoint(
                spec.source_root_label, spec.source_slot, block_registry
            )
        else:
            source = Checkpoint(
                root=hash_tree_root(self.anchor_block),
                slot=self.anchor_block.slot if spec.source_slot is None else spec.source_slot,
            )

        # Apply raw root overrides.
        # These inject roots not in the store for testing unknown block rejection.
        if spec.target_root_override is not None:
            target = Checkpoint(root=spec.target_root_override, slot=target.slot)
        if spec.head_root_override is not None:
            head = Checkpoint(root=spec.head_root_override, slot=head.slot)
        if spec.source_root_override is not None:
            source = Checkpoint(root=spec.source_root_override, slot=source.slot)

        return AttestationData(
            slot=spec.slot,
            head=head,
            target=target,
            source=source,
        )

    def _build_attestation_data_from_gossip_aggregated_spec(
        self,
        spec: GossipAggregatedAttestationSpec,
        block_registry: dict[str, Block],
        state: State,
    ) -> AttestationData:
        """
        Build attestation data for a gossip aggregated attestation.

        Resolves the three checkpoints (target, head, source) from the spec.

        The state provides fallback values for the source checkpoint
        when neither an explicit root nor a label is specified.

        Args:
            spec: Aggregated attestation specification with checkpoint overrides.
            block_registry: Labeled blocks for checkpoint resolution.
            state: Head state providing the latest justified checkpoint as source fallback.

        Returns:
            Attestation data with all three checkpoints resolved.

        Raises:
            ValueError: If the target has neither an explicit root nor
                a label.
        """
        # Resolve the target checkpoint.
        #
        # An explicit root takes highest priority.
        # A label triggers lookup in the block registry.
        # Unlike the other two checkpoints, the target is mandatory.
        if spec.target_root is not None:
            target = Checkpoint(root=spec.target_root, slot=spec.target_slot)
        elif spec.target_root_label is not None:
            target = self._resolve_checkpoint(
                spec.target_root_label, spec.target_slot, block_registry
            )
        else:
            raise ValueError("gossip aggregated attestation spec requires a target root")

        # Resolve the head checkpoint.
        #
        # Priority: explicit root > label > target checkpoint.
        # - When using an explicit root without a slot, the target slot is used.
        # - When no head information is provided at all, the head mirrors the target.
        #
        # This matches honest validator behavior.
        if spec.head_root is not None:
            head = Checkpoint(
                root=spec.head_root,
                slot=spec.head_slot if spec.head_slot is not None else spec.target_slot,
            )
        elif spec.head_root_label is not None:
            head = self._resolve_checkpoint(spec.head_root_label, spec.head_slot, block_registry)
        else:
            head = Checkpoint(
                root=target.root,
                slot=spec.head_slot if spec.head_slot is not None else target.slot,
            )

        # Resolve the source checkpoint.
        #
        # Priority: explicit root > label > latest justified from state.
        # The source represents the most recent justified checkpoint the attester is aware of.
        # When not overridden, the state's latest justified checkpoint provides the correct default.
        if spec.source_root is not None:
            source = Checkpoint(
                root=spec.source_root,
                slot=(
                    spec.source_slot
                    if spec.source_slot is not None
                    else state.latest_justified.slot
                ),
            )
        elif spec.source_root_label is not None:
            source = self._resolve_checkpoint(
                spec.source_root_label, spec.source_slot, block_registry
            )
        else:
            source = Checkpoint(
                root=state.latest_justified.root,
                slot=(
                    spec.source_slot
                    if spec.source_slot is not None
                    else state.latest_justified.slot
                ),
            )

        # Assemble the final attestation data from resolved checkpoints.
        return AttestationData(
            slot=spec.slot,
            head=head,
            target=target,
            source=source,
        )

    def _build_signed_aggregated_attestation_from_spec(
        self,
        spec: GossipAggregatedAttestationSpec,
        store: Store,
        block_registry: dict[str, Block],
        key_manager: XmssKeyManager,
    ) -> SignedAggregatedAttestation:
        """
        Build a signed aggregated attestation from a gossip specification.

        Args:
            spec: Aggregated attestation specification with participant and checkpoint
                configuration.
            store: Fork choice store providing head state for checkpoint resolution.
            block_registry: Labeled blocks for checkpoint resolution.
            key_manager: XMSS key manager for signing attestation data.

        Returns:
            Signed aggregated attestation ready for gossip processing.
        """
        # Resolve checkpoints into concrete attestation data.
        attestation_data = self._build_attestation_data_from_gossip_aggregated_spec(
            spec,
            block_registry,
            store.states[store.head],
        )

        # Separate "claimed" from "actual" participants.
        #
        # - Claimed validators appear in the proof's participant bitfield.
        # - Actual signers produce the cryptographic material.
        # They default to the same set for honest attestations.
        validator_ids = spec.validator_ids
        signer_ids = spec.signer_ids or spec.validator_ids

        # Path 1: Invalid signature.
        #
        # Build a proof with the correct participant bitfield but zeroed-out proof bytes.
        # This exercises signature verification rejection.
        if not spec.valid_signature:
            proof = AggregatedSignatureProof(
                participants=AggregationBits.from_validator_indices(
                    ValidatorIndices(data=validator_ids)
                ),
                proof_data=ByteListMiB(data=b"\x00" * 32),
            )
            return SignedAggregatedAttestation(data=attestation_data, proof=proof)

        # Path 2: Valid signature.
        #
        # Collect each signer's public key and individual signature over the attestation data.
        # These feed into the aggregation step.
        raw_xmss = [
            (
                key_manager.get_public_keys(vid)[0],
                key_manager.sign_attestation_data(vid, attestation_data),
            )
            for vid in signer_ids
        ]

        # Encode which validators actually produced signatures.
        xmss_participants = AggregationBits.from_validator_indices(
            ValidatorIndices(data=signer_ids)
        )

        # Aggregate individual signatures into a single proof.
        #
        # The proof combines all signer contributions so the verifier
        # can check them in one pass against the attestation data root.
        proof = AggregatedSignatureProof.aggregate(
            xmss_participants=xmss_participants,
            children=[],
            raw_xmss=raw_xmss,
            message=attestation_data.data_root_bytes(),
            slot=attestation_data.slot,
        )

        # Path 3: Participant mismatch.
        #
        # Replace the participant bitfield with different validator indices
        # while keeping the original proof bytes intact.
        # The proof is cryptographically valid for the actual signers,
        # but the claimed participants no longer match.
        # The store must detect and reject this inconsistency.
        if spec.signer_ids and spec.signer_ids != spec.validator_ids:
            proof = AggregatedSignatureProof(
                participants=AggregationBits.from_validator_indices(
                    ValidatorIndices(data=validator_ids)
                ),
                proof_data=proof.proof_data,
            )

        return SignedAggregatedAttestation(data=attestation_data, proof=proof)
