"""
Fork choice test fixture format.

Tests fork choice scenarios through time-ordered events.
Validates Store responses to blocks, attestations, and time progression.
"""

from __future__ import annotations

from typing import ClassVar, Self

from pydantic import model_validator

from lean_spec.subspecs.chain.config import SECONDS_PER_SLOT
from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
)
from lean_spec.subspecs.containers.block import (
    Block,
    BlockBody,
    BlockSignatures,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import (
    AggregatedAttestations,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import SignatureKey
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.types import HashDigestList, HashTreeOpening, Randomness
from lean_spec.types import Bytes32, Uint64

from ..keys import LEAN_ENV_TO_SCHEMES, XmssKeyManager, get_shared_key_manager
from ..test_types import (
    AggregatedAttestationSpec,
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceStep,
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
                    max_slot_value = max(max_slot_value, step.attestation.message.slot)

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
        key_manager = get_shared_key_manager(max_slot=self.max_slot)

        # Validator pubkey synchronization
        #
        # Test states use placeholder pubkeys.
        # We must replace them with the key manager's actual keys.
        # Otherwise signature verification will fail.
        updated_validators = [
            validator.model_copy(
                update={"pubkey": key_manager[ValidatorIndex(i)].public.encode_bytes()}
            )
            for i, validator in enumerate(self.anchor_state.validators)
        ]

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
        store = Store.get_forkchoice_store(
            state=self.anchor_state,
            anchor_block=self.anchor_block,
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
                if isinstance(step, TickStep):
                    # Time advancement may trigger slot boundaries.
                    # At slot boundaries, pending attestations may become active.
                    store = store.on_tick(Uint64(step.time), has_proposal=False)

                elif isinstance(step, BlockStep):
                    # Build a complete signed block from the lightweight spec.
                    # The spec contains minimal fields; we fill the rest.
                    signed_block = self._build_block_from_spec(
                        step.block, store, self._block_registry, key_manager
                    )

                    # Store the filled Block for serialization
                    block = signed_block.message.block
                    step._filled_block = signed_block.message

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
                    block_time = store.config.genesis_time + block.slot * Uint64(SECONDS_PER_SLOT)
                    store = store.on_tick(block_time, has_proposal=True)

                    # Process the block through Store.
                    # This validates, applies state transition, and updates head.
                    store = store.on_block(signed_block, LEAN_ENV_TO_SCHEMES[self.lean_env])

                elif isinstance(step, AttestationStep):
                    # Process a gossip attestation.
                    # Gossip attestations arrive outside of blocks.
                    # They influence the fork choice weight calculation.
                    store = store.on_gossip_attestation(
                        step.attestation,
                        scheme=LEAN_ENV_TO_SCHEMES[self.lean_env],
                    )

                else:
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

                # Expected failure occurred. Continue to next step.
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
    ) -> SignedBlockWithAttestation:
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
        attestations, attestation_signatures = self._build_attestations_from_spec(
            spec, store, block_registry, parent_root, key_manager
        )

        # Merge new attestation signatures with existing gossip signatures.
        # These are needed for signature aggregation later.
        gossip_signatures = dict(store.gossip_signatures)
        gossip_signatures.update(attestation_signatures)

        # Collect attestations from the store if requested.
        #
        # Previous proposers' attestations become available for inclusion.
        # This makes test vectors more realistic.
        available_attestations: list[Attestation] | None = None
        known_block_roots: set[Bytes32] | None = None

        if spec.include_store_attestations:
            # Gather all attestations: both active and recently received.
            available_attestations = [
                Attestation(validator_id=vid, data=data)
                for vid, data in store.latest_known_attestations.items()
            ]
            available_attestations.extend(
                Attestation(validator_id=vid, data=data)
                for vid, data in store.latest_new_attestations.items()
            )
            known_block_roots = set(store.blocks.keys())

        # Build the block using spec logic
        #
        # State handles the core block construction.
        # This includes state transition and root computation.
        parent_state = store.states[parent_root]
        final_block, _, _, _ = parent_state.build_block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            attestations=attestations,
            available_attestations=available_attestations,
            known_block_roots=known_block_roots,
            gossip_signatures=gossip_signatures,
            aggregated_payloads=store.aggregated_payloads,
        )

        # Create proposer attestation
        #
        # The proposer must also attest to their own block.
        # This attestation commits to the block they just created.
        block_root = hash_tree_root(final_block)
        proposer_attestation = Attestation(
            validator_id=proposer_index,
            data=AttestationData(
                slot=spec.slot,
                head=Checkpoint(root=block_root, slot=spec.slot),
                target=Checkpoint(root=block_root, slot=spec.slot),
                source=Checkpoint(root=parent_root, slot=parent_state.latest_block_header.slot),
            ),
        )

        # Sign everything
        #
        # Aggregate signatures for all attestations in the block body.
        # Sign the proposer's attestation separately.
        attestation_signatures_blob = key_manager.build_attestation_signatures(
            final_block.body.attestations,
            attestation_signatures,
        )

        proposer_signature = key_manager.sign_attestation_data(
            proposer_attestation.validator_id,
            proposer_attestation.data,
        )

        # Assemble the signed block
        #
        # Combine block, proposer attestation, and all signatures.
        return SignedBlockWithAttestation(
            message=BlockWithAttestation(
                block=final_block,
                proposer_attestation=proposer_attestation,
            ),
            signature=BlockSignatures(
                attestation_signatures=attestation_signatures_blob,
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
    ) -> tuple[list[Attestation], dict[SignatureKey, Signature]]:
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
            Tuple of (attestations list, signature lookup dict).
        """
        # No attestations specified means empty block body.
        if spec.attestations is None:
            return [], {}

        parent_state = store.states[parent_root]
        attestations = []
        signature_lookup: dict[SignatureKey, Signature] = {}

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
                else:
                    # Dummy signature for testing invalid signature handling.
                    # The Store should reject attestations with bad signatures.
                    signature = Signature(
                        path=HashTreeOpening(siblings=HashDigestList(data=[])),
                        rho=Randomness(data=[Fp(0) for _ in range(Randomness.LENGTH)]),
                        hashes=HashDigestList(data=[]),
                    )

                # Index signature by validator and data root.
                # This enables lookup during signature aggregation.
                sig_key = SignatureKey(validator_id, attestation_data.data_root_bytes())
                signature_lookup[sig_key] = signature

        return attestations, signature_lookup

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
        # Resolve target from label.
        # The label references a block that will be the target checkpoint.
        if spec.target_root_label not in block_registry:
            raise ValueError(
                f"target_root_label '{spec.target_root_label}' not found - "
                f"available: {list(block_registry.keys())}"
            )

        target_root = hash_tree_root(block_registry[spec.target_root_label])
        target = Checkpoint(root=target_root, slot=spec.target_slot)

        # Build the attestation data.
        # In simplified tests, head equals target for convenience.
        # Source is the state's last justified checkpoint (Casper FFG link).
        return AttestationData(
            slot=spec.slot,
            head=target,
            target=target,
            source=state.latest_justified,
        )
