"""State transition test fixture format."""

from typing import Any, ClassVar, List

from pydantic import ConfigDict, PrivateAttr, field_serializer

from lean_spec.subspecs.containers.attestation import AttestationData
from lean_spec.subspecs.containers.attestation.aggregation_bits import AggregationBits
from lean_spec.subspecs.containers.block.block import Block, BlockBody
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.containers.validator import ValidatorIndex, ValidatorIndices
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.subspecs.xmss.aggregation import AggregatedSignatureProof
from lean_spec.types import Bytes32

from ..keys import XmssKeyManager
from ..test_types import AggregatedAttestationSpec, BlockSpec, StateExpectation
from .base import BaseConsensusFixture


class StateTransitionTest(BaseConsensusFixture):
    """
    Test fixture for block processing through state_transition().

    This is the primary test type that covers:
    - Operations (attestations via blocks)
    - Slot advancement (empty slots)
    - Multi-block sequences
    - Justification and finalization
    - Invalid blocks

    Tests everything through the main state_transition() public API.

    Structure:
        pre: Initial consensus state
        blocks: Sequence of signed blocks to process
        post: Expected state after processing (None if invalid, filled by spec)
        expect_exception: Expected exception for invalid tests
    """

    format_name: ClassVar[str] = "state_transition_test"
    description: ClassVar[str] = (
        "Tests block processing through state_transition() - covers operations, "
        "epochs, and finality"
    )

    model_config = ConfigDict(arbitrary_types_allowed=True)

    pre: State
    """The initial consensus state before processing."""

    blocks: List[BlockSpec]
    """
    Block specifications to process through the spec.

    Tests provide a list of BlockSpec objects with required slots and optional
    field overrides. The framework fills complete Block objects during
    make_fixture() and stores them in the private _filled_blocks attribute.
    """

    # TODO: We should figure out a configuration to raise if a private attr is
    #  attempted to be set during model initialization.
    _filled_blocks: List[Block] = PrivateAttr(default_factory=list)
    """
    The filled Blocks, processed through the specs.

    This is a private attribute not part of the model schema.

    Tests cannot set this.

    The framework populates it during make_fixture().
    """

    post: StateExpectation | None = None
    """
    Expected state after processing all blocks.

    Only fields explicitly set in the StateExpectation will be validated.
    If None, no post-state validation is performed (e.g., for invalid tests).
    """

    expect_exception: type[Exception] | None = None
    """Expected exception type for invalid tests."""

    expect_exception_message: str | None = None
    """Expected exception message for invalid tests."""

    @field_serializer("blocks", when_used="json")
    def serialize_blocks(self, value: List[BlockSpec]) -> List[dict[str, Any]]:
        """
        Serialize the filled `Block`s instead of the `BlockSpec`s.

        This ensures the fixture output contains the complete `Blocks` that were
        filled from the specs, not the input `BlockSpec`s.

        Parameters:
        ----------
        value : List[BlockSpec]
            The BlockSpec list (ignored, we use _filled_blocks instead).

        Returns:
        -------
        List[dict[str, Any]]
            The serialized Blocks.
        """
        del value
        return [block.to_json() for block in self._filled_blocks]

    @field_serializer("expect_exception", when_used="json")
    def serialize_exception(self, value: type[Exception] | None) -> str | None:
        """Serialize exception type to string."""
        if value is None:
            return None
        # Format: "ExceptionClassName" (just the class name for now)
        # TODO: This can be used to map exceptions to expected exceptions from clients
        #  as in execution-spec-tests - e.g., "StateTransitionException.INVALID_SLOT"
        return value.__name__

    def make_fixture(self) -> "StateTransitionTest":
        """
        Generate the fixture by running the spec.

        Builds blocks from BlockSpec if needed, then processes them through state_transition.

        Returns:
        -------
        StateTransitionTest
            A validated fixture.

        Raises:
        ------
        AssertionError
            If processing fails unexpectedly or validation fails.
        """
        actual_post_state: State | None = None
        exception_raised: Exception | None = None

        # Initialize filled_blocks list that will be populated as we process blocks
        filled_blocks: list[Block] = []
        block_registry: dict[str, Block] = {}
        try:
            state = self.pre

            for block_spec in self.blocks:
                # Build block and optionally get cached post-state to avoid redundant transitions
                block, cached_state = self._build_block_from_spec(block_spec, state, block_registry)

                # Store the filled Block for serialization
                filled_blocks.append(block)

                # Register labeled blocks for parent and attestation target resolution
                if block_spec.label is not None:
                    if block_spec.label in block_registry:
                        raise ValueError(
                            f"Duplicate label '{block_spec.label}' - "
                            f"labels must be unique within a test"
                        )
                    block_registry[block_spec.label] = block

                # Use cached state if available, otherwise run state transition
                if cached_state is not None:
                    state = cached_state
                elif getattr(block_spec, "skip_slot_processing", False):
                    state = state.process_block(block)
                else:
                    state = state.state_transition(
                        block=block,
                        valid_signatures=True,
                    )

            actual_post_state = state
        except (AssertionError, ValueError) as e:
            exception_raised = e
            # If we expect an exception, this is fine
            if self.expect_exception is None:
                # Unexpected failure
                raise AssertionError(f"Unexpected error processing blocks: {e}") from e
        finally:
            # Always store filled blocks for serialization, even if an exception occurred
            # This ensures the test fixture includes all blocks that were attempted
            self._filled_blocks = filled_blocks

        # Validate exception expectations
        if self.expect_exception is not None:
            if exception_raised is None:
                raise AssertionError(
                    f"Expected exception {self.expect_exception.__name__} but processing succeeded"
                )
            if not isinstance(exception_raised, self.expect_exception):
                raise AssertionError(
                    f"Expected {self.expect_exception.__name__} "
                    f"but got {type(exception_raised).__name__}: {exception_raised}"
                )
            if self.expect_exception_message is not None:
                if str(exception_raised) != self.expect_exception_message:
                    raise AssertionError(
                        f"Expected exception message '{self.expect_exception_message}' "
                        f"but got '{exception_raised}'"
                    )

        # Validate post-state expectations if provided
        if self.post is not None and actual_post_state is not None:
            self.post.validate_against_state(actual_post_state)

        # Return self (fixture is already complete)
        return self

    def _build_block_from_spec(
        self,
        spec: BlockSpec,
        state: State,
        block_registry: dict[str, Block],
    ) -> tuple[Block, State | None]:
        """
        Build a Block from a BlockSpec, optionally caching the post-state.

        Returns both the block and the cached post-state (if computed) to avoid
        redundant state transitions.

        Parameters
        ----------
        spec : BlockSpec
            Block specification with optional field overrides.
        state : State
            Current state to build against.
        block_registry : dict[str, Block]
            Map of labels to previously built blocks, used to resolve
            parent_label and attestation target roots.

        Returns:
        -------
        tuple[Block, State | None]
            Block and cached post-state (None if not computed).
        """
        # Use provided proposer index or compute it
        proposer_index = spec.proposer_index or ValidatorIndex(
            int(spec.slot) % len(state.validators)
        )

        temp_state: State | None = None
        if not spec.skip_slot_processing:
            temp_state = state.process_slots(spec.slot)

        # Use provided parent root, resolve from label, or compute from state
        if spec.parent_root is not None:
            parent_root = spec.parent_root
        elif spec.parent_label is not None:
            if spec.parent_label not in block_registry:
                raise ValueError(
                    f"parent_label '{spec.parent_label}' not found - "
                    f"available: {list(block_registry.keys())}"
                )
            parent_root = hash_tree_root(block_registry[spec.parent_label])
        else:
            source_state = temp_state or state
            parent_root = hash_tree_root(source_state.latest_block_header)

        # Extract attestations from body if provided
        aggregated_attestations = (
            spec.body.attestations if spec.body else AggregatedAttestations(data=[])
        )

        # Handle explicit state root override
        if spec.state_root is not None:
            block = Block(
                slot=spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                state_root=spec.state_root,
                body=spec.body or BlockBody(attestations=aggregated_attestations),
            )
            return block, None

        # For invalid tests, return incomplete block without processing
        if self.expect_exception is not None or spec.skip_slot_processing:
            return Block(
                slot=spec.slot,
                proposer_index=proposer_index,
                parent_root=parent_root,
                state_root=Bytes32.zero(),
                body=spec.body or BlockBody(attestations=aggregated_attestations),
            ), None

        # Build aggregated payloads from spec.attestations if provided
        aggregated_payloads: dict[AttestationData, set[AggregatedSignatureProof]] = {}
        if spec.attestations:
            aggregated_payloads = self._build_aggregated_payloads_from_spec(
                spec.attestations, state, block_registry
            )

        # Collect known block roots for attestation validation in build_block
        known_block_roots = frozenset(hash_tree_root(block) for block in block_registry.values())

        block, post_state, _, _ = state.build_block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            known_block_roots=known_block_roots,
            aggregated_payloads=aggregated_payloads,
        )
        return block, post_state

    def _build_aggregated_payloads_from_spec(
        self,
        attestation_specs: list[AggregatedAttestationSpec],
        state: State,
        block_registry: dict[str, Block],
    ) -> dict[AttestationData, set[AggregatedSignatureProof]]:
        """
        Build aggregated signature payloads from attestation specifications.

        For each AggregatedAttestationSpec, builds AttestationData, signs
        individual attestations, and aggregates them into proofs that can
        be passed to State.build_block().

        Parameters
        ----------
        attestation_specs : list[AggregatedAttestationSpec]
            Attestation specifications from the BlockSpec.
        state : State
            Current state for source checkpoint lookup.
        block_registry : dict[str, Block]
            Map of labels to blocks for resolving target roots.

        Returns:
        -------
        dict[AttestationData, set[AggregatedSignatureProof]]
            Aggregated payloads keyed by attestation data.
        """
        # Compute max slot across all attestation specs for XMSS key lifetime.
        # XMSS keys require precomputation up to the highest slot used.
        max_slot = max(spec.slot for spec in attestation_specs)
        key_manager = XmssKeyManager.shared(max_slot=max_slot)
        payloads: dict[AttestationData, set[AggregatedSignatureProof]] = {}

        for spec in attestation_specs:
            if not spec.valid_signature:
                raise NotImplementedError(
                    "valid_signature=False not yet supported in StateTransitionTest"
                )
            if spec.signer_ids is not None:
                raise NotImplementedError("signer_ids not yet supported in StateTransitionTest")

            attestation_data = self._build_attestation_data_from_spec(spec, block_registry, state)

            # Sign each validator's attestation individually
            public_keys = []
            signatures = []
            for validator_id in spec.validator_ids:
                attestation_pubkey, _ = key_manager.get_public_keys(validator_id)
                public_keys.append(attestation_pubkey)
                signatures.append(key_manager.sign_attestation_data(validator_id, attestation_data))

            # Aggregate into a single proof
            xmss_participants = AggregationBits.from_validator_indices(
                ValidatorIndices(data=spec.validator_ids)
            )
            proof = AggregatedSignatureProof.aggregate(
                xmss_participants=xmss_participants,
                children=[],
                raw_xmss=list(zip(public_keys, signatures, strict=True)),
                message=attestation_data.data_root_bytes(),
                slot=attestation_data.slot,
            )

            payloads.setdefault(attestation_data, set()).add(proof)

        return payloads

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
        # Source is the state's last justified checkpoint (3SF-mini link).
        return AttestationData(
            slot=spec.slot,
            head=target,
            target=target,
            source=state.latest_justified,
        )
