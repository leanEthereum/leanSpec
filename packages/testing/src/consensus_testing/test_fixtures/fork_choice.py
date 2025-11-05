"""Fork choice test fixture format."""

from __future__ import annotations

from functools import lru_cache
from typing import ClassVar, List

from pydantic import model_validator

from lean_spec.subspecs.chain.config import SECONDS_PER_SLOT
from lean_spec.subspecs.containers import Signature
from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
    SignedAttestation,
)
from lean_spec.subspecs.containers.block.block import (
    Block,
    BlockBody,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import Attestations, BlockSignatures
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.subspecs.xmss.interface import DEFAULT_SIGNATURE_SCHEME
from lean_spec.types import Bytes32, Uint64, ValidatorIndex

from ..keys import XmssKeyManager
from ..test_types import (
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceStep,
    SignedAttestationSpec,
    TickStep,
)
from .base import BaseConsensusFixture


@lru_cache(maxsize=1)
def _get_shared_key_manager() -> XmssKeyManager:
    """
    Get or create the shared XMSS key manager for reusing keys across tests.
    
    Uses functools.lru_cache to create a singleton instance that's shared
    across all test fixture generations within a session. This optimizes
    performance by reusing keys when possible.
    
    Returns:
        Shared XmssKeyManager instance with max_slot=10.
    """
    return XmssKeyManager(max_slot=Slot(10))

class ForkChoiceTest(BaseConsensusFixture):
    """
    Test fixture for event-driven fork choice scenarios.

    Tests the fork choice Store through a sequence of events:
    - on_tick: Time advancement
    - on_block: Block arrival
    - on_attestation: Attestation arrival (from gossip)
    - checks: Store state validation

    This tests LMD-GHOST algorithm, proposer boost, reorgs, and
    timing-sensitive behavior.

    Structure:
        anchor_state: Initial trusted state
        anchor_block: Initial trusted block
        steps: Sequence of events and checks
    """

    format_name: ClassVar[str] = "fork_choice_test"
    description: ClassVar[str] = "Tests event-driven fork choice through Store operations"

    anchor_state: State | None = None
    """
    The initial trusted consensus state.

    If not provided, the framework will use the genesis fixture from pytest.
    This allows tests to omit genesis for simpler test code while still
    allowing customization when needed.
    """

    anchor_block: Block | None = None
    """
    The initial trusted block (unsigned).

    If not provided, will be auto-generated from anchor_state's latest_block_header.
    This is typically the genesis block.
    """

    steps: List[ForkChoiceStep]
    """
    Sequence of fork choice events to process.

    Events are processed in order, with store state carrying forward.
    """

    max_slot: Slot | None = None
    """
    Maximum slot for which XMSS keys should be valid.

    If not provided, will be auto-calculated from the steps. This determines
    how many slots worth of XMSS signatures can be generated. Keys must be
    valid up to the highest slot used in any block or attestation.
    """

    @model_validator(mode="after")
    def set_anchor_block_default(self) -> ForkChoiceTest:
        """
        Auto-generate anchor_block from anchor_state if not provided.

        This creates a block from the state's latest_block_header, which is
        typically the genesis block. The state_root is set to the hash of the
        anchor_state itself.

        Note: anchor_state can be None at this point - it will be injected
        by the pytest plugin before make_fixture() is called.
        """
        if self.anchor_block is None and self.anchor_state is not None:
            self.anchor_block = Block(
                slot=self.anchor_state.latest_block_header.slot,
                proposer_index=self.anchor_state.latest_block_header.proposer_index,
                parent_root=self.anchor_state.latest_block_header.parent_root,
                state_root=hash_tree_root(self.anchor_state),
                body=BlockBody(attestations=Attestations(data=[])),
            )
        return self

    @model_validator(mode="after")
    def set_max_slot_default(self) -> ForkChoiceTest:
        """
        Auto-calculate max_slot from steps if not provided.

        Scans all steps to find the highest slot value used in blocks or
        attestations. This ensures XMSS keys are generated with sufficient
        capacity for the entire test.
        """
        if self.max_slot is None:
            max_slot_value = 0

            for step in self.steps:
                if isinstance(step, BlockStep):
                    max_slot_value = max(max_slot_value, int(step.block.slot))
                elif isinstance(step, AttestationStep):
                    max_slot_value = max(max_slot_value, int(step.attestation.message.data.slot))

            self.max_slot = Slot(max_slot_value)

        return self

    def make_fixture(self) -> ForkChoiceTest:
        """
        Generate the fixture by running the spec's Store.

        This validates the test by:
        1. Initializing Store from anchor_state and anchor_block
        2. Processing each step through Store methods (building blocks from specs as needed)
        3. Validating check assertions against Store state

        Returns:
        -------
        ForkChoiceTest
            The validated fixture (self, since steps contain the test).

        Raises:
        ------
        AssertionError
            If any step fails unexpectedly or checks don't match Store state.
        """
        # Ensure anchor_state and anchor_block are set
        assert self.anchor_state is not None, "anchor_state must be set before make_fixture"
        assert self.anchor_block is not None, "anchor_block must be set before make_fixture"
        assert self.max_slot is not None, "max_slot must be set before make_fixture"

        # Use shared key manager if it has sufficient capacity, otherwise create a new one
        # This optimizes performance by reusing keys across tests when possible
        shared_key_manager = _get_shared_key_manager()
        if self.max_slot <= shared_key_manager.max_slot:
            key_manager = shared_key_manager
        else:
            # Test needs more slots than shared manager supports, create dedicated one
            key_manager = XmssKeyManager(max_slot=self.max_slot)

        # Update validator pubkeys to match key_manager's generated keys
        updated_validators = []
        for i, validator in enumerate(self.anchor_state.validators):
            pubkey, _ = key_manager.create_and_store_key_pair(ValidatorIndex(i))
            pubkey_bytes = pubkey.to_bytes(DEFAULT_SIGNATURE_SCHEME.config)
            updated_validator = validator.model_copy(update={"pubkey": pubkey_bytes})
            updated_validators.append(updated_validator)

        self.anchor_state = self.anchor_state.model_copy(
            update={"validators": Validators(data=updated_validators)}
        )
        self.anchor_block = self.anchor_block.model_copy(
            update={"state_root": hash_tree_root(self.anchor_state)}
        )

        # Initialize Store from anchor
        store = Store.get_forkchoice_store(
            state=self.anchor_state,
            anchor_block=self.anchor_block,
        )

        # Block registry for label-based fork creation
        self._block_registry: dict[str, Block] = {}

        # Register genesis/anchor block with implicit label
        self._block_registry["genesis"] = self.anchor_block

        # Process each step (immutable pattern: store = store.method())
        for i, step in enumerate(self.steps):
            try:
                if isinstance(step, TickStep):
                    # Advance time (immutable)
                    store = store.advance_time(Uint64(step.time), has_proposal=False)

                elif isinstance(step, BlockStep):
                    # Build SignedBlockWithAttestation from BlockSpec
                    signed_block = self._build_block_from_spec(
                        step.block, store, self._block_registry, key_manager
                    )

                    # Store the filled Block for serialization
                    block = signed_block.message.block
                    step._filled_block = block

                    # Register block if it has a label
                    if step.block.label is not None:
                        if step.block.label in self._block_registry:
                            raise ValueError(
                                f"Step {i}: duplicate label '{step.block.label}' - "
                                f"labels must be unique within a test"
                            )
                        self._block_registry[step.block.label] = block

                    # Automatically advance time to block's slot before processing (immutable)
                    block_time = store.config.genesis_time + block.slot * Uint64(SECONDS_PER_SLOT)
                    store = store.advance_time(block_time, has_proposal=True)

                    # Process the block (immutable)
                    store = store.on_block(signed_block)

                elif isinstance(step, AttestationStep):
                    # Process attestation from gossip (immutable)
                    store = store.on_attestation(step.attestation, is_from_block=False)

                else:
                    raise ValueError(f"Step {i}: unknown step type {type(step).__name__}")

                # Validate checks if provided
                if step.checks is not None:
                    step.checks.validate_against_store(
                        store, step_index=i, block_registry=self._block_registry
                    )

            except Exception as e:
                if step.valid:
                    # Expected to succeed but failed
                    raise AssertionError(
                        f"Step {i} ({type(step).__name__}) failed unexpectedly: {e}"
                    ) from e
                # Expected to fail, continue
                continue

            # If we expected failure but succeeded, that's an error
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
        Build a full SignedBlockWithAttestation from a lightweight BlockSpec.

        Builds blocks via state transition dry-run, similar to state transition tests,
        but also creates a proper proposer attestation for fork choice.
        This mimics what a local block builder would do.

        TODO: We cannot use Store.produce_block_with_signatures() because it has
        side effects (adds block to store at lines 556-559 of store.py). If the spec
        is refactored to separate block production from store updates, we should use
        that method instead. Until then, this manual approach is necessary.

        Parameters
        ----------
        spec : BlockSpec
            The lightweight block specification.
        store : Store
            The fork choice store (used to get head state and latest justified).
        block_registry : dict[str, Block]
            Registry of labeled blocks for fork creation.

        Returns:
        -------
        SignedBlockWithAttestation
            A complete signed block ready for processing.
        """
        # Determine proposer
        if spec.proposer_index is None:
            validator_count = store.states[store.head].validators.count
            proposer_index = ValidatorIndex(int(spec.slot) % int(validator_count))
        else:
            proposer_index = spec.proposer_index

        # Resolve parent block if parent_label is specified
        if spec.parent_label is not None:
            if spec.parent_label not in block_registry:
                raise ValueError(
                    f"parent_label '{spec.parent_label}' not found - "
                    f"available labels: {list(block_registry.keys())}"
                )
            parent_block = block_registry[spec.parent_label]
            parent_root = hash_tree_root(parent_block)

            # Get state at the parent block
            if parent_root not in store.states:
                raise ValueError(
                    f"parent_label '{spec.parent_label}' (root=0x{parent_root.hex()[:16]}...) "
                    f"has no state in store - cannot build on this fork"
                )
            parent_state = store.states[parent_root]

            # Advance state to the new block's slot
            temp_state = parent_state.process_slots(spec.slot)
        else:
            # Default: build on current head
            head_state = store.states[store.head]
            temp_state = head_state.process_slots(spec.slot)
            parent_root = hash_tree_root(temp_state.latest_block_header)

        # Prepare attestations from spec if provided
        attestations = []
        attestation_signatures = []
        if spec.attestations is not None:
            for attestation in spec.attestations:
                if isinstance(attestation, SignedAttestationSpec):
                    # Use the parent state's latest_justified for source checkpoint
                    parent_state = store.states[parent_root]
                    signed_attestation = self._build_signed_attestation_from_spec(
                        attestation, block_registry, parent_state
                    )
                    # Extract the Attestation message and signature
                    attestations.append(signed_attestation.message)
                    attestation_signatures.append(signed_attestation.signature)
                else:
                    # Already a SignedAttestation, extract the message
                    attestations.append(attestation.message)
                    attestation_signatures.append(attestation.signature)

        # Build block with collected attestations
        body = BlockBody(attestations=Attestations(data=attestations))

        # Create temporary block for dry-run
        temp_block = Block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=Bytes32.zero(),
            body=body,
        )

        # Process to get correct state root
        post_state = temp_state.process_block(temp_block)
        correct_state_root = hash_tree_root(post_state)

        # Create final block
        final_block = Block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            state_root=correct_state_root,
            body=body,
        )

        # Create proposer attestation for this block
        block_root = hash_tree_root(final_block)
        proposer_attestation = Attestation(
            validator_id=proposer_index,
            data=AttestationData(
                slot=spec.slot,
                head=Checkpoint(root=block_root, slot=spec.slot),
                target=Checkpoint(root=block_root, slot=spec.slot),
                # Use the anchor block as source for genesis case
                source=Checkpoint(root=parent_root, slot=temp_state.latest_block_header.slot),
            ),
        )

        # Sign all attestations and the proposer attestation
        signature_list = []
        for attestation in final_block.body.attestations:
            signature_list.append(key_manager.sign_attestation(attestation))
        proposer_attestation_signature = key_manager.sign_attestation(proposer_attestation)
        signature_list.append(proposer_attestation_signature)

        return SignedBlockWithAttestation(
            message=BlockWithAttestation(
                block=final_block,
                proposer_attestation=proposer_attestation,
            ),
            signature=BlockSignatures(data=signature_list),
        )

    def _build_signed_attestation_from_spec(
        self,
        spec: SignedAttestationSpec,
        block_registry: dict[str, Block],
        state: State,
    ) -> SignedAttestation:
        """
        Build a SignedAttestation from a SignedAttestationSpec.

        Parameters
        ----------
        spec : SignedAttestationSpec
            The attestation specification to resolve.
        block_registry : dict[str, Block]
            Registry of labeled blocks for resolving target_root_label.
        state : State
            The state to get latest_justified checkpoint from.

        Returns:
        -------
        SignedAttestation
            The resolved signed attestation.
        """
        # Resolve target checkpoint from label
        if spec.target_root_label not in block_registry:
            raise ValueError(
                f"target_root_label '{spec.target_root_label}' not found - "
                f"available labels: {list(block_registry.keys())}"
            )
        target_block = block_registry[spec.target_root_label]
        target_root = hash_tree_root(target_block)
        target_checkpoint = Checkpoint(root=target_root, slot=spec.target_slot)

        # Derive head = target
        head_checkpoint = target_checkpoint

        # Derive source from state's latest justified checkpoint
        source_checkpoint = state.latest_justified

        # Convert validator_id to Uint64 if needed
        validator_id = (
            spec.validator_id
            if isinstance(spec.validator_id, Uint64)
            else Uint64(int(spec.validator_id))
        )

        # Create attestation data
        attestation_data = AttestationData(
            slot=spec.slot,
            head=head_checkpoint,
            target=target_checkpoint,
            source=source_checkpoint,
        )

        # Create attestation
        attestation = Attestation(validator_id=validator_id, data=attestation_data)

        # Create signed attestation
        return SignedAttestation(
            message=attestation,
            signature=spec.signature if spec.signature is not None else Signature.zero(),
        )
