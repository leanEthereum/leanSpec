"""Fork choice test fixture format."""

from typing import ClassVar, List

from pydantic import model_validator

from lean_spec.subspecs.chain.config import SECONDS_PER_SLOT
from lean_spec.subspecs.containers.attestation import Attestation, AttestationData
from lean_spec.subspecs.containers.block.block import (
    Block,
    BlockBody,
    BlockWithAttestation,
    SignedBlockWithAttestation,
)
from lean_spec.subspecs.containers.block.types import Attestations, BlockSignatures
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.state.state import State
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.types import Bytes32, Uint64, ValidatorIndex

from ..keys import XmssKeyManager
from ..test_types import AttestationStep, BlockSpec, BlockStep, ForkChoiceStep, TickStep
from .base import BaseConsensusFixture


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

    @model_validator(mode="after")
    def set_anchor_block_default(self) -> "ForkChoiceTest":
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

    def make_fixture(self) -> "ForkChoiceTest":
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

        # Initialize key manager for signing blocks and attestations
        key_manager = XmssKeyManager()

        # Initialize Store from anchor
        store = Store.get_forkchoice_store(
            state=self.anchor_state,
            anchor_block=self.anchor_block,
        )

        # Process each step
        for i, step in enumerate(self.steps):
            try:
                if isinstance(step, TickStep):
                    # Advance time
                    store.advance_time(Uint64(step.time), has_proposal=False)

                elif isinstance(step, BlockStep):
                    # Build SignedBlockWithAttestation from BlockSpec
                    signed_block = self._build_block_from_spec(step.block, store, key_manager)

                    # Store the filled Block for serialization
                    block = signed_block.message.block
                    step._filled_block = block

                    # Automatically advance time to block's slot before processing
                    # Compute the time corresponding to the block's slot
                    block_time = store.config.genesis_time + block.slot * Uint64(SECONDS_PER_SLOT)

                    # Use spec's advance_time method to handle time progression
                    store.advance_time(block_time, has_proposal=True)

                    # Process the block (which calls state_transition internally)
                    store.process_block(signed_block)

                elif isinstance(step, AttestationStep):
                    # Process attestation from gossip (not from block)
                    store.process_attestation(step.attestation, is_from_block=False)

                else:
                    raise ValueError(f"Step {i}: unknown step type {type(step).__name__}")

                # Validate checks if provided
                if step.checks is not None:
                    step.checks.validate_against_store(store, step_index=i)

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
        self, spec: BlockSpec, store: Store, key_manager: XmssKeyManager
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
        key_manager : XmssKeyManager
            Key manager for signing blocks and attestations.

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

        # Get the current head state from the store
        head_state = store.states[store.head]

        # Dry-run to build block with correct state root
        temp_state = head_state.process_slots(spec.slot)
        parent_root = hash_tree_root(temp_state.latest_block_header)

        # Build body (empty for now, attestations can be added later if needed)
        body = BlockBody(attestations=Attestations(data=[]))

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

        # Create signatures using the key manager
        # One signature for proposer attestation + one for the block
        attestation_signature = key_manager.sign_attestation(proposer_attestation)
        block_signature = key_manager.sign_block(final_block, proposer_index)
        signature_list = [attestation_signature, block_signature]
        return SignedBlockWithAttestation(
            message=BlockWithAttestation(
                block=final_block,
                proposer_attestation=proposer_attestation,
            ),
            signature=BlockSignatures(data=signature_list),
        )
