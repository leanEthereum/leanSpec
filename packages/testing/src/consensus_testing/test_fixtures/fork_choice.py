"""Fork choice test fixture format."""

from __future__ import annotations

from typing import ClassVar, List

from pydantic import model_validator

from lean_spec.subspecs.chain.config import SECONDS_PER_SLOT
from lean_spec.subspecs.containers.attestation import (
    Attestation,
    AttestationData,
    SignedAttestation,
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
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.koalabear import Fp
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.subspecs.xmss.constants import PROD_CONFIG
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.subspecs.xmss.types import HashDigestList, HashTreeOpening, Randomness
from lean_spec.types import Bytes32, Uint64

from ..keys import LEAN_ENV_TO_SCHEMES, XmssKeyManager, get_shared_key_manager
from ..test_types import (
    AttestationStep,
    BlockSpec,
    BlockStep,
    ForkChoiceStep,
    SignedAttestationSpec,
    TickStep,
)
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
                body=BlockBody(attestations=AggregatedAttestations(data=[])),
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
                    max_slot_value = max(max_slot_value, int(step.attestation.message.slot))

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
        # Ensure anchor state and anchor block are set
        assert self.anchor_state is not None, "anchor_state must be set before make_fixture"
        assert self.anchor_block is not None, "anchor_block must be set before make_fixture"
        assert self.max_slot is not None, "max_slot must be set before make_fixture"

        # Get shared key manager with the required maximum slot
        # This reuses keys across tests that require the same or lower maximum slot
        key_manager = get_shared_key_manager(lean_env=self.lean_env, max_slot=self.max_slot)

        # Update validator pubkeys to match key manager's generated keys
        updated_validators = [
            validator.model_copy(update={"pubkey": key_manager[Uint64(i)].public.encode_bytes()})
            for i, validator in enumerate(self.anchor_state.validators)
        ]

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
        # Register genesis/anchor block with implicit label
        self._block_registry: dict[str, Block] = {"genesis": self.anchor_block}

        # Process each step (immutable pattern: store = store.method())
        for i, step in enumerate(self.steps):
            try:
                if isinstance(step, TickStep):
                    # Advance time (immutable)
                    store = store.on_tick(Uint64(step.time), has_proposal=False)

                elif isinstance(step, BlockStep):
                    # Build SignedBlockWithAttestation from BlockSpec
                    signed_block = self._build_block_from_spec(
                        step.block, store, self._block_registry, key_manager
                    )

                    # Store the filled Block for serialization
                    block = signed_block.message.block
                    step._filled_block = signed_block.message

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
                    store = store.on_tick(block_time, has_proposal=True)

                    # Process the block (immutable)
                    store = store.on_block(signed_block, LEAN_ENV_TO_SCHEMES[self.lean_env])

                elif isinstance(step, AttestationStep):
                    # Process attestation from gossip (immutable)
                    store = store.on_attestation(step.attestation, is_from_block=False)

                else:
                    raise ValueError(f"Step {i}: unknown step type {type(step).__name__}")

                # Validate checks if provided
                if step.checks is not None:
                    step.checks.fill_hash_from_label(self._block_registry)
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

        This method combines:
            - spec logic (via the state block building logic),
            - test-specific logic (label resolution and signing),
        to produce a complete signed block.

        Parameters
        ----------
        spec : BlockSpec
            The lightweight block specification.
        store : Store
            The fork choice store (used to get head state and latest justified).
        block_registry : dict[str, Block]
            Registry of labeled blocks for fork creation.
        key_manager : XmssKeyManager
            Key manager for signing attestations.

        Returns:
        -------
        SignedBlockWithAttestation
            A complete signed block ready for processing.
        """
        # Determine proposer index
        proposer_index = spec.proposer_index or Uint64(
            int(spec.slot) % len(store.states[store.head].validators)
        )

        # Resolve parent root from label or default to head
        parent_root = self._resolve_parent_root(spec, store, block_registry)

        # Build attestations from spec
        attestations = self._build_attestations_from_spec(spec, store, block_registry, parent_root)

        # Use State.build_block for core block building (pure spec logic)
        parent_state = store.states[parent_root]
        final_block, _, _, _ = parent_state.build_block(
            slot=spec.slot,
            proposer_index=proposer_index,
            parent_root=parent_root,
            attestations=attestations,
        )

        # Create proposer attestation for this block
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

        # Sign all attestations and the proposer attestation
        attestation_signatures = key_manager.build_attestation_signatures(
            final_block.body.attestations
        )

        proposer_signature = key_manager.sign_attestation_data(
            proposer_attestation.validator_id,
            proposer_attestation.data,
        )

        return SignedBlockWithAttestation(
            message=BlockWithAttestation(
                block=final_block,
                proposer_attestation=proposer_attestation,
            ),
            signature=BlockSignatures(
                attestation_signatures=attestation_signatures,
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
        Resolve parent root from BlockSpec.
            - If parent_label is specified, look it up in the registry.
            - Otherwise, default to the current head's parent.
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
    ) -> list[Attestation]:
        """Build attestations list from BlockSpec."""
        if spec.attestations is None:
            return []

        parent_state = store.states[parent_root]
        attestations = []

        for att_spec in spec.attestations:
            if isinstance(att_spec, SignedAttestationSpec):
                signed_att = self._build_signed_attestation_from_spec(
                    att_spec, block_registry, parent_state
                )
                attestations.append(
                    Attestation(validator_id=signed_att.validator_id, data=signed_att.message)
                )
            else:
                attestations.append(
                    Attestation(validator_id=att_spec.validator_id, data=att_spec.message)
                )

        return attestations

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

        # Create attestation
        attestation = Attestation(
            validator_id=spec.validator_id,
            data=AttestationData(
                slot=spec.slot,
                head=head_checkpoint,
                target=target_checkpoint,
                source=source_checkpoint,
            ),
        )

        # Create signed attestation
        return SignedAttestation(
            validator_id=attestation.validator_id,
            message=attestation.data,
            signature=(
                spec.signature
                or Signature(
                    path=HashTreeOpening(siblings=HashDigestList(data=[])),
                    rho=Randomness(data=[Fp(0) for _ in range(PROD_CONFIG.RAND_LEN_FE)]),
                    hashes=HashDigestList(data=[]),
                )
            ),
        )
