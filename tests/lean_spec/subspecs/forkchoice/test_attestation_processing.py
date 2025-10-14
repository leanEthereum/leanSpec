"""Tests for attestation validation and processing."""

import pytest  # type: ignore[import-not-found]

from lean_spec.subspecs.containers import (
    AttestationData,
    Block,
    BlockBody,
    Checkpoint,
    Config,
    SignedValidatorAttestation,
    ValidatorAttestation,
)
from lean_spec.subspecs.containers.block import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Bytes4000, Uint64, ValidatorIndex


@pytest.fixture
def sample_config() -> Config:
    """Sample configuration for testing."""
    return Config(num_validators=Uint64(100), genesis_time=Uint64(1000))


@pytest.fixture
def sample_store(sample_config: Config) -> Store:
    """Create a sample forkchoice store."""
    checkpoint = Checkpoint(
        root=Bytes32(b"test_root" + b"\x00" * 23),
        slot=Slot(0),
    )

    return Store(
        time=Uint64(100),
        config=sample_config,
        head=Bytes32(b"head_root" + b"\x00" * 23),
        safe_target=Bytes32(b"safe_root" + b"\x00" * 23),
        latest_justified=checkpoint,
        latest_finalized=checkpoint,
    )


def build_signed_attestation(
    validator: ValidatorIndex,
    slot: Slot,
    head: Checkpoint,
    source: Checkpoint,
    target: Checkpoint,
) -> SignedValidatorAttestation:
    """Construct a signed attestation with zeroed signature."""
    data = AttestationData(
        slot=slot,
        head=head,
        target=target,
        source=source,
    )
    message = ValidatorAttestation(
        validator_id=validator,
        data=data,
    )
    return SignedValidatorAttestation(
        message=message,
        signature=Bytes4000.zero(),
    )


class TestAttestationValidation:
    """Test attestation validation logic."""

    def test_validate_attestation_valid(self, sample_store: Store) -> None:
        """Test validation of a valid attestation."""
        # Create valid source and target blocks
        source_block = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"source" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        source_hash = hash_tree_root(source_block)

        target_block = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=source_hash,
            state_root=Bytes32(b"target" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        target_hash = hash_tree_root(target_block)

        # Add blocks to store
        sample_store.blocks[source_hash] = source_block
        sample_store.blocks[target_hash] = target_block

        # Create valid signed vote
        head_checkpoint = Checkpoint(root=target_hash, slot=Slot(2))
        source_checkpoint = Checkpoint(root=source_hash, slot=Slot(1))
        signed_attestation = build_signed_attestation(
            validator=ValidatorIndex(0),
            slot=Slot(2),
            head=head_checkpoint,
            source=source_checkpoint,
            target=head_checkpoint,
        )

        # Should validate without error
        sample_store.validate_attestation(signed_attestation)

    def test_validate_attestation_slot_order_invalid(
        self,
        sample_store: Store,
    ) -> None:
        """Test validation fails when source slot > target slot."""
        # Create blocks with invalid slot ordering
        source_block = Block(
            slot=Slot(2),  # Later than target
            proposer_index=Uint64(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"source" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        source_hash = hash_tree_root(source_block)

        target_block = Block(
            slot=Slot(1),  # Earlier than source
            proposer_index=Uint64(2),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"target" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        target_hash = hash_tree_root(target_block)

        # Add blocks to store
        sample_store.blocks[source_hash] = source_block
        sample_store.blocks[target_hash] = target_block

        head_checkpoint = Checkpoint(root=target_hash, slot=Slot(1))
        source_checkpoint = Checkpoint(root=source_hash, slot=Slot(2))
        signed_attestation = build_signed_attestation(
            validator=ValidatorIndex(0),
            slot=Slot(2),
            head=head_checkpoint,
            source=source_checkpoint,
            target=head_checkpoint,
        )

        with pytest.raises(
            AssertionError,
            match="Source slot must not exceed target",
        ):
            sample_store.validate_attestation(signed_attestation)

    def test_validate_attestation_missing_blocks(
        self,
        sample_store: Store,
    ) -> None:
        """Test validation fails when referenced blocks are missing."""
        source_hash = Bytes32(b"missing_source" + b"\x00" * 18)
        target_hash = Bytes32(b"missing_target" + b"\x00" * 18)

        head_checkpoint = Checkpoint(root=target_hash, slot=Slot(2))
        source_checkpoint = Checkpoint(root=source_hash, slot=Slot(1))
        signed_attestation = build_signed_attestation(
            validator=ValidatorIndex(0),
            slot=Slot(2),
            head=head_checkpoint,
            source=source_checkpoint,
            target=head_checkpoint,
        )

        with pytest.raises(AssertionError, match="Unknown source block"):
            sample_store.validate_attestation(signed_attestation)

    def test_validate_attestation_checkpoint_slot_mismatch(
        self,
        sample_store: Store,
    ) -> None:
        """Test validation fails when checkpoint slots mismatch blocks."""
        # Create blocks
        source_block = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"source" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        source_hash = hash_tree_root(source_block)

        target_block = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=source_hash,
            state_root=Bytes32(b"target" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        target_hash = hash_tree_root(target_block)

        # Add blocks to store
        sample_store.blocks[source_hash] = source_block
        sample_store.blocks[target_hash] = target_block

        head_checkpoint = Checkpoint(root=target_hash, slot=Slot(2))
        wrong_source_checkpoint = Checkpoint(root=source_hash, slot=Slot(0))
        signed_attestation = build_signed_attestation(
            validator=ValidatorIndex(0),
            slot=Slot(2),
            head=head_checkpoint,
            source=wrong_source_checkpoint,
            target=head_checkpoint,
        )

        with pytest.raises(
            AssertionError,
            match="Source checkpoint slot mismatch",
        ):
            sample_store.validate_attestation(signed_attestation)

    def test_validate_attestation_too_far_future(
        self,
        sample_store: Store,
    ) -> None:
        """Test validation fails for attestations too far in the future."""
        # Create blocks
        source_block = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"source" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        source_hash = hash_tree_root(source_block)

        target_block = Block(
            slot=Slot(1000),  # Very far in future
            proposer_index=Uint64(2),
            parent_root=source_hash,
            state_root=Bytes32(b"target" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        target_hash = hash_tree_root(target_block)

        # Add blocks to store
        sample_store.blocks[source_hash] = source_block
        sample_store.blocks[target_hash] = target_block

        head_checkpoint = Checkpoint(root=target_hash, slot=Slot(1000))
        source_checkpoint = Checkpoint(root=source_hash, slot=Slot(1))
        signed_attestation = build_signed_attestation(
            validator=ValidatorIndex(0),
            slot=Slot(1000),
            head=head_checkpoint,
            source=source_checkpoint,
            target=head_checkpoint,
        )

        with pytest.raises(
            AssertionError,
            match="Attestation too far in future",
        ):
            sample_store.validate_attestation(signed_attestation)


class TestAttestationProcessing:
    """Test attestation processing logic."""

    def test_process_network_attestation(self, sample_store: Store) -> None:
        """Test processing attestation from network gossip."""
        # Create valid blocks
        source_block = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"source" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        source_hash = hash_tree_root(source_block)

        target_block = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=source_hash,
            state_root=Bytes32(b"target" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        target_hash = hash_tree_root(target_block)

        # Add blocks to store
        sample_store.blocks[source_hash] = source_block
        sample_store.blocks[target_hash] = target_block

        head_checkpoint = Checkpoint(root=target_hash, slot=Slot(2))
        source_checkpoint = Checkpoint(root=source_hash, slot=Slot(1))
        signed_attestation = build_signed_attestation(
            validator=ValidatorIndex(5),
            slot=Slot(2),
            head=head_checkpoint,
            source=source_checkpoint,
            target=head_checkpoint,
        )

        sample_store.process_attestation(
            signed_attestation,
            is_from_block=False,
        )

        assert ValidatorIndex(5) in sample_store.latest_new_votes
        stored = sample_store.latest_new_votes[ValidatorIndex(5)]
        assert stored.message.data.target == head_checkpoint

    def test_process_block_attestation(self, sample_store: Store) -> None:
        """Test processing attestation from a block."""
        # Create valid blocks
        source_block = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"source" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        source_hash = hash_tree_root(source_block)

        target_block = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=source_hash,
            state_root=Bytes32(b"target" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        target_hash = hash_tree_root(target_block)

        # Add blocks to store
        sample_store.blocks[source_hash] = source_block
        sample_store.blocks[target_hash] = target_block

        head_checkpoint = Checkpoint(root=target_hash, slot=Slot(2))
        source_checkpoint = Checkpoint(root=source_hash, slot=Slot(1))
        signed_attestation = build_signed_attestation(
            validator=ValidatorIndex(7),
            slot=Slot(2),
            head=head_checkpoint,
            source=source_checkpoint,
            target=head_checkpoint,
        )

        sample_store.process_attestation(
            signed_attestation,
            is_from_block=True,
        )

        assert ValidatorIndex(7) in sample_store.latest_known_votes
        stored = sample_store.latest_known_votes[ValidatorIndex(7)]
        assert stored.message.data.target == head_checkpoint

    def test_process_attestation_superseding(
        self,
        sample_store: Store,
    ) -> None:
        """Test that newer attestations supersede older ones."""
        # Create blocks for different slots
        target_block_1 = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"target1" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        target_hash_1 = hash_tree_root(target_block_1)

        target_block_2 = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=target_hash_1,
            state_root=Bytes32(b"target2" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        target_hash_2 = hash_tree_root(target_block_2)

        # Add blocks to store
        sample_store.blocks[target_hash_1] = target_block_1
        sample_store.blocks[target_hash_2] = target_block_2

        validator = ValidatorIndex(10)

        # Process first (older) attestation
        head_checkpoint_1 = Checkpoint(root=target_hash_1, slot=Slot(1))
        signed_attestation_1 = build_signed_attestation(
            validator=validator,
            slot=Slot(1),
            head=head_checkpoint_1,
            source=head_checkpoint_1,
            target=head_checkpoint_1,
        )
        sample_store.process_attestation(
            signed_attestation_1,
            is_from_block=False,
        )

        head_checkpoint_2 = Checkpoint(root=target_hash_2, slot=Slot(2))
        signed_attestation_2 = build_signed_attestation(
            validator=validator,
            slot=Slot(2),
            head=head_checkpoint_2,
            source=head_checkpoint_1,
            target=head_checkpoint_2,
        )
        sample_store.process_attestation(
            signed_attestation_2,
            is_from_block=False,
        )

        assert validator in sample_store.latest_new_votes
        stored = sample_store.latest_new_votes[validator]
        assert stored.message.data.target == head_checkpoint_2

    def test_process_attestation_from_block_supersedes_new(
        self,
        sample_store: Store,
    ) -> None:
        """Test that block attestations remove corresponding new votes."""
        # Create blocks
        source_block = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"source" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        source_hash = hash_tree_root(source_block)

        target_block = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=source_hash,
            state_root=Bytes32(b"target" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        target_hash = hash_tree_root(target_block)

        # Add blocks to store
        sample_store.blocks[source_hash] = source_block
        sample_store.blocks[target_hash] = target_block

        validator = ValidatorIndex(15)

        # First process as network vote
        head_checkpoint = Checkpoint(root=target_hash, slot=Slot(2))
        source_checkpoint = Checkpoint(root=source_hash, slot=Slot(1))
        signed_attestation = build_signed_attestation(
            validator=validator,
            slot=Slot(2),
            head=head_checkpoint,
            source=source_checkpoint,
            target=head_checkpoint,
        )
        sample_store.process_attestation(
            signed_attestation,
            is_from_block=False,
        )

        # Should be in new votes
        assert validator in sample_store.latest_new_votes

        # Process same vote as block attestation
        sample_store.process_attestation(
            signed_attestation,
            is_from_block=True,
        )

        assert validator in sample_store.latest_known_votes
        assert validator not in sample_store.latest_new_votes
        stored = sample_store.latest_known_votes[validator]
        assert stored.message.data.target == head_checkpoint


class TestBlockProcessing:
    """Test block processing that includes attestation processing."""

    def test_process_block_with_attestations(
        self,
        sample_store: Store,
    ) -> None:
        """Test processing a block that contains attestations."""
        # Create parent block
        parent_block = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"parent" + b"\x00" * 26),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        parent_hash = hash_tree_root(parent_block)

        # Add parent to store
        sample_store.blocks[parent_hash] = parent_block

        # Create a vote that will be included in block
        head_checkpoint = Checkpoint(root=parent_hash, slot=Slot(1))
        signed_attestation = build_signed_attestation(
            validator=ValidatorIndex(20),
            slot=Slot(2),
            head=head_checkpoint,
            source=head_checkpoint,
            target=head_checkpoint,
        )

        sample_store.process_attestation(
            signed_attestation,
            is_from_block=True,
        )

        stored = sample_store.latest_known_votes[ValidatorIndex(20)]
        assert stored.message.validator_id == ValidatorIndex(20)
        assert stored.message.data.target.root == parent_hash
