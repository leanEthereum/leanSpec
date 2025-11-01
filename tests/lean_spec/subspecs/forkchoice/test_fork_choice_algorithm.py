"""Tests for the core LMD GHOST fork choice algorithm."""

from typing import Dict

import pytest
from consensus_testing.keys import XmssKeyManager

from lean_spec.subspecs.containers import (
    Block,
    BlockBody,
    Checkpoint,
    Config,
)
from lean_spec.subspecs.containers.block import Attestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.forkchoice.helpers import get_fork_choice_head
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Uint64, ValidatorIndex

from .conftest import build_signed_attestation


@pytest.fixture
def sample_blocks() -> Dict[Bytes32, Block]:
    """Create a valid, linked chain of sample blocks for testing."""
    genesis = Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32(b"genesis" + b"\x00" * 25),
        body=BlockBody(attestations=Attestations(data=[])),
    )
    genesis_hash = hash_tree_root(genesis)

    block_a = Block(
        slot=Slot(1),
        proposer_index=Uint64(1),
        parent_root=genesis_hash,
        state_root=Bytes32(b"block_a" + b"\x00" * 25),
        body=BlockBody(attestations=Attestations(data=[])),
    )
    block_a_hash = hash_tree_root(block_a)

    block_b = Block(
        slot=Slot(2),
        proposer_index=Uint64(2),
        parent_root=block_a_hash,
        state_root=Bytes32(b"block_b" + b"\x00" * 25),
        body=BlockBody(attestations=Attestations(data=[])),
    )
    block_b_hash = hash_tree_root(block_b)

    return {
        genesis_hash: genesis,
        block_a_hash: block_a,
        block_b_hash: block_b,
    }


class TestLMDGHOSTAlgorithm:
    """Test the core LMD GHOST fork choice algorithm."""

    def test_fork_choice_no_attestations(self, sample_blocks: Dict[Bytes32, Block]) -> None:
        """
        Test fork choice algorithm with no attestations walks to the leaf.

        With no attestations, fork choice should walk down the tree and select the
        leaf block (the furthest descendant), breaking ties by lexicographic hash.
        """
        root_hash = list(sample_blocks.keys())[0]
        leaf_hash = list(sample_blocks.keys())[2]  # block_b (slot 2, the leaf)

        head = get_fork_choice_head(
            blocks=sample_blocks,
            root=root_hash,
            latest_attestations={},  # No attestations
            min_score=0,
        )

        assert head == leaf_hash

    def test_fork_choice_single_attestation(
        self, sample_blocks: Dict[Bytes32, Block], xmss_key_manager: XmssKeyManager
    ) -> None:
        """Test fork choice algorithm with a single attestation."""
        root_hash = list(sample_blocks.keys())[0]
        target_hash = list(sample_blocks.keys())[2]  # block_b

        attestations = {
            ValidatorIndex(0): build_signed_attestation(
                key_manager=xmss_key_manager,
                validator=ValidatorIndex(0),
                target=Checkpoint(root=target_hash, slot=Slot(2)),
            )
        }

        head = get_fork_choice_head(
            blocks=sample_blocks,
            root=root_hash,
            latest_attestations=attestations,
            min_score=0,
        )

        assert head == target_hash

    def test_fork_choice_with_multiple_forks(self, xmss_key_manager: XmssKeyManager) -> None:
        """Test fork choice algorithm with competing forks."""
        # Create a fork structure: genesis -> A -> B
        #                                  -> C -> D
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis)

        # Fork 1: A -> B
        block_a = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block_a" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_a_hash = hash_tree_root(block_a)

        block_b = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=block_a_hash,
            state_root=Bytes32(b"block_b" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_b_hash = hash_tree_root(block_b)

        # Fork 2: C -> D
        block_c = Block(
            slot=Slot(1),
            proposer_index=Uint64(3),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block_c" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_c_hash = hash_tree_root(block_c)

        block_d = Block(
            slot=Slot(2),
            proposer_index=Uint64(4),
            parent_root=block_c_hash,
            state_root=Bytes32(b"block_d" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_d_hash = hash_tree_root(block_d)

        blocks = {
            genesis_hash: genesis,
            block_a_hash: block_a,
            block_b_hash: block_b,
            block_c_hash: block_c,
            block_d_hash: block_d,
        }

        # More attestations for fork 2 (C->D)
        attestations = {
            ValidatorIndex(0): build_signed_attestation(
                key_manager=xmss_key_manager,
                validator=ValidatorIndex(0),
                target=Checkpoint(root=block_d_hash, slot=Slot(2)),
            ),
            ValidatorIndex(1): build_signed_attestation(
                key_manager=xmss_key_manager,
                validator=ValidatorIndex(1),
                target=Checkpoint(root=block_d_hash, slot=Slot(2)),
            ),
            ValidatorIndex(2): build_signed_attestation(
                key_manager=xmss_key_manager,
                validator=ValidatorIndex(2),
                target=Checkpoint(root=block_b_hash, slot=Slot(2)),
            ),  # Single attestation for fork 1
        }

        head = get_fork_choice_head(
            blocks=blocks,
            root=genesis_hash,
            latest_attestations=attestations,
            min_score=0,
        )

        # Fork 2 should win with 2 attestations vs 1
        assert head == block_d_hash

    def test_fork_choice_competing_attestations(self, xmss_key_manager: XmssKeyManager) -> None:
        """Test fork choice algorithm with evenly competing attestations."""
        # Create simple fork: genesis -> A
        #                             -> B
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis)

        block_a = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block_a" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_a_hash = hash_tree_root(block_a)

        block_b = Block(
            slot=Slot(1),
            proposer_index=Uint64(2),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block_b" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_b_hash = hash_tree_root(block_b)

        blocks = {
            genesis_hash: genesis,
            block_a_hash: block_a,
            block_b_hash: block_b,
        }

        # Equal attestations for both forks
        attestations = {
            ValidatorIndex(0): build_signed_attestation(
                key_manager=xmss_key_manager,
                validator=ValidatorIndex(0),
                target=Checkpoint(root=block_a_hash, slot=Slot(1)),
            ),
            ValidatorIndex(1): build_signed_attestation(
                key_manager=xmss_key_manager,
                validator=ValidatorIndex(1),
                target=Checkpoint(root=block_b_hash, slot=Slot(1)),
            ),
        }

        head = get_fork_choice_head(
            blocks=blocks,
            root=genesis_hash,
            latest_attestations=attestations,
            min_score=0,
        )

        # Should choose one consistently (lexicographically by hash)
        assert head in [block_a_hash, block_b_hash]

    def test_fork_choice_tie_breaking(self) -> None:
        """Test fork choice algorithm tie-breaking mechanism."""
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis)

        # Create two competing blocks at same slot
        block_a = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block_a" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_a_hash = hash_tree_root(block_a)

        block_b = Block(
            slot=Slot(1),
            proposer_index=Uint64(2),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block_b" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_b_hash = hash_tree_root(block_b)

        blocks = {
            genesis_hash: genesis,
            block_a_hash: block_a,
            block_b_hash: block_b,
        }

        # No attestations - algorithm breaks tie by lexicographically highest hash
        head = get_fork_choice_head(
            blocks=blocks,
            root=genesis_hash,
            latest_attestations={},
            min_score=0,
        )

        # Should return the block with lexicographically highest hash
        expected_head = max(block_a_hash, block_b_hash)
        assert head == expected_head

    def test_fork_choice_deep_chain(self, xmss_key_manager: XmssKeyManager) -> None:
        """Test fork choice algorithm with a deeper chain."""
        blocks = {}
        prev_hash = Bytes32.zero()

        # Create a 10-block chain
        for i in range(10):
            block = Block(
                slot=Slot(i),
                proposer_index=Uint64(i),
                parent_root=prev_hash,
                state_root=Bytes32(f"block{i}".encode() + b"\x00" * (32 - len(f"block{i}"))),
                body=BlockBody(attestations=Attestations(data=[])),
            )
            block_hash = hash_tree_root(block)
            blocks[block_hash] = block
            prev_hash = block_hash

        # Attestation for the head block
        head_hash = prev_hash
        attestations = {
            ValidatorIndex(0): build_signed_attestation(
                key_manager=xmss_key_manager,
                validator=ValidatorIndex(0),
                target=Checkpoint(root=head_hash, slot=Slot(9)),
            )
        }

        # Should find the head
        result = get_fork_choice_head(
            blocks=blocks,
            root=list(blocks.keys())[0],  # Genesis
            latest_attestations=attestations,
            min_score=0,
        )

        assert result == head_hash

    def test_fork_choice_ancestor_attestations(self, xmss_key_manager: XmssKeyManager) -> None:
        """Test that attestations for ancestors are properly counted."""
        # Create chain: genesis -> A -> B -> C
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis)

        block_a = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block_a" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_a_hash = hash_tree_root(block_a)

        block_b = Block(
            slot=Slot(2),
            proposer_index=Uint64(2),
            parent_root=block_a_hash,
            state_root=Bytes32(b"block_b" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_b_hash = hash_tree_root(block_b)

        block_c = Block(
            slot=Slot(3),
            proposer_index=Uint64(3),
            parent_root=block_b_hash,
            state_root=Bytes32(b"block_c" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_c_hash = hash_tree_root(block_c)

        blocks = {
            genesis_hash: genesis,
            block_a_hash: block_a,
            block_b_hash: block_b,
            block_c_hash: block_c,
        }

        # Attestation for ancestor should still find the head
        attestations = {
            ValidatorIndex(0): build_signed_attestation(
                key_manager=xmss_key_manager,
                validator=ValidatorIndex(0),
                target=Checkpoint(root=block_a_hash, slot=Slot(1)),
            ),
        }

        head = get_fork_choice_head(
            blocks=blocks,
            root=genesis_hash,
            latest_attestations=attestations,
            min_score=0,
        )

        # Should follow chain to the end
        assert head == block_c_hash

    def test_fork_choice_with_min_score(self, xmss_key_manager: XmssKeyManager) -> None:
        """Test fork choice algorithm with minimum score threshold."""
        genesis = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis)

        block_a = Block(
            slot=Slot(1),
            proposer_index=Uint64(1),
            parent_root=genesis_hash,
            state_root=Bytes32(b"block_a" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        block_a_hash = hash_tree_root(block_a)

        blocks = {
            genesis_hash: genesis,
            block_a_hash: block_a,
        }

        # Single attestation shouldn't meet min_score of 2
        attestations = {
            ValidatorIndex(0): build_signed_attestation(
                key_manager=xmss_key_manager,
                validator=ValidatorIndex(0),
                target=Checkpoint(root=block_a_hash, slot=Slot(1)),
            )
        }

        head = get_fork_choice_head(
            blocks=blocks,
            root=genesis_hash,
            latest_attestations=attestations,
            min_score=2,  # Require at least 2 attestations
        )

        # Should fall back to root when min_score not met
        assert head == genesis_hash


class TestStoreBasedForkChoice:
    """Test fork choice algorithm through Store integration."""

    @pytest.fixture
    def config(self) -> Config:
        """Sample configuration."""
        return Config(genesis_time=Uint64(1000))

    def test_store_fork_choice_no_attestations(self, config: Config) -> None:
        """Test Store.get_proposal_head with no attestations."""
        genesis_block = Block(
            slot=Slot(0),
            proposer_index=Uint64(0),
            parent_root=Bytes32.zero(),
            state_root=Bytes32(b"genesis" + b"\x00" * 25),
            body=BlockBody(attestations=Attestations(data=[])),
        )
        genesis_hash = hash_tree_root(genesis_block)

        finalized = Checkpoint(root=genesis_hash, slot=Slot(0))

        store = Store(
            time=Uint64(100),
            config=config,
            head=genesis_hash,
            safe_target=genesis_hash,
            latest_justified=finalized,
            latest_finalized=finalized,
            blocks={genesis_hash: genesis_block},
            states={},
        )

        # Get proposal head for slot 0
        head = store.get_proposal_head(Slot(0))

        # Should return current head
        assert head == store.head
