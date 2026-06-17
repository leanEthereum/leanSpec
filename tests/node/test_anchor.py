"""Tests for the boot anchor builder."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from consensus_testing import (
    make_genesis_state,
    reconstruct_block_from_header,
    signed_block_with_empty_proof,
)
from lean_spec.node.anchor import Anchor
from lean_spec.node.genesis import GenesisConfig
from lean_spec.node.sync.checkpoint_sync import CheckpointSyncError
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import SignedBlock, Slot
from lean_spec.spec.forks.lstar import State
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32


def _signed_genesis_block(state: State) -> SignedBlock:
    """Wrap the genesis block matching a state with an empty proof."""
    return signed_block_with_empty_proof(reconstruct_block_from_header(state))


class TestAnchorFromGenesis:
    """Tests for the synchronous genesis anchor builder."""

    def test_anchor_from_genesis_has_zero_status_and_no_store(self) -> None:
        """Genesis anchors carry zero checkpoints and no pre-built store."""
        genesis = GenesisConfig.model_validate({"GENESIS_TIME": 1000, "GENESIS_VALIDATORS": []})

        anchor = Anchor.from_genesis(genesis)

        assert anchor.store is None
        assert anchor.initial_status.finalized.root == Bytes32.zero()
        assert anchor.initial_status.finalized.slot == Slot(0)
        assert anchor.initial_status.head.root == Bytes32.zero()
        assert anchor.initial_status.head.slot == Slot(0)
        assert anchor.validators == genesis.to_validators()


class TestAnchorFromCheckpoint:
    """Tests for the asynchronous checkpoint anchor builder."""

    async def test_genesis_time_mismatch_raises(self) -> None:
        """Mismatched genesis time raises a typed CheckpointSyncError."""
        checkpoint_state = make_genesis_state(num_validators=3, genesis_time=1000)
        local_genesis = GenesisConfig.model_validate(
            {"GENESIS_TIME": 2000, "GENESIS_VALIDATORS": []}
        )

        with (
            patch(
                "lean_spec.node.anchor.fetch_finalized_block",
                new_callable=AsyncMock,
                return_value=_signed_genesis_block(checkpoint_state),
            ),
            patch(
                "lean_spec.node.anchor.fetch_finalized_state",
                new_callable=AsyncMock,
                return_value=checkpoint_state,
            ),
            pytest.raises(CheckpointSyncError) as exception_info,
        ):
            await Anchor.from_checkpoint(
                url="http://localhost:5052",
                genesis=local_genesis,
                fork=LstarSpec(),
                validator_index=None,
            )
        assert str(exception_info.value) == ("genesis time mismatch: checkpoint=1000, local=2000")

    async def test_verification_failure_raises(self) -> None:
        """Structural verification failure raises CheckpointSyncError."""
        checkpoint_state = make_genesis_state(num_validators=3, genesis_time=1000)
        local_genesis = GenesisConfig.model_validate(
            {"GENESIS_TIME": 1000, "GENESIS_VALIDATORS": []}
        )

        with (
            patch(
                "lean_spec.node.anchor.fetch_finalized_block",
                new_callable=AsyncMock,
                return_value=_signed_genesis_block(checkpoint_state),
            ),
            patch(
                "lean_spec.node.anchor.fetch_finalized_state",
                new_callable=AsyncMock,
                return_value=checkpoint_state,
            ),
            patch(
                "lean_spec.node.anchor.verify_checkpoint_state",
                return_value=False,
            ),
            pytest.raises(CheckpointSyncError) as exception_info,
        ):
            await Anchor.from_checkpoint(
                url="http://localhost:5052",
                genesis=local_genesis,
                fork=LstarSpec(),
                validator_index=None,
            )
        assert str(exception_info.value) == ("checkpoint state failed structural verification")

    async def test_block_fetch_failure_propagates(self) -> None:
        """A source that cannot serve the finalized block aborts checkpoint sync."""
        local_genesis = GenesisConfig.model_validate(
            {"GENESIS_TIME": 1000, "GENESIS_VALIDATORS": []}
        )

        with (
            patch(
                "lean_spec.node.anchor.fetch_finalized_block",
                new_callable=AsyncMock,
                side_effect=CheckpointSyncError("HTTP error 503: no signed block source"),
            ),
            pytest.raises(CheckpointSyncError) as exception_info,
        ):
            await Anchor.from_checkpoint(
                url="http://localhost:5052",
                genesis=local_genesis,
                fork=LstarSpec(),
                validator_index=None,
            )
        assert str(exception_info.value) == "HTTP error 503: no signed block source"

    async def test_state_fetch_failure_propagates(self) -> None:
        """Network errors on the state fetch surface as CheckpointSyncError."""
        checkpoint_state = make_genesis_state(num_validators=3, genesis_time=1000)
        local_genesis = GenesisConfig.model_validate(
            {"GENESIS_TIME": 1000, "GENESIS_VALIDATORS": []}
        )

        with (
            patch(
                "lean_spec.node.anchor.fetch_finalized_block",
                new_callable=AsyncMock,
                return_value=_signed_genesis_block(checkpoint_state),
            ),
            patch(
                "lean_spec.node.anchor.fetch_finalized_state",
                new_callable=AsyncMock,
                side_effect=CheckpointSyncError("connection refused"),
            ),
            pytest.raises(CheckpointSyncError) as exception_info,
        ):
            await Anchor.from_checkpoint(
                url="http://localhost:5052",
                genesis=local_genesis,
                fork=LstarSpec(),
                validator_index=None,
            )
        assert str(exception_info.value) == "connection refused"

    async def test_success_builds_store_and_status(self) -> None:
        """Successful checkpoint sync produces a populated anchor."""
        genesis_time = 1000
        checkpoint_state = make_genesis_state(num_validators=3, genesis_time=genesis_time)
        signed_block = _signed_genesis_block(checkpoint_state)
        local_genesis = GenesisConfig.model_validate(
            {"GENESIS_TIME": genesis_time, "GENESIS_VALIDATORS": []}
        )

        with (
            patch(
                "lean_spec.node.anchor.fetch_finalized_state",
                new_callable=AsyncMock,
                return_value=checkpoint_state,
            ),
            patch(
                "lean_spec.node.anchor.fetch_finalized_block",
                new_callable=AsyncMock,
                return_value=signed_block,
            ),
        ):
            anchor = await Anchor.from_checkpoint(
                url="http://localhost:5052",
                genesis=local_genesis,
                fork=LstarSpec(),
                validator_index=None,
            )

        assert anchor.store is not None
        assert anchor.validators == checkpoint_state.validators
        assert anchor.initial_status.finalized == anchor.store.latest_finalized
        # The anchor is keyed by the fetched block's root, so the store's
        # finalized checkpoint matches the root the network agrees on.
        assert anchor.store.latest_finalized.root == hash_tree_root(signed_block.block)
        # The fetched block, not a synthetic placeholder, is the one stored.
        assert hash_tree_root(signed_block.block) in anchor.store.blocks

    async def test_block_state_pairing_mismatch_raises(self) -> None:
        """A block not matching the fetched state raises instead of falling back."""
        genesis_time = 1000
        checkpoint_state = make_genesis_state(num_validators=3, genesis_time=genesis_time)
        other_state = make_genesis_state(num_validators=4, genesis_time=genesis_time)
        mismatched_block = _signed_genesis_block(other_state)
        local_genesis = GenesisConfig.model_validate(
            {"GENESIS_TIME": genesis_time, "GENESIS_VALIDATORS": []}
        )

        with (
            patch(
                "lean_spec.node.anchor.fetch_finalized_state",
                new_callable=AsyncMock,
                return_value=checkpoint_state,
            ),
            patch(
                "lean_spec.node.anchor.fetch_finalized_block",
                new_callable=AsyncMock,
                return_value=mismatched_block,
            ),
            pytest.raises(CheckpointSyncError) as exception_info,
        ):
            await Anchor.from_checkpoint(
                url="http://localhost:5052",
                genesis=local_genesis,
                fork=LstarSpec(),
                validator_index=None,
            )
        assert str(exception_info.value) == (
            "anchor block / state mismatch; source advanced finalization between requests, retry"
        )
