"""Tests for the boot anchor builder."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from lean_spec.node.anchor import Anchor
from lean_spec.node.genesis import GenesisConfig
from lean_spec.node.sync.checkpoint_sync import CheckpointSyncError
from lean_spec.spec.forks import Slot
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import Bytes32
from tests.lean_spec.helpers import make_genesis_state


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
                "lean_spec.node.anchor.fetch_finalized_state",
                new_callable=AsyncMock,
                return_value=checkpoint_state,
            ),
            pytest.raises(CheckpointSyncError, match="genesis time mismatch"),
        ):
            await Anchor.from_checkpoint(
                url="http://localhost:5052",
                genesis=local_genesis,
                fork=LstarSpec(),
                validator_id=None,
            )

    async def test_verification_failure_raises(self) -> None:
        """Structural verification failure raises CheckpointSyncError."""
        checkpoint_state = make_genesis_state(num_validators=3, genesis_time=1000)
        local_genesis = GenesisConfig.model_validate(
            {"GENESIS_TIME": 1000, "GENESIS_VALIDATORS": []}
        )

        with (
            patch(
                "lean_spec.node.anchor.fetch_finalized_state",
                new_callable=AsyncMock,
                return_value=checkpoint_state,
            ),
            patch(
                "lean_spec.node.anchor.verify_checkpoint_state",
                return_value=False,
            ),
            pytest.raises(CheckpointSyncError, match="structural verification"),
        ):
            await Anchor.from_checkpoint(
                url="http://localhost:5052",
                genesis=local_genesis,
                fork=LstarSpec(),
                validator_id=None,
            )

    async def test_network_error_propagates(self) -> None:
        """Network errors surface as CheckpointSyncError."""
        local_genesis = GenesisConfig.model_validate(
            {"GENESIS_TIME": 1000, "GENESIS_VALIDATORS": []}
        )

        with (
            patch(
                "lean_spec.node.anchor.fetch_finalized_state",
                new_callable=AsyncMock,
                side_effect=CheckpointSyncError("connection refused"),
            ),
            pytest.raises(CheckpointSyncError, match="connection refused"),
        ):
            await Anchor.from_checkpoint(
                url="http://localhost:5052",
                genesis=local_genesis,
                fork=LstarSpec(),
                validator_id=None,
            )

    async def test_success_builds_store_and_status(self) -> None:
        """Successful checkpoint sync produces a populated anchor."""
        genesis_time = 1000
        checkpoint_state = make_genesis_state(num_validators=3, genesis_time=genesis_time)
        local_genesis = GenesisConfig.model_validate(
            {"GENESIS_TIME": genesis_time, "GENESIS_VALIDATORS": []}
        )

        with patch(
            "lean_spec.node.anchor.fetch_finalized_state",
            new_callable=AsyncMock,
            return_value=checkpoint_state,
        ):
            anchor = await Anchor.from_checkpoint(
                url="http://localhost:5052",
                genesis=local_genesis,
                fork=LstarSpec(),
                validator_id=None,
            )

        assert anchor.store is not None
        assert anchor.validators == checkpoint_state.validators
        assert anchor.initial_status.finalized == anchor.store.latest_finalized
