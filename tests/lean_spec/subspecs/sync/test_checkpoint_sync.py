"""Tests for checkpoint sync client functionality."""

from __future__ import annotations

import asyncio

from lean_spec.subspecs.api import ApiServer, ApiServerConfig
from lean_spec.subspecs.containers import State
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import Validators
from lean_spec.subspecs.forkchoice import Store
from lean_spec.subspecs.sync.checkpoint_sync import (
    fetch_finalized_state,
    verify_checkpoint_state,
)


class TestStateVerification:
    """Tests for checkpoint state verification logic."""

    def test_valid_state_passes_verification(self, genesis_state: State) -> None:
        """Valid state with validators passes verification checks."""

        async def run_test() -> None:
            result = await verify_checkpoint_state(genesis_state)
            assert result is True

        asyncio.run(run_test())

    def test_state_without_validators_fails_verification(self, genesis_state: State) -> None:
        """State with no validators fails verification."""

        async def run_test() -> None:
            empty_state = State(
                config=genesis_state.config,
                slot=genesis_state.slot,
                latest_block_header=genesis_state.latest_block_header,
                latest_justified=genesis_state.latest_justified,
                latest_finalized=genesis_state.latest_finalized,
                historical_block_hashes=genesis_state.historical_block_hashes,
                justified_slots=genesis_state.justified_slots,
                validators=Validators(data=[]),
                justifications_roots=genesis_state.justifications_roots,
                justifications_validators=genesis_state.justifications_validators,
            )

            result = await verify_checkpoint_state(empty_state)
            assert result is False

        asyncio.run(run_test())


class TestCheckpointSyncClientServerIntegration:
    """Integration tests for checkpoint sync client fetching from server."""

    def test_client_fetches_and_deserializes_state(self, base_store: Store) -> None:
        """Client successfully fetches and deserializes state from server."""

        async def run_test() -> None:
            config = ApiServerConfig(port=15058)
            server = ApiServer(config=config, store_getter=lambda: base_store)

            await server.start()

            try:
                state = await fetch_finalized_state("http://127.0.0.1:15058", State)

                assert state is not None
                assert state.slot == Slot(0)

                is_valid = await verify_checkpoint_state(state)
                assert is_valid is True

            finally:
                server.stop()
                await asyncio.sleep(0.1)

        asyncio.run(run_test())
