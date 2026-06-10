"""API endpoint conformance vectors after the chain has advanced past genesis."""

import pytest

from consensus_testing import ApiEndpointTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


GENESIS_4V_AT_SLOT_3 = {"numValidators": 4, "genesisTime": 0, "anchorSlot": 3}
"""4-validator store advanced through three empty blocks past genesis."""


def test_fork_choice_tree_at_slot_3(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The fork-choice endpoint returns a multi-node tree once the chain advances.

    Given
    -----
    - 4 validators.
    - the chain has advanced to slot 3.
    - the store holds four blocks (genesis plus slots 1 through 3).

    When
    ----
    - the fork-choice endpoint is queried.

    Then
    ----
    - the response lists all four nodes.
    - the response pins the head root.
    - the response pins the parent-root linkage.
    """
    api_endpoint_test(endpoint="/lean/v0/fork_choice", genesis_params=GENESIS_4V_AT_SLOT_3)


def test_finalized_state_at_slot_3(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The finalized-state endpoint returns the anchor state after the chain advances.

    Given
    -----
    - 4 validators.
    - the chain has processed three empty blocks to slot 3.
    - no attestations have been injected.

    When
    ----
    - the finalized-state endpoint is queried.

    Then
    ----
    - finalization stays at genesis.
    - the served state carries non-empty historical block hashes.
    - the exact serialized state bytes are pinned.
    """
    api_endpoint_test(endpoint="/lean/v0/states/finalized", genesis_params=GENESIS_4V_AT_SLOT_3)


def test_justified_checkpoint_at_slot_3(api_endpoint_test: ApiEndpointTestFiller) -> None:
    """
    The justified-checkpoint endpoint reports the genesis root at a non-genesis slot.

    Given
    -----
    - 4 validators.
    - the chain has advanced to slot 3.
    - no attestations have been injected.

    When
    ----
    - the justified-checkpoint endpoint is queried.

    Then
    ----
    - justification stays at genesis.
    - the response reports the slot-0 checkpoint root.
    """
    api_endpoint_test(
        endpoint="/lean/v0/checkpoints/justified",
        genesis_params=GENESIS_4V_AT_SLOT_3,
    )
