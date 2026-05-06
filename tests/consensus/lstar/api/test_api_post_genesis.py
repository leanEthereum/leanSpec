"""API endpoint conformance vectors after the chain has advanced past genesis.

Existing API fixtures pin responses against a genesis-only store. This
file pins the same endpoints after an empty-block chain has advanced,
so clients' response shapes at non-zero slots are also captured.
"""

import pytest
from consensus_testing import ApiEndpointTestFiller

pytestmark = pytest.mark.valid_until("Lstar")


GENESIS_4V_AT_SLOT_3 = {"numValidators": 4, "genesisTime": 0, "anchorSlot": 3}
"""4-validator store advanced through three empty blocks past genesis."""


def test_fork_choice_tree_at_slot_3(api_endpoint: ApiEndpointTestFiller) -> None:
    """Fork-choice response carries a multi-node tree once the chain advances.

    With the chain at slot 3 the store holds four blocks (genesis plus
    slots 1 through 3). The response's nodes list, head root, and
    parent-root linkage are pinned so clients diverge only when their
    tree traversal or SSZ root computation differs.
    """
    api_endpoint(endpoint="/lean/v0/fork_choice", genesis_params=GENESIS_4V_AT_SLOT_3)


def test_finalized_state_at_slot_3(api_endpoint: ApiEndpointTestFiller) -> None:
    """Finalized-state response returns the SSZ-encoded anchor state after chain advance.

    Finalization has not yet moved past genesis (no attestations have
    been injected), but the served state now carries non-empty
    historical_block_hashes because the chain has processed three empty
    blocks. Pins the exact SSZ bytes at that configuration.
    """
    api_endpoint(endpoint="/lean/v0/states/finalized", genesis_params=GENESIS_4V_AT_SLOT_3)


def test_justified_checkpoint_at_slot_3(api_endpoint: ApiEndpointTestFiller) -> None:
    """Justified-checkpoint response at a non-genesis slot pins the slot=0 root.

    Without attestations, justification remains at genesis even after
    the chain advances. This vector pins that the response still
    reports the genesis checkpoint, not a synthesised advance.
    """
    api_endpoint(
        endpoint="/lean/v0/checkpoints/justified",
        genesis_params=GENESIS_4V_AT_SLOT_3,
    )
