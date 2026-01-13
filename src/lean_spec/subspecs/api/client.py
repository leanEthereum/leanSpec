"""
Checkpoint sync client for downloading finalized state from another node.

This client is used for fast synchronization - instead of syncing from genesis,
a node can download the finalized state from a trusted peer and start from there.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

from lean_spec.subspecs.ssz.hash import hash_tree_root

if TYPE_CHECKING:
    from lean_spec.subspecs.containers import State

logger = logging.getLogger(__name__)

# Constants
DEFAULT_TIMEOUT = 60.0
FINALIZED_STATE_ENDPOINT = "/lean/states/finalized"


class CheckpointSyncError(Exception):
    """Error during checkpoint sync."""

    pass


async def fetch_finalized_state(url: str, state_class: type[Any]) -> "State":
    """
    Fetch finalized state from a node via checkpoint sync.

    Downloads the finalized state as SSZ binary and deserializes it.

    Args:
        url: Base URL of the node API (e.g., "http://localhost:5052")
        state_class: The State class to deserialize into

    Returns:
        The finalized State object

    Raises:
        CheckpointSyncError: If the request fails or state is invalid
    """
    base_url = url.rstrip("/")
    full_url = f"{base_url}{FINALIZED_STATE_ENDPOINT}"

    logger.info(f"Fetching finalized state from {full_url}")

    headers = {
        "Accept": "application/octet-stream",
    }

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.get(full_url, headers=headers)
            response.raise_for_status()

            ssz_data = response.content
            logger.info(f"Downloaded {len(ssz_data)} bytes of SSZ state data")

            state = state_class.decode_bytes(ssz_data)
            logger.info(f"Deserialized state at slot {state.slot}")

            return state

    except httpx.RequestError as exc:
        raise CheckpointSyncError(
            f"Network error while connecting to {exc.request.url}: {exc}"
        ) from exc
    except httpx.HTTPStatusError as exc:
        raise CheckpointSyncError(
            f"HTTP error {exc.response.status_code}: {exc.response.text[:200]}"
        ) from exc
    except CheckpointSyncError:
        raise
    except Exception as e:
        raise CheckpointSyncError(f"Failed to fetch state: {e}") from e


async def verify_checkpoint_state(state: "State") -> bool:
    """
    Verify that a checkpoint state is valid.

    Performs basic validation checks on the downloaded state.

    Args:
        state: The state to verify

    Returns:
        True if valid, False otherwise
    """
    try:
        computed_root = hash_tree_root(state)

        if int(state.slot) < 0:
            logger.error("Invalid state: negative slot")
            return False

        if len(state.validators) == 0:
            logger.error("Invalid state: no validators")
            return False

        root_preview = computed_root.hex()[:16]
        logger.info(f"Checkpoint state verified: slot={state.slot}, root={root_preview}...")
        return True

    except Exception as e:
        logger.error(f"State verification failed: {e}")
        return False
