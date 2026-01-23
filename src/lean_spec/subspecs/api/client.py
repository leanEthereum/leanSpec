"""
Checkpoint sync client for downloading finalized state from another node.

Checkpoint sync enables fast startup by skipping historical block processing.
Instead of replaying every block from genesis, a node downloads a recent
finalized state and starts from there.

Trust model:

- The operator trusts the checkpoint source to provide valid finalized state
- This trust is acceptable because finalized state has 2/3 validator support
- The alternative (genesis sync) may take hours or days on mainnet

The trade-off is trustlessness for speed. Most operators accept this because
they already trust their checkpoint source (often their own infrastructure
or a well-known provider).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx

from lean_spec.subspecs.chain.config import VALIDATOR_REGISTRY_LIMIT
from lean_spec.subspecs.containers import Slot
from lean_spec.subspecs.ssz.hash import hash_tree_root

if TYPE_CHECKING:
    from lean_spec.subspecs.containers import State

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 60.0
"""HTTP request timeout in seconds. Large states may take time to transfer."""

FINALIZED_STATE_ENDPOINT = "/lean/v0/states/finalized"
"""API endpoint for fetching finalized state. Follows Beacon API conventions."""


class CheckpointSyncError(Exception):
    """
    Error during checkpoint sync.

    Raised when the checkpoint state cannot be fetched or is invalid.
    Callers should handle this by aborting startup (not falling back).
    """


async def fetch_finalized_state(url: str, state_class: type[Any]) -> "State":
    """
    Fetch finalized state from a node via checkpoint sync.

    Downloads the state as SSZ binary and deserializes it. SSZ format is
    preferred over JSON because state objects are large (tens of MB) and
    SSZ is more compact and faster to parse.

    Args:
        url: Base URL of the node API (e.g., "http://localhost:5052").
        state_class: The State class to deserialize into.

    Returns:
        The finalized State object.

    Raises:
        CheckpointSyncError: If the request fails or state is invalid.
    """
    base_url = url.rstrip("/")
    full_url = f"{base_url}{FINALIZED_STATE_ENDPOINT}"

    logger.info(f"Fetching finalized state from {full_url}")

    # Request SSZ binary format.
    #
    # The Accept header tells the server we want raw bytes, not JSON.
    # This is faster to transfer and parse than JSON encoding.
    headers = {"Accept": "application/octet-stream"}

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.get(full_url, headers=headers)
            response.raise_for_status()

            ssz_data = response.content
            logger.info(f"Downloaded {len(ssz_data)} bytes of SSZ state data")

            # Deserialize from SSZ bytes.
            #
            # This validates the byte stream matches the expected schema.
            # Malformed data will raise an exception here.
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
    except Exception as e:
        raise CheckpointSyncError(f"Failed to fetch state: {e}") from e


async def verify_checkpoint_state(state: "State") -> bool:
    """
    Verify that a checkpoint state is structurally valid.

    This is defense-in-depth validation. We trust the checkpoint source,
    but still verify basic invariants before using the state. These checks
    catch corrupted downloads or misconfigured servers.

    The checks are intentionally minimal:

    - Slot is non-negative (sanity check)
    - Validators exist (empty state is useless)
    - Validator count within limits (prevents DoS)

    We do NOT verify cryptographic proofs here. That would require
    the full block history, defeating the purpose of checkpoint sync.

    Args:
        state: The state to verify.

    Returns:
        True if valid, False otherwise.
    """
    try:
        # Sanity check: slot must be non-negative.
        if state.slot < Slot(0):
            logger.error("Invalid state: negative slot")
            return False

        # A state with no validators cannot produce blocks.
        validator_count = len(state.validators)
        if validator_count == 0:
            logger.error("Invalid state: no validators")
            return False

        # Guard against oversized states that could exhaust memory.
        if validator_count > int(VALIDATOR_REGISTRY_LIMIT):
            logger.error(
                f"Invalid state: validator count {validator_count} exceeds "
                f"registry limit {VALIDATOR_REGISTRY_LIMIT}"
            )
            return False

        # Compute state root to verify SSZ deserialization worked correctly.
        #
        # If the data was corrupted, hashing will likely fail or produce
        # an unexpected result. We log the root for debugging.
        state_root = hash_tree_root(state)
        root_preview = state_root.hex()[:16]
        logger.info(f"Checkpoint state verified: slot={state.slot}, root={root_preview}...")
        return True

    except Exception as e:
        logger.error(f"State verification failed: {e}")
        return False
