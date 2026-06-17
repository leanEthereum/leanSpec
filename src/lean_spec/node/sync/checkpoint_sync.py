"""Checkpoint sync: download a recent finalized state instead of replaying from genesis."""

from __future__ import annotations

import logging
from typing import Final

import httpx

from lean_spec.spec.forks import VALIDATOR_REGISTRY_LIMIT, SignedBlock, State

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT: Final = 60.0
"""
Seconds allowed per request.

Finalized state runs tens of megabytes, so the transfer needs a wide window.
"""

FINALIZED_STATE_ENDPOINT: Final = "/lean/v0/states/finalized"
"""Beacon API path for the finalized state."""

FINALIZED_BLOCK_ENDPOINT: Final = "/lean/v0/blocks/finalized"
"""API endpoint for fetching the signed block matching the finalized state."""


class CheckpointSyncError(Exception):
    """
    Checkpoint state could not be fetched or failed validation.

    Startup aborts on this error rather than falling back to genesis sync.
    """


async def fetch_finalized_state(url: str, state_class: type[State]) -> State:
    """
    Download and decode finalized state from a node.

    Args:
        url: Base URL of the node API.
        state_class: State class used to decode the SSZ bytes.

    Returns:
        The decoded finalized state.

    Raises:
        CheckpointSyncError: The request failed or the bytes did not decode.
    """
    base_url = url.rstrip("/")
    full_url = f"{base_url}{FINALIZED_STATE_ENDPOINT}"

    logger.info("Fetching finalized state from %s", full_url)

    # Ask for raw SSZ bytes rather than JSON.
    headers = {"Accept": "application/octet-stream"}

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.get(full_url, headers=headers)
            response.raise_for_status()
            ssz_bytes = response.content
    except httpx.HTTPStatusError as exception:
        raise CheckpointSyncError(
            f"HTTP error {exception.response.status_code}: {exception.response.text[:200]}"
        ) from exception
    except httpx.RequestError as exception:
        raise CheckpointSyncError(
            f"Network error while connecting to {exception.request.url}: {exception}"
        ) from exception

    logger.info("Downloaded %d bytes of SSZ state data", len(ssz_bytes))

    # SSZ decode validates the byte stream against the schema.
    # A truncated download or a JSON body fails here.
    try:
        state = state_class.decode_bytes(ssz_bytes)
    except Exception as exception:
        raise CheckpointSyncError(f"Corrupt checkpoint state payload: {exception}") from exception

    logger.info("Deserialized state at slot %s", state.slot)
    return state


async def fetch_finalized_block(url: str) -> SignedBlock:
    """
    Fetch the signed block matching the finalized state via checkpoint sync.

    Args:
        url: Base URL of the node API.

    Returns:
        The finalized signed block.

    Raises:
        CheckpointSyncError: If the request fails or block bytes are invalid.
    """
    base_url = url.rstrip("/")
    full_url = f"{base_url}{FINALIZED_BLOCK_ENDPOINT}"

    logger.info("Fetching finalized signed block from %s", full_url)

    headers = {"Accept": "application/octet-stream"}

    try:
        async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.get(full_url, headers=headers)
            response.raise_for_status()

            ssz_data = response.content
            logger.info("Downloaded %d bytes of SSZ signed block data", len(ssz_data))

            signed_block = SignedBlock.decode_bytes(ssz_data)
            logger.info("Deserialized signed block at slot %s", signed_block.block.slot)

            return signed_block

    except httpx.RequestError as exception:
        raise CheckpointSyncError(
            f"Network error while connecting to {exception.request.url}: {exception}"
        ) from exception
    except httpx.HTTPStatusError as exception:
        raise CheckpointSyncError(
            f"HTTP error {exception.response.status_code}: {exception.response.text[:200]}"
        ) from exception
    except Exception as exception:
        raise CheckpointSyncError(f"Failed to fetch signed block: {exception}") from exception


def verify_checkpoint_state(state: State) -> bool:
    """
    Check structural invariants on a downloaded checkpoint state.

    Args:
        state: The state to check.

    Returns:
        True when every invariant holds, False otherwise.
    """
    # A state with no validators cannot drive fork choice or produce blocks.
    validator_count = len(state.validators)
    if validator_count == 0:
        logger.error("Invalid checkpoint state: no validators")
        return False

    # Bound an attacker-supplied blob against the registry capacity.
    if validator_count > int(VALIDATOR_REGISTRY_LIMIT):
        logger.error(
            "Invalid checkpoint state: validator count %d exceeds registry limit %s",
            validator_count,
            VALIDATOR_REGISTRY_LIMIT,
        )
        return False

    logger.info("Checkpoint state verified at slot %s", state.slot)
    return True
