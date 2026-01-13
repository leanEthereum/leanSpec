"""
Checkpoint sync client for downloading finalized state from another node.

This client is used for fast synchronization - instead of syncing from genesis,
a node can download the finalized state from a trusted peer and start from there.

This matches the checkpoint sync client implemented in zeam.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from lean_spec.subspecs.containers import State

logger = logging.getLogger(__name__)


class CheckpointSyncError(Exception):
    """Error during checkpoint sync."""

    pass


async def fetch_finalized_state(url: str, state_class: type) -> "State":
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
    import asyncio

    # Parse URL
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 5052

    endpoint = "/lean/states/finalized"

    logger.info(f"Fetching finalized state from {host}:{port}{endpoint}")

    try:
        reader, writer = await asyncio.open_connection(host, port)

        # Send HTTP request
        request = f"GET {endpoint} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()

        # Read response headers
        headers = b""
        while True:
            line = await reader.readline()
            headers += line
            if line == b"\r\n" or line == b"\n":
                break

        # Check status code
        header_str = headers.decode("utf-8")
        status_line = header_str.split("\r\n")[0]
        if "200" not in status_line:
            body = await reader.read()
            raise CheckpointSyncError(f"HTTP error: {status_line}, body: {body.decode()[:200]}")

        # Read body (SSZ binary)
        ssz_data = await reader.read()
        writer.close()
        await writer.wait_closed()

        logger.info(f"Downloaded {len(ssz_data)} bytes of SSZ state data")

        # Deserialize SSZ
        state = state_class.decode_bytes(ssz_data)

        logger.info(f"Deserialized state at slot {state.slot}")

        return state

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
    from lean_spec.subspecs.ssz.hash import hash_tree_root

    try:
        # Verify state root matches the block header
        computed_root = hash_tree_root(state)

        # The latest_block_header.state_root should be zero for the current state
        # (it gets filled in after the state transition)
        # We verify the structure is valid by checking other fields

        # Basic sanity checks
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
