"""
API server module for checkpoint sync and node status endpoints.

Provides HTTP endpoints for:
- /lean/v0/states/finalized - Serve finalized checkpoint state as SSZ
- /lean/v0/health - Health check endpoint

Also provides a client for checkpoint sync:
- fetch_finalized_state: Download finalized state from a node
"""

from .client import (
    CheckpointSyncError,
    fetch_finalized_state,
    verify_checkpoint_state,
)
from .server import ApiServer, ApiServerConfig

__all__ = [
    "ApiServer",
    "ApiServerConfig",
    "CheckpointSyncError",
    "fetch_finalized_state",
    "verify_checkpoint_state",
]
