"""
API server module for checkpoint sync and node status endpoints.

Provides HTTP endpoints for:
- /lean/v0/states/finalized - Serve finalized checkpoint state as SSZ
- /lean/v0/checkpoints/justified - Return latest justified checkpoint information
- /lean/v0/health - Health check endpoint
- /metrics - Prometheus metrics endpoint
"""

from .server import ApiServer, ApiServerConfig

__all__ = [
    "ApiServer",
    "ApiServerConfig",
]
