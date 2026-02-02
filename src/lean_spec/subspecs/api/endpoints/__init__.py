"""
API endpoint specifications.

Each module defines the spec (routes, constants, response formats) and handlers
for a specific endpoint:

- health: Health check endpoint
- checkpoint_sync: Finalized state and justified checkpoint endpoints
- metrics: Prometheus metrics endpoint (optional)
"""

from . import checkpoint_sync, health, metrics

__all__ = [
    "checkpoint_sync",
    "health",
    "metrics",
]
