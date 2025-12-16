"""
Global configuration for the Lean Ethereum specifications.

This module contains environment-specific settings that apply across all subspecs.
"""

import os

_SUPPORTED_LEAN_ENVS: list[str] = ["prod", "test"]

LEAN_ENV = os.environ.get("LEAN_ENV", "prod").lower()
"""The environment flag ('prod' or 'test'). Defaults to 'prod' for the specs."""

if LEAN_ENV not in _SUPPORTED_LEAN_ENVS:
    raise ValueError(
        f"Invalid LEAN_ENV environment variable: '{LEAN_ENV}'. "
        f"Supported values: {_SUPPORTED_LEAN_ENVS}"
    )
