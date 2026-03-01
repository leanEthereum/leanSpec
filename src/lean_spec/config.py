"""
Global configuration for the Lean Ethereum specifications.

This module contains environment-specific settings that apply across all subspecs.
"""

from __future__ import annotations

import os
from typing import Final, Literal, cast, get_args

type LeanEnvMode = Literal["test", "prod"]
"""The supported environment modes."""

_SUPPORTED_LEAN_ENVS: Final[set[str]] = set(get_args(LeanEnvMode.__value__))

_raw_env = os.environ.get("LEAN_ENV", "prod").lower()

if _raw_env not in _SUPPORTED_LEAN_ENVS:
    raise ValueError(
        f"Invalid LEAN_ENV environment variable: '{_raw_env}'. "
        f"Supported values: {sorted(_SUPPORTED_LEAN_ENVS)}"
    )

LEAN_ENV: Final[LeanEnvMode] = cast("LeanEnvMode", _raw_env)
"""The environment flag ('prod' or 'test'). Defaults to 'prod' for the specs."""
