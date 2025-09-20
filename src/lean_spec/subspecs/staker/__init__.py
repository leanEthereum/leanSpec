"""
Specifications for the staker's protocol participation roles and
settings.
"""

from .config import DEVNET_STAKER_CONFIG
from .role import AttesterRole, IncluderRole, ProposerRole
from .settings import StakerSettings

__all__ = ["DEVNET_STAKER_CONFIG", "AttesterRole", "IncluderRole", "ProposerRole", "StakerSettings"]
