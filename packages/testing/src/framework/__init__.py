"""
Shared testing infrastructure for Ethereum consensus and execution layers.

This module provides base classes and utilities that are common across
both consensus and execution layer testing.
"""

from .markers import requires_capability

__all__ = ["requires_capability"]
