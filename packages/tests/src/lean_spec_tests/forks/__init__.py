"""Fork definitions for consensus layer testing."""

from typing import Type

from .base import BaseFork
from .devnet import Devnet

Fork = Type[BaseFork]

__all__ = ["BaseFork", "Fork", "Devnet"]
