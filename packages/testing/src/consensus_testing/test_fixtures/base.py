"""Base fixture definitions for consensus test formats."""

import os
from functools import cached_property
from typing import Any, ClassVar

from framework.test_fixtures import BaseFixture
from pydantic import computed_field


class BaseConsensusFixture(BaseFixture):
    """
    Base class for all consensus test fixtures.

    Inherits shared functionality from framework.fixtures.BaseFixture
    and adds consensus-specific behavior if needed.
    """

    # Class-level registry of all consensus fixture formats
    # Override parent's formats to maintain a separate registry
    formats: ClassVar[dict[str, type["BaseConsensusFixture"]]] = {}  # type: ignore[assignment]

    @computed_field  # type: ignore[prop-decorator]
    @cached_property
    def lean_env(self) -> str:
        """The lean environment being used (e.g. 'test' or 'prod'). Defaults to 'test'."""
        return os.environ.get("LEAN_ENV", "test").lower()

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        """
        Auto-register consensus fixture formats when subclasses are defined.

        Overrides parent to register in BaseConsensusFixture.formats instead
        of BaseFixture.formats.
        """
        super().__pydantic_init_subclass__(**kwargs)
        if cls.format_name:
            BaseConsensusFixture.formats[cls.format_name] = cls
