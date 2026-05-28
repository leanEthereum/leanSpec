"""Base fixture definitions for Ethereum test formats."""

import hashlib
import json
from functools import cached_property
from typing import Any, ClassVar

from pydantic import Field

from framework.forks import BaseFork
from lean_spec.base import CamelModel
from lean_spec.config import LEAN_ENV


class BaseFixture(CamelModel):
    """
    Base class for all Ethereum test fixtures (consensus and execution layers).

    Provides:
    - Auto-registration of fixture formats
    - JSON serialization with custom encoders
    - Hash generation for fixtures
    - Common metadata handling

    This base class is layer-agnostic and can be used for both consensus
    and execution layer fixtures.
    """

    # Class-level registry of all fixture formats
    formats: ClassVar[dict[str, type["BaseFixture"]]] = {}

    # Fixture format metadata
    format_name: ClassVar[str] = ""
    """The name of this fixture format (e.g., 'state_transition_test')."""

    description: ClassVar[str] = "Unknown fixture format"
    """Human-readable description of what this fixture tests."""

    # Instance fields
    network: str | None = None
    """The fork/network this fixture is valid for (e.g., 'Devnet', 'Shanghai')."""

    lean_env: str = Field(default=LEAN_ENV)
    """The target lean environment (e.g. 'test' or 'prod')."""

    info: dict[str, Any] = Field(default_factory=dict, alias="_info")
    """Metadata about the test (description, fork, etc.)."""

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        """
        Auto-register fixture formats when subclasses are defined.

        This hook is called automatically when a new subclass is created.
        Registration is a no-op here; layer base classes (e.g. BaseConsensusFixture)
        override this to register into their own separate registry.
        """
        super().__pydantic_init_subclass__(**kwargs)

    @cached_property
    def json_dict(self) -> dict[str, Any]:
        """
        Return the JSON representation of the fixture.

        Excludes the `info` field and converts snake_case to camelCase.
        """
        return self.to_json(
            exclude_none=True,
            exclude={"info"},
        )

    @cached_property
    def hash(self) -> str:
        """
        Generate a deterministic hash for this fixture.

        The hash is computed from the JSON representation to ensure
        consistency across runs.
        """
        json_str = json.dumps(
            self.json_dict,
            sort_keys=True,
            separators=(",", ":"),
        )
        h = hashlib.sha256(json_str.encode("utf-8")).hexdigest()
        return f"0x{h}"

    def json_dict_with_info(self, hash_only: bool = False) -> dict[str, Any]:
        """
        Return JSON representation with the info field included.

        Args:
            hash_only: If True, only include the hash in _info.

        Returns:
            Dictionary ready for JSON serialization.
        """
        dict_with_info = self.json_dict.copy()
        dict_with_info["_info"] = {"hash": self.hash}
        if not hash_only:
            dict_with_info["_info"].update(self.info)
        return dict_with_info

    def fill_info(
        self,
        test_id: str,
        description: str,
        fork: BaseFork,
    ) -> None:
        """
        Fill metadata information for this fixture.

        Args:
            test_id: Unique identifier for the test case.
            description: Human-readable description of the test.
            fork: The fork this test is valid for.
        """
        if "comment" not in self.info:
            self.info["comment"] = "`leanSpec` generated test"
        self.info["testId"] = test_id
        self.info["description"] = description
        self.info["fixtureFormat"] = self.format_name

        # Set network field on the fixture itself
        self.network = fork.name()
