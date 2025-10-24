"""Base Pydantic models for Ethereum test fixtures."""

from typing import Any

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel
from typing_extensions import Self


class CamelModel(BaseModel):
    """
    A base model that converts field names to camel case when serializing.

    For example, the field name `current_slot` in a Python model will be
    represented as `currentSlot` when it is serialized to JSON.

    This is used across both consensus and execution layer test fixtures
    to maintain consistency with Ethereum test format specifications.
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        validate_default=True,
        arbitrary_types_allowed=True,
    )

    def copy(self: Self, **kwargs: Any) -> Self:
        """Create a copy of the model with the updated fields that are validated."""
        return self.__class__(**(self.model_dump(exclude_unset=True) | kwargs))
