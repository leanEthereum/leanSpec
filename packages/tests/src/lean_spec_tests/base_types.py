"""Base Pydantic models for consensus test fixtures."""

from typing import Any

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel
from typing_extensions import Self


class CamelModel(BaseModel):
    """
    A base model that converts field names to camel case when serializing.

    For example, the field name `current_slot` in a Python model will be
    represented as `currentSlot` when it is serialized to JSON.
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

    @staticmethod
    def json_encoder(obj: Any) -> Any:
        """
        Custom JSON encoder for leanSpec types.

        Converts:
        - Bytes32 and other BaseBytes types → "0x..." hex string
        - Uint64 and other BaseUint types → int
        """
        # Check if it's a bytes type (has hex() method)
        if hasattr(obj, "hex") and callable(obj.hex):
            return f"0x{obj.hex()}"
        # Check if it's a uint type (subclass of int but not bool)
        if isinstance(obj, int) and not isinstance(obj, bool):
            return int(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
