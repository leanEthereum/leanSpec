"""Reusable, strict base models for the specification."""

from typing import Any

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


class CamelModel(BaseModel):
    """Base model that serializes field names as camelCase.

    All spec types inherit from this model so that JSON test vectors
    use camelCase keys for cross-client compatibility.
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        validate_default=True,
        arbitrary_types_allowed=True,
    )

    def to_json(self, **kwargs: Any) -> dict[str, Any]:
        """
        Serialize to a JSON-encodable dict with camelCase keys.

        Serialization mode is pinned to JSON.
        Alias style is pinned to camelCase.
        A caller that overrides either almost certainly expects the override to apply.
        The override is rejected to avoid silently surprising the caller.

        Raises:
            TypeError: If mode or by_alias is passed as a keyword argument.
        """
        if "mode" in kwargs or "by_alias" in kwargs:
            raise TypeError(
                "to_json() does not accept 'mode' or 'by_alias'; "
                "mode is pinned to 'json' and by_alias to True"
            )

        return self.model_dump(
            mode="json",
            by_alias=True,
            **kwargs,
        )


class StrictBaseModel(CamelModel):
    """Strict base model for all spec types.

    Adds two constraints on top of CamelModel:

    - Extra forbidden: unknown fields rejected at construction
    - Strict: no implicit type coercion
    """

    model_config = CamelModel.model_config | {
        "extra": "forbid",
        "strict": True,
    }
