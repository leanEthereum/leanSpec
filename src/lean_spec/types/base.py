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
        """Serialize to a JSON-encodable dict with camelCase keys.

        Always uses JSON mode and camelCase aliases regardless of kwargs.
        Callers cannot override mode or by_alias — these are stripped
        silently to guarantee correct test vector output.
        """
        kwargs.pop("mode", None)
        kwargs.pop("by_alias", None)

        return self.model_dump(
            mode="json",
            by_alias=True,
            **kwargs,
        )


class StrictBaseModel(CamelModel):
    """Immutable, strict base model for all spec types.

    Adds three constraints on top of CamelModel:

    - Frozen: attribute assignment after construction raises
    - Extra forbidden: unknown fields rejected at construction
    - Strict: no implicit type coercion
    """

    model_config = CamelModel.model_config | {
        "extra": "forbid",
        "frozen": True,
        "strict": True,
    }
