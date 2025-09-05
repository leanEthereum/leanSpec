"""Reusable, strict base models for the specification."""

from pydantic import BaseModel, ConfigDict


class StrictBaseModel(BaseModel):
    """A strict, immutable pydantic base model."""

    model_config = ConfigDict(frozen=True, extra="forbid")
