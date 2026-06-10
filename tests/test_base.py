"""Tests for CamelModel and StrictBaseModel base classes."""

import pytest
from pydantic import ValidationError

from lean_spec.base import CamelModel, StrictBaseModel


class SampleCamelModel(CamelModel):
    """A minimal model with snake_case fields for testing camelCase conversion."""

    first_name: str
    current_slot: int


class SampleStrictModel(StrictBaseModel):
    """A minimal strict model for testing frozen/extra/strict behavior."""

    slot_number: int
    block_root: str


class TestCamelModelToJson:
    """Tests for CamelModel.to_json() camelCase serialization."""

    def test_to_json_converts_snake_case_to_camel(self) -> None:
        """Snake_case field names become camelCase in JSON output."""
        model = SampleCamelModel(first_name="Alice", current_slot=42)

        serialized = model.to_json()

        assert serialized == {"firstName": "Alice", "currentSlot": 42}

    def test_to_json_rejects_mode_kwarg(self) -> None:
        """Overriding serialization mode raises an error instead of being silently accepted."""
        model = SampleCamelModel(first_name="Bob", current_slot=7)

        with pytest.raises(TypeError) as exception_info:
            model.to_json(mode="python")
        assert str(exception_info.value) == (
            "to_json() does not accept 'mode' or 'by_alias'; "
            "mode is pinned to 'json' and by_alias to True"
        )

    def test_to_json_rejects_by_alias_kwarg(self) -> None:
        """Overriding alias style raises an error instead of being silently accepted."""
        model = SampleCamelModel(first_name="Carol", current_slot=0)

        with pytest.raises(TypeError) as exception_info:
            model.to_json(by_alias=False)
        assert str(exception_info.value) == (
            "to_json() does not accept 'mode' or 'by_alias'; "
            "mode is pinned to 'json' and by_alias to True"
        )

    def test_to_json_forwards_extra_kwargs(self) -> None:
        """
        Other kwargs (e.g., exclude_defaults) pass through to model_dump.

        Only mode and by_alias are stripped. Everything else is forwarded.
        """
        model = SampleCamelModel(first_name="Dave", current_slot=0)

        # exclude_defaults=True should be forwarded to model_dump.
        serialized = model.to_json(exclude_defaults=True)

        # current_slot=0 is the default for int, so it gets excluded.
        assert "firstName" in serialized


class TestStrictBaseModel:
    """Tests for StrictBaseModel constraints."""

    def test_frozen_rejects_assignment(self) -> None:
        """
        Attribute assignment after construction raises an error.

        Spec types must be immutable.
        """
        model = SampleStrictModel(slot_number=5, block_root="0xabc")

        with pytest.raises(ValidationError):
            model.slot_number = 10

    def test_extra_fields_forbidden(self) -> None:
        """
        Unknown fields are rejected at construction time.

        This catches typos and schema mismatches early.
        """
        with pytest.raises(ValidationError):
            SampleStrictModel(
                slot_number=5,
                block_root="0xabc",
                unknown_field="oops",  # type: ignore[call-arg]
            )

    def test_strict_rejects_type_coercion(self) -> None:
        """
        Strict mode rejects values that would require type coercion.

        Without strict mode, Pydantic would silently convert "5" to 5.
        In spec code, this kind of silent coercion hides bugs.
        """
        with pytest.raises(ValidationError):
            SampleStrictModel(slot_number="5", block_root="0xabc")  # type: ignore[arg-type]

    def test_inherits_camel_serialization(self) -> None:
        """
        StrictBaseModel inherits camelCase serialization from CamelModel.

        Verifies the inheritance chain works end-to-end.
        """
        model = SampleStrictModel(slot_number=42, block_root="0xdef")

        serialized = model.to_json()

        assert serialized == {"slotNumber": 42, "blockRoot": "0xdef"}
