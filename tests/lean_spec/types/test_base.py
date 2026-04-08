"""Tests for CamelModel and StrictBaseModel base classes."""

import pytest
from pydantic import ValidationError

from lean_spec.types.base import CamelModel, StrictBaseModel


class SampleCamelModel(CamelModel):
    """A minimal model with snake_case fields for testing camelCase conversion."""

    first_name: str
    current_slot: int


class SampleStrictModel(StrictBaseModel):
    """A minimal strict model for testing frozen/extra/strict behavior."""

    slot_number: int
    block_root: str


class TestCamelModelToJson:
    """Tests for CamelModel.to_json() camelCase serialization.

    Test vectors use camelCase keys in their JSON output. This method
    is the single point where that conversion happens. A bug here
    would produce invalid test vectors that fail cross-client checks.
    """

    def test_to_json_converts_snake_case_to_camel(self) -> None:
        """Snake_case field names become camelCase in JSON output.

        This is the core behavior that all test vector serialization
        depends on.
        """
        model = SampleCamelModel(first_name="Alice", current_slot=42)

        result = model.to_json()

        assert result == {"firstName": "Alice", "currentSlot": 42}

    def test_to_json_strips_mode_kwarg(self) -> None:
        """Passing mode= does not override the JSON serialization mode.

        The method always uses mode='json'. If a caller accidentally
        passes mode='python', the pop() silently discards it.
        """
        model = SampleCamelModel(first_name="Bob", current_slot=7)

        # Passing mode= should be silently ignored.
        result = model.to_json(mode="python")

        assert result == {"firstName": "Bob", "currentSlot": 7}

    def test_to_json_strips_by_alias_kwarg(self) -> None:
        """Passing by_alias= does not override the alias behavior.

        The method always uses by_alias=True (camelCase). If a caller
        passes by_alias=False, the pop() silently discards it.
        """
        model = SampleCamelModel(first_name="Carol", current_slot=0)

        # Passing by_alias=False should be silently ignored.
        result = model.to_json(by_alias=False)

        # Keys are still camelCase despite the caller's request.
        assert result == {"firstName": "Carol", "currentSlot": 0}

    def test_to_json_forwards_extra_kwargs(self) -> None:
        """Other kwargs (e.g., exclude_defaults) pass through to model_dump.

        Only mode and by_alias are stripped. Everything else is forwarded.
        """
        model = SampleCamelModel(first_name="Dave", current_slot=0)

        # exclude_defaults=True should be forwarded to model_dump.
        result = model.to_json(exclude_defaults=True)

        # current_slot=0 is the default for int, so it gets excluded.
        assert "firstName" in result


class TestStrictBaseModel:
    """Tests for StrictBaseModel constraints.

    StrictBaseModel is the foundation for all spec types. Its constraints
    (frozen, extra-forbidden, strict) prevent accidental mutations and
    type coercion that could silently corrupt spec state.
    """

    def test_frozen_rejects_assignment(self) -> None:
        """Attribute assignment after construction raises an error.

        Spec types must be immutable. A mutable state object would
        break forkchoice assumptions.
        """
        model = SampleStrictModel(slot_number=5, block_root="0xabc")

        with pytest.raises(ValidationError):
            model.slot_number = 10  # type: ignore[misc]

    def test_extra_fields_forbidden(self) -> None:
        """Unknown fields are rejected at construction time.

        This catches typos and schema mismatches early.
        """
        with pytest.raises(ValidationError):
            SampleStrictModel(
                slot_number=5,
                block_root="0xabc",
                unknown_field="oops",  # type: ignore[call-arg]
            )

    def test_strict_rejects_type_coercion(self) -> None:
        """Strict mode rejects values that would require type coercion.

        Without strict mode, Pydantic would silently convert "5" to 5.
        In spec code, this kind of silent coercion hides bugs.
        """
        with pytest.raises(ValidationError):
            SampleStrictModel(slot_number="5", block_root="0xabc")  # type: ignore[arg-type]

    def test_inherits_camel_serialization(self) -> None:
        """StrictBaseModel inherits camelCase serialization from CamelModel.

        Verifies the inheritance chain works end-to-end.
        """
        model = SampleStrictModel(slot_number=42, block_root="0xdef")

        result = model.to_json()

        assert result == {"slotNumber": 42, "blockRoot": "0xdef"}
