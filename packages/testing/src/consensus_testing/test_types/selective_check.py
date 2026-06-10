"""Shared base for expectation models that validate only their set fields."""

from collections.abc import Callable
from typing import Any, ClassVar

from lean_spec.base import CamelModel


class SelectiveCheck(CamelModel):
    """Validates only the fields a test explicitly set, via a subclass accessor table."""

    _SCALAR_ACCESSORS: ClassVar[dict[str, Callable[[Any], Any]]] = {}
    """Field name to reader over the validated target."""

    def validate_scalar_fields(self, target: Any, failure_prefix: str) -> None:
        """
        Check every explicitly-set scalar field against the target.

        Args:
            target: Object the accessors read the actual values from.
            failure_prefix: Prefix for the assertion message on mismatch.

        Raises:
            AssertionError: When a set field disagrees with the target.
        """
        for field_name in self.model_fields_set & self._SCALAR_ACCESSORS.keys():
            expected_value = getattr(self, field_name)
            actual_value = self._SCALAR_ACCESSORS[field_name](target)
            if actual_value != expected_value:
                raise AssertionError(
                    f"{failure_prefix}: {field_name} = {actual_value}, expected {expected_value}"
                )
