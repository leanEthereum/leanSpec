"""Internal validation utilities for the XMSS scheme."""

from __future__ import annotations

from typing import Any


def enforce_strict_types(instance: Any, **field_types: type) -> None:
    """
    Validate that specified fields are exact types, not subclasses.

    This is a helper function to be called from Pydantic model validators.

    It enforces that field values are exactly the declared type, preventing
    type confusion attacks where a malicious subclass could override behavior.

    Args:
        instance: The model instance being validated.
        **field_types: Mapping of field names to their exact expected types.

    Raises:
        TypeError: If any field is a subclass rather than the exact type.
    """
    for field_name, expected_type in field_types.items():
        value = getattr(instance, field_name)
        if type(value) is not expected_type:
            raise TypeError(
                f"{field_name} must be exactly {expected_type.__name__}, not a subclass"
            )
