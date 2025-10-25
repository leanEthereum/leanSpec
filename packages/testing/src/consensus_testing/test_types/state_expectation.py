"""State expectation model for selective validation in state transition tests."""

from typing import TYPE_CHECKING

from pydantic import BaseModel

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32

if TYPE_CHECKING:
    from lean_spec.subspecs.containers.state import State


class StateExpectation(BaseModel):
    """
    Expected State fields after state transition (selective validation).

    All fields are optional - only specified fields are validated.
    Uses Pydantic's model_fields_set to track which fields were explicitly set.

    This allows test writers to specify only the fields they care about,
    making tests more focused and maintainable.

    Example:
        # Only validate slot and justified checkpoint
        StateExpectation(
            slot=Slot(10),
            latest_justified_slot=Slot(8),
        )
    """

    slot: Slot | None = None
    """Expected current slot."""

    latest_justified_slot: Slot | None = None
    """Expected latest justified checkpoint slot."""

    latest_justified_root: Bytes32 | None = None
    """Expected latest justified checkpoint root."""

    latest_finalized_slot: Slot | None = None
    """Expected latest finalized checkpoint slot."""

    latest_finalized_root: Bytes32 | None = None
    """Expected latest finalized checkpoint root."""

    validator_count: int | None = None
    """Expected number of validators."""

    def validate_against_state(self, state: "State") -> None:
        """
        Validate this expectation against actual State.

        Only validates fields that were explicitly set by the test writer.
        Uses Pydantic's model_fields_set to determine which fields to check.

        Parameters:
        ----------
        state : State
            The actual state to validate against.

        Raises:
        ------
        AssertionError
            If any explicitly set field doesn't match the actual state value.
        """
        # Get the set of fields that were explicitly provided
        fields_to_check = self.model_fields_set

        for field_name in fields_to_check:
            expected_value = getattr(self, field_name)

            if field_name == "slot":
                actual = state.slot
                if actual != expected_value:
                    raise AssertionError(
                        f"State validation failed: slot = {actual}, expected {expected_value}"
                    )

            elif field_name == "latest_justified_slot":
                actual = state.latest_justified.slot
                if actual != expected_value:
                    raise AssertionError(
                        f"State validation failed: latest_justified.slot = {actual}, "
                        f"expected {expected_value}"
                    )

            elif field_name == "latest_justified_root":
                actual_root = state.latest_justified.root
                if actual_root != expected_value:
                    raise AssertionError(
                        f"State validation failed: latest_justified.root = 0x{actual_root.hex()}, "
                        f"expected 0x{expected_value.hex()}"
                    )

            elif field_name == "latest_finalized_slot":
                actual = state.latest_finalized.slot
                if actual != expected_value:
                    raise AssertionError(
                        f"State validation failed: latest_finalized.slot = {actual}, "
                        f"expected {expected_value}"
                    )

            elif field_name == "latest_finalized_root":
                actual_root = state.latest_finalized.root
                if actual_root != expected_value:
                    raise AssertionError(
                        f"State validation failed: latest_finalized.root = 0x{actual_root.hex()}, "
                        f"expected 0x{expected_value.hex()}"
                    )

            elif field_name == "validator_count":
                actual_count = state.validators.count
                if actual_count != expected_value:
                    raise AssertionError(
                        f"State validation failed: validator_count = {actual_count}, "
                        f"expected {expected_value}"
                    )
