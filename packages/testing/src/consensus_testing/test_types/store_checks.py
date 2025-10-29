"""Store checks model for selective validation in fork choice tests."""

from typing import TYPE_CHECKING

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, CamelModel, Uint64

if TYPE_CHECKING:
    from lean_spec.subspecs.forkchoice.store import Store


class StoreChecks(CamelModel):
    """
    Store state checks for fork choice tests.

    All fields are optional - only specified fields are validated.
    Uses Pydantic's model_fields_set to track which fields were explicitly set.

    This allows test writers to specify only the fields they care about,
    making tests more focused and maintainable.

    Example:
        # Only validate head slot and justified checkpoint
        StoreChecks(
            head_slot=Slot(5),
            latest_justified_slot=Slot(4),
        )
    """

    time: Uint64 | None = None
    """Expected store time (in intervals since genesis)."""

    head_slot: Slot | None = None
    """Expected head block slot."""

    head_root: Bytes32 | None = None
    """Expected head block root."""

    latest_justified_slot: Slot | None = None
    """Expected latest justified checkpoint slot."""

    latest_justified_root: Bytes32 | None = None
    """Expected latest justified checkpoint root."""

    latest_finalized_slot: Slot | None = None
    """Expected latest finalized checkpoint slot."""

    latest_finalized_root: Bytes32 | None = None
    """Expected latest finalized checkpoint root."""

    safe_target: Bytes32 | None = None
    """Expected safe target root."""

    def validate_against_store(self, store: "Store", step_index: int) -> None:
        """
        Validate these checks against actual Store state.

        Only validates fields that were explicitly set by the test writer.
        Uses Pydantic's model_fields_set to determine which fields to check.

        Parameters:
        ----------
        store : Store
            The fork choice store to validate against.
        step_index : int
            Index of the step being validated (for error messages).

        Raises:
        ------
        AssertionError
            If any explicitly set field doesn't match the actual store value.
        """
        # Get the set of fields that were explicitly provided
        fields_to_check = self.model_fields_set

        for field_name in fields_to_check:
            expected_value = getattr(self, field_name)

            if field_name == "time":
                actual = store.time
                if actual != expected_value:
                    raise AssertionError(
                        f"Step {step_index}: time = {actual}, expected {expected_value}"
                    )

            elif field_name == "head_slot":
                actual = store.blocks[store.head].slot
                if actual != expected_value:
                    raise AssertionError(
                        f"Step {step_index}: head.slot = {actual}, expected {expected_value}"
                    )

            elif field_name == "head_root":
                actual_root = store.head
                if actual_root != expected_value:
                    raise AssertionError(
                        f"Step {step_index}: head.root = 0x{actual_root.hex()}, "
                        f"expected 0x{expected_value.hex()}"
                    )

            elif field_name == "latest_justified_slot":
                actual = store.latest_justified.slot
                if actual != expected_value:
                    raise AssertionError(
                        f"Step {step_index}: latest_justified.slot = {actual}, "
                        f"expected {expected_value}"
                    )

            elif field_name == "latest_justified_root":
                actual_root = store.latest_justified.root
                if actual_root != expected_value:
                    raise AssertionError(
                        f"Step {step_index}: latest_justified.root = 0x{actual_root.hex()}, "
                        f"expected 0x{expected_value.hex()}"
                    )

            elif field_name == "latest_finalized_slot":
                actual = store.latest_finalized.slot
                if actual != expected_value:
                    raise AssertionError(
                        f"Step {step_index}: latest_finalized.slot = {actual}, "
                        f"expected {expected_value}"
                    )

            elif field_name == "latest_finalized_root":
                actual_root = store.latest_finalized.root
                if actual_root != expected_value:
                    raise AssertionError(
                        f"Step {step_index}: latest_finalized.root = 0x{actual_root.hex()}, "
                        f"expected 0x{expected_value.hex()}"
                    )

            elif field_name == "safe_target":
                actual_root = store.safe_target
                if actual_root != expected_value:
                    raise AssertionError(
                        f"Step {step_index}: safe_target = 0x{actual_root.hex()}, "
                        f"expected 0x{expected_value.hex()}"
                    )
