"""State expectation model for selective validation in state transition tests."""

from typing import TYPE_CHECKING

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.types import Bytes32, CamelModel

if TYPE_CHECKING:
    from lean_spec.subspecs.containers.state import State


class StateExpectation(CamelModel):
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

    config_genesis_time: int | None = None
    """Expected genesis time in the config."""

    latest_block_header_slot: Slot | None = None
    """Expected slot of the latest block header."""

    latest_block_header_proposer_index: int | None = None
    """Expected proposer index in the latest block header."""

    latest_block_header_parent_root: Bytes32 | None = None
    """Expected parent root in the latest block header."""

    latest_block_header_state_root: Bytes32 | None = None
    """Expected state root in the latest block header."""

    latest_block_header_body_root: Bytes32 | None = None
    """Expected body root in the latest block header."""

    historical_block_hashes_count: int | None = None
    """Expected number of historical block hashes."""

    historical_block_hashes: HistoricalBlockHashes | None = None
    """Expected historical block hashes collection."""

    justified_slots: JustifiedSlots | None = None
    """Expected justified slots bitlist."""

    justifications_roots: JustificationRoots | None = None
    """Expected justifications roots collection."""

    justifications_validators: JustificationValidators | None = None
    """Expected justifications validators bitlist."""

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
                actual_count = len(state.validators)
                if actual_count != expected_value:
                    raise AssertionError(
                        f"State validation failed: validator_count = {actual_count}, "
                        f"expected {expected_value}"
                    )

            elif field_name == "config_genesis_time":
                actual_time = int(state.config.genesis_time)
                if actual_time != expected_value:
                    raise AssertionError(
                        f"State validation failed: config.genesis_time = {actual_time}, "
                        f"expected {expected_value}"
                    )

            elif field_name == "latest_block_header_slot":
                actual_slot = state.latest_block_header.slot
                if actual_slot != expected_value:
                    raise AssertionError(
                        f"State validation failed: latest_block_header.slot = {actual_slot}, "
                        f"expected {expected_value}"
                    )

            elif field_name == "latest_block_header_proposer_index":
                actual_proposer = int(state.latest_block_header.proposer_index)
                if actual_proposer != expected_value:
                    raise AssertionError(
                        f"State validation failed: latest_block_header.proposer_index = "
                        f"{actual_proposer}, expected {expected_value}"
                    )

            elif field_name == "latest_block_header_parent_root":
                actual_parent_root = state.latest_block_header.parent_root
                if actual_parent_root != expected_value:
                    raise AssertionError(
                        f"State validation failed: latest_block_header.parent_root = "
                        f"0x{actual_parent_root.hex()}, expected 0x{expected_value.hex()}"
                    )

            elif field_name == "latest_block_header_state_root":
                actual_state_root = state.latest_block_header.state_root
                if actual_state_root != expected_value:
                    raise AssertionError(
                        f"State validation failed: latest_block_header.state_root = "
                        f"0x{actual_state_root.hex()}, expected 0x{expected_value.hex()}"
                    )

            elif field_name == "latest_block_header_body_root":
                actual_body_root = state.latest_block_header.body_root
                if actual_body_root != expected_value:
                    raise AssertionError(
                        f"State validation failed: latest_block_header.body_root = "
                        f"0x{actual_body_root.hex()}, expected 0x{expected_value.hex()}"
                    )

            elif field_name == "historical_block_hashes_count":
                actual_count = len(state.historical_block_hashes)
                if actual_count != expected_value:
                    raise AssertionError(
                        f"State validation failed: historical_block_hashes count = {actual_count}, "
                        f"expected {expected_value}"
                    )

            elif field_name == "historical_block_hashes":
                if state.historical_block_hashes != expected_value:
                    raise AssertionError(
                        f"State validation failed: historical_block_hashes = "
                        f"{state.historical_block_hashes}, expected {expected_value}"
                    )

            elif field_name == "justified_slots":
                if state.justified_slots != expected_value:
                    raise AssertionError(
                        f"State validation failed: justified_slots = "
                        f"{state.justified_slots}, expected {expected_value}"
                    )

            elif field_name == "justifications_roots":
                if state.justifications_roots != expected_value:
                    raise AssertionError(
                        f"State validation failed: justifications_roots = "
                        f"{state.justifications_roots}, expected {expected_value}"
                    )

            elif field_name == "justifications_validators":
                if state.justifications_validators != expected_value:
                    raise AssertionError(
                        f"State validation failed: justifications_validators = "
                        f"{state.justifications_validators}, expected {expected_value}"
                    )
