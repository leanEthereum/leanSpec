"""State expectation model for selective validation in state transition tests."""

from collections.abc import Callable
from typing import Any, ClassVar

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.types import Bytes32, CamelModel


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

    _ACCESSORS: ClassVar[dict[str, Callable[["State"], Any]]] = {
        "slot": lambda s: s.slot,
        "latest_justified_slot": lambda s: s.latest_justified.slot,
        "latest_justified_root": lambda s: s.latest_justified.root,
        "latest_finalized_slot": lambda s: s.latest_finalized.slot,
        "latest_finalized_root": lambda s: s.latest_finalized.root,
        "validator_count": lambda s: len(s.validators),
        "config_genesis_time": lambda s: int(s.config.genesis_time),
        "latest_block_header_slot": lambda s: s.latest_block_header.slot,
        "latest_block_header_proposer_index": lambda s: int(s.latest_block_header.proposer_index),
        "latest_block_header_parent_root": lambda s: s.latest_block_header.parent_root,
        "latest_block_header_state_root": lambda s: s.latest_block_header.state_root,
        "latest_block_header_body_root": lambda s: s.latest_block_header.body_root,
        "historical_block_hashes_count": lambda s: len(s.historical_block_hashes),
        "historical_block_hashes": lambda s: s.historical_block_hashes,
        "justified_slots": lambda s: s.justified_slots,
        "justifications_roots": lambda s: s.justifications_roots,
        "justifications_validators": lambda s: s.justifications_validators,
    }

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

        Args:
            state: The actual state to validate against.

        Raises:
            AssertionError: If any explicitly set field doesn't match the actual state value.
        """
        for field_name in self.model_fields_set:
            accessor = self._ACCESSORS.get(field_name)
            if accessor is None:
                raise ValueError(f"No accessor defined for field: {field_name}")
            expected = getattr(self, field_name)
            actual = accessor(state)
            if actual != expected:
                raise AssertionError(
                    f"State validation failed: {field_name} = {actual}, expected {expected}"
                )
