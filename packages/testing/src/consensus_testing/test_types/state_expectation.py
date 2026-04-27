"""State expectation model for selective validation in state transition tests."""

from collections.abc import Callable
from typing import Any, ClassVar

from lean_spec.forks.lstar.containers.block.block import Block
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.state import State
from lean_spec.forks.lstar.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
)
from lean_spec.types import Bytes32, CamelModel

from .utils import resolve_block_root


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
        "justifications_roots_count": lambda s: len(s.justifications_roots),
        "justifications_validators": lambda s: s.justifications_validators,
        "justifications_validators_count": lambda s: len(s.justifications_validators),
    }
    """Field name to accessor function for reading expected values from a State."""

    slot: Slot | None = None
    """Expected current slot."""

    latest_justified_slot: Slot | None = None
    """Expected latest justified checkpoint slot."""

    latest_justified_root: Bytes32 | None = None
    """Expected latest justified checkpoint root."""

    latest_justified_root_label: str | None = None
    """
    Expected latest justified checkpoint root by label reference.

    Alternative to latest_justified_root that uses the block label system.
    The framework resolves this label to the actual block root.
    """

    latest_finalized_slot: Slot | None = None
    """Expected latest finalized checkpoint slot."""

    latest_finalized_root: Bytes32 | None = None
    """Expected latest finalized checkpoint root."""

    latest_finalized_root_label: str | None = None
    """
    Expected latest finalized checkpoint root by label reference.

    Alternative to latest_finalized_root that uses the block label system.
    The framework resolves this label to the actual block root.
    """

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

    justifications_roots_labels: list[str] | None = None
    """
    Expected pending justification roots by label reference.

    Alternative to justifications_roots that uses the block label system.
    The framework resolves each label to the actual block root.
    """

    justifications_roots_count: int | None = None
    """Expected number of pending justification target roots."""

    justifications_validators: JustificationValidators | None = None
    """Expected justifications validators bitlist."""

    justifications_validators_count: int | None = None
    """Expected number of entries in the flat justification voters bitlist."""

    def validate_against_state(
        self,
        state: "State",
        block_registry: dict[str, Block] | None = None,
    ) -> None:
        """
        Validate this expectation against actual State.

        Only validates fields that were explicitly set by the test writer.
        Uses Pydantic's model_fields_set to determine which fields to check.

        Args:
            state: The actual state to validate against.
            block_registry: Optional labeled blocks for resolving label-based checks.

        Raises:
            AssertionError: If any explicitly set field doesn't match the actual state value.
        """
        fields = self.model_fields_set

        def _resolve(label: str) -> Bytes32:
            if block_registry is None:
                raise ValueError(f"label '{label}' specified but block_registry not provided")
            return resolve_block_root(label, block_registry)

        for field_name in fields & self._ACCESSORS.keys():
            accessor = self._ACCESSORS[field_name]
            expected = getattr(self, field_name)
            actual = accessor(state)
            if actual != expected:
                raise AssertionError(
                    f"State validation failed: {field_name} = {actual}, expected {expected}"
                )

        if "latest_justified_root_label" in fields:
            assert self.latest_justified_root_label is not None
            expected = _resolve(self.latest_justified_root_label)
            if state.latest_justified.root != expected:
                raise AssertionError(
                    f"State validation failed: latest_justified.root = "
                    f"{state.latest_justified.root}, expected {expected}"
                )

        if "latest_finalized_root_label" in fields:
            assert self.latest_finalized_root_label is not None
            expected = _resolve(self.latest_finalized_root_label)
            if state.latest_finalized.root != expected:
                raise AssertionError(
                    f"State validation failed: latest_finalized.root = "
                    f"{state.latest_finalized.root}, expected {expected}"
                )

        if "justifications_roots_labels" in fields:
            assert self.justifications_roots_labels is not None
            expected_sorted = sorted(_resolve(label) for label in self.justifications_roots_labels)
            actual_sorted = sorted(state.justifications_roots.data)
            if actual_sorted != expected_sorted:
                raise AssertionError(
                    "State validation failed: justifications_roots = "
                    f"{state.justifications_roots}, expected "
                    f"{JustificationRoots(data=expected_sorted)}"
                )
