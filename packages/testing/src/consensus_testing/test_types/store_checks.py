"""Store checks model for selective validation in fork choice tests."""

from typing import TYPE_CHECKING, Literal

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import Bytes32, CamelModel, Uint64, ValidatorIndex

if TYPE_CHECKING:
    from lean_spec.subspecs.containers import SignedAttestation
    from lean_spec.subspecs.containers.block.block import Block
    from lean_spec.subspecs.forkchoice.store import Store


class AttestationCheck(CamelModel):
    """
    Validation checks for a specific validator's attestation.

    All fields optional - only check fields explicitly set.
    Used to validate attestation content beyond just counting.
    """

    validator: ValidatorIndex
    """Which validator's attestation to check."""

    attestation_slot: Slot | None = None
    """Expected attestation data slot."""

    head_slot: Slot | None = None
    """Expected head checkpoint slot."""

    source_slot: Slot | None = None
    """Expected source checkpoint slot."""

    target_slot: Slot | None = None
    """Expected target checkpoint slot."""

    location: Literal["new", "known"]
    """
    Expected attestation location:
        - "new" for `latest_new_attestations`
        - "known" for `latest_known_attestations`
    """

    def validate_attestation(
        self, attestation: "SignedAttestation", location: str, step_index: int
    ) -> None:
        """Validate attestation properties."""
        fields_to_check = self.model_fields_set - {"validator", "location"}

        for field_name in fields_to_check:
            expected = getattr(self, field_name)

            if field_name == "attestation_slot":
                actual = attestation.message.data.slot
                if actual != expected:
                    raise AssertionError(
                        f"Step {step_index}: validator {self.validator} {location} "
                        f"attestation slot = {actual}, expected {expected}"
                    )

            elif field_name == "head_slot":
                actual = attestation.message.data.head.slot
                if actual != expected:
                    raise AssertionError(
                        f"Step {step_index}: validator {self.validator} {location} "
                        f"head slot = {actual}, expected {expected}"
                    )

            elif field_name == "source_slot":
                actual = attestation.message.data.source.slot
                if actual != expected:
                    raise AssertionError(
                        f"Step {step_index}: validator {self.validator} {location} "
                        f"source slot = {actual}, expected {expected}"
                    )

            elif field_name == "target_slot":
                actual = attestation.message.data.target.slot
                if actual != expected:
                    raise AssertionError(
                        f"Step {step_index}: validator {self.validator} {location} "
                        f"target slot = {actual}, expected {expected}"
                    )


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

    head_root_label: str | None = None
    """
    Expected head block root by label reference.

    Alternative to head_root that uses the block label system.
    The framework will resolve this label to the actual block root
    and validate the head matches.

    Example:
        StoreChecks(head_root_label="fork_a")  # Validates head is fork_a block
    """

    latest_justified_slot: Slot | None = None
    """Expected latest justified checkpoint slot."""

    latest_justified_root: Bytes32 | None = None
    """Expected latest justified checkpoint root."""

    latest_finalized_slot: Slot | None = None
    """Expected latest finalized checkpoint slot."""

    latest_justified_root_label: str | None = None
    """
    Expected latest justified checkpoint root by label reference.

    Alternative to latest_justified_root that uses the block label system.
    The framework will resolve this label to the actual block root
    and validate the latest justified checkpointroot matches.
    """

    latest_finalized_root: Bytes32 | None = None
    """Expected latest finalized checkpoint root."""

    safe_target: Bytes32 | None = None
    """Expected safe target root."""

    attestation_target_slot: Slot | None = None
    """
    Expected attestation target checkpoint slot.

    Validates the complete checkpoint (both slot and root):
    - The checkpoint slot matches the expected value
    - The checkpoint root references an actual block at that slot
    """

    attestation_checks: list[AttestationCheck] | None = None
    """Optional list of attestation content checks for specific validators."""

    def validate_against_store(
        self, store: "Store", step_index: int, block_registry: dict[str, "Block"] | None = None
    ) -> None:
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
        block_registry : dict[str, Block] | None
            Optional registry of labeled blocks for resolving head_root_label.

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

            elif field_name == "head_root_label":
                # Resolve label to root
                if block_registry is None:
                    raise ValueError(
                        f"Step {step_index}: head_root_label='{expected_value}' specified "
                        f"but block_registry not provided to validate_against_store()"
                    )

                if expected_value not in block_registry:
                    available = list(block_registry.keys())
                    raise ValueError(
                        f"Step {step_index}: head_root_label='{expected_value}' not found "
                        f"in block registry. Available labels: {available}"
                    )

                # Import hash_tree_root locally to avoid circular import
                from lean_spec.subspecs.ssz import hash_tree_root

                expected_block = block_registry[expected_value]
                expected_root = hash_tree_root(expected_block)
                actual_root = store.head

                if actual_root != expected_root:
                    raise AssertionError(
                        f"Step {step_index}: head.root = 0x{actual_root.hex()}, "
                        f"expected 0x{expected_root.hex()} "
                        f"(label '{expected_value}')"
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

            elif field_name == "latest_justified_root_label":
                # Resolve label to root
                if block_registry is None:
                    raise ValueError(
                        f"Step {step_index}: latest_justified_root_label='{expected_value}' "
                        f"specified but block_registry not provided to validate_against_store()"
                    )

                if expected_value not in block_registry:
                    available = list(block_registry.keys())
                    raise ValueError(
                        f"Step {step_index}: latest_justified_root_label='{expected_value}' "
                        f"not found in block registry. Available labels: {available}"
                    )

                # Import hash_tree_root locally to avoid circular import
                from lean_spec.subspecs.ssz import hash_tree_root

                expected_block = block_registry[expected_value]
                expected_root = hash_tree_root(expected_block)
                actual_root = store.latest_justified.root

                if actual_root != expected_root:
                    raise AssertionError(
                        f"Step {step_index}: latest_justified.root = 0x{actual_root.hex()}, "
                        f"expected 0x{expected_root.hex()} "
                        f"(label '{expected_value}')"
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

            elif field_name == "attestation_target_slot":
                # Get attestation target and check slot
                target = store.get_attestation_target()
                actual_slot = target.slot
                if actual_slot != expected_value:
                    raise AssertionError(
                        f"Step {step_index}: attestation_target.slot = {actual_slot}, "
                        f"expected {expected_value}"
                    )

                # ALSO validate the root matches a block at this slot
                #
                # This ensures we're validating the complete checkpoint (root + slot)
                block_found = False
                for root, block in store.blocks.items():
                    if block.slot == expected_value and root == target.root:
                        block_found = True
                        break

                if not block_found:
                    available = [
                        f"0x{r.hex()[:16]}..."
                        for r, b in store.blocks.items()
                        if b.slot == expected_value
                    ]
                    raise AssertionError(
                        f"Step {step_index}: attestation_target.root = "
                        f"0x{target.root.hex()[:16]}... does not match any "
                        f"block at slot {expected_value}. "
                        f"Available blocks: {available}"
                    )

            elif field_name == "attestation_checks":
                # Validate specific attestation contents
                for check in expected_value:
                    validator_idx = check.validator

                    # Check attestation location
                    if check.location == "new":
                        if validator_idx not in store.latest_new_attestations:
                            raise AssertionError(
                                f"Step {step_index}: validator {validator_idx} not found "
                                f"in latest_new_attestations"
                            )
                        attestation = store.latest_new_attestations[validator_idx]
                        check.validate_attestation(attestation, "in latest_new", step_index)

                    else:  # check.location == "known"
                        if validator_idx not in store.latest_known_attestations:
                            raise AssertionError(
                                f"Step {step_index}: validator {validator_idx} not found "
                                f"in latest_known_attestations"
                            )
                        attestation = store.latest_known_attestations[validator_idx]
                        check.validate_attestation(attestation, "in latest_known", step_index)
