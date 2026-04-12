"""Store checks model for selective validation in fork choice tests."""

from typing import Literal

from lean_spec.subspecs.containers import AttestationData
from lean_spec.subspecs.containers.block.block import Block
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.subspecs.forkchoice.store import Store
from lean_spec.subspecs.ssz import hash_tree_root
from lean_spec.types import Bytes32, CamelModel, Uint64


class AggregatedAttestationCheck(CamelModel):
    """
    Validation checks for an aggregated attestation in the block body.

    Used to verify signature aggregation results by checking which validators
    are covered by each aggregated attestation.
    """

    participants: set[int]
    """Expected validator indices covered by this aggregated attestation."""

    attestation_slot: Slot | None = None
    """Expected attestation data slot (optional - only check if set)."""

    target_slot: Slot | None = None
    """Expected target checkpoint slot (optional - only check if set)."""


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
        - "new" for `latest_new_aggregated_payloads`
        - "known" for `latest_known_aggregated_payloads`
    """

    def validate_attestation(
        self, attestation: "AttestationData", location: str, step_index: int
    ) -> None:
        """Validate attestation properties."""
        fields_to_check = self.model_fields_set - {"validator", "location"}

        for field_name in fields_to_check:
            expected = getattr(self, field_name)

            if field_name == "attestation_slot":
                actual = attestation.slot
                if actual != expected:
                    raise AssertionError(
                        f"Step {step_index}: validator {self.validator} {location} "
                        f"attestation slot = {actual}, expected {expected}"
                    )

            elif field_name == "head_slot":
                actual = attestation.head.slot
                if actual != expected:
                    raise AssertionError(
                        f"Step {step_index}: validator {self.validator} {location} "
                        f"head slot = {actual}, expected {expected}"
                    )

            elif field_name == "source_slot":
                actual = attestation.source.slot
                if actual != expected:
                    raise AssertionError(
                        f"Step {step_index}: validator {self.validator} {location} "
                        f"source slot = {actual}, expected {expected}"
                    )

            elif field_name == "target_slot":
                actual = attestation.target.slot
                if actual != expected:
                    raise AssertionError(
                        f"Step {step_index}: validator {self.validator} {location} "
                        f"target slot = {actual}, expected {expected}"
                    )


class StoreChecks(CamelModel):
    """
    Store state checks for fork choice tests.

    All fields are optional. Only specified fields are validated.
    This allows tests to focus on the properties they care about.
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
    The framework resolves this label to the actual block root.
    """

    filled_block_root_label: str | None = None
    """
    Expected root of the block built for this step, resolved by label.

    This is useful when a test needs to prove that the fixture rebuilt or
    resubmitted an exact previously known block rather than merely producing a
    different block that leaves the head unchanged.
    """

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

    block_attestation_count: int | None = None
    """
    Expected number of aggregated attestations in the block body.

    Use this to verify signature aggregation behavior:
    - 1 = all attestations aggregated into a single proof
    - >1 = attestations split due to incompatible sources
    """

    block_attestations: list[AggregatedAttestationCheck] | None = None
    """
    Detailed checks for each aggregated attestation in the block body.

    Each check validates:
    - participants: which validators are covered by this aggregation
    - attestation_slot: the attestation data slot (optional)
    - target_slot: the target checkpoint slot (optional)
    """

    lexicographic_head_among: list[str] | None = None
    """
    Verify that the head is chosen via lexicographic tiebreaker.

    When specified, validates that:
    1. All listed fork labels have equal attestation weight
    2. The current head is one of these forks
    3. The head has the lexicographically highest block root among them

    This is used to test the fork choice tiebreaker rule: when multiple forks
    have equal weight, the fork with the highest block root (lexicographically)
    should be selected as the head.
    """

    reorg_depth: int | None = None
    """
    Expected reorg depth after this step.

    Reorg depth is the number of blocks reverted when the head switches
    from the old chain to the new chain. Computed by finding the common
    ancestor of the old and new heads, then counting blocks from the old
    head back to that ancestor.

    Only meaningful when the head actually changes. If the head didn't
    change, the actual reorg depth is 0.
    """

    labels_in_store: list[str] | None = None
    """
    Block labels that must be present in the store's block tree.

    Each label is resolved to a block root via the block registry,
    then checked for presence in ``store.blocks``. This verifies
    that blocks from abandoned forks are retained (not pruned).
    """

    def validate_against_store(
        self,
        store: "Store",
        step_index: int,
        block_registry: dict[str, "Block"] | None = None,
        filled_block: "Block | None" = None,
        old_head: "Bytes32 | None" = None,
    ) -> None:
        """
        Validate these checks against actual Store state.

        Only validates fields that were explicitly set by the test writer.

        Args:
            store: The fork choice store to validate against.
            step_index: Index of the step being validated (for error messages).
            block_registry: Optional labeled blocks for resolving label-based checks.
            filled_block: Optional block for validating block body attestations.
            old_head: Previous head root before this step executed. Required
                for reorg_depth checks.
        """
        fields = self.model_fields_set

        def _check(name: str, actual: object, expected: object) -> None:
            if actual != expected:
                raise AssertionError(f"Step {step_index}: {name} = {actual}, expected {expected}")

        def _resolve_label(field_name: str, label: str) -> Bytes32:
            if block_registry is None:
                raise ValueError(
                    f"Step {step_index}: {field_name}='{label}' specified "
                    f"but block_registry not provided"
                )
            if label not in block_registry:
                raise ValueError(
                    f"Step {step_index}: {field_name}='{label}' not found "
                    f"in block registry. Available: {list(block_registry.keys())}"
                )
            return hash_tree_root(block_registry[label])

        # Scalar store fields
        if "time" in fields:
            _check("time", store.time, self.time)
        if "head_slot" in fields:
            _check("head.slot", store.blocks[store.head].slot, self.head_slot)
        if "head_root" in fields:
            _check("head.root", store.head, self.head_root)
        if "latest_justified_slot" in fields:
            _check("latest_justified.slot", store.latest_justified.slot, self.latest_justified_slot)
        if "latest_justified_root" in fields:
            _check("latest_justified.root", store.latest_justified.root, self.latest_justified_root)
        if "latest_finalized_slot" in fields:
            _check("latest_finalized.slot", store.latest_finalized.slot, self.latest_finalized_slot)
        if "latest_finalized_root" in fields:
            _check("latest_finalized.root", store.latest_finalized.root, self.latest_finalized_root)
        if "safe_target" in fields:
            _check("safe_target", store.safe_target, self.safe_target)

        # Label-based root checks (resolve label -> root, then compare)
        if "head_root_label" in fields:
            assert self.head_root_label is not None
            expected = _resolve_label("head_root_label", self.head_root_label)
            _check("head.root", store.head, expected)
        if "filled_block_root_label" in fields:
            if filled_block is None:
                raise ValueError(
                    f"Step {step_index}: filled_block_root_label specified but "
                    f"filled_block not provided"
                )
            assert self.filled_block_root_label is not None
            expected = _resolve_label("filled_block_root_label", self.filled_block_root_label)
            _check("filled_block.root", hash_tree_root(filled_block), expected)
        if "latest_justified_root_label" in fields:
            assert self.latest_justified_root_label is not None
            expected = _resolve_label(
                "latest_justified_root_label", self.latest_justified_root_label
            )
            _check("latest_justified.root", store.latest_justified.root, expected)
        if "latest_finalized_root_label" in fields:
            assert self.latest_finalized_root_label is not None
            expected = _resolve_label(
                "latest_finalized_root_label", self.latest_finalized_root_label
            )
            _check("latest_finalized.root", store.latest_finalized.root, expected)

        # Attestation target checkpoint (slot + root consistency)
        if "attestation_target_slot" in fields:
            target = store.get_attestation_target()
            _check("attestation_target.slot", target.slot, self.attestation_target_slot)

            block_found = any(
                b.slot == self.attestation_target_slot and r == target.root
                for r, b in store.blocks.items()
            )
            if not block_found:
                available = [
                    f"0x{r.hex()}"
                    for r, b in store.blocks.items()
                    if b.slot == self.attestation_target_slot
                ]
                raise AssertionError(
                    f"Step {step_index}: attestation_target.root = "
                    f"0x{target.root.hex()} does not match any "
                    f"block at slot {self.attestation_target_slot}. "
                    f"Available blocks: {available}"
                )

        # Per-validator attestation content checks
        if "attestation_checks" in fields:
            assert self.attestation_checks is not None
            for check in self.attestation_checks:
                if check.location == "new":
                    payloads = store.latest_new_aggregated_payloads
                    label = "in latest_new"
                else:
                    payloads = store.latest_known_aggregated_payloads
                    label = "in latest_known"

                extracted = store.extract_attestations_from_aggregated_payloads(payloads)
                if check.validator not in extracted:
                    raise AssertionError(
                        f"Step {step_index}: validator {check.validator} not found "
                        f"{label}_aggregated_payloads"
                    )
                check.validate_attestation(extracted[check.validator], label, step_index)

        # Block body attestation count
        if "block_attestation_count" in fields:
            if filled_block is None:
                raise ValueError(
                    f"Step {step_index}: block_attestation_count specified but "
                    f"filled_block not provided"
                )
            actual_count = len(filled_block.body.attestations.data)
            if actual_count != self.block_attestation_count:
                att_info = [
                    f"  - participants={list(att.aggregation_bits.to_validator_indices())}"
                    for att in filled_block.body.attestations.data
                ]
                raise AssertionError(
                    f"Step {step_index}: block body has {actual_count} aggregated "
                    f"attestations, expected {self.block_attestation_count}\n"
                    f"Attestations in block:\n" + ("\n".join(att_info) if att_info else "  (empty)")
                )

        # Detailed block body attestation structure
        if "block_attestations" in fields:
            if filled_block is None:
                raise ValueError(
                    f"Step {step_index}: block_attestations specified but filled_block not provided"
                )
            assert self.block_attestations is not None
            StoreChecks._validate_block_attestations(
                self.block_attestations, filled_block, step_index
            )

        # Lexicographic tiebreaker
        if "lexicographic_head_among" in fields:
            if block_registry is None:
                raise ValueError(
                    f"Step {step_index}: lexicographic_head_among specified "
                    f"but block_registry not provided"
                )
            assert self.lexicographic_head_among is not None
            StoreChecks._validate_lexicographic_head(
                self.lexicographic_head_among, store, block_registry, step_index
            )

        # Reorg depth
        if "reorg_depth" in fields:
            if old_head is None:
                raise ValueError(
                    f"Step {step_index}: reorg_depth specified but old_head not provided"
                )
            actual_depth = (
                store.blocks.reorg_depth(old_head, store.head) if store.head != old_head else 0
            )
            _check("reorg_depth", actual_depth, self.reorg_depth)

        # Verify labeled blocks are present in the store
        if "labels_in_store" in fields:
            assert self.labels_in_store is not None
            for label in self.labels_in_store:
                root = _resolve_label("labels_in_store", label)
                if root not in store.blocks:
                    raise AssertionError(
                        f"Step {step_index}: block '{label}' (root=0x{root.hex()}) "
                        f"not found in store.blocks"
                    )

    @staticmethod
    def _validate_block_attestations(
        expected_checks: list["AggregatedAttestationCheck"],
        filled_block: "Block",
        step_index: int,
    ) -> None:
        """Validate detailed attestation structure in the block body."""
        actual_attestations = filled_block.body.attestations.data
        actual_participants_list = [
            {int(v) for v in att.aggregation_bits.to_validator_indices()}
            for att in actual_attestations
        ]

        for check in expected_checks:
            matching_att = None
            matching_idx = None
            for idx, att in enumerate(actual_attestations):
                actual_participants = {int(v) for v in att.aggregation_bits.to_validator_indices()}
                if actual_participants == check.participants:
                    matching_att = att
                    matching_idx = idx
                    break

            if matching_att is None:
                raise AssertionError(
                    f"Step {step_index}: no aggregated attestation found with "
                    f"participants={check.participants}\n"
                    f"Available attestations: {actual_participants_list}"
                )

            if check.attestation_slot is not None:
                if matching_att.data.slot != check.attestation_slot:
                    raise AssertionError(
                        f"Step {step_index}: attestation[{matching_idx}] with "
                        f"participants={check.participants} has "
                        f"slot={matching_att.data.slot}, expected {check.attestation_slot}"
                    )

            if check.target_slot is not None:
                if matching_att.data.target.slot != check.target_slot:
                    raise AssertionError(
                        f"Step {step_index}: attestation[{matching_idx}] with "
                        f"participants={check.participants} has "
                        f"target_slot={matching_att.data.target.slot}, "
                        f"expected {check.target_slot}"
                    )

    @staticmethod
    def _validate_lexicographic_head(
        fork_labels: list[str],
        store: "Store",
        block_registry: dict[str, "Block"],
        step_index: int,
    ) -> None:
        """Validate lexicographic tiebreaker behavior."""
        if len(fork_labels) < 2:
            raise ValueError(
                f"Step {step_index}: lexicographic_head_among requires at least 2 forks "
                f"to test tiebreaker behavior, got {len(fork_labels)}: {fork_labels}"
            )

        # Resolve all fork labels to roots and compute their weights
        fork_data: dict[str, tuple[Bytes32, Slot, int]] = {}
        for label in fork_labels:
            if label not in block_registry:
                raise ValueError(
                    f"Step {step_index}: lexicographic_head_among label '{label}' "
                    f"not found in block registry. Available: {list(block_registry.keys())}"
                )

            block = block_registry[label]
            root = hash_tree_root(block)
            slot = block.slot

            known_attestations = store.extract_attestations_from_aggregated_payloads(
                store.latest_known_aggregated_payloads
            )
            weight = 0
            for attestation in known_attestations.values():
                att_head_root = attestation.head.root
                if att_head_root == root:
                    weight += 1
                elif att_head_root in store.blocks:
                    current = att_head_root
                    while current in store.blocks and store.blocks[current].slot > slot:
                        parent = store.blocks[current].parent_root
                        if parent == root:
                            weight += 1
                            break
                        current = parent

            fork_data[label] = (root, slot, weight)

        # Verify all forks have equal weight
        weights = [weight for _, _, weight in fork_data.values()]
        if len(set(weights)) > 1:
            weight_info = {label: weight for label, (_, _, weight) in fork_data.items()}
            raise AssertionError(
                f"Step {step_index}: lexicographic_head_among forks have "
                f"unequal weights: {weight_info}. All forks must have equal "
                f"attestation weight for tiebreaker to apply.\n"
                f"This check tests the lexicographic tiebreaker, which only "
                f"applies when competing forks have identical weight."
            )

        fork_roots = {label: root for label, (root, _, _) in fork_data.items()}
        expected_head_root = max(fork_roots.values())

        actual_head_root = store.head
        if actual_head_root != expected_head_root:
            highest_label = next(
                label for label, root in fork_roots.items() if root == expected_head_root
            )
            actual_label = next(
                (label for label, root in fork_roots.items() if root == actual_head_root),
                "unknown",
            )
            fork_info = "\n".join(
                f"  {label}: root=0x{root.hex()} weight={weight}"
                for label, (root, _, weight) in sorted(fork_data.items())
            )
            raise AssertionError(
                f"Step {step_index}: lexicographic tiebreaker failed.\n"
                f"Expected head: '{highest_label}' (0x{expected_head_root.hex()})\n"
                f"Actual head:   '{actual_label}' (0x{actual_head_root.hex()})\n"
                f"All competing forks (equal weight={weights[0]}):\n{fork_info}\n"
                f"When forks have equal weight, the fork with the lexicographically "
                f"highest root should be selected as head."
            )
