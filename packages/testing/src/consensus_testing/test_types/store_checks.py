"""Store checks model for selective validation in fork choice tests."""

from collections.abc import Callable
from typing import Any, ClassVar, Literal

from consensus_testing.test_types.selective_check import SelectiveCheck
from consensus_testing.test_types.utils import resolve_block_root
from lean_spec.base import CamelModel
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.forks import Interval, Slot, ValidatorIndex
from lean_spec.spec.forks.lstar.containers import AttestationData, Block, Store
from lean_spec.spec.forks.lstar.spec import LstarSpec
from lean_spec.spec.ssz import ZERO_HASH, Bytes32

_ATTESTATION_SLOT_ACCESSORS: dict[str, Callable[[AttestationData], Slot]] = {
    "attestation_slot": lambda attestation: attestation.slot,
    "head_slot": lambda attestation: attestation.head.slot,
    "source_slot": lambda attestation: attestation.source.slot,
    "target_slot": lambda attestation: attestation.target.slot,
}
"""Per-validator attestation check field to the slot it reads."""


def _ancestor_set(blocks: dict[Bytes32, Block], head: Bytes32) -> set[Bytes32]:
    """Walk parent links from head and collect every reachable block root."""
    seen: set[Bytes32] = set()
    root = head
    while root in blocks:
        seen.add(root)
        parent = blocks[root].parent_root
        if parent == ZERO_HASH:
            break
        root = parent
    return seen


class AggregatedAttestationCheck(CamelModel):
    """Validation checks for one aggregated attestation in the block body."""

    participants: set[int]
    """Expected validator indices covered by this aggregated attestation."""

    attestation_slot: Slot | None = None
    """Expected attestation data slot, checked only when set."""

    target_slot: Slot | None = None
    """Expected target checkpoint slot, checked only when set."""


class AttestationCheck(CamelModel):
    """Validation checks for one validator's attestation, limited to fields explicitly set."""

    validator: ValidatorIndex
    """Which validator's attestation to check."""

    attestation_slot: Slot | None = None
    """Expected attestation data slot."""

    head_slot: Slot | None = None
    """Expected head checkpoint slot."""

    source_slot: Slot | None = None
    """Expected source checkpoint slot."""

    source_root_label: str | None = None
    """Expected source checkpoint root, named by label and resolved to a root."""

    target_slot: Slot | None = None
    """Expected target checkpoint slot."""

    location: Literal["new", "known", "signatures"]
    """Which pool the attestation should sit in: the pending pool, the accepted pool, or the raw
    per-validator signature pool."""

    def validate_attestation(
        self,
        attestation: AttestationData,
        location: str,
        step_index: int,
        expected_source_root: Bytes32 | None = None,
    ) -> None:
        """Validate attestation properties."""
        for field_name in self.model_fields_set & _ATTESTATION_SLOT_ACCESSORS.keys():
            expected_slot = getattr(self, field_name)
            actual_slot = _ATTESTATION_SLOT_ACCESSORS[field_name](attestation)
            if actual_slot != expected_slot:
                raise AssertionError(
                    f"Step {step_index}: validator {self.validator} {location} "
                    f"{field_name} = {actual_slot}, expected {expected_slot}"
                )

        if expected_source_root is not None and attestation.source.root != expected_source_root:
            raise AssertionError(
                f"Step {step_index}: validator {self.validator} {location} "
                f"source root = 0x{attestation.source.root.hex()}, "
                f"expected 0x{expected_source_root.hex()}"
            )


class StoreChecks(SelectiveCheck):
    """Store state checks for fork choice tests, validating only the fields a test sets."""

    _SCALAR_ACCESSORS: ClassVar[dict[str, Callable[[Store], Any]]] = {
        "time": lambda store: store.time,
        "head_slot": lambda store: store.blocks[store.head].slot,
        "head_root": lambda store: store.head,
        "latest_justified_slot": lambda store: store.latest_justified.slot,
        "latest_justified_root": lambda store: store.latest_justified.root,
        "latest_finalized_slot": lambda store: store.latest_finalized.slot,
        "latest_finalized_root": lambda store: store.latest_finalized.root,
        "safe_target": lambda store: store.safe_target,
        "safe_target_slot": lambda store: store.blocks[store.safe_target].slot,
    }
    """Scalar field to the store value it must equal."""

    _LABEL_ROOT_ACCESSORS: ClassVar[dict[str, Callable[[Store], Bytes32]]] = {
        "head_root_label": lambda store: store.head,
        "latest_justified_root_label": lambda store: store.latest_justified.root,
        "latest_finalized_root_label": lambda store: store.latest_finalized.root,
        "safe_target_root_label": lambda store: store.safe_target,
    }
    """Label-reference field to the store root it must resolve to."""

    _POOL_TARGET_SLOT_ACCESSORS: ClassVar[dict[str, Callable[[Store], Any]]] = {
        "attestation_signature_target_slots": lambda store: store.attestation_signatures,
        "latest_new_aggregated_target_slots": lambda store: store.latest_new_aggregated_payloads,
        "latest_known_aggregated_target_slots": (
            lambda store: store.latest_known_aggregated_payloads
        ),
    }
    """Pool target-slot field to the pool whose keyed target slots it compares."""

    time: Interval | None = None
    """Expected store time (in intervals since genesis)."""

    head_slot: Slot | None = None
    """Expected head block slot."""

    head_root: Bytes32 | None = None
    """Expected head block root."""

    head_root_label: str | None = None
    """Expected head block root, named by label and resolved to a root."""

    filled_block_root_label: str | None = None
    """Expected root of the block built for this step, named by label.

    Proves the fixture rebuilt the exact known block, not a different one with an unchanged head.
    """

    latest_justified_slot: Slot | None = None
    """Expected latest justified checkpoint slot."""

    latest_justified_root: Bytes32 | None = None
    """Expected latest justified checkpoint root."""

    latest_justified_root_label: str | None = None
    """Expected latest justified checkpoint root, named by label and resolved to a root."""

    latest_finalized_slot: Slot | None = None
    """Expected latest finalized checkpoint slot."""

    latest_finalized_root: Bytes32 | None = None
    """Expected latest finalized checkpoint root."""

    latest_finalized_root_label: str | None = None
    """Expected latest finalized checkpoint root, named by label and resolved to a root."""

    safe_target: Bytes32 | None = None
    """Expected safe target root."""

    safe_target_slot: Slot | None = None
    """Expected safe target block slot."""

    safe_target_root_label: str | None = None
    """Expected safe target root, named by label and resolved to a root."""

    attestation_target_slot: Slot | None = None
    """Expected attestation target checkpoint slot.

    The checkpoint root must also reference an actual block at that slot.
    """

    attestation_target_root_label: str | None = None
    """Expected attestation target root, named by label and resolved to a root."""

    attestation_checks: list[AttestationCheck] | None = None
    """Attestation content checks for specific validators."""

    attestation_signature_target_slots: list[Slot] | None = None
    """Expected set of target slots keyed in the raw gossip signature map."""

    latest_new_aggregated_target_slots: list[Slot] | None = None
    """Expected set of target slots keyed in the pending aggregated proof map."""

    latest_known_aggregated_target_slots: list[Slot] | None = None
    """Expected set of target slots keyed in the accepted aggregated proof map."""

    new_pool_proof_participants: dict[Slot, set[int]] | None = None
    """Expected union of validator indices across pending-pool proofs, per target slot."""

    block_attestation_count: int | None = None
    """Expected number of aggregated attestations in the block body.

    More than one means attestations split over incompatible sources rather than merging.
    """

    block_attestations: list[AggregatedAttestationCheck] | None = None
    """Detailed per-attestation checks for the block body."""

    lexicographic_head_among: list[str] | None = None
    """Fork labels expected to tie, with the head chosen by the lexicographic tiebreaker.

    All listed forks must have equal attestation weight, and the head carries the highest root.
    """

    reorg_depth: int | None = None
    """Expected count of blocks from the old head back to its common ancestor with the new head."""

    labels_in_store: list[str] | None = None
    """Block labels still present in the block tree, verifying abandoned forks are retained."""

    def validate_against_store(
        self,
        store: Store,
        step_index: int,
        block_registry: dict[str, Block] | None = None,
        filled_block: Block | None = None,
        old_head: Bytes32 | None = None,
    ) -> None:
        """
        Validate these checks against actual store state, limited to fields the test set.

        Args:
            store: The fork choice store to validate against.
            step_index: Index of the step being validated (for error messages).
            block_registry: Optional labeled blocks for resolving label-based checks.
            filled_block: Optional block for validating block body attestations.
            old_head: Previous head root before this step executed.
                Required for reorg_depth checks.
        """
        fields = self.model_fields_set

        def _check(name: str, actual: object, expected: object) -> None:
            if actual != expected:
                raise AssertionError(f"Step {step_index}: {name} = {actual}, expected {expected}")

        def _resolve(label: str) -> Bytes32:
            if block_registry is None:
                raise ValueError(
                    f"Step {step_index}: label '{label}' specified but block_registry not provided"
                )
            return resolve_block_root(label, block_registry)

        # Scalar store fields
        self.validate_scalar_fields(store, f"Step {step_index}")

        # Resolve each label to a root, then compare.
        for field_name in fields & self._LABEL_ROOT_ACCESSORS.keys():
            expected_root = _resolve(getattr(self, field_name))
            _check(field_name, self._LABEL_ROOT_ACCESSORS[field_name](store), expected_root)

        if "filled_block_root_label" in fields:
            if filled_block is None:
                raise ValueError(
                    f"Step {step_index}: filled_block_root_label specified but "
                    f"filled_block not provided"
                )
            assert self.filled_block_root_label is not None
            expected_filled_block_root = _resolve(self.filled_block_root_label)
            _check("filled_block.root", hash_tree_root(filled_block), expected_filled_block_root)

        # Attestation target checkpoint (slot + root consistency)
        if "attestation_target_slot" in fields or "attestation_target_root_label" in fields:
            attestation_target = LstarSpec().get_attestation_target(store)

        if "attestation_target_slot" in fields:
            _check("attestation_target.slot", attestation_target.slot, self.attestation_target_slot)

            block_found = any(
                block.slot == self.attestation_target_slot and block_root == attestation_target.root
                for block_root, block in store.blocks.items()
            )
            if not block_found:
                block_roots_at_target_slot = [
                    f"0x{block_root.hex()}"
                    for block_root, block in store.blocks.items()
                    if block.slot == self.attestation_target_slot
                ]
                raise AssertionError(
                    f"Step {step_index}: attestation_target.root = "
                    f"0x{attestation_target.root.hex()} does not match any "
                    f"block at slot {self.attestation_target_slot}. "
                    f"Available blocks: {block_roots_at_target_slot}"
                )

        # Attestation target root pinned to a labeled block
        if "attestation_target_root_label" in fields:
            assert self.attestation_target_root_label is not None
            expected_attestation_target_root = _resolve(self.attestation_target_root_label)
            _check(
                "attestation_target.root",
                attestation_target.root,
                expected_attestation_target_root,
            )

        # Per-validator attestation content checks
        if "attestation_checks" in fields:
            assert self.attestation_checks is not None
            for attestation_check in self.attestation_checks:
                # Map each validator to its highest-slot vote in the named pool.
                #
                # The checker inspects pool content before pruning, so no finality cutoff applies.
                # On equal slots the first vote seen wins, matching the fork-choice rule.
                extracted_attestations: dict[ValidatorIndex, AttestationData] = {}
                if attestation_check.location == "signatures":
                    # The raw signature pool groups one entry per validator under each vote.
                    label = "in attestation_signatures"
                    for attestation_data, entries in store.attestation_signatures.items():
                        for signature_entry in entries:
                            voter_index = signature_entry.validator_index
                            previous_vote = extracted_attestations.get(voter_index)
                            if previous_vote is None or previous_vote.slot < attestation_data.slot:
                                extracted_attestations[voter_index] = attestation_data
                else:
                    # The aggregated pools group proofs covering many validators under each vote.
                    if attestation_check.location == "new":
                        payloads = store.latest_new_aggregated_payloads
                        label = "in latest_new_aggregated_payloads"
                    else:
                        payloads = store.latest_known_aggregated_payloads
                        label = "in latest_known_aggregated_payloads"
                    for attestation_data, proofs in payloads.items():
                        for proof in proofs:
                            for participant_index in proof.participants.to_validator_indices():
                                previous_vote = extracted_attestations.get(participant_index)
                                if (
                                    previous_vote is None
                                    or previous_vote.slot < attestation_data.slot
                                ):
                                    extracted_attestations[participant_index] = attestation_data

                if attestation_check.validator not in extracted_attestations:
                    raise AssertionError(
                        f"Step {step_index}: validator {attestation_check.validator} not found "
                        f"{label}"
                    )
                expected_source_root = (
                    _resolve(attestation_check.source_root_label)
                    if attestation_check.source_root_label is not None
                    else None
                )
                attestation_check.validate_attestation(
                    extracted_attestations[attestation_check.validator],
                    label,
                    step_index,
                    expected_source_root,
                )

        # Target slots keyed in each attestation pool
        for field_name in fields & self._POOL_TARGET_SLOT_ACCESSORS.keys():
            pool = self._POOL_TARGET_SLOT_ACCESSORS[field_name](store)
            actual_target_slots = sorted(
                {attestation_data.target.slot for attestation_data in pool}
            )
            expected_target_slots = sorted(getattr(self, field_name))
            _check(field_name, actual_target_slots, expected_target_slots)

        # Participant union across pending-pool proofs, per target slot
        if "new_pool_proof_participants" in fields:
            assert self.new_pool_proof_participants is not None
            participants_by_target_slot: dict[Slot, set[int]] = {}
            for attestation_data, proofs in store.latest_new_aggregated_payloads.items():
                target_slot = attestation_data.target.slot
                participants = participants_by_target_slot.setdefault(target_slot, set())
                for proof in proofs:
                    participants.update(
                        int(validator_index)
                        for validator_index in proof.participants.to_validator_indices()
                    )
            for target_slot, expected_participants in self.new_pool_proof_participants.items():
                _check(
                    f"new_pool_proof_participants[{target_slot}]",
                    participants_by_target_slot.get(target_slot, set()),
                    expected_participants,
                )

        # Block body attestation count
        if "block_attestation_count" in fields:
            if filled_block is None:
                raise ValueError(
                    f"Step {step_index}: block_attestation_count specified but "
                    f"filled_block not provided"
                )
            actual_count = len(filled_block.body.attestations.data)
            if actual_count != self.block_attestation_count:
                attestation_info = [
                    f"  - participants={list(attestation.aggregation_bits.to_validator_indices())}"
                    for attestation in filled_block.body.attestations.data
                ]
                raise AssertionError(
                    f"Step {step_index}: block body has {actual_count} aggregated "
                    f"attestations, expected {self.block_attestation_count}\n"
                    f"Attestations in block:\n"
                    + ("\n".join(attestation_info) if attestation_info else "  (empty)")
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
            actual_depth = len(
                _ancestor_set(store.blocks, old_head) - _ancestor_set(store.blocks, store.head)
            )
            _check("reorg_depth", actual_depth, self.reorg_depth)

        # Verify labeled blocks are present in the store
        if "labels_in_store" in fields:
            assert self.labels_in_store is not None
            for label in self.labels_in_store:
                root = _resolve(label)
                if root not in store.blocks:
                    raise AssertionError(
                        f"Step {step_index}: block '{label}' (root=0x{root.hex()}) "
                        f"not found in store.blocks"
                    )

    @staticmethod
    def _validate_block_attestations(
        expected_checks: list[AggregatedAttestationCheck],
        filled_block: Block,
        step_index: int,
    ) -> None:
        """Validate detailed attestation structure in the block body."""
        actual_attestations = filled_block.body.attestations.data
        actual_participants_list = [
            {
                int(validator_index)
                for validator_index in attestation.aggregation_bits.to_validator_indices()
            }
            for attestation in actual_attestations
        ]

        for attestation_check in expected_checks:
            matching_attestation = None
            matching_index = None
            for attestation_index, attestation in enumerate(actual_attestations):
                actual_participants = {
                    int(validator_index)
                    for validator_index in attestation.aggregation_bits.to_validator_indices()
                }
                if actual_participants == attestation_check.participants:
                    matching_attestation = attestation
                    matching_index = attestation_index
                    break

            if matching_attestation is None:
                raise AssertionError(
                    f"Step {step_index}: no aggregated attestation found with "
                    f"participants={attestation_check.participants}\n"
                    f"Available attestations: {actual_participants_list}"
                )

            if attestation_check.attestation_slot is not None:
                if matching_attestation.data.slot != attestation_check.attestation_slot:
                    raise AssertionError(
                        f"Step {step_index}: attestation[{matching_index}] with "
                        f"participants={attestation_check.participants} has "
                        f"slot={matching_attestation.data.slot}, "
                        f"expected {attestation_check.attestation_slot}"
                    )

            if attestation_check.target_slot is not None:
                if matching_attestation.data.target.slot != attestation_check.target_slot:
                    raise AssertionError(
                        f"Step {step_index}: attestation[{matching_index}] with "
                        f"participants={attestation_check.participants} has "
                        f"target_slot={matching_attestation.data.target.slot}, "
                        f"expected {attestation_check.target_slot}"
                    )

    @staticmethod
    def _validate_lexicographic_head(
        fork_labels: list[str],
        store: Store,
        block_registry: dict[str, Block],
        step_index: int,
    ) -> None:
        """Validate lexicographic tiebreaker behavior."""
        if len(fork_labels) < 2:
            raise ValueError(
                f"Step {step_index}: lexicographic_head_among requires at least 2 forks "
                f"to test tiebreaker behavior, got {len(fork_labels)}: {fork_labels}"
            )

        # Resolve all fork labels to roots and compute their weights.
        spec_block_weights = LstarSpec().compute_block_weights(store)

        fork_data: dict[str, tuple[Bytes32, int]] = {}
        for label in fork_labels:
            if label not in block_registry:
                raise ValueError(
                    f"Step {step_index}: lexicographic_head_among label '{label}' "
                    f"not found in block registry. Available: {list(block_registry.keys())}"
                )

            fork_root = hash_tree_root(block_registry[label])
            fork_data[label] = (fork_root, spec_block_weights.get(fork_root, 0))

        # Verify all forks have equal weight
        weights = [weight for _, weight in fork_data.values()]
        if len(set(weights)) > 1:
            weight_info = {label: weight for label, (_, weight) in fork_data.items()}
            raise AssertionError(
                f"Step {step_index}: lexicographic_head_among forks have "
                f"unequal weights: {weight_info}. All forks must have equal "
                f"attestation weight for tiebreaker to apply.\n"
                f"This check tests the lexicographic tiebreaker, which only "
                f"applies when competing forks have identical weight."
            )

        fork_roots = {label: root for label, (root, _) in fork_data.items()}
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
                for label, (root, weight) in sorted(fork_data.items())
            )
            raise AssertionError(
                f"Step {step_index}: lexicographic tiebreaker failed.\n"
                f"Expected head: '{highest_label}' (0x{expected_head_root.hex()})\n"
                f"Actual head:   '{actual_label}' (0x{actual_head_root.hex()})\n"
                f"All competing forks (equal weight={weights[0]}):\n{fork_info}\n"
                f"When forks have equal weight, the fork with the lexicographically "
                f"highest root should be selected as head."
            )
