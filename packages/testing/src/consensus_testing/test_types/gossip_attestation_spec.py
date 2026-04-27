"""Lightweight gossip attestation specification for test definitions."""

from __future__ import annotations

from lean_spec.forks.lstar.containers.attestation import AttestationData, SignedAttestation
from lean_spec.forks.lstar.containers.block.block import Block
from lean_spec.forks.lstar.containers.checkpoint import Checkpoint
from lean_spec.forks.lstar.containers.slot import Slot
from lean_spec.forks.lstar.containers.validator import ValidatorIndex
from lean_spec.forks.lstar.store import Store
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, CamelModel

from ..keys import XmssKeyManager, create_dummy_signature
from .utils import resolve_checkpoint


class GossipAttestationSpec(CamelModel):
    """
    Gossip attestation specification for test definitions.

    Specifies a single validator attesting via gossip network.
    Similar to AggregatedAttestationSpec but for individual gossip attestations.
    """

    validator_id: ValidatorIndex
    """The index of the validator making the attestation (required)."""

    slot: Slot
    """The slot for which the attestation is made (required)."""

    target_slot: Slot
    """The slot of the target block being attested to (required)."""

    target_root_label: str
    """
    Label referencing a previously created block as the target (required).

    The block must exist in the block registry with this label.
    """

    head_root_label: str | None = None
    """
    Label referencing a previously created block as the head.

    When None (default), head is set equal to the target checkpoint.
    When specified, resolves to a different block for testing topology violations.
    """

    head_slot: Slot | None = None
    """
    Override for the head checkpoint slot.

    When None (default), uses the actual slot of the head block.
    When specified, creates a mismatch for testing consistency checks.
    """

    source_root_label: str | None = None
    """
    Label referencing a previously created block as the source.

    When None (default), source is the anchor (genesis) block.
    When specified, resolves to a different block for testing source overrides.
    """

    source_slot: Slot | None = None
    """
    Override for the source checkpoint slot.

    When None (default), uses the actual slot of the source block.
    When specified, creates a mismatch for testing consistency checks.
    """

    target_root_override: Bytes32 | None = None
    """
    Raw root override for the target checkpoint.

    Bypasses label resolution. Used to inject roots not in the store
    for testing unknown block rejection.
    """

    head_root_override: Bytes32 | None = None
    """
    Raw root override for the head checkpoint.

    Bypasses label resolution. Used to inject roots not in the store
    for testing unknown block rejection.
    """

    source_root_override: Bytes32 | None = None
    """
    Raw root override for the source checkpoint.

    Bypasses label resolution. Used to inject roots not in the store
    for testing unknown block rejection.
    """

    valid_signature: bool = True
    """
    Flag whether the generated attestation signature should be valid.

    Used for testing that verification properly rejects invalid attestation signatures.
    When False, a structurally valid but cryptographically invalid signature
    (all zeros) will be generated instead of a proper XMSS signature.

    Defaults to True (valid signature).
    """

    @property
    def has_overrides(self) -> bool:
        """Whether any checkpoint field is explicitly overridden."""
        return (
            self.head_root_label is not None
            or self.head_slot is not None
            or self.source_root_label is not None
            or self.source_slot is not None
            or self.target_root_override is not None
            or self.head_root_override is not None
            or self.source_root_override is not None
        )

    def build_attestation_data(
        self,
        block_registry: dict[str, Block],
        anchor_block: Block,
    ) -> AttestationData:
        """
        Build attestation data with explicit checkpoint overrides.

        Used for invalid or non-standard attestations where the test
        intentionally creates mismatches for validation testing.

        Args:
            block_registry: Labeled blocks for checkpoint resolution.
            anchor_block: Genesis/anchor block used as default source.

        Returns:
            Attestation data with overridden checkpoints.
        """
        target = resolve_checkpoint(self.target_root_label, self.target_slot, block_registry)

        # Resolve head checkpoint.
        # Defaults to the target checkpoint when not overridden.
        if self.head_root_label is not None:
            head = resolve_checkpoint(self.head_root_label, self.head_slot, block_registry)
        else:
            head = Checkpoint(
                root=target.root,
                slot=target.slot if self.head_slot is None else self.head_slot,
            )

        # Resolve source checkpoint.
        # Defaults to the anchor (genesis) block when not overridden.
        if self.source_root_label is not None:
            source = resolve_checkpoint(self.source_root_label, self.source_slot, block_registry)
        else:
            source = Checkpoint(
                root=hash_tree_root(anchor_block),
                slot=anchor_block.slot if self.source_slot is None else self.source_slot,
            )

        # Apply raw root overrides.
        # These inject roots not in the store for testing unknown block rejection.
        if self.target_root_override is not None:
            target = Checkpoint(root=self.target_root_override, slot=target.slot)
        if self.head_root_override is not None:
            head = Checkpoint(root=self.head_root_override, slot=head.slot)
        if self.source_root_override is not None:
            source = Checkpoint(root=self.source_root_override, slot=source.slot)

        return AttestationData(
            slot=self.slot,
            head=head,
            target=target,
            source=source,
        )

    def build_signed(
        self,
        block_registry: dict[str, Block],
        key_manager: XmssKeyManager,
        store: Store,
        anchor_block: Block,
        expected_valid: bool,
    ) -> SignedAttestation:
        """
        Build a complete signed attestation from this specification.

        Valid attestations without overrides use honest data from the Store.
        Invalid or overridden attestations use this spec's checkpoint fields.

        Args:
            block_registry: Labeled blocks for target resolution.
            key_manager: XMSS key manager for signing.
            store: Fork choice store for honest attestation data production.
            anchor_block: Genesis/anchor block for source checkpoint default.
            expected_valid: Whether the step expects this attestation to succeed.

        Returns:
            Signed attestation ready for gossip processing.
        """
        if not expected_valid or self.has_overrides:
            attestation_data = self.build_attestation_data(block_registry, anchor_block)
        else:
            # Honest path: use the Store's own attestation data production.
            attestation_data = store.produce_attestation_data(self.slot)

        signature = (
            key_manager.sign_attestation_data(self.validator_id, attestation_data)
            if self.valid_signature
            else create_dummy_signature()
        )

        return SignedAttestation(
            validator_id=self.validator_id,
            data=attestation_data,
            signature=signature,
        )
