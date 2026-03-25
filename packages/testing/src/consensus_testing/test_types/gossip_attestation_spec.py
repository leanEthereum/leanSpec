"""Lightweight gossip attestation specification for test definitions."""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import CamelModel


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

    valid_signature: bool = True
    """
    Flag whether the generated attestation signature should be valid.

    Used for testing that verification properly rejects invalid attestation signatures.
    When False, a structurally valid but cryptographically invalid signature
    (all zeros) will be generated instead of a proper XMSS signature.

    Defaults to True (valid signature).
    """
