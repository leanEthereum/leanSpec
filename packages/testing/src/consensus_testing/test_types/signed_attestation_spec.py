"""Lightweight attestation specification for test definitions."""

from lean_spec.subspecs.containers.signature import Signature
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import CamelModel, Uint64, ValidatorIndex


class SignedAttestationSpec(CamelModel):
    """
    Signed attestation specification for test definitions.

    Simplified interface that only requires the essential fields.
    Head and source are automatically derived from target.
    """

    validator_id: ValidatorIndex | Uint64
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

    signature: Signature | None = None
    """
    The signature for the attestation.

    If None, uses Signature.zero() for testing.
    """
