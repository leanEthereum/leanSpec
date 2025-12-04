"""Lightweight attestation specification for test definitions."""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.xmss.containers import Signature
from lean_spec.types import CamelModel, Uint64


class SignedAttestationSpec(CamelModel):
    """
    Signed attestation specification for test definitions.

    Simplified interface that only requires the essential fields.
    Head and source are automatically derived from target.
    """

    validator_id: Uint64
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

    If None, uses an empty signature for testing.
    """

    valid_signature: bool = True
    """
    Flag whether the generated attestation signature should be valid.

    Used for testing that verification properly rejects invalid attestation signatures.
    When False, a structurally valid but cryptographically invalid signature
    (all zeros) will be generated for the attestation instead of a proper XMSS signature.

    Defaults to True (valid signature).
    If False, the attestation will be given a dummy/invalid signature.
    """
