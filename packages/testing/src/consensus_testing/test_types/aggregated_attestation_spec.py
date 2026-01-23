"""Lightweight aggregated attestation specification for test definitions."""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.types import CamelModel, Uint64


class AggregatedAttestationSpec(CamelModel):
    """
    Aggregated attestation specification for test definitions.

    Specifies multiple validators attesting to the same data.
    Head and source are automatically derived from target.
    """

    validator_ids: list[Uint64]
    """The indices of validators making the attestation (required)."""

    slot: Slot
    """The slot for which the attestation is made (required)."""

    target_slot: Slot
    """The slot of the target block being attested to (required)."""

    target_root_label: str
    """
    Label referencing a previously created block as the target (required).

    The block must exist in the block registry with this label.
    """

    valid_signature: bool = True
    """
    Flag whether the generated attestation signatures should be valid.

    Used for testing that verification properly rejects invalid attestation signatures.
    When False, structurally valid but cryptographically invalid signatures
    (all zeros) will be generated for all attestations instead of proper XMSS signatures.

    Defaults to True (valid signatures).
    """
