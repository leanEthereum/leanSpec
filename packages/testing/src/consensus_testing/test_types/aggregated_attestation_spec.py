"""Lightweight aggregated attestation specification for test definitions."""

from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import CamelModel


class AggregatedAttestationSpec(CamelModel):
    """
    Aggregated attestation specification for test definitions.

    Specifies multiple validators attesting to the same data.
    Head and source are automatically derived from target.
    """

    validator_ids: list[ValidatorIndex]
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

    signer_ids: list[ValidatorIndex] | None = None
    """
    Override which validators actually sign the attestation.

    When None (default), signatures are generated using the validators in validator_ids.
    When specified, signatures are generated using these validator indices instead.

    This creates a mismatch between claimed participants and actual signers.
    Useful for testing that verification rejects attestations where valid signatures
    don't correspond to the claimed validators.

    Must have same length as validator_ids when specified.
    """
