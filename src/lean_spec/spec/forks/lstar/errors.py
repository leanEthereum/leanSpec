"""Rejection reasons and the typed error that carries them."""

from enum import StrEnum


class RejectionReason(StrEnum):
    """Language-neutral reason the spec rejects an invalid input."""

    # Block validation
    BLOCK_SLOT_NOT_IN_FUTURE = "BLOCK_SLOT_NOT_IN_FUTURE"
    """The block slot is not strictly greater than the current state slot."""

    BLOCK_OLDER_THAN_LATEST_HEADER = "BLOCK_OLDER_THAN_LATEST_HEADER"
    """The block slot is not newer than the latest block header."""

    BLOCK_SLOT_MISMATCH = "BLOCK_SLOT_MISMATCH"
    """The block slot disagrees with the state slot after slot processing."""

    PARENT_ROOT_MISMATCH = "PARENT_ROOT_MISMATCH"
    """The block parent root disagrees with the latest block header root."""

    STATE_ROOT_MISMATCH = "STATE_ROOT_MISMATCH"
    """The block state root disagrees with the computed post-state root."""

    UNKNOWN_PARENT_BLOCK = "UNKNOWN_PARENT_BLOCK"
    """The block references a parent the store has never seen."""

    PROPOSER_INDEX_OUT_OF_RANGE = "PROPOSER_INDEX_OUT_OF_RANGE"
    """The proposer index does not address any registered validator."""

    WRONG_PROPOSER = "WRONG_PROPOSER"
    """The block proposer is not the scheduled proposer for its slot."""

    TOO_MANY_ATTESTATION_DATA = "TOO_MANY_ATTESTATION_DATA"
    """The block carries more distinct attestation data entries than allowed."""

    DUPLICATE_ATTESTATION_DATA = "DUPLICATE_ATTESTATION_DATA"
    """The block carries the same attestation data entry more than once."""

    EMPTY_AGGREGATION_BITS = "EMPTY_AGGREGATION_BITS"
    """An aggregated attestation references no validator at all."""

    # Attestation validation
    UNKNOWN_SOURCE_BLOCK = "UNKNOWN_SOURCE_BLOCK"
    """The attestation source root is not a known block."""

    UNKNOWN_TARGET_BLOCK = "UNKNOWN_TARGET_BLOCK"
    """The attestation target root is not a known block."""

    UNKNOWN_HEAD_BLOCK = "UNKNOWN_HEAD_BLOCK"
    """The attestation head root is not a known block."""

    SOURCE_AFTER_TARGET = "SOURCE_AFTER_TARGET"
    """The attestation source checkpoint slot exceeds its target slot."""

    HEAD_OLDER_THAN_TARGET = "HEAD_OLDER_THAN_TARGET"
    """The attestation head checkpoint is older than its target."""

    SOURCE_SLOT_MISMATCH = "SOURCE_SLOT_MISMATCH"
    """The source checkpoint slot disagrees with the referenced block."""

    TARGET_SLOT_MISMATCH = "TARGET_SLOT_MISMATCH"
    """The target checkpoint slot disagrees with the referenced block."""

    HEAD_SLOT_MISMATCH = "HEAD_SLOT_MISMATCH"
    """The head checkpoint slot disagrees with the referenced block."""

    SOURCE_NOT_ANCESTOR_OF_TARGET = "SOURCE_NOT_ANCESTOR_OF_TARGET"
    """The attestation source checkpoint is not an ancestor of its target."""

    TARGET_NOT_ANCESTOR_OF_HEAD = "TARGET_NOT_ANCESTOR_OF_HEAD"
    """The attestation target checkpoint is not an ancestor of its head."""

    ATTESTATION_TOO_FAR_IN_FUTURE = "ATTESTATION_TOO_FAR_IN_FUTURE"
    """The attestation slot is beyond the store's acceptance horizon."""

    VALIDATOR_NOT_IN_STATE = "VALIDATOR_NOT_IN_STATE"
    """The referenced validator does not exist in the state registry."""

    VALIDATOR_INDEX_OUT_OF_RANGE = "VALIDATOR_INDEX_OUT_OF_RANGE"
    """The validator index does not address any registered validator."""

    # Cryptographic verification
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    """An attestation signature or aggregate proof fails cryptographic verification."""

    INVALID_BLOCK_PROOF = "INVALID_BLOCK_PROOF"
    """The block's multi-message aggregate proof fails verification."""

    # Anchor initialization
    ANCHOR_STATE_ROOT_MISMATCH = "ANCHOR_STATE_ROOT_MISMATCH"
    """The anchor block state root disagrees with the anchor state."""

    # Wire decoding
    DECODE_ERROR = "DECODE_ERROR"
    """The input bytes cannot be decoded into the expected structure."""


class SpecRejectionError(AssertionError):
    """
    A rejection carrying its language-neutral reason.

    Subclassing the assertion error keeps existing rejection handlers working.
    """

    def __init__(self, reason: RejectionReason, message: str) -> None:
        """
        Bind the rejection to its reason.

        Args:
            reason: Language-neutral reason clients assert against.
            message: Human-readable explanation for logs and debugging.
        """
        super().__init__(message)
        self.reason = reason
