"""Classification of spec rejections into language-neutral reasons."""

from lean_spec.spec.forks import RejectionReason
from lean_spec.spec.forks.lstar.containers import AggregationError

_REASON_BY_MESSAGE_FRAGMENT: list[tuple[str, RejectionReason]] = [
    ("Target slot must be in the future", RejectionReason.BLOCK_SLOT_NOT_IN_FUTURE),
    ("Block is older than latest header", RejectionReason.BLOCK_OLDER_THAN_LATEST_HEADER),
    ("Block slot mismatch", RejectionReason.BLOCK_SLOT_MISMATCH),
    ("Block parent root mismatch", RejectionReason.PARENT_ROOT_MISMATCH),
    ("Invalid block state root", RejectionReason.STATE_ROOT_MISMATCH),
    ("Parent state not found", RejectionReason.UNKNOWN_PARENT_BLOCK),
    ("Sync parent chain", RejectionReason.UNKNOWN_PARENT_BLOCK),
    ("Proposer index out of range", RejectionReason.PROPOSER_INDEX_OUT_OF_RANGE),
    ("is not the proposer for slot", RejectionReason.WRONG_PROPOSER),
    ("Incorrect block proposer", RejectionReason.WRONG_PROPOSER),
    (
        "Aggregated attestation must reference at least one validator",
        RejectionReason.EMPTY_AGGREGATION_BITS,
    ),
    ("distinct AttestationData entries", RejectionReason.TOO_MANY_ATTESTATION_DATA),
    ("duplicate AttestationData", RejectionReason.DUPLICATE_ATTESTATION_DATA),
    ("Unknown source block", RejectionReason.UNKNOWN_SOURCE_BLOCK),
    ("Unknown target block", RejectionReason.UNKNOWN_TARGET_BLOCK),
    ("Unknown head block", RejectionReason.UNKNOWN_HEAD_BLOCK),
    ("Source checkpoint slot must not exceed target", RejectionReason.SOURCE_AFTER_TARGET),
    ("Head checkpoint must not be older than target", RejectionReason.HEAD_OLDER_THAN_TARGET),
    ("Source checkpoint slot mismatch", RejectionReason.SOURCE_SLOT_MISMATCH),
    ("Target checkpoint slot mismatch", RejectionReason.TARGET_SLOT_MISMATCH),
    ("Head checkpoint slot mismatch", RejectionReason.HEAD_SLOT_MISMATCH),
    (
        "Source checkpoint must be ancestor of target",
        RejectionReason.SOURCE_NOT_ANCESTOR_OF_TARGET,
    ),
    (
        "Target checkpoint must be ancestor of head",
        RejectionReason.TARGET_NOT_ANCESTOR_OF_HEAD,
    ),
    ("Attestation too far in future", RejectionReason.ATTESTATION_TOO_FAR_IN_FUTURE),
    ("not found in state", RejectionReason.VALIDATOR_NOT_IN_STATE),
    ("Validator index out of range", RejectionReason.VALIDATOR_INDEX_OUT_OF_RANGE),
    ("Signature verification failed", RejectionReason.INVALID_SIGNATURE),
    ("Block proof verification failed", RejectionReason.INVALID_SIGNATURE),
    ("Anchor block state root must match", RejectionReason.ANCHOR_STATE_ROOT_MISMATCH),
]
"""
Ordered mapping from spec rejection messages to reasons.

The first fragment contained in the exception message wins.
Fragments mirror the spec's assertion messages one-to-one.
"""


def classify_rejection(exception: Exception) -> RejectionReason:
    """
    Resolve the language-neutral reason behind a spec rejection.

    Args:
        exception: The exception the spec raised for the invalid input.

    Returns:
        The reason emitted into the test vector.

    Raises:
        ValueError: If the rejection is not in the vocabulary yet.
    """
    # Aggregate proof failures carry library-specific messages.
    # The type alone identifies them as signature verification failures.
    if isinstance(exception, AggregationError):
        return RejectionReason.INVALID_SIGNATURE

    message = str(exception)
    for message_fragment, reason in _REASON_BY_MESSAGE_FRAGMENT:
        if message_fragment in message:
            return reason

    raise ValueError(
        f"no rejection reason mapped for {type(exception).__name__}: {message}\n"
        "Add the new rejection to the reason vocabulary and this mapping."
    )
