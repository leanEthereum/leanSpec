"""Classification of spec rejections into language-neutral reasons."""

from lean_spec.spec.forks import RejectionReason, SpecRejectionError
from lean_spec.spec.forks.lstar.containers import AggregationError


def classify_rejection(exception: Exception) -> RejectionReason:
    """
    Resolve the language-neutral reason behind a spec rejection.

    Args:
        exception: The exception the spec raised for the invalid input.

    Returns:
        The reason emitted into the test vector.

    Raises:
        ValueError: If the exception carries no reason.
    """
    # Typed rejections carry their reason directly.
    if isinstance(exception, SpecRejectionError):
        return exception.reason

    # Aggregate proof failures carry library-specific messages.
    # The type alone identifies them as signature verification failures.
    if isinstance(exception, AggregationError):
        return RejectionReason.INVALID_SIGNATURE

    raise ValueError(
        f"no rejection reason carried by {type(exception).__name__}: {exception}\n"
        "Spec rejections must raise the typed rejection error with a reason."
    )
