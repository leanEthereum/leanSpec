"""Base fixture definitions for consensus test formats."""

from typing import Any, ClassVar

from framework.test_fixtures import BaseFixture
from pydantic import field_serializer


class BaseConsensusFixture(BaseFixture):
    """
    Base class for all consensus test fixtures.

    Inherits shared functionality from framework.fixtures.BaseFixture
    and adds consensus-specific behavior if needed.
    """

    # Class-level registry of all consensus fixture formats
    # Override parent's formats to maintain a separate registry
    formats: ClassVar[dict[str, type["BaseConsensusFixture"]]] = {}  # type: ignore[assignment]

    expect_exception: type[Exception] | None = None
    """
    Expected exception type for invalid tests.

    If set, the fixture expects this exception during processing.
    The test passes only if the exception is raised.
    """

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        """
        Auto-register consensus fixture formats when subclasses are defined.

        Overrides parent to register in BaseConsensusFixture.formats instead
        of BaseFixture.formats.
        """
        super().__pydantic_init_subclass__(**kwargs)
        if cls.format_name:
            BaseConsensusFixture.formats[cls.format_name] = cls

    @field_serializer("expect_exception", when_used="json")
    def serialize_exception(self, value: type[Exception] | None) -> str | None:
        """Serialize exception type to its class name for JSON output."""
        if value is None:
            return None
        return value.__name__

    def assert_expected_outcome(self, exception_raised: Exception | None) -> None:
        """Compare a self-verification outcome against the configured expectation.

        A fixture that self-verifies its own output catches the verifier exception.
        It then hands the caught exception here to decide pass or fail.

        Args:
            exception_raised: The exception the verifier raised, or None on success.

        Raises:
            AssertionError: When the outcome disagrees with the expectation.
        """
        # No expectation means the bundle is honest and must verify.
        if self.expect_exception is None:
            if exception_raised is not None:
                raise AssertionError(f"Verifier rejected an honest bundle: {exception_raised}")
        # An expectation that produced no exception means the tamper went undetected.
        elif exception_raised is None:
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} but verification succeeded"
            )
        # A wrong exception type means the rejection fired for the wrong reason.
        elif not isinstance(exception_raised, self.expect_exception):
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} but got "
                f"{type(exception_raised).__name__}: {exception_raised}"
            )
