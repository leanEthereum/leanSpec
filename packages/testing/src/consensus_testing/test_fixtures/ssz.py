"""SSZ test fixture format for serialization conformance testing."""

from typing import Any, ClassVar

from pydantic import field_serializer

from lean_spec.base import CamelModel
from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.merkleization import hash_tree_root
from lean_spec.spec.ssz.boolean import Boolean
from lean_spec.spec.ssz.ssz_base import SSZType

from .base import BaseConsensusFixture


class SSZTest(BaseConsensusFixture):
    """Fixture for SSZ conformance testing.

    Supports two modes:

    - Roundtrip mode (default): encode `value`, decode back, verify equality
      and compute `hash_tree_root`. JSON output: typeName, value, serialized, root.
    - Decode-failure mode: when `expect_exception` is set, `raw_bytes` holds
      the malformed input. The fixture decodes the input as `type(value)` and
      asserts the expected exception is raised. JSON output keeps the same
      shape; `serialized` holds the malformed bytes and `root` is empty.
    """

    format_name: ClassVar[str] = "ssz"
    description: ClassVar[str] = "Tests SSZ serialization roundtrip and hash_tree_root"

    type_name: str
    """SSZ type class name."""

    value: SSZType
    """
    The SSZ value under test.

    Roundtrip mode: the value to encode and round-trip.
    Decode-failure mode: acts as a type tag; its class is used as the decoder.
    Supply any instance of the target type (often a default-constructed one).
    """

    raw_bytes: str | None = None
    """
    Hex-encoded malformed input for decode-failure mode.

    Only consulted when `expect_exception` is set. The fixture decodes these
    bytes using `type(value).decode_bytes` and asserts the decoder raises.
    """

    serialized: str = ""
    """Hex SSZ bytes. Empty until fixture generation fills it."""

    root: str = ""
    """Hex hash_tree_root. Empty in decode-failure mode."""

    @field_serializer("value", when_used="json")
    def serialize_value(self, value: SSZType) -> Any:
        """Convert an SSZ value to a JSON-safe representation."""
        if isinstance(value, CamelModel):
            return value.to_json()
        # Boolean before int — Boolean subclasses int.
        if isinstance(value, Boolean):
            return bool(value)
        if isinstance(value, bytes):
            return "0x" + value.hex()
        if isinstance(value, int):
            return str(value)
        if isinstance(value, Fp):
            return str(value.value)
        return str(value)

    def make_fixture(self) -> "SSZTest":
        """Verify SSZ roundtrip or decode-failure and produce the reference output.

        Returns:
            A copy of this fixture with `serialized` and `root` populated.

        Raises:
            AssertionError:
                - In roundtrip mode, if `decode(encode(value)) != value`.
                - In decode-failure mode, if the decoder does not raise the
                  expected exception type.
        """
        if self.expect_exception is not None:
            return self._make_decode_failure()

        ssz_bytes = self.value.encode_bytes()
        decoded = self.value.decode_bytes(ssz_bytes)

        assert decoded == self.value, (
            f"SSZ roundtrip failed for {self.type_name}: "
            f"original != decoded\n"
            f"Original: {self.value}\n"
            f"Decoded: {decoded}"
        )

        root = hash_tree_root(self.value)

        self.serialized = "0x" + ssz_bytes.hex()
        self.root = "0x" + root.hex()
        return self

    def _make_decode_failure(self) -> "SSZTest":
        """Run the decode-failure path: assert decoding `raw_bytes` raises.

        The class of `value` is used as the decoder. `serialized` carries
        the malformed bytes verbatim so consumers can reproduce the input.

        Raises:
            AssertionError: If the decoder succeeds or raises a different type.
            ValueError: If `raw_bytes` is missing.
        """
        assert self.expect_exception is not None
        if self.raw_bytes is None:
            raise ValueError("raw_bytes is required when expect_exception is set")

        raw = bytes.fromhex(self.raw_bytes.removeprefix("0x"))
        decoder = type(self.value)
        exception_raised: Exception | None = None
        try:
            decoder.decode_bytes(raw)
        except Exception as exc:
            exception_raised = exc

        if exception_raised is None:
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} from "
                f"{decoder.__name__}.decode_bytes, but decode succeeded"
            )
        if not isinstance(exception_raised, self.expect_exception):
            raise AssertionError(
                f"Expected {self.expect_exception.__name__} but got "
                f"{type(exception_raised).__name__}: {exception_raised}"
            )

        self.serialized = "0x" + raw.hex()
        self.root = ""
        return self
