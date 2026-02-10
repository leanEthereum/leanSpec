"""SSZ test fixture format for serialization conformance testing."""

from typing import Any, ClassVar

from pydantic import field_serializer

from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32
from lean_spec.types.container import Container

from .base import BaseConsensusFixture


class SSZTest(BaseConsensusFixture):
    """
    Test fixture for SSZ serialization/deserialization conformance.

    Tests roundtrip serialization and hash tree root computation for SSZ containers.

    Structure:
        type_name: Name of the container class
        value: The container instance
        serialized: Hex-encoded SSZ bytes (computed)
        root: Hex-encoded hash tree root (computed)
    """

    format_name: ClassVar[str] = "ssz"
    description: ClassVar[str] = "Tests SSZ serialization roundtrip and hash tree root computation"

    type_name: str
    """Name of the container class being tested."""

    value: Container
    """The container instance to test."""

    serialized: str = ""
    """Hex-encoded SSZ serialized bytes (computed during make_fixture)."""

    root: str = ""
    """Hex-encoded hash tree root (computed during make_fixture)."""

    @field_serializer("value", when_used="json")
    def serialize_value(self, value: Container) -> dict[str, Any]:
        """Serialize the container value to JSON using its native serialization."""
        return value.to_json()

    def make_fixture(self) -> "SSZTest":
        """
        Generate the fixture by testing SSZ roundtrip and computing root.

        1. Serialize the value to SSZ bytes
        2. Deserialize the bytes back to a container
        3. Verify the roundtrip produces the same value
        4. Compute the hash tree root

        Returns:
            SSZTest with computed serialized and root fields.

        Raises:
            AssertionError: If roundtrip fails or types don't match.
        """
        # Serialize to SSZ bytes
        ssz_bytes = self.value.encode_bytes()

        # Deserialize back
        container_cls = type(self.value)
        decoded = container_cls.decode_bytes(ssz_bytes)

        # Verify roundtrip
        assert decoded == self.value, (
            f"SSZ roundtrip failed for {self.type_name}: "
            f"original != decoded\n"
            f"Original: {self.value}\n"
            f"Decoded: {decoded}"
        )

        # Compute hash tree root
        htr: Bytes32 = hash_tree_root(self.value)

        # Return fixture with computed fields
        return self.model_copy(
            update={
                "serialized": "0x" + ssz_bytes.hex(),
                "root": "0x" + htr.hex(),
            }
        )
