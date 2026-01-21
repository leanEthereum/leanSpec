"""Tests for deeply nested SSZ structures."""

from __future__ import annotations

from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types.byte_arrays import BaseByteList, Bytes32
from lean_spec.types.collections import SSZList, SSZVector
from lean_spec.types.container import Container
from lean_spec.types.uint import Uint8, Uint16, Uint32, Uint64

# Test type definitions for nested structures


class Level0(Container):
    """Innermost container (level 0)."""

    value: Uint64


class Level1(Container):
    """Level 1 container containing Level0."""

    inner: Level0
    extra: Uint16


class Level2(Container):
    """Level 2 container containing Level1."""

    inner: Level1
    extra: Uint32


class Level3(Container):
    """Level 3 container containing Level2."""

    inner: Level2
    extra: Uint8


class Level4(Container):
    """Level 4 container containing Level3."""

    inner: Level3
    extra: Uint16


class Level5(Container):
    """Level 5 container (outermost) containing Level4."""

    inner: Level4
    extra: Uint32


# Variable-size nested types


class Uint64List4(SSZList[Uint64]):
    """List of up to 4 Uint64 values."""

    LIMIT = 4


class ByteList16(BaseByteList):
    """ByteList with max 16 bytes."""

    LIMIT = 16


class VarInner(Container):
    """Inner container with variable-size field."""

    fixed: Uint32
    variable: Uint64List4


class VarInnerList4(SSZList):
    """List of VarInner containers."""

    ELEMENT_TYPE = VarInner
    LIMIT = 4


class VarMiddle(Container):
    """Middle container with nested variable-size container."""

    header: Uint16
    items: VarInnerList4
    footer: Uint8


class VarOuter(Container):
    """Outer container with multiple levels of variable-size nesting."""

    prefix: Uint32
    content: VarMiddle
    data: ByteList16


# All variable-size fields container


class AllVarInner(Container):
    """Container with all variable-size fields."""

    list1: Uint64List4
    list2: Uint64List4


class AllVarOuter(Container):
    """Container containing AllVarInner (all variable)."""

    inner: AllVarInner
    extra_list: Uint64List4


# Mixed fixed/variable nested structures


class FixedInner(Container):
    """Fixed-size inner container."""

    a: Uint32
    b: Uint64


class FixedVector3(SSZVector):
    """Vector of 3 FixedInner containers."""

    ELEMENT_TYPE = FixedInner
    LENGTH = 3


class MixedContainer(Container):
    """Container with mixed fixed and variable nested structures."""

    fixed_vec: FixedVector3
    var_list: Uint64List4
    trailing: Uint16


# List of lists (via container wrapper)


class Uint16List8(SSZList[Uint16]):
    """List of Uint16 values."""

    LIMIT = 8


class ListWrapper(Container):
    """Wrapper containing a list."""

    items: Uint16List8


class ListWrapperList4(SSZList):
    """List of list wrappers (simulating list of lists)."""

    ELEMENT_TYPE = ListWrapper
    LIMIT = 4


# Tests for deeply nested containers


class TestDeeplyNestedContainers:
    """Tests for containers nested 5+ levels deep."""

    def test_5_level_nesting_roundtrip(self) -> None:
        """5 levels of nested containers roundtrip correctly."""
        original = Level5(
            inner=Level4(
                inner=Level3(
                    inner=Level2(
                        inner=Level1(
                            inner=Level0(value=Uint64(0xDEADBEEF12345678)),
                            extra=Uint16(0x1234),
                        ),
                        extra=Uint32(0x56789ABC),
                    ),
                    extra=Uint8(0xEF),
                ),
                extra=Uint16(0xABCD),
            ),
            extra=Uint32(0x11223344),
        )

        encoded = original.encode_bytes()
        decoded = Level5.decode_bytes(encoded)

        # Verify all levels
        assert decoded.extra == Uint32(0x11223344)
        assert decoded.inner.extra == Uint16(0xABCD)
        assert decoded.inner.inner.extra == Uint8(0xEF)
        assert decoded.inner.inner.inner.extra == Uint32(0x56789ABC)
        assert decoded.inner.inner.inner.inner.extra == Uint16(0x1234)
        assert decoded.inner.inner.inner.inner.inner.value == Uint64(0xDEADBEEF12345678)

    def test_5_level_nesting_hash_tree_root(self) -> None:
        """Hash tree root works for 5-level nested container."""
        container = Level5(
            inner=Level4(
                inner=Level3(
                    inner=Level2(
                        inner=Level1(
                            inner=Level0(value=Uint64(42)),
                            extra=Uint16(1),
                        ),
                        extra=Uint32(2),
                    ),
                    extra=Uint8(3),
                ),
                extra=Uint16(4),
            ),
            extra=Uint32(5),
        )

        root = hash_tree_root(container)

        assert isinstance(root, Bytes32)
        assert len(root) == 32


# Tests for variable-size nested structures


class TestVariableSizeNesting:
    """Tests for nested structures with variable-size fields."""

    def test_nested_var_containers_roundtrip(self) -> None:
        """Nested containers with variable-size fields roundtrip correctly."""
        original = VarOuter(
            prefix=Uint32(0x12345678),
            content=VarMiddle(
                header=Uint16(0xABCD),
                items=VarInnerList4(
                    data=[
                        VarInner(
                            fixed=Uint32(1),
                            variable=Uint64List4(data=[Uint64(10), Uint64(20)]),
                        ),
                        VarInner(
                            fixed=Uint32(2),
                            variable=Uint64List4(data=[Uint64(30)]),
                        ),
                    ]
                ),
                footer=Uint8(0xFF),
            ),
            data=ByteList16(data=b"hello"),
        )

        encoded = original.encode_bytes()
        decoded = VarOuter.decode_bytes(encoded)

        assert decoded.prefix == Uint32(0x12345678)
        assert decoded.content.header == Uint16(0xABCD)
        assert len(decoded.content.items) == 2
        assert decoded.content.items[0].fixed == Uint32(1)
        assert len(decoded.content.items[0].variable) == 2
        assert decoded.content.items[0].variable[0] == Uint64(10)
        assert decoded.content.footer == Uint8(0xFF)
        assert decoded.data.data == b"hello"

    def test_all_variable_fields_roundtrip(self) -> None:
        """Container with all variable-size fields roundtrips correctly."""
        original = AllVarOuter(
            inner=AllVarInner(
                list1=Uint64List4(data=[Uint64(1), Uint64(2)]),
                list2=Uint64List4(data=[Uint64(3), Uint64(4), Uint64(5)]),
            ),
            extra_list=Uint64List4(data=[Uint64(100)]),
        )

        encoded = original.encode_bytes()
        decoded = AllVarOuter.decode_bytes(encoded)

        assert len(decoded.inner.list1) == 2
        assert decoded.inner.list1[0] == Uint64(1)
        assert len(decoded.inner.list2) == 3
        assert decoded.inner.list2[2] == Uint64(5)
        assert len(decoded.extra_list) == 1

    def test_empty_nested_lists_roundtrip(self) -> None:
        """Nested containers with empty lists roundtrip correctly."""
        original = VarOuter(
            prefix=Uint32(0),
            content=VarMiddle(
                header=Uint16(0),
                items=VarInnerList4(data=[]),  # Empty list of containers
                footer=Uint8(0),
            ),
            data=ByteList16(data=b""),  # Empty byte list
        )

        encoded = original.encode_bytes()
        decoded = VarOuter.decode_bytes(encoded)

        assert decoded.prefix == Uint32(0)
        assert len(decoded.content.items) == 0
        assert len(decoded.data.data) == 0


# Tests for mixed fixed/variable nested structures


class TestMixedNesting:
    """Tests for mixed fixed and variable-size nested structures."""

    def test_mixed_container_roundtrip(self) -> None:
        """Container with fixed vector and variable list roundtrips correctly."""
        original = MixedContainer(
            fixed_vec=FixedVector3(
                data=[
                    FixedInner(a=Uint32(1), b=Uint64(100)),
                    FixedInner(a=Uint32(2), b=Uint64(200)),
                    FixedInner(a=Uint32(3), b=Uint64(300)),
                ]
            ),
            var_list=Uint64List4(data=[Uint64(1000), Uint64(2000)]),
            trailing=Uint16(0xFFFF),
        )

        encoded = original.encode_bytes()
        decoded = MixedContainer.decode_bytes(encoded)

        assert len(decoded.fixed_vec) == 3
        assert decoded.fixed_vec[0].a == Uint32(1)
        assert decoded.fixed_vec[2].b == Uint64(300)
        assert len(decoded.var_list) == 2
        assert decoded.var_list[1] == Uint64(2000)
        assert decoded.trailing == Uint16(0xFFFF)

    def test_mixed_container_hash_tree_root(self) -> None:
        """Hash tree root works for mixed container."""
        container = MixedContainer(
            fixed_vec=FixedVector3(
                data=[
                    FixedInner(a=Uint32(1), b=Uint64(100)),
                    FixedInner(a=Uint32(2), b=Uint64(200)),
                    FixedInner(a=Uint32(3), b=Uint64(300)),
                ]
            ),
            var_list=Uint64List4(data=[Uint64(1000)]),
            trailing=Uint16(42),
        )

        root = hash_tree_root(container)

        assert isinstance(root, Bytes32)
        assert len(root) == 32


# Tests for lists of lists (via container wrapper)


class TestListOfLists:
    """Tests for list of lists structures."""

    def test_list_of_lists_roundtrip(self) -> None:
        """List of list wrappers (simulating list of lists) roundtrips correctly."""
        original = ListWrapperList4(
            data=[
                ListWrapper(items=Uint16List8(data=[Uint16(1), Uint16(2), Uint16(3)])),
                ListWrapper(items=Uint16List8(data=[Uint16(10), Uint16(20)])),
                ListWrapper(items=Uint16List8(data=[])),
            ]
        )

        encoded = original.encode_bytes()
        decoded = ListWrapperList4.decode_bytes(encoded)

        assert len(decoded) == 3
        assert len(decoded[0].items) == 3
        assert decoded[0].items[2] == Uint16(3)
        assert len(decoded[1].items) == 2
        assert len(decoded[2].items) == 0

    def test_empty_list_of_lists(self) -> None:
        """Empty list of list wrappers roundtrips correctly."""
        original = ListWrapperList4(data=[])

        encoded = original.encode_bytes()
        decoded = ListWrapperList4.decode_bytes(encoded)

        assert len(decoded) == 0
        assert encoded == b""

    def test_list_of_lists_hash_tree_root(self) -> None:
        """Hash tree root works for list of list wrappers."""
        container = ListWrapperList4(
            data=[
                ListWrapper(items=Uint16List8(data=[Uint16(1), Uint16(2)])),
                ListWrapper(items=Uint16List8(data=[Uint16(3)])),
            ]
        )

        root = hash_tree_root(container)

        assert isinstance(root, Bytes32)
        assert len(root) == 32
