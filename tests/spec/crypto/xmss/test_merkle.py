"""Tests for the sparse Merkle subtree implementation."""

import pytest

from lean_spec.spec.crypto.xmss.constants import PROD_CONFIG, TEST_CONFIG, XmssConfig
from lean_spec.spec.crypto.xmss.field import random_domain, random_parameter
from lean_spec.spec.crypto.xmss.merkle import (
    HashSubTree,
    HashTreeLayer,
    HashTreeLayers,
    combined_path,
    verify_path,
)
from lean_spec.spec.crypto.xmss.poseidon import POSEIDON, PoseidonXmss
from lean_spec.spec.crypto.xmss.prf import PRFKey
from lean_spec.spec.crypto.xmss.types import (
    HashDigestList,
    HashDigestVector,
    HashTreeOpening,
    Parameter,
    TreeTweak,
)
from lean_spec.spec.ssz import Uint64
from lean_spec.spec.ssz.exceptions import SSZValueError


def _run_commit_open_verify_roundtrip(
    poseidon: PoseidonXmss,
    config: XmssConfig,
    num_leaves: int,
    depth: int,
    start_index: int,
    leaf_chain_ends_length: int,
) -> None:
    """Build a tree, then open and verify every active leaf against its root."""
    parameter = random_parameter(config)
    leaves: list[list[HashDigestVector]] = [
        [random_domain(config) for _ in range(leaf_chain_ends_length)] for _ in range(num_leaves)
    ]

    leaf_hashes: list[HashDigestVector] = [
        poseidon.tweak_hash(
            config,
            parameter,
            TreeTweak(level=0, index=Uint64(start_index + i)),
            leaf_chain_ends,
        )
        for i, leaf_chain_ends in enumerate(leaves)
    ]

    tree = HashSubTree.new(
        poseidon=poseidon,
        config=config,
        lowest_layer=Uint64(0),
        depth=Uint64(depth),
        start_index=Uint64(start_index),
        parameter=parameter,
        lowest_layer_nodes=leaf_hashes,
    )
    root = tree.root()

    for i, leaf_chain_ends in enumerate(leaves):
        position = Uint64(start_index + i)
        opening = tree.path(position)
        assert verify_path(
            poseidon=poseidon,
            config=config,
            parameter=parameter,
            root=root,
            position=position,
            leaf_chain_ends=leaf_chain_ends,
            opening=opening,
        )


@pytest.mark.parametrize(
    "num_leaves, depth, start_index, leaf_chain_ends_length",
    [
        pytest.param(16, 4, 0, 3, id="Full tree (depth 4)", marks=pytest.mark.slow),
        pytest.param(12, 5, 0, 5, id="Half tree, left-aligned (depth 5)", marks=pytest.mark.slow),
        pytest.param(16, 5, 16, 2, id="Half tree, right-aligned (depth 5)"),
        pytest.param(22, 6, 13, 3, id="Sparse, non-aligned tree (depth 6)", marks=pytest.mark.slow),
        pytest.param(2, 2, 2, 6, id="Half tree, right-aligned (small)"),
        pytest.param(1, 1, 0, 1, id="Tree with a single leaf at the start"),
        pytest.param(1, 1, 1, 1, id="Tree with a single leaf at an odd index"),
        pytest.param(16, 5, 7, 2, id="Small sparse tree starting at an odd index"),
    ],
)
def test_commit_open_verify_roundtrip(
    num_leaves: int,
    depth: int,
    start_index: int,
    leaf_chain_ends_length: int,
) -> None:
    """A built tree opens and verifies every leaf for various shapes."""
    assert start_index + num_leaves <= (1 << depth)
    # Verification binds the opening length to the configured log lifetime.
    # Match the configured height to this tree's depth so every opening is well formed.
    config_for_depth = PROD_CONFIG.model_copy(update={"LOG_LIFETIME": depth})
    _run_commit_open_verify_roundtrip(
        POSEIDON, config_for_depth, num_leaves, depth, start_index, leaf_chain_ends_length
    )


def test_new_rejects_nodes_overflowing_their_level() -> None:
    """A node run that does not fit its level raises with the level and bounds named."""
    with pytest.raises(ValueError) as exception_info:
        HashSubTree.new(
            poseidon=POSEIDON,
            config=TEST_CONFIG,
            lowest_layer=Uint64(0),
            depth=Uint64(2),
            start_index=Uint64(3),
            parameter=random_parameter(TEST_CONFIG),
            lowest_layer_nodes=[random_domain(TEST_CONFIG), random_domain(TEST_CONFIG)],
        )
    assert str(exception_info.value) == "Overflow at layer 0: start=3, count=2, max=4"


def test_new_top_tree_rejects_odd_depth() -> None:
    """The top tree requires an even depth for the top-bottom split."""
    with pytest.raises(ValueError) as exception_info:
        HashSubTree.new_top_tree(
            POSEIDON, TEST_CONFIG, 7, Uint64(0), random_parameter(TEST_CONFIG), []
        )
    assert str(exception_info.value) == "Depth must be even for top-bottom split, got 7."


def test_new_bottom_tree_rejects_odd_depth() -> None:
    """The bottom tree requires an even depth for the top-bottom split."""
    with pytest.raises(ValueError) as exception_info:
        HashSubTree.new_bottom_tree(
            POSEIDON, TEST_CONFIG, 7, Uint64(0), random_parameter(TEST_CONFIG), []
        )
    assert str(exception_info.value) == "Depth must be even for top-bottom split, got 7."


def test_new_bottom_tree_rejects_wrong_leaf_count() -> None:
    """The bottom tree requires exactly the square-root-of-lifetime leaves."""
    with pytest.raises(ValueError) as exception_info:
        HashSubTree.new_bottom_tree(
            POSEIDON, TEST_CONFIG, 8, Uint64(0), random_parameter(TEST_CONFIG), []
        )
    assert str(exception_info.value) == "Expected 16 leaves for depth=8, got 0."


def test_root_rejects_empty_subtree() -> None:
    """A subtree with no layers has no root."""
    subtree = HashSubTree(
        depth=Uint64(8),
        lowest_layer=Uint64(0),
        layers=HashTreeLayers(data=[]),
    )
    with pytest.raises(ValueError) as exception_info:
        subtree.root()
    assert str(exception_info.value) == "Empty subtree has no root."


def test_root_rejects_empty_top_layer() -> None:
    """A subtree whose top layer holds no nodes has no root."""
    empty_layer = HashTreeLayer(start_index=Uint64(0), nodes=HashDigestList(data=[]))
    subtree = HashSubTree(
        depth=Uint64(8),
        lowest_layer=Uint64(0),
        layers=HashTreeLayers(data=[empty_layer]),
    )
    with pytest.raises(ValueError) as exception_info:
        subtree.root()
    assert str(exception_info.value) == "Top layer is empty."


def test_path_rejects_empty_subtree() -> None:
    """Opening a path on a subtree with no layers raises."""
    subtree = HashSubTree(
        depth=Uint64(8),
        lowest_layer=Uint64(0),
        layers=HashTreeLayers(data=[]),
    )
    with pytest.raises(ValueError) as exception_info:
        subtree.path(Uint64(0))
    assert str(exception_info.value) == "Empty subtree."


def test_path_rejects_position_out_of_bounds() -> None:
    """A position outside the lowest layer's stored range raises."""
    layer = HashTreeLayer(
        start_index=Uint64(0),
        nodes=HashDigestList(data=[random_domain(TEST_CONFIG), random_domain(TEST_CONFIG)]),
    )
    subtree = HashSubTree(
        depth=Uint64(8),
        lowest_layer=Uint64(0),
        layers=HashTreeLayers(data=[layer]),
    )
    with pytest.raises(ValueError) as exception_info:
        subtree.path(Uint64(5))
    assert str(exception_info.value) == "Position 5 out of bounds."


def test_path_rejects_sibling_out_of_bounds() -> None:
    """A non-root layer too small to hold the needed sibling raises."""
    leaf_layer = HashTreeLayer(
        start_index=Uint64(0),
        nodes=HashDigestList(data=[random_domain(TEST_CONFIG), random_domain(TEST_CONFIG)]),
    )
    # The middle layer lacks the sibling at index one.
    middle_layer = HashTreeLayer(
        start_index=Uint64(0), nodes=HashDigestList(data=[random_domain(TEST_CONFIG)])
    )
    root_layer = HashTreeLayer(
        start_index=Uint64(0), nodes=HashDigestList(data=[random_domain(TEST_CONFIG)])
    )
    subtree = HashSubTree(
        depth=Uint64(8),
        lowest_layer=Uint64(0),
        layers=HashTreeLayers(data=[leaf_layer, middle_layer, root_layer]),
    )
    with pytest.raises(ValueError) as exception_info:
        subtree.path(Uint64(0))
    assert str(exception_info.value) == "Sibling index 1 out of bounds."


@pytest.fixture(scope="module")
def prf_trees() -> tuple[Parameter, HashSubTree, HashSubTree, HashSubTree]:
    """Build a top tree over two prf-derived bottom trees for combined-path tests."""
    config = TEST_CONFIG
    prf_key = PRFKey.generate()
    parameter = random_parameter(config)
    bottom_zero = HashSubTree.from_prf_key(
        poseidon=POSEIDON,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(0),
        parameter=parameter,
    )
    bottom_one = HashSubTree.from_prf_key(
        poseidon=POSEIDON,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(1),
        parameter=parameter,
    )
    top = HashSubTree.new_top_tree(
        POSEIDON,
        config,
        config.LOG_LIFETIME,
        Uint64(0),
        parameter,
        [bottom_zero.root(), bottom_one.root()],
    )
    return parameter, top, bottom_zero, bottom_one


def test_combined_path_authenticates_leaf_to_global_root(
    prf_trees: tuple[Parameter, HashSubTree, HashSubTree, HashSubTree],
) -> None:
    """A combined opening spans the full depth from leaf to global root."""
    _, top, bottom_zero, _ = prf_trees
    opening = combined_path(top, bottom_zero, Uint64(0))
    assert len(opening.siblings) == TEST_CONFIG.LOG_LIFETIME


def test_combined_path_rejects_depth_mismatch(
    prf_trees: tuple[Parameter, HashSubTree, HashSubTree, HashSubTree],
) -> None:
    """Top and bottom trees of disagreeing depth cannot be stitched."""
    _, top, bottom_zero, _ = prf_trees
    mismatched = HashSubTree(
        depth=Uint64(6), lowest_layer=bottom_zero.lowest_layer, layers=bottom_zero.layers
    )
    with pytest.raises(ValueError) as exception_info:
        combined_path(top, mismatched, Uint64(0))
    assert str(exception_info.value) == "Depth mismatch: top=8, bottom=6."


def test_combined_path_rejects_odd_depth(
    prf_trees: tuple[Parameter, HashSubTree, HashSubTree, HashSubTree],
) -> None:
    """Stitching requires an even depth."""
    _, top, bottom_zero, _ = prf_trees
    odd_top = HashSubTree(depth=Uint64(7), lowest_layer=top.lowest_layer, layers=top.layers)
    odd_bottom = HashSubTree(
        depth=Uint64(7), lowest_layer=bottom_zero.lowest_layer, layers=bottom_zero.layers
    )
    with pytest.raises(ValueError) as exception_info:
        combined_path(odd_top, odd_bottom, Uint64(7))
    assert str(exception_info.value) == "Depth must be even, got 7."


def test_combined_path_rejects_wrong_bottom_tree(
    prf_trees: tuple[Parameter, HashSubTree, HashSubTree, HashSubTree],
) -> None:
    """A position belonging to a sibling bottom tree is refused."""
    _, top, bottom_zero, _ = prf_trees
    with pytest.raises(ValueError) as exception_info:
        combined_path(top, bottom_zero, Uint64(16))
    assert str(exception_info.value) == "Wrong bottom tree: position 16 needs start 16, got 0."


def test_from_prf_key_builds_a_bottom_tree() -> None:
    """A prf-derived bottom tree has the expected depth, layers, and leaf count."""
    config = TEST_CONFIG
    bottom_tree = HashSubTree.from_prf_key(
        poseidon=POSEIDON,
        config=config,
        prf_key=PRFKey.generate(),
        bottom_tree_index=Uint64(0),
        parameter=random_parameter(config),
    )
    assert bottom_tree.depth == Uint64(config.LOG_LIFETIME)
    assert bottom_tree.lowest_layer == Uint64(0)
    assert len(bottom_tree.layers[-1].nodes) == 1
    assert len(bottom_tree.layers[0].nodes) == config.LEAVES_PER_BOTTOM_TREE


def test_from_prf_key_is_deterministic() -> None:
    """The same seed and index rebuild the same bottom-tree root."""
    config = TEST_CONFIG
    prf_key = PRFKey.generate()
    parameter = random_parameter(config)
    first = HashSubTree.from_prf_key(
        poseidon=POSEIDON,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(0),
        parameter=parameter,
    )
    second = HashSubTree.from_prf_key(
        poseidon=POSEIDON,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(0),
        parameter=parameter,
    )
    assert first.root() == second.root()


def test_from_prf_key_distinct_indices_give_distinct_roots() -> None:
    """Different bottom-tree indices produce different roots."""
    config = TEST_CONFIG
    prf_key = PRFKey.generate()
    parameter = random_parameter(config)
    tree_zero = HashSubTree.from_prf_key(
        poseidon=POSEIDON,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(0),
        parameter=parameter,
    )
    tree_one = HashSubTree.from_prf_key(
        poseidon=POSEIDON,
        config=config,
        prf_key=prf_key,
        bottom_tree_index=Uint64(1),
        parameter=parameter,
    )
    assert tree_zero.root() != tree_one.root()


def test_verify_path_rejects_excessive_depth_at_ssz_level() -> None:
    """
    The SSZ type system caps an opening at the layer limit.

    The defensive depth guard inside verification cannot be reached through a
    well-formed opening, since the digest list rejects more than its limit.
    """
    with pytest.raises(SSZValueError):
        HashDigestList(data=[random_domain(PROD_CONFIG) for _ in range(33)])


@pytest.mark.parametrize("sibling_count", [3, 5])
def test_verify_path_rejects_opening_length_mismatch(sibling_count: int) -> None:
    """An opening whose length differs from the configured log lifetime fails without raising."""
    # A configured lifetime of two-to-the-four demands exactly four siblings per opening.
    config_with_lifetime_sixteen = PROD_CONFIG.model_copy(update={"LOG_LIFETIME": 4})
    siblings = [random_domain(config_with_lifetime_sixteen) for _ in range(sibling_count)]
    opening = HashTreeOpening(siblings=HashDigestList(data=siblings))
    assert (
        verify_path(
            poseidon=POSEIDON,
            config=config_with_lifetime_sixteen,
            parameter=random_parameter(config_with_lifetime_sixteen),
            root=random_domain(config_with_lifetime_sixteen),
            position=Uint64(0),
            leaf_chain_ends=[random_domain(config_with_lifetime_sixteen)],
            opening=opening,
        )
        is False
    )


@pytest.mark.parametrize("position", [16, 100])
def test_verify_path_rejects_position_exceeding_capacity(position: int) -> None:
    """A position at or beyond the configured lifetime fails without raising."""
    # A configured lifetime of two-to-the-four caps valid positions at fifteen.
    config_with_lifetime_sixteen = PROD_CONFIG.model_copy(update={"LOG_LIFETIME": 4})
    siblings = [random_domain(config_with_lifetime_sixteen) for _ in range(4)]
    opening = HashTreeOpening(siblings=HashDigestList(data=siblings))
    assert (
        verify_path(
            poseidon=POSEIDON,
            config=config_with_lifetime_sixteen,
            parameter=random_parameter(config_with_lifetime_sixteen),
            root=random_domain(config_with_lifetime_sixteen),
            position=Uint64(position),
            leaf_chain_ends=[random_domain(config_with_lifetime_sixteen)],
            opening=opening,
        )
        is False
    )


def test_verify_path_accepts_boundary_position_without_raising() -> None:
    """The maximum valid position for the configured lifetime does not trip the bounds guard."""
    # A configured lifetime of two-to-the-four makes fifteen the last valid position.
    config_with_lifetime_sixteen = PROD_CONFIG.model_copy(update={"LOG_LIFETIME": 4})
    siblings = [random_domain(config_with_lifetime_sixteen) for _ in range(4)]
    opening = HashTreeOpening(siblings=HashDigestList(data=siblings))
    verification_result = verify_path(
        poseidon=POSEIDON,
        config=config_with_lifetime_sixteen,
        parameter=random_parameter(config_with_lifetime_sixteen),
        root=random_domain(config_with_lifetime_sixteen),
        position=Uint64(15),
        leaf_chain_ends=[random_domain(config_with_lifetime_sixteen)],
        opening=opening,
    )
    assert isinstance(verification_result, bool)
