"""Shared pytest fixtures for Discovery v5 tests."""

from __future__ import annotations

import pytest

from lean_spec.subspecs.networking.enr import ENR
from lean_spec.subspecs.networking.types import NodeId
from lean_spec.types import Bytes64, Uint64

# From devp2p test vectors
NODE_A_PRIVKEY = bytes.fromhex("eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f")
NODE_A_ID = NodeId(
    bytes.fromhex("aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb")
)
NODE_B_PRIVKEY = bytes.fromhex("66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628")
NODE_B_ID = NodeId(
    bytes.fromhex("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9")
)
NODE_B_PUBKEY = bytes.fromhex("0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91")

# Spec id-nonce used in WHOAREYOU test vectors.
SPEC_ID_NONCE = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")


@pytest.fixture
def local_private_key() -> bytes:
    """Node B's private key from devp2p test vectors."""
    return NODE_B_PRIVKEY


@pytest.fixture
def local_node_id() -> NodeId:
    """Node B's ID from devp2p test vectors."""
    return NodeId(NODE_B_ID)


@pytest.fixture
def remote_node_id() -> NodeId:
    """Node A's ID from devp2p test vectors."""
    return NodeId(NODE_A_ID)


@pytest.fixture
def local_enr() -> ENR:
    """Minimal local ENR for testing."""
    return ENR(
        signature=Bytes64(bytes(64)),
        seq=Uint64(1),
        pairs={
            "id": b"v4",
            "secp256k1": NODE_B_PUBKEY,
            "ip": bytes([127, 0, 0, 1]),
            "udp": (9000).to_bytes(2, "big"),
        },
    )
