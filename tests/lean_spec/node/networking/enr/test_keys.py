"""Tests for ENR key constants."""

from lean_spec.node.networking.enr import keys


class TestEnrKeys:
    """Tests for ENR key constants."""

    def test_identity_keys(self) -> None:
        """Identity keys have correct values."""
        assert keys.ID == "id"
        assert keys.SECP256K1 == "secp256k1"

    def test_network_keys(self) -> None:
        """Network keys have correct values."""
        assert keys.IP == "ip"
        assert keys.UDP == "udp"

    def test_ethereum_keys(self) -> None:
        """Ethereum-specific keys have correct values."""
        assert keys.ETH2 == "eth2"
        assert keys.ATTNETS == "attnets"
