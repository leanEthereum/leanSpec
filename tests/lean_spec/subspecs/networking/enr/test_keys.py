"""Tests for ENR key constants."""

from lean_spec.subspecs.networking.enr import keys


class TestEnrKeys:
    """Tests for ENR key constants."""

    def test_identity_keys(self) -> None:
        """Identity keys have correct values."""
        assert keys.ID == "id"
        assert keys.SECP256K1 == "secp256k1"

    def test_network_keys(self) -> None:
        """Network keys have correct values."""
        assert keys.IP == "ip"
        assert keys.IP6 == "ip6"
        assert keys.TCP == "tcp"
        assert keys.UDP == "udp"
        assert keys.TCP6 == "tcp6"
        assert keys.UDP6 == "udp6"

    def test_ethereum_keys(self) -> None:
        """Ethereum-specific keys have correct values."""
        assert keys.ETH2 == "eth2"
        assert keys.ATTNETS == "attnets"
        assert keys.SYNCNETS == "syncnets"
