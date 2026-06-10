"""Chain configuration committed into the consensus state."""

from lean_spec.spec.ssz import Container, Uint64


class GenesisConfig(Container):
    """Chain configuration committed into consensus state."""

    genesis_time: Uint64
    """The timestamp of the genesis block."""
