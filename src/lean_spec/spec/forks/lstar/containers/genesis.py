"""Chain configuration committed into the consensus state."""

from ssz import Uint64

from lean_spec.spec.ssz_types import Container


class GenesisConfig(Container):
    """Chain configuration committed into consensus state."""

    genesis_time: Uint64
    """The timestamp of the genesis block."""
