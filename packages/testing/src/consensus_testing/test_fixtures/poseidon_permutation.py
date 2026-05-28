"""Poseidon permutation test fixture.

Generates JSON test vectors for the Poseidon permutation over the
KoalaBear field at widths 16 and 24. Clients must produce identical
output states bit-for-bit for every input state.
"""

from typing import Any, ClassVar

from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.poseidon import PARAMS_16, PARAMS_24, Poseidon

from .base import BaseConsensusFixture


class PoseidonPermutationTest(BaseConsensusFixture):
    """Fixture for Poseidon permutation conformance.

    Each vector names the permutation width and supplies an input state
    as decimal strings. The fixture runs the spec's permutation engine
    and emits the output state as decimal strings.

    JSON output: width, input, output.
    """

    format_name: ClassVar[str] = "poseidon_permutation"
    description: ClassVar[str] = "Tests Poseidon permutation at widths 16 and 24"

    width: int
    """State width. Must be 16 or 24."""

    input: dict[str, Any]
    """Input state. Key inputState holds a list of decimal element strings."""

    output: dict[str, Any] = {}
    """Computed output state. Filled by make_fixture."""

    def make_fixture(self) -> "PoseidonPermutationTest":
        """Run the Poseidon permutation and produce the output state.

        Returns:
            A copy of this fixture with output populated.

        Raises:
            ValueError: If the width is unsupported.
        """
        if self.width == 16:
            engine = Poseidon(PARAMS_16)
        elif self.width == 24:
            engine = Poseidon(PARAMS_24)
        else:
            raise ValueError(f"Unsupported Poseidon width: {self.width}")

        state_ints = [int(x) for x in self.input["inputState"]]
        if len(state_ints) != self.width:
            raise ValueError(
                f"Input state length {len(state_ints)} does not match width {self.width}"
            )

        input_state = [Fp(v) for v in state_ints]
        output_state = engine.permute(input_state)

        self.output = {"outputState": [str(int(fp)) for fp in output_state]}
        return self
