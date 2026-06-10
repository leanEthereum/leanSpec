"""Poseidon permutation test fixture."""

from typing import ClassVar, Literal, Self

from pydantic import model_validator

from consensus_testing.test_fixtures.base import BaseConsensusFixture, BaseTestSpec
from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.poseidon import PARAMS_16, PARAMS_24, Poseidon

PARAMETERS_BY_WIDTH = {16: PARAMS_16, 24: PARAMS_24}
"""Permutation parameter sets keyed by the supported state widths."""


class PoseidonPermutationFixture(BaseConsensusFixture):
    """
    Emitted vector for Poseidon permutation conformance.

    JSON output: width, inputState, outputState.
    """

    width: int
    """State width of the permutation."""

    input_state: list[str]
    """Input state as decimal element strings."""

    output_state: list[str]
    """Computed output state as decimal element strings."""


class PoseidonPermutationTest(BaseTestSpec):
    """
    Spec for Poseidon permutation conformance.

    Each vector names the permutation width and supplies an input state
    as decimal strings. Generation runs the spec's permutation engine
    and emits the output state as decimal strings.
    """

    format_name: ClassVar[str] = "poseidon_permutation_test"
    description: ClassVar[str] = "Tests Poseidon permutation at widths 16 and 24"

    width: Literal[16, 24]
    """State width. Only the two spec-defined widths exist."""

    input_state: list[str]
    """Input state as decimal element strings, one per state element."""

    @model_validator(mode="after")
    def validate_state_length(self) -> Self:
        """Require exactly one input element per state slot."""
        if len(self.input_state) != self.width:
            raise ValueError(
                f"Input state length {len(self.input_state)} does not match width {self.width}"
            )
        return self

    def generate(self) -> PoseidonPermutationFixture:
        """Run the Poseidon permutation and produce the output state."""
        engine = Poseidon(PARAMETERS_BY_WIDTH[self.width])
        input_state = [Fp(int(raw_element)) for raw_element in self.input_state]
        output_state = engine.permute(input_state)

        return PoseidonPermutationFixture(
            width=self.width,
            input_state=self.input_state,
            output_state=[str(int(field_element)) for field_element in output_state],
        )
