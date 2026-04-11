"""Tests for the Poseidon1 permutation for widths 16 and 24.

Test vectors are taken from Plonky3 (koala-bear/src/poseidon1.rs).
To verify independently, run `cargo test` in the Plonky3 koala-bear crate.
"""

import pytest

from lean_spec.subspecs.koalabear.field import Fp
from lean_spec.subspecs.poseidon1.permutation import (
    PARAMS_16,
    PARAMS_24,
    Poseidon1,
    Poseidon1Params,
)

# --- Test Vectors (from Plonky3 koala-bear/src/poseidon1.rs) ---

# Input vector for width 16: [0, 1, 2, ..., 15]
INPUT_16 = [Fp(value=i) for i in range(16)]

# Expected output for width 16.
#
# From Plonky3.
EXPECTED_16 = [
    Fp(value=610090613),
    Fp(value=935319874),
    Fp(value=1893335292),
    Fp(value=796792199),
    Fp(value=356405232),
    Fp(value=552237741),
    Fp(value=55134556),
    Fp(value=1215104204),
    Fp(value=1823723405),
    Fp(value=1133298033),
    Fp(value=1780633798),
    Fp(value=1453946561),
    Fp(value=710069176),
    Fp(value=1128629550),
    Fp(value=1917333254),
    Fp(value=1175481618),
]

# Input vector for width 24: [0, 1, 2, ..., 23]
INPUT_24 = [Fp(value=i) for i in range(24)]

# Expected output for width 24.
#
# From Plonky3.
EXPECTED_24 = [
    Fp(value=511672087),
    Fp(value=215882318),
    Fp(value=237782537),
    Fp(value=740528428),
    Fp(value=712760904),
    Fp(value=54615367),
    Fp(value=751514671),
    Fp(value=110231969),
    Fp(value=1905276435),
    Fp(value=992525666),
    Fp(value=918312360),
    Fp(value=18628693),
    Fp(value=749929200),
    Fp(value=1916418953),
    Fp(value=691276896),
    Fp(value=1112901727),
    Fp(value=1163558623),
    Fp(value=882867603),
    Fp(value=673396520),
    Fp(value=1480278156),
    Fp(value=1402044758),
    Fp(value=1693467175),
    Fp(value=1766273044),
    Fp(value=433841551),
]


@pytest.mark.parametrize(
    "params, input_state, expected_output",
    [
        (PARAMS_16, INPUT_16, EXPECTED_16),
        (PARAMS_24, INPUT_24, EXPECTED_24),
    ],
    ids=["width_16", "width_24"],
)
def test_permutation_vector(
    params: Poseidon1Params, input_state: list[Fp], expected_output: list[Fp]
) -> None:
    """
    Test the Poseidon1 permutation against known answer vectors.

    Serves as a regression test to ensure logic consistency.
    Reference: Plonky3 koala-bear/src/poseidon1.rs tests.
    """
    engine = Poseidon1(params)
    output_state = engine.permute(input_state)

    assert len(output_state) == params.width
    assert output_state == expected_output, (
        f"Permutation output for width {params.width} did not match."
    )


class TestPoseidon1ParamsValidation:
    """Tests for Poseidon1Params validation."""

    def test_invalid_mds_first_row_length(self) -> None:
        """Raises error when mds_first_row length doesn't match width."""
        with pytest.raises(ValueError, match="Length of mds_first_row must equal width"):
            Poseidon1Params(
                width=3,
                rounds_f=8,
                rounds_p=20,
                mds_first_row=[Fp(1), Fp(2)],
                round_constants=[Fp(1)] * 84,
            )

    def test_invalid_round_constants_count(self) -> None:
        """Raises error when round_constants count is incorrect."""
        with pytest.raises(ValueError, match="Incorrect number of round constants"):
            Poseidon1Params(
                width=3,
                rounds_f=8,
                rounds_p=20,
                mds_first_row=[Fp(1), Fp(2), Fp(3)],
                round_constants=[Fp(1)] * 20,
            )


class TestPoseidon1Engine:
    """Tests for Poseidon1 engine."""

    def test_permute_wrong_state_length_too_short(self) -> None:
        """Raises error when input state is too short."""
        engine = Poseidon1(PARAMS_16)
        with pytest.raises(ValueError, match="Input state must have length 16"):
            engine.permute([Fp(1)] * 10)

    def test_permute_wrong_state_length_too_long(self) -> None:
        """Raises error when input state is too long."""
        engine = Poseidon1(PARAMS_16)
        with pytest.raises(ValueError, match="Input state must have length 16"):
            engine.permute([Fp(1)] * 20)

    def test_permute_determinism(self) -> None:
        """Same input produces same output."""
        engine = Poseidon1(PARAMS_16)
        state = [Fp(value=i) for i in range(16)]

        output1 = engine.permute(state)
        output2 = engine.permute(state)

        assert output1 == output2

    def test_permute_output_differs_from_input(self) -> None:
        """Permutation changes the state."""
        engine = Poseidon1(PARAMS_16)
        state = [Fp(value=i) for i in range(16)]

        output = engine.permute(state)

        assert output != state
