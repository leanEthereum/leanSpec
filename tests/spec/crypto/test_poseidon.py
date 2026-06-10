"""
Tests for the Poseidon permutation for widths 16 and 24.

Test vectors are taken from Plonky3 (koala-bear/src/poseidon1.rs).
To verify independently, run `cargo test` in the Plonky3 koala-bear crate.
"""

import pytest
from pydantic import ValidationError

from lean_spec.spec.crypto.koalabear import Fp, P
from lean_spec.spec.crypto.poseidon import (
    PARAMS_16,
    PARAMS_24,
    Poseidon,
    PoseidonParams,
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
    params: PoseidonParams, input_state: list[Fp], expected_output: list[Fp]
) -> None:
    """
    Test the Poseidon permutation against known answer vectors.

    Serves as a regression test to ensure logic consistency.
    Reference: Plonky3 koala-bear/src/poseidon1.rs tests.
    """
    engine = Poseidon(params)
    output_state = engine.permute(input_state)

    assert len(output_state) == params.width
    assert output_state == expected_output, (
        f"Permutation output for width {params.width} did not match."
    )


class TestPoseidonParamsValidation:
    """Tests for PoseidonParams validation."""

    def test_invalid_mds_first_row_length(self) -> None:
        """Raises error when mds_first_row length doesn't match width."""
        with pytest.raises(
            ValueError,
            match=r"(?s)^1 validation error for PoseidonParams\n"
            r"  Value error, Length of mds_first_row must equal width\. .*\Z",
        ):
            PoseidonParams(
                width=3,
                rounds_f=8,
                rounds_p=20,
                mds_first_row=[Fp(1), Fp(2)],
                round_constants=[Fp(1)] * 84,
            )

    def test_invalid_round_constants_count(self) -> None:
        """Raises error when round_constants count is incorrect."""
        with pytest.raises(
            ValueError,
            match=r"(?s)^1 validation error for PoseidonParams\n"
            r"  Value error, Incorrect number of round constants provided\. .*\Z",
        ):
            PoseidonParams(
                width=3,
                rounds_f=8,
                rounds_p=20,
                mds_first_row=[Fp(1), Fp(2), Fp(3)],
                round_constants=[Fp(1)] * 20,
            )

    def test_width_must_be_positive(self) -> None:
        """Rejects a non-positive width."""
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for PoseidonParams\nwidth\n"
            r"  Input should be greater than 0 .*\Z",
        ):
            PoseidonParams(
                width=0,
                rounds_f=8,
                rounds_p=20,
                mds_first_row=[Fp(1), Fp(2), Fp(3)],
                round_constants=[Fp(1)] * 84,
            )

    def test_rounds_f_must_be_positive(self) -> None:
        """Rejects a non-positive full-round count before the even-check runs."""
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for PoseidonParams\nrounds_f\n"
            r"  Input should be greater than 0 .*\Z",
        ):
            PoseidonParams(
                width=3,
                rounds_f=0,
                rounds_p=20,
                mds_first_row=[Fp(1), Fp(2), Fp(3)],
                round_constants=[Fp(1)] * 60,
            )

    def test_rounds_p_must_be_non_negative(self) -> None:
        """Rejects a negative partial-round count."""
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for PoseidonParams\nrounds_p\n"
            r"  Input should be greater than or equal to 0 .*\Z",
        ):
            PoseidonParams(
                width=3,
                rounds_f=8,
                rounds_p=-1,
                mds_first_row=[Fp(1), Fp(2), Fp(3)],
                round_constants=[Fp(1)] * 21,
            )

    def test_mds_first_row_must_be_non_empty(self) -> None:
        """Rejects an empty MDS first row."""
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for PoseidonParams\nmds_first_row\n"
            r"  List should have at least 1 item after validation, not 0 .*\Z",
        ):
            PoseidonParams(
                width=3,
                rounds_f=8,
                rounds_p=20,
                mds_first_row=[],
                round_constants=[Fp(1)] * 84,
            )

    def test_round_constants_must_be_non_empty(self) -> None:
        """Rejects an empty round-constants list."""
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for PoseidonParams\nround_constants\n"
            r"  List should have at least 1 item after validation, not 0 .*\Z",
        ):
            PoseidonParams(
                width=3,
                rounds_f=8,
                rounds_p=20,
                mds_first_row=[Fp(1), Fp(2), Fp(3)],
                round_constants=[],
            )

    def test_rounds_f_must_be_even(self) -> None:
        """Rejects odd full-round counts that would leave constants unused."""
        with pytest.raises(
            ValidationError,
            match=r"(?s)^1 validation error for PoseidonParams\nrounds_f\n"
            r"  Input should be a multiple of 2 .*\Z",
        ):
            PoseidonParams(
                width=3,
                rounds_f=7,
                rounds_p=20,
                mds_first_row=[Fp(1)] * 3,
                round_constants=[Fp(1)] * 81,
            )


class TestPoseidonEngine:
    """Tests for Poseidon engine."""

    def test_permute_wrong_state_length_too_short(self) -> None:
        """Raises error when input state is too short."""
        engine = Poseidon(PARAMS_16)
        with pytest.raises(ValueError) as exception_info:
            engine.permute([Fp(1)] * 10)
        assert str(exception_info.value) == "Input state must have length 16"

    def test_permute_wrong_state_length_too_long(self) -> None:
        """Raises error when input state is too long."""
        engine = Poseidon(PARAMS_16)
        with pytest.raises(ValueError) as exception_info:
            engine.permute([Fp(1)] * 20)
        assert str(exception_info.value) == "Input state must have length 16"

    def test_permute_determinism(self) -> None:
        """Same input produces same output."""
        engine = Poseidon(PARAMS_16)
        input_state = [Fp(value=i) for i in range(16)]

        output1 = engine.permute(input_state)
        output2 = engine.permute(input_state)

        assert output1 == output2

    def test_permute_output_differs_from_input(self) -> None:
        """Permutation changes the state."""
        engine = Poseidon(PARAMS_16)
        input_state = [Fp(value=i) for i in range(16)]

        permuted_output = engine.permute(input_state)

        assert permuted_output != input_state

    @pytest.mark.parametrize(
        "params, input_state",
        [
            (PARAMS_16, INPUT_16),
            (PARAMS_24, INPUT_24),
        ],
        ids=["width_16", "width_24"],
    )
    def test_permute_output_in_field(self, params: PoseidonParams, input_state: list[Fp]) -> None:
        """Every output element lies strictly below the field modulus."""
        engine = Poseidon(params)

        permuted_output = engine.permute(input_state)

        assert all(int(output_element) < P for output_element in permuted_output)

    def test_permute_all_zero_input(self) -> None:
        """All-zero input produces an in-field output of the expected width."""
        engine = Poseidon(PARAMS_16)

        permuted_output = engine.permute([Fp(0)] * 16)

        assert len(permuted_output) == 16
        assert all(int(output_element) < P for output_element in permuted_output)

    def test_permute_field_boundary_input(self) -> None:
        """Maximum-value input stays in-field and exposes int64 regressions."""
        engine = Poseidon(PARAMS_16)

        permuted_output = engine.permute([Fp(value=P - 1)] * 16)

        assert len(permuted_output) == 16
        assert all(int(output_element) < P for output_element in permuted_output)
