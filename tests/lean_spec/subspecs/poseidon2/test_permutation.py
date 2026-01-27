"""Tests for the Poseidon2 permutation for widths 16 and 24."""

import pytest

from lean_spec.subspecs.koalabear.field import Fp
from lean_spec.subspecs.poseidon2.permutation import (
    PARAMS_16,
    PARAMS_24,
    Poseidon2,
    Poseidon2Params,
)

# --- Test Vectors ---

# Input vector for width 16
INPUT_16 = [
    Fp(value=894848333),
    Fp(value=1437655012),
    Fp(value=1200606629),
    Fp(value=1690012884),
    Fp(value=71131202),
    Fp(value=1749206695),
    Fp(value=1717947831),
    Fp(value=120589055),
    Fp(value=19776022),
    Fp(value=42382981),
    Fp(value=1831865506),
    Fp(value=724844064),
    Fp(value=171220207),
    Fp(value=1299207443),
    Fp(value=227047920),
    Fp(value=1783754913),
]
# Expected output for width 16.
EXPECTED_16 = [
    Fp(value=190453639),
    Fp(value=458899855),
    Fp(value=383789123),
    Fp(value=1958965770),
    Fp(value=1470307143),
    Fp(value=135446903),
    Fp(value=1980271247),
    Fp(value=26609194),
    Fp(value=337889870),
    Fp(value=543343594),
    Fp(value=900082402),
    Fp(value=1267415354),
    Fp(value=1018710090),
    Fp(value=902823573),
    Fp(value=1161524658),
    Fp(value=1483653556),
]

# Input vector for width 24
INPUT_24 = [
    Fp(value=886409618),
    Fp(value=1327899896),
    Fp(value=1902407911),
    Fp(value=591953491),
    Fp(value=648428576),
    Fp(value=1844789031),
    Fp(value=1198336108),
    Fp(value=355597330),
    Fp(value=1799586834),
    Fp(value=59617783),
    Fp(value=790334801),
    Fp(value=1968791836),
    Fp(value=559272107),
    Fp(value=31054313),
    Fp(value=1042221543),
    Fp(value=474748436),
    Fp(value=135686258),
    Fp(value=263665994),
    Fp(value=1962340735),
    Fp(value=1741539604),
    Fp(value=2026927696),
    Fp(value=449439011),
    Fp(value=1131357108),
    Fp(value=50869465),
]
# Expected output for width 24.
EXPECTED_24 = [
    Fp(value=556605495),
    Fp(value=885256863),
    Fp(value=899046610),
    Fp(value=1365261647),
    Fp(value=799824470),
    Fp(value=1363091631),
    Fp(value=588658632),
    Fp(value=173515151),
    Fp(value=783308499),
    Fp(value=1346358755),
    Fp(value=1865380489),
    Fp(value=1166148328),
    Fp(value=1402826941),
    Fp(value=434428806),
    Fp(value=928050984),
    Fp(value=1402941053),
    Fp(value=201160368),
    Fp(value=1850628943),
    Fp(value=651578331),
    Fp(value=12196116),
    Fp(value=759351756),
    Fp(value=948448587),
    Fp(value=1529251366),
    Fp(value=456048743),
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
    params: Poseidon2Params, input_state: list[Fp], expected_output: list[Fp]
) -> None:
    """
    Test the Poseidon2 permutation against known answer vectors.

    Serves as a regression test to ensure logic consistency.
    """
    engine = Poseidon2(params)
    output_state = engine.permute(input_state)

    assert len(output_state) == params.width
    assert output_state == expected_output, (
        f"Permutation output for width {params.width} did not match."
    )
