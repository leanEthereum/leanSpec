"""
Tests for the Poseidon2 permutation for widths 16 and 24.
"""

from typing import List

import pytest

from lean_spec.subspecs.koalabear.field import Fp
from lean_spec.subspecs.poseidon2.permutation import (
    PARAMS_16,
    PARAMS_24,
    Poseidon2Params,
    permute,
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
    Fp(value=1934285469),
    Fp(value=604889435),
    Fp(value=133449501),
    Fp(value=1026180808),
    Fp(value=1830659359),
    Fp(value=176667110),
    Fp(value=1391183747),
    Fp(value=351743874),
    Fp(value=1238264085),
    Fp(value=1292768839),
    Fp(value=2023573270),
    Fp(value=1201586780),
    Fp(value=1360691759),
    Fp(value=1230682461),
    Fp(value=748270449),
    Fp(value=651545025),
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
    Fp(value=544562271),
    Fp(value=1080511267),
    Fp(value=1756383923),
    Fp(value=788990568),
    Fp(value=532394516),
    Fp(value=221857361),
    Fp(value=955309929),
    Fp(value=1826092461),
    Fp(value=998503261),
    Fp(value=952982720),
    Fp(value=1838946801),
    Fp(value=912684781),
    Fp(value=1518565874),
    Fp(value=1776484523),
    Fp(value=2080906429),
    Fp(value=541434228),
    Fp(value=1778869883),
    Fp(value=564012824),
    Fp(value=1488627785),
    Fp(value=326648728),
    Fp(value=1960688765),
    Fp(value=1179431492),
    Fp(value=362798943),
    Fp(value=470273636),
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
    params: Poseidon2Params, input_state: List[Fp], expected_output: List[Fp]
):
    """
    Tests the Poseidon2 permutation against known answer vectors.

    This serves as a regression test to ensure the logic is consistent.
    """
    # Run the permutation
    output_state = permute(input_state, params)

    # Verify the output
    assert len(output_state) == params.width
    assert output_state == expected_output, (
        f"Permutation output for width {params.width} did not match."
    )
