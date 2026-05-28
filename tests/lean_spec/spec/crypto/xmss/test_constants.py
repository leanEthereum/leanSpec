"""
Tests for the XMSS cryptographic constants, configuration presets, and security margins.

The security-margin tests validate that the production parameter choices achieve
adequate classical and quantum security.

Based on:

- [DKKW25c] "Hash-Based Multi-Signatures for Post-Quantum Ethereum"
  (https://eprint.iacr.org/2025/055.pdf)
- [HKKTW26] "Aborting Random Oracles"
  (https://eprint.iacr.org/2026/016)

The security analysis follows the framework of [DKKW25c] Section 6.
"""

import math

import pytest

from lean_spec.spec.crypto.koalabear import P_BYTES, P
from lean_spec.spec.crypto.xmss.constants import (
    PROD_CONFIG,
    TARGET_CONFIG,
    TEST_CONFIG,
    XmssConfig,
)
from lean_spec.spec.ssz import Uint64
from lean_spec.spec.ssz.ssz_base import BYTES_PER_LENGTH_OFFSET


def _valid_config_kwargs() -> dict[str, int]:
    """Return a copy of the production configuration fields as plain kwargs."""
    return PROD_CONFIG.model_dump()


def test_decomposition_validator_rejects_bad_product() -> None:
    """A configuration whose product does not equal the prime minus one is rejected."""
    kwargs = _valid_config_kwargs()
    kwargs["Q"] = 128
    with pytest.raises(ValueError, match=f"Q \\* BASE\\^Z must equal P-1={P - 1}"):
        XmssConfig(**kwargs)


def test_decomposition_validator_accepts_valid_product() -> None:
    """A configuration whose product equals the prime minus one validates."""
    config = XmssConfig(**_valid_config_kwargs())
    assert config.Q * config.BASE**config.Z == P - 1


def test_target_config_is_test_config_under_test_env() -> None:
    """The active configuration under the test environment is the test preset."""
    assert TARGET_CONFIG is TEST_CONFIG


def test_lifetime_is_two_to_the_log_lifetime() -> None:
    """The lifetime is two raised to the configured base-two logarithm."""
    assert TEST_CONFIG.LIFETIME == Uint64(1 << TEST_CONFIG.LOG_LIFETIME)


def test_leaves_per_bottom_tree_is_square_root_of_lifetime() -> None:
    """One bottom tree covers the square root of the lifetime in leaves."""
    assert TEST_CONFIG.LEAVES_PER_BOTTOM_TREE == 1 << (TEST_CONFIG.LOG_LIFETIME // 2)


@pytest.mark.parametrize(
    "dimension, z, expected",
    [
        pytest.param(4, 8, 1, id="dimension below one field element rounds up to one"),
        pytest.param(46, 8, 6, id="production dimension needs six field elements"),
        pytest.param(16, 8, 2, id="two full field elements exactly cover sixteen digits"),
    ],
)
def test_mh_hash_len_rounds_up(dimension: int, z: int, expected: int) -> None:
    """The aborting-decode output length is the dimension divided by digits, rounded up."""
    kwargs = _valid_config_kwargs()
    kwargs["DIMENSION"] = dimension
    kwargs["Z"] = z
    assert XmssConfig(**kwargs).MH_HASH_LEN_FE == expected


def test_signature_len_bytes_matches_layout() -> None:
    """The advertised signature length equals the sum of its SSZ-encoded fields."""
    config = TEST_CONFIG
    path = config.LOG_LIFETIME * config.HASH_LEN_FE * P_BYTES
    rho = config.RAND_LEN_FE * P_BYTES
    hashes = config.DIMENSION * config.HASH_LEN_FE * P_BYTES
    expected = path + rho + hashes + 3 * BYTES_PER_LENGTH_OFFSET
    assert config.SIGNATURE_LEN_BYTES == expected


@pytest.mark.parametrize(
    "param_name, value",
    [
        ("DIMENSION", 46),
        ("BASE", 8),
        ("Z", 8),
        ("Q", 127),
        ("TARGET_SUM", 200),
        ("LOG_LIFETIME", 32),
        ("PARAMETER_LEN", 5),
        ("TWEAK_LEN_FE", 2),
        ("MSG_LEN_FE", 9),
        ("RAND_LEN_FE", 7),
        ("HASH_LEN_FE", 8),
        ("CAPACITY", 9),
    ],
)
def test_prod_config_matches_reference(param_name: str, value: int) -> None:
    """Production parameters must match the canonical Rust implementation."""
    assert getattr(PROD_CONFIG, param_name) == value


def _calculate_layer_size(w: int, v: int, d: int) -> int:
    """Count a hypercube layer's size using inclusion-exclusion.

    Counts integer solutions to x_1 + ... + x_v = k with 0 <= x_i <= w-1,
    where k = v*(w-1) - d.
    """
    coord_sum = v * (w - 1) - d
    return sum(
        ((-1) ** s) * math.comb(v, s) * math.comb(coord_sum - s * w + v - 1, v - 1)
        for s in range(coord_sum // w + 1)
    )


def _compute_security_levels(config: XmssConfig) -> dict[str, float]:
    """Compute classical and quantum security levels for a configuration.

    Returns a dict with keys:

    - k_classical: effective classical security in bits
    - k_quantum: effective quantum security in bits
    - expected_attempts: expected signing attempts per message
    - signing_failure_log2: log2 of the probability that all attempts fail
    """
    v = config.DIMENSION
    w_bits = int(math.log2(config.BASE))
    base = config.BASE

    # Each field element contributes floor(log2(P)) = 31 bits.
    fe_bits = 31
    bits_digest = config.HASH_LEN_FE * fe_bits
    bits_param = config.PARAMETER_LEN * fe_bits
    bits_rand = config.RAND_LEN_FE * fe_bits

    # Raw message hash output is v chunks of w bits each.
    bits_msg = v * w_bits

    # Abort correction from [HKKTW26] Corollary 1, Remark 14.
    #
    # Each field element aborts iff it equals the prime minus one.
    # The non-abort probability per element is (P - 1) / P.
    # Over ell field elements the total non-abort probability is that ratio to the ell.
    wz = base**config.Z
    q = config.Q
    ell = math.ceil(v / config.Z)

    non_abort_total = ((q * wz) / P) ** ell
    abort_correction_bits = -math.log2(non_abort_total)

    bits_msg_eff = bits_msg + abort_correction_bits

    log5 = math.log2(5)
    log12 = math.log2(12)
    log3 = math.log2(3)
    log_lifetime = math.log2(config.LIFETIME)
    logv = math.log2(v)
    log_max_tries = math.log2(config.MAX_TRIES)
    logqs = math.log2(config.LIFETIME)

    # Classical security is the minimum over four attack surfaces.
    k_classical = min(
        bits_digest - log5 - 2 * w_bits - log_lifetime - logv,
        bits_param - log5 - 3,
        bits_msg_eff - log5 - 1,
        bits_rand - log5 - logqs - log_max_tries - 1,
    )

    # Quantum security is the minimum over four attack surfaces.
    k_quantum = min(
        bits_digest / 2 - log5 - 2 * w_bits - log_lifetime - logv - log12,
        (bits_param - 5) / 2 - log5 - 2,
        (bits_msg_eff - 3) / 2 - log5 - 1,
        (bits_rand - logqs) / 2 - log5 - log3 - log_max_tries,
    )

    # Expected signing attempts for target-sum encoding.
    d = v * (base - 1) - config.TARGET_SUM
    layer_size = _calculate_layer_size(base, v, d)
    layer_prob = layer_size / base**v
    success_prob = non_abort_total * layer_prob
    expected_attempts = 1 / success_prob

    signing_failure_log2 = config.MAX_TRIES * math.log2(1 - success_prob)

    return {
        "k_classical": k_classical,
        "k_quantum": k_quantum,
        "expected_attempts": expected_attempts,
        "signing_failure_log2": signing_failure_log2,
    }


def test_prod_classical_security() -> None:
    """Production parameters achieve at least 128-bit classical security."""
    levels = _compute_security_levels(PROD_CONFIG)
    assert levels["k_classical"] >= 128


def test_prod_quantum_security() -> None:
    """Production parameters achieve at least 64-bit quantum security."""
    levels = _compute_security_levels(PROD_CONFIG)
    assert levels["k_quantum"] >= 64


def test_prod_expected_signing_attempts_are_bounded() -> None:
    """Signing succeeds within a manageable number of attempts on average."""
    levels = _compute_security_levels(PROD_CONFIG)
    assert levels["expected_attempts"] < 1000


def test_prod_signing_failure_is_negligible() -> None:
    """The probability of exhausting every attempt is below two to the minus 128."""
    levels = _compute_security_levels(PROD_CONFIG)
    assert levels["signing_failure_log2"] < -128


def test_prod_abort_probability_is_negligible() -> None:
    """The aborting decode rejection probability is below two to the minus 28."""
    config = PROD_CONFIG
    ell = math.ceil(config.DIMENSION / config.Z)
    non_abort_per_fe = (config.Q * config.BASE**config.Z) / P
    total_non_abort = non_abort_per_fe**ell
    assert 1 - total_non_abort < 2**-28


def test_prod_base_is_power_of_two() -> None:
    """The alphabet size is a power of two so digits map cleanly onto bits."""
    w_bits = int(math.log2(PROD_CONFIG.BASE))
    assert PROD_CONFIG.BASE == 2**w_bits


def test_prod_digit_width_divides_twenty_four() -> None:
    """The digit width divides twenty-four so rejection sampling works for KoalaBear."""
    w_bits = int(math.log2(PROD_CONFIG.BASE))
    assert 24 % w_bits == 0


def test_prod_z_equals_twenty_four_over_digit_width() -> None:
    """The digit count equals twenty-four divided by the digit width for the optimal decode."""
    w_bits = int(math.log2(PROD_CONFIG.BASE))
    assert PROD_CONFIG.Z == 24 // w_bits


def test_prod_mh_hash_len_covers_dimension() -> None:
    """The aborting-decode output produces at least one digit per hash chain."""
    config = PROD_CONFIG
    assert config.MH_HASH_LEN_FE * config.Z >= config.DIMENSION


def test_prod_binding_constraint_is_message_hash() -> None:
    """The tightest classical bound is the message hash, matching the design intent."""
    config = PROD_CONFIG
    v = config.DIMENSION
    w_bits = int(math.log2(config.BASE))
    fe_bits = 31

    bits_digest = config.HASH_LEN_FE * fe_bits
    bits_param = config.PARAMETER_LEN * fe_bits
    bits_rand = config.RAND_LEN_FE * fe_bits
    bits_msg = v * w_bits

    log5 = math.log2(5)
    log_lifetime = math.log2(config.LIFETIME)
    logv = math.log2(v)
    log_max_tries = math.log2(config.MAX_TRIES)

    classical_bounds = [
        bits_digest - log5 - 2 * w_bits - log_lifetime - logv,
        bits_param - log5 - 3,
        bits_msg - log5 - 1,
        bits_rand - log5 - log_lifetime - log_max_tries - 1,
    ]
    assert classical_bounds.index(min(classical_bounds)) == 2
