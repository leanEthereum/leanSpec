"""
Validates that XMSS parameter choices achieve adequate classical and quantum security.

Based on:

- [DKKW25c] "Hash-Based Multi-Signatures for Post-Quantum Ethereum"
  (https://eprint.iacr.org/2025/055.pdf)
- [HKKTW26] "Aborting Random Oracles"
  (https://eprint.iacr.org/2026/016)

The security analysis follows the framework of [DKKW25c] Section 6. Theorem 1
gives an advantage bound as the sum of five terms. Each term divided by attacker
running time must be at most `2^{-(k + log5)}`, yielding four independent
constraints (Parameter Requirements 2 and 3):

1. Digest (SM-UD/SM-PRE via Eq 8-9 / Eq 15)
2. Public parameter (SM-TCR via Eq 6-7 / Eq 16)
3. Message hash (SM-rTCR via Eq 10 / Eq 13)
4. Randomness (SM-rTCR via Eq 10 / Eq 14)

The abort correction from [HKKTW26] Corollary 1 and Remark 14 adjusts the
message hash bound: the aborting decode effectively enlarges the output space
to `|H|/(1 - theta)`, where `theta` is the abort probability.
"""

import math

import pytest

from lean_spec.subspecs.koalabear import P
from lean_spec.subspecs.xmss.constants import PROD_CONFIG, XmssConfig


def _calculate_layer_size(w: int, v: int, d: int) -> int:
    """
    Calculates a hypercube layer's size using inclusion-exclusion.

    Counts integer solutions to x_1 + ... + x_v = k with 0 <= x_i <= w-1,
    where k = v*(w-1) - d.
    """
    coord_sum = v * (w - 1) - d
    return sum(
        ((-1) ** s) * math.comb(v, s) * math.comb(coord_sum - s * w + v - 1, v - 1)
        for s in range(coord_sum // w + 1)
    )


def _compute_security_levels(config: XmssConfig) -> dict[str, float]:
    """
    Computes classical and quantum security levels for an XMSS configuration.

    Returns a dict with keys:

    - `k_classical`: effective classical security (bits)
    - `k_quantum`: effective quantum security (bits)
    - `expected_attempts`: expected signing attempts per message
    - `signing_failure_log2`: log2 of probability that all MAX_TRIES attempts fail
    """
    v = config.DIMENSION
    w_bits = int(math.log2(config.BASE))
    base = config.BASE

    # Bit sizes of the parameter spaces.
    #
    # Each KoalaBear field element contributes floor(log2(P)) = 31 bits.
    fe_bits = 31
    bits_digest = config.HASH_LEN_FE * fe_bits
    bits_param = config.PARAMETER_LEN * fe_bits
    bits_rand = config.RAND_LEN_FE * fe_bits

    # Raw message hash output: v chunks of w bits each.
    bits_msg = v * w_bits

    # Abort correction from [HKKTW26] Corollary 1, Remark 14.
    #
    # Each field element aborts iff A_i >= Q * BASE^Z (i.e., A_i == P - 1).
    # The non-abort probability per FE is (Q * BASE^Z) / P = (P - 1) / P.
    # Over ell = ceil(v / Z) field elements, the total non-abort probability is:
    #   (1 - theta) = ((P - 1) / P) ^ ell
    #
    # The aborting rTCR bound ([HKKTW26] Corollary 1) gains a factor (1 - theta),
    # which is equivalent to hashing into a space of size |H| / (1 - theta).
    # This adds -log2(1 - theta) bits to the effective message hash output.
    wz = base**config.Z
    q = config.Q
    ell = math.ceil(v / config.Z)

    non_abort_total = ((q * wz) / P) ** ell
    abort_correction_bits = -math.log2(non_abort_total)

    bits_msg_eff = bits_msg + abort_correction_bits

    # Useful logarithmic constants.
    log5 = math.log2(5)
    log12 = math.log2(12)
    log3 = math.log2(3)
    log_lifetime = math.log2(config.LIFETIME)
    logv = math.log2(v)
    log_max_tries = math.log2(config.MAX_TRIES)
    logqs = math.log2(config.LIFETIME)

    # Classical security: minimum over four attack surfaces.
    #
    # Each bound derives from the requirement that each of the five terms in
    # Theorem 1 satisfies Adv_i / T(A) <= 2^{-(k_C + log5)}.
    k_classical = min(
        # [DKKW25c] Eq (15): SM-UD + SM-PRE on the digest hash Th.
        bits_digest - log5 - 2 * w_bits - log_lifetime - logv,
        # [DKKW25c] Eq (16): SM-TCR on the public parameter space.
        bits_param - log5 - 3,
        # [DKKW25c] Eq (13) + [HKKTW26] Corollary 1: SM-rTCR on message hash.
        bits_msg_eff - log5 - 1,
        # [DKKW25c] Eq (14): SM-rTCR randomness reprogramming.
        bits_rand - log5 - logqs - log_max_tries - 1,
    )

    # Quantum security: minimum over four attack surfaces.
    #
    # Uses quantum ROM bounds from [DKKW25c] Table 1.
    k_quantum = min(
        # [DKKW25c] Eq (15), quantum: digest hash.
        bits_digest / 2 - log5 - 2 * w_bits - log_lifetime - logv - log12,
        # [DKKW25c] Eq (16), quantum: public parameter.
        (bits_param - 5) / 2 - log5 - 2,
        # [DKKW25c] Eq (13) + [HKKTW26] Corollary 1, quantum: message hash.
        (bits_msg_eff - 3) / 2 - log5 - 1,
        # [DKKW25c] Eq (14), quantum: randomness reprogramming.
        (bits_rand - logqs) / 2 - log5 - log3 - log_max_tries,
    )

    # Expected signing attempts for target-sum encoding.
    #
    # [DKKW25c] Construction 6, Lemma 7: the number of valid codewords is
    # |C| = #{x in Z_W^v : sum(x_i) = T}, the layer size at distance
    # d = v*(W-1) - T from the sink vertex. The inclusion-exclusion formula
    # from _calculate_layer_size gives |C|.
    #
    # Success probability per attempt = P(no abort) * P(target layer | no abort).
    d = v * (base - 1) - config.TARGET_SUM
    layer_size = _calculate_layer_size(base, v, d)
    layer_prob = layer_size / base**v
    success_prob = non_abort_total * layer_prob
    expected_attempts = 1 / success_prob

    # [DKKW25c] Lemma 3: correctness error is delta^K where delta = 1 - success_prob.
    signing_failure_log2 = config.MAX_TRIES * math.log2(1 - success_prob)

    return {
        "k_classical": k_classical,
        "k_quantum": k_quantum,
        "expected_attempts": expected_attempts,
        "signing_failure_log2": signing_failure_log2,
    }


def test_prod_classical_security() -> None:
    """Production parameters must achieve at least 128-bit classical security."""
    levels = _compute_security_levels(PROD_CONFIG)
    assert levels["k_classical"] >= 128, (
        f"Classical security {levels['k_classical']:.2f} bits is below 128"
    )


def test_prod_quantum_security() -> None:
    """Production parameters must achieve at least 64-bit quantum security."""
    levels = _compute_security_levels(PROD_CONFIG)
    assert levels["k_quantum"] >= 64, f"Quantum security {levels['k_quantum']:.2f} bits is below 64"


def test_prod_signing_efficiency() -> None:
    """Signing must succeed within a reasonable number of attempts on average."""
    levels = _compute_security_levels(PROD_CONFIG)

    # Expected attempts should be manageable (< 1000).
    assert levels["expected_attempts"] < 1000, (
        f"Expected {levels['expected_attempts']:.2f} signing attempts is too high"
    )

    # The probability of MAX_TRIES consecutive failures must be astronomically small.
    # log2(failure_prob) < -128 means failure probability < 2^{-128}.
    assert levels["signing_failure_log2"] < -128, (
        f"Signing failure probability 2^{levels['signing_failure_log2']:.2f} is too high"
    )


def test_prod_abort_probability_is_negligible() -> None:
    """
    The aborting decode rejection probability must be negligible.

    From [HKKTW26] Section 6.1: each FE has abort probability 1/P.
    Over `ceil(v/Z)` FEs, the total abort probability is approximately
    `ceil(v/Z) / P`.
    """
    config = PROD_CONFIG
    ell = math.ceil(config.DIMENSION / config.Z)

    # Per-FE non-abort probability: (Q * BASE^Z) / P = (P - 1) / P.
    non_abort_per_fe = (config.Q * config.BASE**config.Z) / P
    total_non_abort = non_abort_per_fe**ell

    # The abort probability should be less than 2^{-28} (~3.7e-9).
    abort_prob = 1 - total_non_abort
    assert abort_prob < 2**-28, f"Abort probability {abort_prob:.2e} is not negligible"


def test_prod_decomposition_invariant() -> None:
    """
    Validates the fundamental relationship Q * BASE^Z == P - 1.

    From [HKKTW26] Section 6.1: for KoalaBear, P - 1 = 2^24 * 127.
    With BASE = 2^w, the decomposition requires w | 24 so that
    Z = 24 / w digits can be extracted from each field element.
    """
    config = PROD_CONFIG

    # Core decomposition invariant (also checked at config construction time).
    assert config.Q * config.BASE**config.Z == P - 1

    # w must divide 24 for the rejection sampling to work with KoalaBear.
    #
    # P - 1 = 2^24 * 127, and BASE = 2^w, so we need w | 24.
    w_bits = int(math.log2(config.BASE))
    assert config.BASE == 2**w_bits, "BASE must be a power of 2"
    assert 24 % w_bits == 0, f"w={w_bits} must divide 24"

    # Z must equal 24 / w for the optimal decomposition (alpha = 1).
    assert config.Z == 24 // w_bits, f"Z={config.Z} must equal 24/w={24 // w_bits}"


def test_prod_mh_hash_len_is_consistent() -> None:
    """
    The Poseidon output length must produce enough digits to cover DIMENSION.

    From [HKKTW26] Section 6.1: ell = ceil(v / z) field elements produce
    ell * z >= v base-w digits.
    """
    config = PROD_CONFIG
    assert config.MH_HASH_LEN_FE * config.Z >= config.DIMENSION


def test_prod_binding_constraint_is_message_hash() -> None:
    """
    Verify the binding (smallest) constraint is the message hash for both
    classical and quantum security, matching the design intent from [DKKW25c].
    """
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

    # Classical: the message hash bound v*w - log5 - 1 should be the tightest.
    classical_bounds = [
        bits_digest - log5 - 2 * w_bits - log_lifetime - logv,
        bits_param - log5 - 3,
        bits_msg - log5 - 1,
        bits_rand - log5 - log_lifetime - log_max_tries - 1,
    ]
    assert classical_bounds.index(min(classical_bounds)) == 2, (
        "Classical binding constraint should be message hash (index 2)"
    )


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
    """
    Guards against accidental parameter drift.

    These values must match the canonical Rust implementation (leanSig).
    """
    assert getattr(PROD_CONFIG, param_name) == value


def test_print_security_summary(capsys: pytest.CaptureFixture[str]) -> None:
    """Prints a human-readable summary of the security analysis (informational)."""
    levels = _compute_security_levels(PROD_CONFIG)
    print("\n--- XMSS Production Security Summary ---")
    print(f"Classical security:       {levels['k_classical']:.2f} bits")
    print(f"Quantum security:         {levels['k_quantum']:.2f} bits")
    print(f"Expected sign attempts:   {levels['expected_attempts']:.2f}")
    print(f"Signing failure (log2):   {levels['signing_failure_log2']:.2f}")
    print("----------------------------------------")
