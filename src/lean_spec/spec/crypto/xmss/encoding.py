"""
Message-to-codeword pipeline for the Generalized XMSS scheme.

# Overview

The pipeline has two layers:

- Encoding maps a message to a codeword, the vector of digits a signature commits to.
- Decoding is the inner step that unpacks hash field elements into those digits.

A codeword is a vertex of a high-dimensional hypercube.
Encoding accepts the vertex only when its digits lie on the target-sum layer.
A signer retries with fresh randomness until the filter accepts.

Concretely, the test preset uses 4 digits in base 8 with target sum 6:

- The vector [5, 0, 1, 0] sums to 6, lands on the layer, and is accepted.
- The vector [2, 2, 2, 2] sums to 8, misses the layer, and forces a retry.

# Construction

The hypercube decode is the aborting encoding of Aborting Random Oracles, Section 6.1.
https://eprint.iacr.org/2026/016.pdf

The target-sum filter is the top-level acceptance test from the canonical Rust instantiation.

# Abort condition

The decode turns each uniform field element into uniform base-BASE digits.
Uniform output is what lets the security analysis model the hash as a random oracle.

A field element takes one of the P values from 0 to P - 1.
The prime is chosen so that P - 1 = Q * BASE^Z.
The values 0 to P - 2 therefore form BASE^Z groups of Q consecutive integers.

Integer division by Q maps each group to one quotient in 0 to BASE^Z - 1:

    0       .. Q-1     ->  quotient 0
    Q       .. 2Q-1    ->  quotient 1
      ...
    P-1-Q   .. P-2     ->  quotient BASE^Z - 1
    P-1                ->  no quotient

Each quotient expands into Z base-BASE digits.
Every quotient is equally likely, which makes the digits uniform.

The value P - 1 falls outside every group.
The decode rejects it, a rare event near 4.7e-10 that barely affects signing.
"""

from lean_spec.spec.crypto.koalabear import Fp
from lean_spec.spec.crypto.xmss.constants import TWEAK_PREFIX_MESSAGE, XmssConfig
from lean_spec.spec.crypto.xmss.field import int_to_base_p
from lean_spec.spec.crypto.xmss.poseidon import PoseidonXmss
from lean_spec.spec.crypto.xmss.types import Parameter, Randomness
from lean_spec.spec.ssz import Bytes32, Uint64


def encode_message(config: XmssConfig, message: Bytes32) -> list[Fp]:
    """
    Encode a 32-byte message into field elements via base-P decomposition.

    The bytes are read little-endian as a single integer.
    """
    message_integer = int.from_bytes(message, "little")
    return int_to_base_p(message_integer, config.MESSAGE_LENGTH_FIELD_ELEMENTS)


def encode_epoch(config: XmssConfig, epoch: Uint64) -> list[Fp]:
    """
    Encode the epoch and the message-hash subdomain into field elements.

    The 8-bit prefix separates the message-hash subdomain from the chain and tree subdomains.
    """
    # Layout:
    #
    #     (epoch << 8) | MESSAGE_PREFIX
    encoded_tweak = (int(epoch) << 8) | TWEAK_PREFIX_MESSAGE
    return int_to_base_p(encoded_tweak, config.TWEAK_LENGTH_FIELD_ELEMENTS)


def aborting_decode(config: XmssConfig, field_elements: list[Fp]) -> list[int] | None:
    """
    Reject-sample each field element into base-BASE digits.

    For each element A_i:

    1. If A_i >= Q * BASE^Z, that is A_i == P - 1, abort and return None.
    2. Compute d_i = A_i // Q in [0, BASE^Z - 1].
    3. Emit Z base-BASE digits of d_i, least significant first.

    Return the first DIMENSION digits.
    """
    threshold = config.Q * config.BASE**config.Z

    digits: list[int] = []
    for field_element in field_elements:
        element_value = int(field_element)

        # The only rejection case is A_i == P - 1.
        if element_value >= threshold:
            return None

        # Quotient by Q strips the residue.
        # The remainder is uniform in [0, BASE^Z - 1].
        quotient = element_value // config.Q
        for _ in range(config.Z):
            quotient, digit = divmod(quotient, config.BASE)
            digits.append(digit)

    return digits[: config.DIMENSION]


def message_hash(
    poseidon: PoseidonXmss,
    config: XmssConfig,
    parameter: Parameter,
    epoch: Uint64,
    rho: Randomness,
    message: Bytes32,
) -> list[int] | None:
    """
    Hash the inputs with Poseidon and decode into a candidate codeword.

    Args:
        poseidon: Cached Poseidon engine.
        config: Active XMSS configuration.
        parameter: Public parameter P.
        epoch: Current epoch.
        rho: Per-attempt randomness.
        message: Message being signed.

    Returns:
        Codeword of DIMENSION digits in [0, BASE-1], or None on rejection.
    """
    # Encode the message and epoch as field elements before hashing.
    message_field_elements = encode_message(config, message)
    epoch_field_elements = encode_epoch(config, epoch)

    # One Poseidon call produces enough output for the aborting decode.
    base_input = message_field_elements + parameter.elements + epoch_field_elements + rho.elements
    poseidon_output = poseidon.compress(base_input, 24, config.MH_HASH_LENGTH_FIELD_ELEMENTS)

    return aborting_decode(config, poseidon_output)


def target_sum_encode(
    poseidon: PoseidonXmss,
    config: XmssConfig,
    parameter: Parameter,
    epoch: Uint64,
    rho: Randomness,
    message: Bytes32,
) -> list[int] | None:
    """
    Encode a message into a codeword if it meets the target sum.

    The signer retries with fresh randomness on rejection.

    Args:
        poseidon: Cached Poseidon engine.
        config: Active XMSS configuration.
        parameter: Public parameter for domain separation.
        epoch: Current epoch.
        rho: Per-attempt randomness.
        message: Message being signed.

    Returns:
        Codeword on success, None when the attempt must be retried.
    """
    # Phase 1: aborting hypercube decode of the Poseidon output.
    codeword_candidate = message_hash(poseidon, config, parameter, epoch, rho, message)
    if codeword_candidate is None:
        return None

    # Phase 2: target-sum acceptance condition.
    # A valid codeword is a vertex on the hypercube layer whose digit sum is TARGET_SUM.
    if sum(codeword_candidate) == config.TARGET_SUM:
        return codeword_candidate

    # The caller retries with new randomness.
    return None
