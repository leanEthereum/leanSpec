"""SSZ conformance test vectors for the types leanSpec declares itself."""

import pytest

from consensus_testing import SSZTestFiller
from lean_spec.node.networking.enr.eth2 import AttestationSubnets
from lean_spec.spec.crypto.koalabear import Fp, P

pytestmark = pytest.mark.valid_until("Lstar")


def test_fp_zero(ssz_test: SSZTestFiller) -> None:
    """
    The zero field element round-trips unchanged.

    Given
    -----
    - the field element zero.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Fp", value=Fp(0))


def test_fp_one(ssz_test: SSZTestFiller) -> None:
    """
    The one field element round-trips unchanged.

    Given
    -----
    - the field element one.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Fp", value=Fp(1))


def test_fp_max(ssz_test: SSZTestFiller) -> None:
    """
    The largest valid field element round-trips unchanged.

    Given
    -----
    - the field element p minus one, the largest valid element.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="Fp", value=Fp(P - 1))


def test_attestation_subnets_none(ssz_test: SSZTestFiller) -> None:
    """
    An attestation subnet bitfield with no subscriptions round-trips unchanged.

    Given
    -----
    - a subnet bitfield with all 64 bits clear.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="AttestationSubnets", value=AttestationSubnets.none())


def test_attestation_subnets_all(ssz_test: SSZTestFiller) -> None:
    """
    An attestation subnet bitfield with all subscriptions round-trips unchanged.

    Given
    -----
    - a subnet bitfield with all 64 bits set.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(type_name="AttestationSubnets", value=AttestationSubnets.all())


def test_attestation_subnets_partial(ssz_test: SSZTestFiller) -> None:
    """
    An attestation subnet bitfield with some subscriptions round-trips unchanged.

    Given
    -----
    - a subnet bitfield with five subnet identifiers set.
    - the set identifiers spanning the full 64-bit range.

    When
    ----
    - the value is encoded and then decoded.

    Then
    ----
    - the decoded value equals the original.
    """
    ssz_test(
        type_name="AttestationSubnets",
        value=AttestationSubnets.from_subnet_ids([0, 7, 15, 31, 63]),
    )
