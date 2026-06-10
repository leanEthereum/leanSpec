"""Test vectors for ENR encoding and PeerId derivation."""

import pytest

from consensus_testing import EnrRoundtrip, NetworkingCodecTestFiller, PeerIdentifierDerivation

pytestmark = pytest.mark.valid_until("Lstar")

OFFICIAL_ENR = (
    "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjz"
    "CBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQ"
    "PKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8"
)
"""Official EIP-778 test vector with valid signature."""

ENR_WITH_EXTENSIONS = (
    "enr:-PK4QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFh2F0dG5ldHOIgQAAAAAAAICEZXRoMpASNF"
    "Z4q83vAGQAAAAAAAAAgmlkgnY0gmlwhAoAAAGDaXA2kCABDbgAAAAAAAAAAAAAAAG"
    "NaXNfYWdncmVnYXRvcgGEcXVpY4IjKYVxdWljNoIjKolzZWNwMjU2azGhA8pjTK4N"
    "Say0Adikxrb-jFW3DRFb9AB2nMFADzJYzTE4iHN5bmNuZXRzCoN1ZHCCdl-EdWRwN"
    "oJ2YA"
)
"""Constructed ENR with all EIP-778 + consensus extension keys."""

ENR_MINIMAL = (
    "enr:-HW4QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAACAgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrL"
    "QB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg"
)
"""Minimal ENR with seq=0 and only required keys."""

ENR_NO_ETH2 = (
    "enr:-IS4QDohXCCn6lWtmPJGwLPaUz9uZbIcvDotMiTRS2RpRLLaExazyVAAWYwB"
    "gZu_w8M-3NHdkIC7dKuyKgxbxV8mr0cBgmlkgnY0gmlwhAoAAAGJc2VjcDI1NmsxoQ"
    "PKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8"
)
"""ENR with ip4 + udp but no eth2 or attnets keys."""

ENR_ETH2_FAR_FUTURE = (
    "enr:-Iu4QH9jczrZFmQYFzYOnzvoHr0x_oqo6uiVwYyfW4JqmzieRFUycscJpHoQ"
    "oAudebpIM0ty96ktM0ZdV0Cb_Xc_oD4BhGV0aDKQEjRWeAAAAAD__________4JpZI"
    "J2NIlzZWNwMjU2azGhA8pjTK4NSay0Adikxrb-jFW3DRFb9AB2nMFADzJYzTE4"
)
"""ENR with eth2 key where next_fork_epoch = 0xFFFFFFFFFFFFFFFF (far future)."""

ENR_ATTNETS_ALL_ZEROS = (
    "enr:-Ia4QFsi_88hNR5d3KfyPKuHFo9ED0vFol9U3Nwaax848VdNSwaX3URcX3ap"
    "fTnK88gKRyr76KV948B3NAW4k419194Bh2F0dG5ldHOIAAAAAAAAAACCaWSCdjSJc2"
    "VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOA"
)
"""ENR with attnets bitfield all zeros (no subscribed subnets)."""

ENR_ATTNETS_ALL_ONES = (
    "enr:-Ia4QCqe1oTI3hKJukNRiknmVCjHYZaLdgZeUGjS0A3uF1CgbnlM-Meg6FrQ"
    "L8WOH0pTY0OltuMufXVnqvcPu3Y7xh8Bh2F0dG5ldHOI__________-CaWSCdjSJc2"
    "VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOA"
)
"""ENR with attnets bitfield all ones (all 64 subnets subscribed)."""

ENR_HIGH_SEQ = (
    "enr:-Hm4QIijml7AMdlciWFY1S7qh7egBawTx_IqvFhHI4xQh6jdDEJv9Slx_lVG"
    "PznU65wh0BzwxMGkbEpzuzO2K7Z_xfSE_____4JpZIJ2NIlzZWNwMjU2azGhA8pjTK"
    "4NSay0Adikxrb-jFW3DRFb9AB2nMFADzJYzTE4"
)
"""ENR with high sequence number (2^32 - 1)."""


def test_enr_official_eip778(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The official EIP-778 record round-trips unchanged.

    Given
    -----
    - the official EIP-778 ENR text vector.
    - the record carries node_id, ip4, udp port, multiaddr, and signature.

    When
    ----
    - the record is decoded and re-encoded.

    Then
    ----
    - the re-encoded record matches the input.
    """
    networking_codec_test(
        codec=EnrRoundtrip(enr_string=OFFICIAL_ENR),
    )


def test_enr_with_extensions(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A record carrying every extension key round-trips unchanged.

    Given
    -----
    - an ENR with the eth2, attnets, QUIC, and aggregator extension keys.

    When
    ----
    - the record is decoded and re-encoded.

    Then
    ----
    - the re-encoded record matches the input.
    """
    networking_codec_test(
        codec=EnrRoundtrip(enr_string=ENR_WITH_EXTENSIONS),
    )


def test_enr_minimal_seq_zero(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A minimal record with only required keys round-trips unchanged.

    Given
    -----
    - an ENR with seq=0.
    - only the required id and secp256k1 keys are present.

    When
    ----
    - the record is decoded and re-encoded.

    Then
    ----
    - the re-encoded record matches the input.
    """
    networking_codec_test(
        codec=EnrRoundtrip(enr_string=ENR_MINIMAL),
    )


def test_enr_no_eth2_field(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A record with no eth2 or attnets keys round-trips with those fields absent.

    Given
    -----
    - an ENR with ip4 and udp keys.
    - the eth2 and attnets keys are absent.

    When
    ----
    - the record is decoded and re-encoded.

    Then
    ----
    - the re-encoded record matches the input.
    - the optional eth2 and attnets fields stay absent.
    """
    networking_codec_test(
        codec=EnrRoundtrip(enr_string=ENR_NO_ETH2),
    )


def test_enr_eth2_far_future_fork(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A record with a far-future fork epoch round-trips unchanged.

    Given
    -----
    - an ENR whose eth2 key sets the next fork epoch to the maximum uint64.

    When
    ----
    - the record is decoded and re-encoded.

    Then
    ----
    - the re-encoded record matches the input.
    - the large fork epoch survives the round-trip.
    """
    networking_codec_test(
        codec=EnrRoundtrip(enr_string=ENR_ETH2_FAR_FUTURE),
    )


def test_enr_attnets_all_zeros(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A record with an all-zero attnets bitfield round-trips unchanged.

    Given
    -----
    - an ENR whose attnets bitfield is all zeros.

    When
    ----
    - the record is decoded and re-encoded.

    Then
    ----
    - the re-encoded record matches the input.
    - no subnets are reported as subscribed.
    """
    networking_codec_test(
        codec=EnrRoundtrip(enr_string=ENR_ATTNETS_ALL_ZEROS),
    )


def test_enr_attnets_all_ones(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A record with an all-ones attnets bitfield round-trips unchanged.

    Given
    -----
    - an ENR whose attnets bitfield is all ones.

    When
    ----
    - the record is decoded and re-encoded.

    Then
    ----
    - the re-encoded record matches the input.
    - all 64 subnets are reported as subscribed.
    """
    networking_codec_test(
        codec=EnrRoundtrip(enr_string=ENR_ATTNETS_ALL_ONES),
    )


def test_enr_high_seq(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A record with a large sequence number round-trips unchanged.

    Given
    -----
    - an ENR whose seq field is 2^32 - 1.

    When
    ----
    - the record is decoded and re-encoded.

    Then
    ----
    - the re-encoded record matches the input.
    - the large seq value survives the round-trip.
    """
    networking_codec_test(
        codec=EnrRoundtrip(enr_string=ENR_HIGH_SEQ),
    )


def test_peer_id_ed25519(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An ed25519 key derives the libp2p peer_id.

    Given
    -----
    - a 32-byte ed25519 public key from the libp2p test vectors.

    When
    ----
    - the peer_id is derived from the key.

    Then
    ----
    - the derived peer_id uses an identity multihash over the key.
    """
    networking_codec_test(
        codec=PeerIdentifierDerivation(
            key_type="ed25519",
            public_key="0x1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e",
        ),
    )


def test_peer_id_secp256k1(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    A secp256k1 key derives the libp2p peer_id.

    Given
    -----
    - a 33-byte secp256k1 public key from the libp2p test vectors.

    When
    ----
    - the peer_id is derived from the key.

    Then
    ----
    - the derived peer_id uses an identity multihash over the key.
    """
    networking_codec_test(
        codec=PeerIdentifierDerivation(
            key_type="secp256k1",
            public_key="0x037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99",
        ),
    )


def test_peer_id_ecdsa(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    An ECDSA key derives the libp2p peer_id with a hashed multihash.

    Given
    -----
    - a 91-byte ECDSA public key from the libp2p test vectors.

    When
    ----
    - the peer_id is derived from the key.

    Then
    ----
    - the derived peer_id uses a SHA-256 multihash (digest is 42 bytes).
    """
    networking_codec_test(
        codec=PeerIdentifierDerivation(
            key_type="ecdsa",
            public_key="0x3059301306072a8648ce3d020106082a8648ce3d030107034200"
            "04de3d300fa36ae0e8f5d530899d83abab44abf3161f162a4bc901d8e6ec"
            "da020e8b6d5f8da30525e71d6851510c098e5c47c646a597fb4dcec034e9"
            "f77c409e62",
        ),
    )


def test_peer_id_secp256k1_from_enr(networking_codec_test: NetworkingCodecTestFiller) -> None:
    """
    The secp256k1 key from the official record derives its peer_id.

    Given
    -----
    - the secp256k1 public key taken from the official EIP-778 ENR.

    When
    ----
    - the peer_id is derived from the key.

    Then
    ----
    - the derived peer_id uses an identity multihash over the key.
    """
    networking_codec_test(
        codec=PeerIdentifierDerivation(
            key_type="secp256k1",
            public_key="0x03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138",
        ),
    )
