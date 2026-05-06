"""Test vectors for ENR encoding and PeerId derivation."""

import pytest
from consensus_testing import NetworkingCodecTestFiller

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
"""ENR with ip4 + udp but no eth2, attnets, or syncnets keys."""

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

ENR_SYNCNETS_ONLY = (
    "enr:-H-4QE_YuRp32SAUCRWpLtCZnfsZWnD8SrO0SJE8T3x6XdYJvBKI9eW79Vy9"
    "AEIjRGL8jLSgCV2BpEJ4-5NQSksSvyEBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrL"
    "QB2KTGtv6MVbcNEVv0AHacwUAPMljNMTiIc3luY25ldHMK"
)
"""ENR with syncnets key (subnets 1, 3) but no eth2 or attnets."""

ENR_IPV6_ONLY = (
    "enr:-JK4QGjix5Zy3h0NXP7WkXobaBJtkv_bAMf5pkq17EIThF7rSvyRoBA_dQ93_u"
    "-icZRoK_-vdEy2RM1AKuAKArf2z3UBgmlkgnY0g2lwNpAgAQ24AAAAAAAAAAAAAAAB"
    "iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTiEdWRwNo"
    "IjKQ"
)
"""ENR with IPv6 address (2001:db8::1) and udp6 port, no IPv4."""

ENR_HIGH_SEQ = (
    "enr:-Hm4QIijml7AMdlciWFY1S7qh7egBawTx_IqvFhHI4xQh6jdDEJv9Slx_lVG"
    "PznU65wh0BzwxMGkbEpzuzO2K7Z_xfSE_____4JpZIJ2NIlzZWNwMjU2azGhA8pjTK"
    "4NSay0Adikxrb-jFW3DRFb9AB2nMFADzJYzTE4"
)
"""ENR with high sequence number (2^32 - 1)."""


# --- ENR ---


def test_enr_official_eip778(networking_codec: NetworkingCodecTestFiller) -> None:
    """Official EIP-778 vector. Exercises node_id, ip4, udp_port, multiaddr, signature."""
    networking_codec(codec_name="enr", input={"enrString": OFFICIAL_ENR})


def test_enr_with_extensions(networking_codec: NetworkingCodecTestFiller) -> None:
    """ENR with all extension keys: eth2, subnets, IPv6, QUIC, udp6, quic6, is_aggregator."""
    networking_codec(codec_name="enr", input={"enrString": ENR_WITH_EXTENSIONS})


def test_enr_minimal_seq_zero(networking_codec: NetworkingCodecTestFiller) -> None:
    """Minimal ENR with seq=0. Only required keys (id + secp256k1)."""
    networking_codec(codec_name="enr", input={"enrString": ENR_MINIMAL})


def test_enr_no_eth2_field(networking_codec: NetworkingCodecTestFiller) -> None:
    """ENR with ip4 + udp but no eth2, attnets, or syncnets. Verifies absent optional fields."""
    networking_codec(codec_name="enr", input={"enrString": ENR_NO_ETH2})


def test_enr_eth2_far_future_fork(networking_codec: NetworkingCodecTestFiller) -> None:
    """ENR with eth2 where next_fork_epoch is max uint64 (far future). Verifies large epoch."""
    networking_codec(codec_name="enr", input={"enrString": ENR_ETH2_FAR_FUTURE})


def test_enr_attnets_all_zeros(networking_codec: NetworkingCodecTestFiller) -> None:
    """ENR with attnets bitfield all zeros. Verifies empty subscribed subnet list."""
    networking_codec(codec_name="enr", input={"enrString": ENR_ATTNETS_ALL_ZEROS})


def test_enr_attnets_all_ones(networking_codec: NetworkingCodecTestFiller) -> None:
    """ENR with attnets bitfield all ones. Verifies all 64 subnets are subscribed."""
    networking_codec(codec_name="enr", input={"enrString": ENR_ATTNETS_ALL_ONES})


def test_enr_syncnets_only(networking_codec: NetworkingCodecTestFiller) -> None:
    """ENR with syncnets (subnets 1, 3) but no eth2 or attnets. Verifies independent parsing."""
    networking_codec(codec_name="enr", input={"enrString": ENR_SYNCNETS_ONLY})


def test_enr_ipv6_only(networking_codec: NetworkingCodecTestFiller) -> None:
    """ENR with IPv6 address (2001:db8::1) and udp6 port, no IPv4."""
    networking_codec(codec_name="enr", input={"enrString": ENR_IPV6_ONLY})


def test_enr_high_seq(networking_codec: NetworkingCodecTestFiller) -> None:
    """ENR with high sequence number (2^32 - 1). Verifies large seq parsing."""
    networking_codec(codec_name="enr", input={"enrString": ENR_HIGH_SEQ})


# --- PeerId ---


def test_peer_id_ed25519(networking_codec: NetworkingCodecTestFiller) -> None:
    """ED25519 PeerId from libp2p spec. 32-byte key, identity multihash."""
    networking_codec(
        codec_name="peer_id",
        input={
            "keyType": "ed25519",
            "publicKey": "0x1ed1e8fae2c4a144b8be8fd4b47bf3d3b34b871c3cacf6010f0e42d474fce27e",
        },
    )


def test_peer_id_secp256k1(networking_codec: NetworkingCodecTestFiller) -> None:
    """secp256k1 PeerId from libp2p spec. 33-byte key, identity multihash."""
    networking_codec(
        codec_name="peer_id",
        input={
            "keyType": "secp256k1",
            "publicKey": "0x037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99",
        },
    )


def test_peer_id_ecdsa(networking_codec: NetworkingCodecTestFiller) -> None:
    """ECDSA PeerId from libp2p spec. 91-byte key, SHA256 multihash (over 42 bytes)."""
    networking_codec(
        codec_name="peer_id",
        input={
            "keyType": "ecdsa",
            "publicKey": (
                "0x3059301306072a8648ce3d020106082a8648ce3d030107034200"
                "04de3d300fa36ae0e8f5d530899d83abab44abf3161f162a4bc901d8e6ec"
                "da020e8b6d5f8da30525e71d6851510c098e5c47c646a597fb4dcec034e9"
                "f77c409e62"
            ),
        },
    )


def test_peer_id_secp256k1_from_enr(networking_codec: NetworkingCodecTestFiller) -> None:
    """secp256k1 PeerId using the public key from the official EIP-778 ENR."""
    networking_codec(
        codec_name="peer_id",
        input={
            "keyType": "secp256k1",
            "publicKey": "0x03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138",
        },
    )
