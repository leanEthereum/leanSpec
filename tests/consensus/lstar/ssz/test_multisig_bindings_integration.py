"""Integration tests for devnet5 multisig bindings used by leanSpec.

These tests exercise the real `lean_multisig_py` API for:

- Type-1 aggregation + verification
- Type-2 merge + verification
- Deconstruction via split/decompress helpers

The raw XMSS vectors are deterministic and stored in
`tests/data/multisig/devnet5_vectors.json`.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any, SupportsInt

import pytest

from lean_spec.config import LeanEnvMode
from lean_spec.subspecs.xmss.aggregation import (
    AggregationError,
    TypeOneInfo,
    TypeOneInfos,
    TypeOneMultiSignature,
    TypeTwoMultiSignature,
)
from lean_spec.subspecs.xmss.containers import PublicKey
from lean_spec.types import ByteListMiB, Bytes32, Slot, ValidatorIndex, ValidatorIndices

VECTORS_PATH = Path(__file__).resolve().parents[3] / "data/multisig/devnet5_vectors.json"
REQUIRED_APIS = (
    "setup_prover",
    "setup_verifier",
    "aggregate_type_1",
    "verify_type_1",
    "merge_many_type_1",
    "verify_type_2",
    "split_type_2",
    "split_type_2_by_msg",
    "type1_compress_with_pubkeys",
    "type1_decompress_with_pubkeys",
    "type1_compress_without_pubkeys",
    "type2_compress_with_pubkeys",
    "type2_decompress_with_pubkeys",
    "type2_compress_without_pubkeys",
    "ssz_encode_type1_signature",
    "ssz_decode_type1_signature",
    "ssz_encode_type2_signature",
    "ssz_decode_type2_signature",
)


def _load_bindings_module():
    workspace_override = os.environ.get("LEAN_MULTISIG_BINDINGS_PATH")
    if workspace_override:
        workspace = Path(workspace_override)
        if not workspace.exists():
            raise RuntimeError(f"LEAN_MULTISIG_BINDINGS_PATH does not exist: {workspace}")
        sys.path.insert(0, str(workspace))

    # Force reload so this test can prefer the explicit workspace override
    # over any previously imported site-package variant in the same process.
    for name in list(sys.modules):
        if name == "lean_multisig_py" or name.startswith("lean_multisig_py."):
            sys.modules.pop(name, None)
    importlib.invalidate_caches()

    return importlib.import_module("lean_multisig_py")


@pytest.fixture(scope="session")
def bindings_and_mode() -> tuple[Any, LeanEnvMode]:
    try:
        lm = _load_bindings_module()
    except Exception as exc:  # pragma: no cover - environment-specific
        pytest.skip(f"lean_multisig_py import failed: {exc}")

    missing = [name for name in REQUIRED_APIS if not hasattr(lm, name)]
    if missing:
        pytest.skip("lean_multisig_py does not expose devnet5 APIs: " + ", ".join(sorted(missing)))

    if getattr(lm, "_module", None) is not None:
        mode = "prod"
    elif getattr(lm, "_test_module", None) is not None:
        mode = "test"
    else:
        pytest.skip("No usable lean_multisig_py runtime module loaded")

    lm.setup_prover(mode=mode)
    lm.setup_verifier(mode=mode)
    return lm, mode


@pytest.fixture(scope="session")
def vectors() -> dict[str, bytes | int]:
    raw = json.loads(VECTORS_PATH.read_text())
    return {
        "msg_a": bytes.fromhex(raw["msg_a"]),
        "msg_b": bytes.fromhex(raw["msg_b"]),
        "slot_a": int(raw["slot_a"]),
        "slot_b": int(raw["slot_b"]),
        "pk_a": bytes.fromhex(raw["pk_a"]),
        "pk_b": bytes.fromhex(raw["pk_b"]),
        "sig_a": bytes.fromhex(raw["sig_a"]),
        "sig_b": bytes.fromhex(raw["sig_b"]),
    }


def test_type_1_aggregation_deconstruction_and_verification(
    bindings_and_mode: tuple[Any, LeanEnvMode],
    vectors: dict[str, Any],
) -> None:
    lm, mode = bindings_and_mode

    pks_a, type1_a = lm.aggregate_type_1(
        [vectors["pk_a"]],
        [vectors["sig_a"]],
        vectors["msg_a"],
        vectors["slot_a"],
        1,
        mode=mode,
    )
    lm.verify_type_1(pks_a, vectors["msg_a"], vectors["slot_a"], type1_a, mode=mode)

    compact = lm.type1_compress_with_pubkeys(pks_a, type1_a, mode=mode)
    compact_no_pubkeys = lm.type1_compress_without_pubkeys(compact, mode=mode)
    assert compact_no_pubkeys == type1_a
    compact_rehydrated = lm.type1_compress_with_pubkeys(pks_a, compact_no_pubkeys, mode=mode)
    assert compact_rehydrated == compact
    pks_roundtrip, type1_roundtrip = lm.type1_decompress_with_pubkeys(compact, mode=mode)
    lm.verify_type_1(
        pks_roundtrip,
        vectors["msg_a"],
        vectors["slot_a"],
        type1_roundtrip,
        mode=mode,
    )

    # Roundtrip the no-pubkeys Type-1 blob through SSZ wrappers.
    type1_ssz = lm.ssz_encode_type1_signature(type1_roundtrip, mode=mode)
    type1_no_pubkeys = lm.ssz_decode_type1_signature(type1_ssz, mode=mode)
    lm.verify_type_1(
        pks_roundtrip,
        vectors["msg_a"],
        vectors["slot_a"],
        type1_no_pubkeys,
        mode=mode,
    )

    # Build leanSpec Type-1 payload container and verify through wrapper.
    type1_payload = TypeOneMultiSignature(
        info=TypeOneInfo(
            participants=ValidatorIndices(data=[ValidatorIndex(0)]).to_aggregation_bits(),
            proof=ByteListMiB(data=type1_no_pubkeys),
        ),
        proof=ByteListMiB(data=type1_no_pubkeys),
    )
    decoded_type1_payload = TypeOneMultiSignature.decode_bytes(type1_payload.encode_bytes())
    decoded_type1_payload.verify(
        [PublicKey.decode_bytes(pk_ssz) for pk_ssz in pks_roundtrip],
        message=Bytes32(vectors["msg_a"]),
        slot=Slot(vectors["slot_a"]),
        mode=mode,
    )


def test_type_2_merge_split_deconstruction_and_verification(
    bindings_and_mode: tuple[Any, LeanEnvMode],
    vectors: dict[str, Any],
) -> None:
    lm, mode = bindings_and_mode

    type1_a = lm.aggregate_type_1(
        [vectors["pk_a"]],
        [vectors["sig_a"]],
        vectors["msg_a"],
        vectors["slot_a"],
        1,
        mode=mode,
    )
    type1_b = lm.aggregate_type_1(
        [vectors["pk_b"]],
        [vectors["sig_b"]],
        vectors["msg_b"],
        vectors["slot_b"],
        1,
        mode=mode,
    )

    pks_per_component, type2 = lm.merge_many_type_1([type1_a, type1_b], 1, mode=mode)
    lm.verify_type_2(pks_per_component, type2, mode=mode)

    compact = lm.type2_compress_with_pubkeys(pks_per_component, type2, mode=mode)
    compact_no_pubkeys = lm.type2_compress_without_pubkeys(compact, mode=mode)
    assert compact_no_pubkeys == type2
    compact_rehydrated = lm.type2_compress_with_pubkeys(
        pks_per_component, compact_no_pubkeys, mode=mode
    )
    assert compact_rehydrated == compact
    pks_roundtrip, type2_roundtrip = lm.type2_decompress_with_pubkeys(compact, mode=mode)
    lm.verify_type_2(pks_roundtrip, type2_roundtrip, mode=mode)

    # Roundtrip the no-pubkeys Type-2 blob through SSZ wrappers.
    type2_ssz = lm.ssz_encode_type2_signature(type2_roundtrip, mode=mode)
    type2_no_pubkeys = lm.ssz_decode_type2_signature(type2_ssz, mode=mode)
    lm.verify_type_2(pks_roundtrip, type2_no_pubkeys, mode=mode)

    split_by_msg_pks, split_by_msg_type1 = lm.split_type_2_by_msg(
        pks_roundtrip,
        type2_no_pubkeys,
        vectors["msg_a"],
        1,
        mode=mode,
    )
    lm.verify_type_1(
        split_by_msg_pks,
        vectors["msg_a"],
        vectors["slot_a"],
        split_by_msg_type1,
        mode=mode,
    )

    split_by_index_pks, split_by_index_type1 = lm.split_type_2(
        pks_roundtrip,
        type2_no_pubkeys,
        1,
        1,
        mode=mode,
    )
    lm.verify_type_1(
        split_by_index_pks,
        vectors["msg_b"],
        vectors["slot_b"],
        split_by_index_type1,
        mode=mode,
    )

    # Build leanSpec Type-2 payload container and verify through wrapper.
    type2_payload = TypeTwoMultiSignature(
        info=TypeOneInfos(
            data=[
                TypeOneInfo(
                    participants=ValidatorIndices(data=[ValidatorIndex(0)]).to_aggregation_bits(),
                    proof=ByteListMiB(data=type1_a[1]),
                ),
                TypeOneInfo(
                    participants=ValidatorIndices(data=[ValidatorIndex(1)]).to_aggregation_bits(),
                    proof=ByteListMiB(data=type1_b[1]),
                ),
            ]
        ),
        proof=ByteListMiB(data=type2_no_pubkeys),
    )
    decoded_type2_payload = TypeTwoMultiSignature.decode_bytes(type2_payload.encode_bytes())
    decoded_type2_payload.verify(
        [
            [PublicKey.decode_bytes(pk_ssz) for pk_ssz in pks_roundtrip[0]],
            [PublicKey.decode_bytes(pk_ssz) for pk_ssz in pks_roundtrip[1]],
        ],
        mode=mode,
    )


def test_type_1_info_participant_cardinality_validation(
    bindings_and_mode: tuple[Any, LeanEnvMode],
    vectors: dict[str, SupportsInt],
) -> None:
    """Type-1 verification enforces pubkey count equals participant cardinality."""
    lm, mode = bindings_and_mode
    pks_ssz, type1_wire = lm.aggregate_type_1(
        [vectors["pk_a"]],
        [vectors["sig_a"]],
        vectors["msg_a"],
        vectors["slot_a"],
        1,
        mode=mode,
    )
    pk = PublicKey.decode_bytes(pks_ssz[0])
    message = Bytes32(vectors["msg_a"])
    slot = Slot(vectors["slot_a"])
    participants = ValidatorIndices(data=[ValidatorIndex(0)]).to_aggregation_bits()
    proof = ByteListMiB(data=type1_wire)

    single_participant = TypeOneMultiSignature(
        info=TypeOneInfo(participants=participants, proof=proof),
        proof=proof,
    )
    single_participant.verify([pk], message=message, slot=slot, mode=mode)

    # Mismatched participant cardinality is rejected.
    invalid_bits = ValidatorIndices(
        data=[ValidatorIndex(0), ValidatorIndex(1)]
    ).to_aggregation_bits()
    invalid = TypeOneMultiSignature(
        info=TypeOneInfo(participants=invalid_bits, proof=proof),
        proof=proof,
    )
    with pytest.raises(AggregationError, match="expected 2 pubkeys"):
        invalid.verify([pk], message=message, slot=slot, mode=mode)
