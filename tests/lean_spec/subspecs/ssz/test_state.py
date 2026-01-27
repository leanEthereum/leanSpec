from lean_spec.subspecs.containers import (
    State,
)
from lean_spec.subspecs.containers.block.block import (
    BlockHeader,
)
from lean_spec.subspecs.containers.checkpoint import Checkpoint
from lean_spec.subspecs.containers.config import Config
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state.types import (
    HistoricalBlockHashes,
    JustificationRoots,
    JustificationValidators,
    JustifiedSlots,
    Validators,
)
from lean_spec.subspecs.containers.validator import ValidatorIndex
from lean_spec.types import Bytes32, Uint64


def test_encode_decode_state_roundtrip() -> None:
    block_header = BlockHeader(
        slot=Slot(0),
        proposer_index=ValidatorIndex(0),
        parent_root=Bytes32.zero(),
        state_root=Bytes32.zero(),
        body_root=Bytes32.zero(),
    )
    temp_finalized = Checkpoint(root=Bytes32.zero(), slot=Slot(0))
    state = State(
        config=Config(genesis_time=Uint64(1000)),
        slot=Slot(0),
        latest_block_header=block_header,
        latest_justified=temp_finalized,
        latest_finalized=temp_finalized,
        historical_block_hashes=HistoricalBlockHashes(data=[]),
        justified_slots=JustifiedSlots(data=[]),
        justifications_roots=JustificationRoots(data=[]),
        justifications_validators=JustificationValidators(data=[]),
        validators=Validators(data=[]),
    )

    encode = state.encode_bytes()
    expected_value = (
        "e80300000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000e4000000e4000000e5000000e5000000e5"
        "0000000101"
    )
    assert encode.hex() == expected_value
    assert State.decode_bytes(encode) == state
