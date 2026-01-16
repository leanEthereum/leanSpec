"""Unit tests for genesis state generation."""

from lean_spec.subspecs.containers.block import Block, BlockBody
from lean_spec.subspecs.containers.block.types import AggregatedAttestations
from lean_spec.subspecs.containers.slot import Slot
from lean_spec.subspecs.containers.state import State, Validators
from lean_spec.subspecs.containers.validator import Validator
from lean_spec.subspecs.ssz.hash import hash_tree_root
from lean_spec.types import Bytes32, Bytes52, Uint64


def test_genesis_block_hash_comparison() -> None:
    """Test that genesis block hashes are deterministic and differ with different inputs."""
    # Create first genesis state with 3 validators
    # Fill pubkeys with different values (1, 2, 3)
    pubkeys1 = [Bytes52(bytes([i + 1] * 52)) for i in range(3)]
    validators1 = Validators(
        data=[Validator(pubkey=pubkey, index=Uint64(i)) for i, pubkey in enumerate(pubkeys1)]
    )

    genesis_state1 = State.generate_genesis(
        genesis_time=Uint64(1000),
        validators=validators1,
    )

    # Generate genesis block from first state
    genesis_block1 = Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state1),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    # Compute hash of first genesis block
    genesis_block_hash1 = hash_tree_root(genesis_block1)

    # Create a second genesis state with same config but regenerated (should produce same hash)
    genesis_state1_copy = State.generate_genesis(
        genesis_time=Uint64(1000),
        validators=validators1,
    )

    genesis_block1_copy = Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state1_copy),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    genesis_block_hash1_copy = hash_tree_root(genesis_block1_copy)

    # Same genesis spec should produce same hash
    assert genesis_block_hash1 == genesis_block_hash1_copy

    # Create second genesis state with different validators
    # Fill pubkeys with different values (10, 11, 12)
    pubkeys2 = [Bytes52(bytes([i + 10] * 52)) for i in range(3)]
    validators2 = Validators(
        data=[Validator(pubkey=pubkey, index=Uint64(i)) for i, pubkey in enumerate(pubkeys2)]
    )

    genesis_state2 = State.generate_genesis(
        genesis_time=Uint64(1000),  # Same genesis_time but different validators
        validators=validators2,
    )

    genesis_block2 = Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state2),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    genesis_block_hash2 = hash_tree_root(genesis_block2)

    # Different validators should produce different genesis block hash
    assert genesis_block_hash1 != genesis_block_hash2

    # Create third genesis state with same validators but different genesis_time
    # Same as pubkeys1
    pubkeys3 = [Bytes52(bytes([i + 1] * 52)) for i in range(3)]
    validators3 = Validators(
        data=[Validator(pubkey=pubkey, index=Uint64(i)) for i, pubkey in enumerate(pubkeys3)]
    )

    genesis_state3 = State.generate_genesis(
        genesis_time=Uint64(2000),  # Different genesis_time but same validators
        validators=validators3,
    )

    genesis_block3 = Block(
        slot=Slot(0),
        proposer_index=Uint64(0),
        parent_root=Bytes32.zero(),
        state_root=hash_tree_root(genesis_state3),
        body=BlockBody(attestations=AggregatedAttestations(data=[])),
    )

    genesis_block_hash3 = hash_tree_root(genesis_block3)

    # Different genesis_time should produce different genesis block hash
    assert genesis_block_hash1 != genesis_block_hash3

    # Compare genesis block hashes with expected hex values
    hash1_hex = f"0x{genesis_block_hash1.hex()}"
    assert hash1_hex == "0xcc03f11dd80dd79a4add86265fad0a141d0a553812d43b8f2c03aa43e4b002e3"

    hash2_hex = f"0x{genesis_block_hash2.hex()}"
    assert hash2_hex == "0x6bd5347aa1397c63ed8558079fdd3042112a5f4258066e3a659a659ff75ba14f"

    hash3_hex = f"0x{genesis_block_hash3.hex()}"
    assert hash3_hex == "0xce48a709189aa2b23b6858800996176dc13eb49c0c95d717c39e60042de1ac91"
