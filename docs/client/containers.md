# Containers

<!-- mdformat-toc start --slug=github --no-anchors --maxlevel=6 --minlevel=2 -->

- [Encoding](#encoding)
- [`Config`](#config)
- [`Checkpoint`](#checkpoint)
- [`State`](#state)
- [`Block`](#block)
- [`BlockHeader`](#blockheader)
- [`BlockBody`](#blockbody)
- [`SignedBlock`](#signedblock)
- [`Vote`](#vote)
- [`SignedVote`](#signedvote)
  - [`Attestation`](#attestation)
- [Remarks](#remarks)

<!-- mdformat-toc end -->

## Encoding

The containers for various blockchain consensus objects are primarily SSZ objects. To be more prover friendly, the Poseidon2 hasher will be used for hash tree rooting of these objects. However `devnet0` & `devnet1` continue to use the sha256 hasher.

## `Config`

```python
class Config(Container):
    # temporary property to support simplified round robin block production in absence of randao & deposit mechanisms
    num_validators: uint64
    genesis_time: uint64
```

## `Checkpoint`

```python
class Checkpoint(Container):
    root: Bytes32
    slot: uint64
```

## `State`

```python
class State(Container):
    config: Config
    slot: uint64
    latest_block_header: BlockHeader

    latest_justified: Checkpoint
    latest_finalized: Checkpoint

    historical_block_hashes: List[Bytes32, HISTORICAL_ROOTS_LIMIT]
    justified_slots: List[bool, HISTORICAL_ROOTS_LIMIT]

    # Diverged from 3SF-mini.py:
    # Flattened `justifications: Dict[str, List[bool]]` for SSZ compatibility
    justifications_roots: List[Bytes32, HISTORICAL_ROOTS_LIMIT]
    justifications_validators: Bitlist[HISTORICAL_ROOTS_LIMIT * VALIDATOR_REGISTRY_LIMIT]
```

## `Block`

```python
class Block(Container):
    slot: uint64
    proposer_index: uint64
    parent_root: Bytes32
    state_root: Bytes32
    body: BlockBody
```

## `BlockHeader`

```python
class BlockHeader(Container):
    slot: uint64
    proposer_index: uint64
    parent_root: Bytes32
    state_root: Bytes32
    body_root: Bytes32
```

## `BlockBody`

```python
class BlockBody(Container):
    # all the signatures are aggregated now in a common field - the block signatures
    attestations: List[ValidatorAttestation, VALIDATOR_REGISTRY_LIMIT]
    # keeping proposer vote separate as attestation would be an aggregated packed
    # structures and standalone vote would waste aggregation bits
    proposer_attestation: AttestationData
```

Remark: `ValidatorAttestation` will be replaced by aggregated `Attestation` in future devnets.

## `SignedBlock`

```python
class SignedBlock(Container):
    message: Block
    # aggregated signature for all of block's signatures, currently a naive list:
    #   attestation signatures in the same sequence followed by proposer signature
    #
    # to be replaced by a single zk aggregated and verifiable signature in a future devnet
    # Note that signature list max is still validator registry limit because of proposer
    # attestation has not separate signature
    signature: List[Vector[byte, 4000], VALIDATOR_REGISTRY_LIMIT]
```

## `AttestationData`

Vote is the attestation data that can be aggregated. Although note there is no aggregation yet in `devnet0`.

```python
class AttestationData(Container):
    slot: uint64
    head: Checkpoint
    target: Checkpoint
    source: Checkpoint
```

## `Attestation`

```python
class ValidatorAttestation(Container):
    validator_id: uint64
    message: AttestationData
```

## `SignedValidatorAttestation`

```python
class SignedValidatorAttestation(Container):
    validator_id: uint64
    message: AttestationData
    # signature over vote message only as it would be aggregated later in attestation
    signature: Vector[byte, 4000]
```


## `Attestation`

The votes are aggregated in `Attestation` similar to beacon protocol but without complication of committees. This is currently not used in devnets.

```python
class Attestation(Container):
    aggregation_bits: Bitlist[VALIDATOR_REGISTRY_LIMIT]
    message: AttestationData
```

#### `SignedAttestation`

Aggregated votes exactly as `Attestation` but also with the aggregated signature. Since there is no specialized role envisioned as of now for aggregation (vs that of beacon protocol), this structure is much simpler.

This is also not currently used in devnets.

```python
class SignedAttestation(Container):
    aggregation_bits: Bitlist[VALIDATOR_REGISTRY_LIMIT]
    message: AttestationData
    # aggregated signature for all of validator's signatures, currently a naive list:
    #
    # to be replaced by a single zk aggregated and verifiable signature in a future devnet
    signature: List[Vector[byte, 4000], VALIDATOR_REGISTRY_LIMIT]
```

## Remarks

- The signature type is still to be determined so `Bytes32` is used in the
  interim. The actual signature size is expected to be a lot larger (~3 KiB).
