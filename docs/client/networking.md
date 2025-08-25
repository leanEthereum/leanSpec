# Networking

## Setup

- Transport: QUIC on IPv4, secured by TLS 1.3 with `secp256k1` identities
- Protocol negotiation: [multistream-select 1.0](https://github.com/multiformats/multistream-select/)
- Multiplexing: Native support by QUIC
- Gossip: [gossipsub v1](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md)

## Node identification

Nodes are defined as a list of their ENRs in a yaml file at [`src/lean_spec/client/nodes.yaml`](../../src/lean_spec/client/nodes.yaml).
For example:

```yaml
- enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsB91LTOleFmyWWrFVATGngBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhAMRHkWJc2VjcDI1NmsxoQKLVXFOhp2uX6jeT0DvvDpPcU8FWMjQdR4wMuORMhpX24N1ZHCCIyg
- enr:-Ku4QPn5eVhcoF1opaFEvg1b6JNFD2rqVkHQ8HApOKK61OIcIXD127bKWgAtbwI7pnxx6cDyk_nI88TrZKQaGMZj0q0Bh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhDayLMaJc2VjcDI1NmsxoQK2sBOLGcUb4AwuYzFuAVCaNHA-dy24UuEKkeFNgCVCsIN1ZHCCIyg
- enr:-Ku4QG-2_Md3sZIAUebGYT6g0SMskIml77l6yR-M_JXc-UdNHCmHQeOiMLbylPejyJsdAPsTHJyjJB2sYGDLe0dn8uYBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpC1MD8qAAAAAP__________gmlkgnY0gmlwhBLY-NyJc2VjcDI1NmsxoQORcM6e19T1T9gi7jxEZjk_sjVLGFscUNqAY9obgZaxbIN1ZHCCIyg
```

## ENR structure (modified)

The Ethereum Node Record (ENR) for an Ethereum consensus client MUST contain the
following entries (exclusive of the sequence number and signature, which MUST be
present in an ENR):

- The compressed secp256k1 publickey, 32 bytes (`secp256k1` field).

The ENR MAY contain the following entries:

- An IPv4 address (`ip` field).
- An IPv4 QUIC port (`quic` field) representing the local libp2p QUIC (UDP)
  listening port.

Specifications of these parameters can be found in the
[ENR Specification](http://eips.ethereum.org/EIPS/eip-778).

## Configuration

This section outlines configurations that are used in this spec.

| Name                                 | Value                                    | Description                                                                           |
| ------------------------------------ | ---------------------------------------- | ------------------------------------------------------------------------------------- |
| `MAX_REQUEST_BLOCKS`                 | `2**10` (= 1024)                         | Maximum number of blocks in a single request                                          |
| `MESSAGE_DOMAIN_INVALID_SNAPPY`      | `DomainType('0x00000000')`               | 4-byte domain for gossip message-id isolation of *invalid* snappy messages            |
| `MESSAGE_DOMAIN_VALID_SNAPPY`        | `DomainType('0x01000000')`               | 4-byte domain for gossip message-id isolation of *valid* snappy messages              |

## Gossip domain

**Protocol ID:** `/meshsub/1.0.0`

**Gossipsub Parameters**

The following gossipsub
[parameters](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md#parameters)
will be used:

- `D` (topic stable mesh target count): 8
- `D_low` (topic stable mesh low watermark): 6
- `D_high` (topic stable mesh high watermark): 12
- `D_lazy` (gossip target): 6
- `heartbeat_interval` (frequency of heartbeat, seconds): 0.7
- `fanout_ttl` (ttl for fanout maps for topics we are not subscribed to but have
  published to, seconds): 60
- `mcache_len` (number of windows to retain full messages in cache for `IWANT`
  responses): 6
- `mcache_gossip` (number of windows to gossip about): 3
- `seen_ttl` (expiry time for cache of seen message ids, seconds):
  SECONDS_PER_SLOT * SLOTS_PER_EPOCH * 2

#### Topics and messages

Topics are plain UTF-8 strings and are encoded on the wire as determined by
protobuf (gossipsub messages are enveloped in protobuf messages). Topic strings
have form: `/leanconsensus/devnet{N}/Name/Encoding`. This defines both the type of
data being sent on the topic and how the data field of the message is encoded.

- `Name` - see table below
- `Encoding` - the encoding strategy describes a specific representation of
  bytes that will be transmitted over the wire. See the [Encodings](#Encodings)
  section for further details.

The optional `from` (1), `seqno` (3), `signature` (5) and `key` (6) protobuf
fields are omitted from the message, since messages are identified by content,
anonymous, and signed where necessary in the application layer.

The `message-id` of a gossipsub message MUST be the following 20 byte value
computed from the message data:

- If `message.data` has a valid snappy decompression, set `message-id` to the
  first 20 bytes of the `SHA256` hash of the concatenation of
  `MESSAGE_DOMAIN_VALID_SNAPPY` with the snappy decompressed message data, i.e.
  `SHA256(MESSAGE_DOMAIN_VALID_SNAPPY + snappy_decompress(message.data))[:20]`.
- Otherwise, set `message-id` to the first 20 bytes of the `SHA256` hash of the
  concatenation of `MESSAGE_DOMAIN_INVALID_SNAPPY` with the raw message data,
  i.e. `SHA256(MESSAGE_DOMAIN_INVALID_SNAPPY + message.data)[:20]`.

Where relevant, clients MUST reject messages with `message-id` sizes other than
20 bytes.

*Note*: The above logic handles two exceptional cases: (1) multiple snappy
`data` can decompress to the same value, and (2) some message `data` can fail to
snappy decompress altogether.

The payload is carried in the `data` field of a gossipsub message, and varies
depending on the topic:

| Name                             | Message Type              |
| -------------------------------- | ------------------------- |
| `block`                          | `SignedBlock`             |
| `vote`                           | `SignedVote`              |

Clients MUST reject (fail validation) messages containing an incorrect type, or
invalid payload.

#### Encodings

Topics are post-fixed with an encoding. Encodings define how the payload of a
gossipsub message is encoded.

- `ssz_snappy` - All objects are SSZ-encoded and then compressed with
  [Snappy](https://github.com/google/snappy) block compression. Example: The
  lean block topic string is `/leanconsensus/devnet{N}/block/ssz_snappy`,
  and the data field of a gossipsub message is an `Block` that has been
  SSZ-encoded and then compressed with Snappy.

### The Req/Resp domain

#### Encoding strategies

The token of the negotiated protocol ID specifies the type of encoding to be
used for the req/resp interaction. Only one value is possible at this time:

- `ssz_snappy`: The contents are first
  [SSZ-encoded](../../ssz/simple-serialize.md) and then compressed with
  [Snappy](https://github.com/google/snappy) frames compression. For objects
  containing a single field, only the field is SSZ-encoded not a container with
  a single field. For example, the `BlocksByRoot` request is an SSZ-encoded
  list of `Root`'s.

#### Messages

##### Status v1

**Protocol ID:** `/leanconsensus/req/status/1/`

Request, Response Content:

```
(
  finalized_root: Bytes32
  finalized_slot: uint64
  head_root: Bytes32
  head_slot: uint64
)
```

The fields are, as seen by the client at the time of sending the message:

- `finalized_root`: `store.finalized_checkpoint.root` according to
  [3SF-mini](https://github.com/ethereum/research/tree/master/3sf-mini).
  (Note this defaults to `Root(b'\x00' * 32)` for the genesis finalized
  checkpoint).
- `finalized_epoch`: `store.finalized_checkpoint.epoch` according to
  [3SF-mini](https://github.com/ethereum/research/tree/master/3sf-mini).
- `head_root`: The `hash_tree_root` root of the current head block
  (`Block`).
- `head_slot`: The slot of the block corresponding to the `head_root`.

The dialing client MUST send a `Status` request upon connection.

The request/response MUST be encoded as an SSZ-container.

The response MUST consist of a single `response_chunk`.

Clients SHOULD immediately disconnect from one another following the handshake
above under the following conditions:

1. If the (`finalized_root`, `finalized_epoch`) shared by the peer is not in the
   client's chain at the expected epoch. For example, if Peer 1 sends (root,
   epoch) of (A, 5) and Peer 2 sends (B, 3) but Peer 1 has root C at epoch 3,
   then Peer 1 would disconnect because it knows that their chains are
   irreparably disjoint.

Once the handshake completes, the client with the lower `finalized_epoch` or
`head_slot` (if the clients have equal `finalized_epoch`s) SHOULD request blocks
from its counterparty via the `BlocksByRoot` request.

*Note*: Under abnormal network condition or after some rounds of
`BlocksByRoot` requests, the client might need to send `Status` request
again to learn if the peer has a higher head. Implementers are free to implement
such behavior in their own way.

##### BlocksByRoot v1

**Protocol ID:** `/leanconsensus/req/blocks_by_root/1/`

Request Content:

```
(
  List[Root, MAX_REQUEST_BLOCKS]
)
```

Response Content:

```
(
  List[SignedBlock, MAX_REQUEST_BLOCKS]
)
```

Requests blocks by block root (= `hash_tree_root(SignedBlock.message)`).
The response is a list of `SignedBlock` whose length is less than or equal
to the number of requested blocks. It may be less in the case that the
responding peer is missing blocks.

`BlocksByRoot` is primarily used to recover recent blocks (e.g. when
receiving a block or attestation whose parent is unknown).

The request MUST be encoded as an SSZ-field.

The response MUST consist of zero or more `response_chunk`. Each _successful_
`response_chunk` MUST contain a single `SignedBlock` payload.

Clients MUST respond with at least one block, if they have it. Clients MAY limit
the number of blocks in the response.
