# Networking

## Setup

- Transport: QUIC on IPv4
- Encryption and identification: [Libp2p-noise](https://github.com/libp2p/specs/tree/master/noise) with `secp256k1` identities
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
have form: `/leanconsensus/devnet0/Name/Encoding`. This defines both the type of
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
| `lean_block`                     | `SignedBlock`                   |
| `lean_vote`               | `SignedVote`             |

Clients MUST reject (fail validation) messages containing an incorrect type, or
invalid payload.

#### Encodings

Topics are post-fixed with an encoding. Encodings define how the payload of a
gossipsub message is encoded.

- `ssz_snappy` - All objects are SSZ-encoded and then compressed with
  [Snappy](https://github.com/google/snappy) block compression. Example: The
  lean block topic string is `/leanconsensus/devnet0/lean_block/ssz_snappy`,
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
  a single field. For example, the `LeanBlocksByRoot` request is an
  SSZ-encoded list of `Root`'s.

#### Messages

##### LeanBlocksByRoot v1

**Protocol ID:** `/leanconsensus/req/lean_blocks_by_root/1/`

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

`LeanBlocksByRoot` is primarily used to recover recent blocks (e.g. when
receiving a block or attestation whose parent is unknown).

The request MUST be encoded as an SSZ-field.

The response MUST consist of zero or more `response_chunk`. Each _successful_
`response_chunk` MUST contain a single `SignedBlock` payload.

Clients MUST respond with at least one block, if they have it. Clients MAY limit
the number of blocks in the response.
