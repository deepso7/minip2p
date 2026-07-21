# minip2p-pubsub

Sans-I/O libp2p pubsub for minip2p: a shared floodsub/meshsub RPC wire codec
with StrictSign message signing, plus the `FloodsubAgent` state machine that
routes published messages to subscribed peers by flooding.

The codec exposes floodsub message fields, meshsub IHAVE/IWANT/GRAFT/PRUNE
control fields, and protocol ids for `/floodsub/1.0.0`, `/meshsub/1.0.0`, and
`/meshsub/1.1.0`. The router is still floodsub-only in this release:
`FloodsubAgent` negotiates `/floodsub/1.0.0` and skips meshsub control fields.

`no_std + alloc`, no I/O, no clocks, no async.

## Wire compatibility

- RPC framing: varint length prefix per RPC. The codec is stream-model
  independent; `FloodsubAgent` accepts many RPCs per inbound stream and uses
  one RPC per outbound stream.
- `Rpc::control` preserves meshsub v1.0 controls plus the v1.1 `PeerInfo` and
  prune-backoff additions. Message ids are opaque bytes, matching upstream
  behavior despite their protobuf `string` declaration.
- Messages are signed by default (libp2p StrictSign): Ed25519 over
  `"libp2p-pubsub:" ++ Message` with `signature`/`key` omitted, re-encoded
  canonically from the decoded fields — exactly how go-libp2p and
  rust-libp2p verify. The `key` field is omitted on the wire; verifiers
  recover the public key from the inline-Ed25519 `from` peer id.
- minip2p emits exactly one topic per published message (current go-libp2p
  singular `topic` field); the repeated `topic_ids` form is decoded for
  legacy compatibility.
Delivered message events include a `signed` flag. It is `true` only when a
signature was present and verified; accepted unsigned interoperability messages
carry `false`, allowing higher-level protocols such as peer discovery to require
authentication independently of application-message policy.
