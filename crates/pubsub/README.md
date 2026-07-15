# minip2p-pubsub

Sans-I/O floodsub (`/floodsub/1.0.0`) for minip2p: the libp2p pubsub RPC
wire codec with StrictSign message signing, and (upcoming) a `FloodsubAgent`
state machine that routes published messages to subscribed peers by
flooding.

`no_std + alloc`, no I/O, no clocks, no async.

## Wire compatibility

- RPC framing: varint length prefix per RPC, many RPCs per inbound stream
  (go-libp2p's persistent streams), one RPC per outbound stream
  (rust-libp2p's one-shot handler). This crate speaks the intersection.
- Messages are signed by default (libp2p StrictSign): Ed25519 over
  `"libp2p-pubsub:" ++ Message` with `signature`/`key` omitted, re-encoded
  canonically from the decoded fields — exactly how go-libp2p and
  rust-libp2p verify. The `key` field is omitted on the wire; verifiers
  recover the public key from the inline-Ed25519 `from` peer id.
- minip2p emits exactly one topic per published message (current go-libp2p
  singular `topic` field); the repeated `topic_ids` form is decoded for
  legacy compatibility.
