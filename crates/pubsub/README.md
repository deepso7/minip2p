# minip2p-pubsub

Sans-I/O libp2p pubsub for minip2p. The crate provides two routing engines
over a shared RPC codec:

- `GossipsubAgent` implements mesh-based routing over `/meshsub/1.1.0` and
  `/meshsub/1.0.0`.
- `FloodsubAgent` implements flood routing over `/floodsub/1.0.0`.
- `PubsubAgent` and `PubsubConfig` provide static engine selection without
  trait objects.

The core is `no_std + alloc`: it performs no I/O, reads no clock, and uses no
async runtime. Callers feed swarm events and timestamps, execute emitted
actions, and echo stream-operation results.

## Stream and delivery model

Gossipsub keeps one long-lived outbound stream per ready peer and writes
varint-framed RPCs back-to-back. At most one write is awaiting its synchronous
result. A successful result commits exactly that frame; a failed result resets
the stream while retaining unsent messages and logical control work for a
later retry. Subscription state is resynchronized whenever a stream reopens.

Floodsub retains its one-RPC-per-outbound-stream model: open, negotiate, write,
half-close, and commit on terminal close. Both engines accept multiple framed
RPCs on each inbound stream and bound reassembly, peer subscriptions, pending
messages, and concurrent inbound streams.

Publishing uses all-or-nothing backpressure across the selected recipients.
Forwarding, gossip replies, and cache serving are best effort within the
configured per-peer queue bound. `OutboundFailure` means work never reached an
accepted stream write; it is not an end-to-end delivery receipt.

## Gossipsub scope

The gossipsub router implements the interoperability core used by meshsub v1.0
and the v1.1 PRUNE extension:

- subscription exchange, mesh GRAFT/PRUNE, degree repair, prune backoff, and
  fanout for publishes made while locally unsubscribed;
- heartbeat gossip through IHAVE/IWANT, with per-heartbeat spam budgets;
- a heartbeat-windowed and capacity-bounded message cache;
- StrictSign validation before deduplication, delivery, forwarding, or cache
  insertion;
- negotiated-version-aware PRUNE encoding: v1.1 streams include backoff and
  v1.0 streams omit it;
- deterministic tests and reproducible peer selection through the constructor's
  injected entropy seed.

This is deliberately a focused compatibility implementation, not a claim of
complete gossipsub conformance. Peer scoring, opportunistic grafting, peer
exchange dialing, flood-publish, gossip promises/penalties, and v1.2 extensions
are not implemented. Decoded PRUNE peer-exchange records are preserved by the
wire codec but ignored by the router.

`GossipsubConfig` exposes mesh degrees, heartbeat/cache/fanout lifetimes,
backoff limits, spam budgets, memory bounds, stream-establishment timeout, and
unsigned-message policy. Call `validate()` before constructing an agent
directly; `PubsubAgent::new` validates automatically. `d_lazy = 0` disables
gossip emission, while `fanout_ttl_ms = 0` disables fanout reuse.

## Wire compatibility and signing

`Rpc` covers floodsub message fields plus meshsub IHAVE, IWANT, GRAFT, PRUNE,
peer-exchange, and prune-backoff fields. Message ids are opaque bytes, matching
upstream behavior despite their protobuf `string` declaration. Frames use a
varint length prefix and enforce a 64 KiB RPC-body limit.

Messages use libp2p StrictSign by default: Ed25519 over
`"libp2p-pubsub:" ++ Message`, with `signature` and `key` omitted and the
decoded fields canonically re-encoded. The wire message is preserved verbatim
for forwarding. minip2p omits the key field because its Ed25519 public key is
recoverable from the inline peer id.

Delivered `PubsubEvent::Message` values include a `signed` flag. It is true
only when a signature was present and verified. With `allow_unsigned`, accepted
unsigned messages carry `signed = false`, so higher-level protocols can still
require authentication independently of the router policy.
