# minip2p-pubsub

Sans-I/O libp2p gossipsub for minip2p. `GossipsubAgent` implements mesh-based routing over `/meshsub/1.1.0` and `/meshsub/1.0.0`; `GOSSIPSUB_PROTOCOL_IDS` lists them in preference order for Identify advertisement.

The core is `no_std + alloc`: it performs no I/O, reads no clock, and uses no async runtime. Callers feed swarm events and timestamps, execute emitted actions, and echo stream-operation results.

## Stream and delivery model

Gossipsub keeps one long-lived outbound stream per ready peer and writes varint-framed RPCs back-to-back. At most one write is awaiting its synchronous result. A successful result commits exactly that frame; a failed result resets the stream while retaining unsent messages and logical control work for a later retry. Subscription state is resynchronized whenever a stream reopens.

Readiness is per connection. On `SwarmEvent::ConnectionReplaced` the agent drops queued work (reported through the usual aggregated `OutboundFailure`), clears everything derived from the old connection — its streams, the advertised meshsub version, and the peer's announced topics — and pauses sends while keeping the peer's backoff. `PeerReady` for the new connection picks the version again and re-announces subscriptions on a fresh stream.

A peer's announced subscriptions belong to the connection that carried them. When the agent forgets them, on `ConnectionReplaced` or `ConnectionClosed`, it emits one `PeerUnsubscribed` per topic, so `PeerSubscribed` and `PeerUnsubscribed` alternate per topic: a replacement shows up as an unsubscribe followed by a fresh subscribe once the peer re-announces.

Inbound streams may carry multiple framed RPCs; reassembly, peer subscriptions, pending messages, and concurrent inbound streams are all bounded.

Publishing uses all-or-nothing backpressure across the selected recipients. Forwarding, gossip replies, and cache serving are best effort within the configured per-peer queue bound. `OutboundFailure` means work never reached an accepted stream write; it is not an end-to-end delivery receipt.

## Gossipsub scope

The gossipsub router implements the interoperability core used by meshsub v1.0 and the v1.1 PRUNE extension:

- subscription exchange, mesh GRAFT/PRUNE, degree repair, prune backoff, and fanout for publishes made while locally unsubscribed;
- heartbeat gossip through IHAVE/IWANT, with per-heartbeat spam budgets;
- a heartbeat-windowed and capacity-bounded message cache;
- StrictSign validation before deduplication, delivery, forwarding, or cache insertion;
- negotiated-version-aware PRUNE encoding: v1.1 streams include backoff and v1.0 streams omit it;
- deterministic tests and reproducible peer selection through the constructor's injected entropy seed.

This is deliberately a focused compatibility implementation, not a claim of complete gossipsub conformance. Peer scoring, opportunistic grafting, peer exchange dialing, flood-publish, gossip promises/penalties, and v1.2 extensions are not implemented. Decoded PRUNE peer-exchange records are preserved by the wire codec but ignored by the router.

`GossipsubConfig` exposes mesh degrees, heartbeat/cache/fanout lifetimes, backoff limits, spam budgets, memory bounds, stream-establishment timeout, and unsigned-message policy. `GossipsubAgent::new` validates it and returns `GossipsubConfigError` for inconsistent or zero bounds. `d_lazy = 0` disables gossip emission, while `fanout_ttl_ms = 0` disables fanout reuse.

## Wire compatibility and signing

`Rpc` covers pubsub message and subscription fields plus meshsub IHAVE, IWANT, GRAFT, PRUNE, peer-exchange, and prune-backoff fields. Message ids are opaque bytes, matching upstream behavior despite their protobuf `string` declaration. Field framing uses the shared protobuf vocabulary in `minip2p-core`; this crate keeps RPC/control types, StrictSign canonicalization, the 64 KiB RPC-body limit, and contextual `GossipsubWireError` values.

Messages use libp2p StrictSign by default: Ed25519 over `"libp2p-pubsub:" ++ Message`, with `signature` and `key` omitted and the decoded fields canonically re-encoded. The wire message is preserved verbatim for forwarding. minip2p omits the key field because its Ed25519 public key is recoverable from the inline peer id.

Delivered `GossipsubEvent::Message` values include a `signed` flag. It is true only when a signature was present and verified. With `allow_unsigned`, accepted unsigned messages carry `signed = false`, so higher-level protocols can still require authentication independently of the router policy.

## Benchmarks

Fixtures live in `benches/common.rs`; every measurement uses a fresh one built outside the measured region.

- `publish` / `publish_ir`: a local 60 KiB publish to a 32-peer mesh.
- `router` / `router_ir`: forwarding one fresh, StrictSigned 1 KiB message, delivered and authored by a mesh peer, to the other N−1 peers of an N = 8, 32 or 128 mesh, from handing the inbound frame to the agent through draining its actions; and one heartbeat at 1,000 peers and 100 topics with 500 cached messages over 5 history windows. Each run asserts the forward reached exactly the non-source mesh peers, or that the heartbeat ran, left every mesh alone, and sent each topic's ids from the 3 newest windows to `d_lazy` non-mesh subscribers of that topic.
- `router_allocs`: heap allocations and bytes allocated over the same forwarding boundary, counted by `stats_alloc` as the binary's global allocator.

```bash
cargo bench -p minip2p-pubsub --bench router
cargo bench -p minip2p-pubsub --bench router_allocs
cargo bench -p minip2p-pubsub --bench router_ir   # needs Valgrind
```
