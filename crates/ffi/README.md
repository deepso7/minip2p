# minip2p-ffi

UniFFI bindings for embedding minip2p in React Native and other mobile hosts.
The ABI, generated bindings, event enums, and error enums are pre-1.0 and may
change between releases.

The current surface contains identity and relay-address helpers plus validated
endpoint construction, immutable identity/listen-address queries, and a live
connected-peer query. Secret key bytes are passed separately to the constructor
so the host-visible configuration record cannot stringify them. The lifecycle
surface includes detached background driving, listener callbacks, activity
hints, running-state inspection, flag-only stop, and bounded stopped-state
waits. Swarm, custom-stream, NAT, pubsub, signed-discovery, and mDNS events are
converted to the flattened `P2pEvent` model. The command surface covers ping,
pubsub, custom protocols and streams, and NAT connection attempts; live queries
cover connected and ready peers, Identify snapshots, discovered peers,
reachability, and the active relay reservation.

## Lifecycle and ownership

`P2pEndpoint::new` validates configuration, binds sockets, and returns an
endpoint in the created state. Call `start` once before issuing application
work. The detached native driver owns all network progress and invokes the
listener synchronously on its own thread.

`stop` only requests shutdown. It never joins the driver and callbacks already
in progress may finish after `stop` returns. `wait_stopped` is the native
quietness barrier: after it returns `true`, the endpoint has released its
listener and no later callback can begin. It returns `false` for a created
endpoint until that endpoint is explicitly stopped, and returns immediately
with `false` when called from the driver callback itself.

Dropping the final native `P2pEndpoint` reference requests the same shutdown as
`stop`; it does not synchronously join the detached thread. UniFFI object
destruction therefore does not replace `stop` plus `wait_stopped` when the host
needs an observable native shutdown barrier. The platform-neutral SDK in
`bindings/ts/core` owns separate handler-suppression and close semantics; the
React Native adapter in `bindings/ts/react-native` translates this UniFFI
surface into that SDK backend contract.

The endpoint and its driver share one mutex. Synchronous commands interrupt an
in-flight transport wait before acquiring it, and the driver yields ownership
while commands are pending. Listener callbacks never run while that mutex is
held.

Identify snapshots and custom-stream lifecycle/data events are delivered
directly. Protocol ids can be registered in endpoint configuration or through
`add_protocol`; stream ids remain opaque endpoint-local integers. Listener
callbacks run on the native driver thread and must not block waiting for that
same driver to stop; `wait_stopped` called from a listener returns `false`
immediately.

Connection-attempt IDs are retained in an endpoint-lifetime map. This assumes
chat-scale connection volume; a long-lived service issuing unbounded attempts
should periodically recreate its endpoint until a bounded retirement policy is
added. Cancellation suppresses queued connection-attempt events on a
best-effort basis; an event whose callback already won the dispatch race may
still be observed after `cancel_connect` returns. Cancellation cannot retract a
transport connection that completed concurrently. A host that wants cancel to
also mean "close any resulting session" must call `disconnect` for the target
peer.

The native driver owns connection keepalive. Every 10 seconds it pings every
currently connected peer, keeping quiet connections inside QUIC's default
30-second idle timeout. The driver releases its shared endpoint mutex between
peer pings so commands can interleave with a large keepalive pass. Successful
replies and timeouts surface normally as
`PingRttMeasured` and `PingTimeout` events; hosts should not run a second
keepalive loop. Keepalive is serviced between callback deliveries while
draining a backlog. One listener callback that blocks for roughly the entire
QUIC idle window can still cause connection loss, so callbacks must return
promptly and hand expensive work to the host runtime.

## Addresses, discovery, and event ordering

`listen_addrs` returns locally bound addresses. Wildcard, loopback, and private
addresses are not automatically remotely dialable. Public observations arrive
through `PublicAddressesChanged`; a relay circuit address is composed from
`active_reservation` and `circuit_address`.

Signed-beacon discovery and local-link mDNS are independent opt-ins that feed
one address book. mDNS observations are unauthenticated and retain explicit
source provenance. Applications must add the platform multicast/local-network
permissions required by Android and Apple platforms. Background socket
operation and iOS background networking are outside the v1 contract.

Events preserve FIFO order within each upstream source. There is no total order
across swarm, NAT, pubsub, and discovery queues because their original
cross-source production order is not observable. Hosts must track readiness,
subscriptions, and paths independently.

`P2pEndpoint::path(peer_id)` exposes the facade's authoritative current
NAT-orchestrated path. `EndpointError` also preserves a `stream_id` when the
swarm can identify the failed stream, allowing Promise-based hosts to
correlate asynchronous open and negotiation failures.

## Queue and memory policy

Native callback carry is capped at 4096 source events and delivered in batches
of at most 512. Overflow discards oldest pubsub-message or stream-data events
first, then oldest remaining events, and reports the loss through a dedicated
`EventsDropped` diagnostic. Rust-side tests can inspect exact accounting through
`P2pEndpoint::driver_stats`; this diagnostic method is not exported by UniFFI.

The upstream audit is:

- QUIC accepts at most 128 UDP datagrams per transport poll and separately
  bounds connections, streams, pending datagrams, and pending stream bytes.
- Swarm, NAT, and pubsub events are drained after every endpoint pump. While
  native callback carry is being delivered, the endpoint is not pumped, so
  those source queues do not cumulatively grow behind a slow listener.
- Pubsub bounds each encoded RPC to 65,536 bytes and bounds pending outbound
  work per peer.
- Signed discovery defaults to 128 known peers, 16 addresses per source and
  four pending protocol-violation slots; peer state changes are coalesced.
- NAT event/state volume can still scale with endpoint-lifetime connection
  attempts. The v1 operational assumption is chat-scale connect volume, as
  described above. The 4096-event carry cap bounds retained converted events,
  not every transient allocation inside an upstream poll.
- Any out-of-repository host wrapper queue must define its own hard cap and
  overflow notification; the native carry limit does not bound host queues.

## Stability and exclusions

The entire FFI ABI and generated binding shape are unstable before 1.0.
Regenerate downstream bindings after every change to this crate. The
background driver is the foreign-runtime equivalent of the Rust facade's
caller-driven `poll`/`next_wake` methods. v1 deliberately does not expose
`swarm`/`swarm_mut` implementation escape hatches, standalone Swift/Kotlin
packages, or background-networking guarantees.

Android currently pins `boring` and `boring-sys` to the immutable fix proposed
in [cloudflare/boring#518](https://github.com/cloudflare/boring/pull/518).
Remove the workspace patch when an upstream crates.io release contains that
fix.
