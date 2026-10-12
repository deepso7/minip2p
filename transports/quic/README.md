# minip2p-quic

Synchronous QUIC transport adapter for minip2p, on the [quinn-proto](https://github.com/quinn-rs/quinn) engine with [rustls](https://github.com/rustls/rustls) (`ring` provider) for libp2p TLS and [quinn-udp](https://crates.io/crates/quinn-udp) for socket I/O.

No async runtime required. quinn-proto owns no sockets and no clock: the adapter feeds it datagrams and a time sample, and sends what it produces. The host drives the transport by calling `poll(now)` with its own time sample.

## Features

- Implements `minip2p_transport::Transport` and the std `BlockingTransport` wait.
- One `QuicTransport` over one or two non-blocking UDP sockets, at most one per IP family, served by one quinn-proto endpoint. `QuicTransport::bind(config, &addrs)` takes one `/ip4/<ip>/udp/<port>/quic-v1` address, one `/ip6/...` address, or one of each (an IPv6 socket is IPv6-only); `QuicTransport::dual_stack(config)` binds an IPv4 and an IPv6 wildcard socket. Each transmit leaves from the socket of its destination's family. Every socket has its own connection namespace, connection count against `QuicLimits::max_connections`, and retry queue.
- Connection lifecycle events (`IncomingConnection`, `Connected`, `PeerIdentityVerified`, `Error`, `Closed`).
- Native QUIC stream operations: `open_stream`, `send_stream`, `close_stream_write`, `reset_stream`, `ack_stream`.
- Stream events (`StreamOpened`, `IncomingStream`, `StreamData`, `StreamWritable`, `StreamRemoteWriteClosed`, `StreamWriteStopped`, `StreamClosed`). Data always precedes the FIN, reset or `StreamClosed` of its stream, and nothing follows a stream's `StreamClosed`.
- Read backpressure (ADR 0012): the engine returns flow-control credit as bytes are read, so the transport stops reading a stream once it has delivered `STREAM_RECEIVE_WINDOW` bytes that were not acknowledged with `ack_stream`. Acknowledging re-reads that stream at once, without waiting for another packet. Stream and connection windows are fixed at their initial size, so the engine buffers at most one more window behind the gate. A FIN or reset right behind a spent budget still surfaces. Each read is copied into a buffer of exactly its length, so delivered data never pins a larger packet allocation. A closed stream with unacknowledged bytes keeps its slot, and new peer streams past `max_streams_per_connection` are refused (stopped and reset, with no event) until it settles.
- Write backpressure (ADR 0012): `send_stream` takes what the engine accepts now plus what fits `QuicLimits::max_pending_stream_bytes`, whatever the peer's credit, and returns `TransportError::Full` with the exact unsent tail for the rest. `StreamWritable` fires for every armed stream once at least half of that queue is free again. `open_stream` succeeds below the local stream limit even while the peer has granted no stream credit: the stream's writes and FIN queue until the engine can open it.
- Stream errors stay stream-scoped: a peer's STOP_SENDING resets the stream's send half, drops its queued writes and emits `StreamWriteStopped` while the read half stays open; writes waiting on peer credit stay queued; any other engine stream error hit while draining closes only its connection, with `Error` then `Closed`.
- Close semantics: an orderly close (error code 0) from either side gives only `Closed`, as do an idle timeout and a stateless reset of an established connection. A connection lost while handshaking (a timeout, a TLS rejection) or closed with a non-zero error code reports `Error` with the reason, then `Closed`.
- Mutual libp2p TLS peer authentication inside the handshake (see [Authentication Notes](#authentication-notes)). `QuicNodeConfig` is identity-first: constructing a transport requires an Ed25519 host keypair.
- A `ConnectionToken` on the established endpoint: 32 bytes of TLS exporter output (label `minip2p quic connection token`, empty context), which both ends of one session derive identically. minip2p releases on the earlier quiche engine derived the token from connection IDs instead, so a mixed-version pair computes different tokens (ADR 0014).
- Dial and `send_datagram` accept `/ip4` and `/ip6` QUIC transport addresses only, of a family with a bound socket. The transport never resolves names, because a blocking lookup would stall every connection on the driver thread: a `/dns*` address is rejected with `TransportError::InvalidAddress`. The std `minip2p` `Endpoint` resolves `/dns*` candidates off its driver thread; direct transport users resolve names themselves first.
- QUIC deadlines are exposed through `Transport::next_deadline()` and processed by `poll()`; no async runtime or hidden timer thread is used. It owns no poll of its own: as a `PollSource` it registers a clone of each socket with the host's one shared readiness poll (a std `Swarm` attaches it when built), so an idle host blocks on both families and every other source at once. Nothing is dispatched to it: every `poll()` reads every socket until `WouldBlock`, and a receive batch cut off by its bound reports `next_deadline()` as immediate, as do buffered events, so calls made between polls -- `listen`, `open_stream`, and the stream operations -- never leave a host asleep on an undelivered event. Unattached (driven by a `SwarmCore` host), it behaves the same; only the wakeups are the host's to arrange.
- Quiet connections send an ack-eliciting packet at half `idle_timeout_ms` (15 s by default) so NAT bindings and the peer's idle timer stay warm without an application ping. A dead path still idle-times out, after roughly the keepalive interval plus the idle timeout.
- Only connections with work are serviced in a `poll`: those it routed datagrams to, those whose engine timer is due (kept in an ordered timer index), and those a previous service left unfinished. Each receive batch is handed to the engine first, and each serviced connection then sends its output once. Every stream or connection call also services its own connection, so its output leaves without waiting for the next poll.
- Each socket reads at most 128 logical datagrams per `poll`, so a packet flood cannot starve connection timers. A batch that hits the bound makes `next_deadline()` report `Deadline::IMMEDIATE`.
- Inbound admission, in order: on a socket that is not listening, nothing is accepted and nothing is sent in reply; at `max_connections` an Initial is ignored silently, before any Retry; with `require_address_validation` (the default), a stateless Retry validates the source address before any connection state is allocated. Retry tokens are valid for 10 s, and no NEW_TOKEN is issued, so Retry is the only validation path. Configurable limits bound connections, streams, queued stream bytes, queued UDP datagrams, and idle time.

### Transport parameters

Every value the adapter relies on is set explicitly:

- stream receive window `STREAM_RECEIVE_WINDOW` (1,000,000 bytes) and connection receive window 10,000,000 bytes, both fixed; send window 10,000,000 bytes;
- `max_streams_per_connection` concurrent bidirectional streams, and no unidirectional streams (libp2p uses only bidirectional ones);
- QUIC DATAGRAM is not advertised;
- idle timeout `idle_timeout_ms` (0 is rejected, because QUIC reads it as "no timeout"), keepalive at half of it;
- TLS 1.3 only, ALPN `libp2p`, no session resumption.

quinn-proto's own defaults stand for the rest: CUBIC congestion control, path MTU discovery (from 1200 bytes, probing up; enabled only where the platform keeps datagrams from being fragmented), 8-byte connection IDs, and passive connection migration. A migrated connection keeps the `ConnectionEndpoint` of its handshake address.

## Basic usage

```rust
use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::Ed25519Keypair;
use minip2p_platform::{Clock, StdClock};
use minip2p_quic::{QuicNodeConfig, QuicTransport};
use minip2p_transport::{Bytes, Transport, TransportEvent};

let loopback: Multiaddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse()?;

let listener_key = Ed25519Keypair::generate();
let mut listener =
    QuicTransport::bind(QuicNodeConfig::new(listener_key.clone()), &[loopback.clone()])?;
let listen_addrs = listener.listen_on_bound_addrs()?;

let mut dialer = QuicTransport::bind(QuicNodeConfig::generate(), &[loopback])?;
let peer_addr = PeerAddr::new(listen_addrs[0].clone(), listener_key.peer_id())?;
let conn_id = dialer.dial(&peer_addr)?;

// Drive both ends until the handshake completes; a real host waits on
// on its shared readiness poll and `next_deadline()` between polls.
let mut clock = StdClock::new();
let mut connected = false;
while !connected {
    let now = clock.now();
    listener.poll(now)?;
    connected = dialer
        .poll(now)?
        .iter()
        .any(|event| matches!(event, TransportEvent::Connected { id, .. } if *id == conn_id));
}

let stream_id = dialer.open_stream(conn_id)?;
dialer.send_stream(conn_id, stream_id, Bytes::from_static(b"hello"))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Scope

This crate is a concrete transport adapter and depends on `std`. For Sans-I/O contracts and shared types, use `minip2p-transport`.

## Clocks

The engine runs every connection timer (loss detection, PTO, pacing, idle timeout and keepalive) on the `Instant` the adapter passes it. Each `poll(now)` samples `Instant::now()` once, alongside the host's `Now`, and hands that one instant to every engine call in the poll; calls made between polls (`dial` and the stream and connection operations) sample their own. The host's millisecond `Now` is never handed to the engine as time: on low-RTT paths it is too coarse, so the adapter keeps a fine-grained clock of its own and is `std`-only.

Nothing on that clock leaks into what the host sees:

- `poll(now)` retains the host sample together with its `Instant`, purely to map engine timeouts onto the host's timeline. `next_deadline()` measures the delay to the earliest timeout from the poll's `Instant` and adds it to the poll's `Now`, so a host driving several transports can still compare their deadlines.
- Sub-millisecond delays (common on loopback) are rounded _up_ to a whole millisecond rather than truncated to zero. Truncation would report "already due" and spin a driver's budget loop until wall time caught up.
- Buffered events and a receive batch cut off by its bound report `Deadline::IMMEDIATE`. Datagrams retained on `WouldBlock`, and connections whose last service left work, report one millisecond after the last sample (`IMMEDIATE` before the first poll), so the driver retries the flush soon.

Two wall-clock reads remain, neither on the connection timers:

- Retry tokens are issued and expired on the engine's `TimeSource`, quinn's system-time default.
- Certificate validity is checked against the host's wall-clock time (`Now::unix_seconds` from the last poll, falling back to the system clock when absent).

## Routing

Datagrams route by destination connection ID only, never by source address, so peers sharing an address (e.g. behind one NAT) cannot receive each other's packets. On a listening socket, the engine answers a short-header packet with an unknown connection ID with a rate-limited stateless reset (RFC 9000 §10.3). A socket that is not listening sends no stateless reply of any kind (no reset, no Retry, no version negotiation), while outbound connections on it work as usual.

## Socket I/O

Each socket is driven through quinn-udp, which uses what the platform offers:

- **GSO.** One transmit carries up to 10 datagrams of one segment size, quinn's own cap; larger trains arrive as bursts a receiver's socket buffer drops. Where the platform refuses a segmented send (`EIO`/`EINVAL` on Linux), quinn-udp sends single datagrams from then on. The refused batch is treated as lost, and loss recovery resends it.
- **GRO.** One receive buffer holds a full GRO batch, which is split into its datagrams by stride.
- **ECN** codepoints are read and set, and **packet info** gives the local address a datagram was sent to, so a reply leaves from that address.

Limits count logical datagrams, never transmits: `QuicLimits::max_pending_datagrams` bounds the individual UDP datagrams retained after `WouldBlock`, and the receive bound counts each segment of a GRO batch. Before each transmit the engine is asked for at most what the platform can segment and the retry queue could still keep; when the queue is full it is not asked for output at all. A transmit is retained only when every one of its datagrams fits, and a retained transmit never lets a later one overtake it. A GRO batch already read is always split to the end, so a receive batch can overshoot its bound by less than one GRO batch.

A hard send error drops that datagram as lost: loss recovery resends what mattered, and a path that stays dead ends in the idle timeout. Only a dial whose first flight the socket refuses outright fails at once. A receive error fails `poll()`, and the events already queued are kept for the next call.

`send_datagram` is a plain single-datagram send from the socket of the target's family, for NAT hole punching (DCUtR): it leaves from the socket later QUIC packets will arrive on.

Dropping the transport sends every connection's CONNECTION_CLOSE at once, since nothing polls afterwards.

## Diagnostics

The off-by-default `diagnostics` feature compiles in counters for comparing fast and slow runs. Without it they do not exist and their recording hooks are empty.

- `QuicTransport::connection_diagnostics(id)` returns a live connection's `ConnectionDiagnostics`: datagrams routed to it, flushes (passes that asked the engine for output, from any trigger), and the engine's own figures from quinn's connection stats: UDP datagrams and bytes it produced (sent, or retained for a writable socket), packets it declared lost, the current congestion window and the smoothed RTT. `flushes_per_datagram()` and `average_datagram_bytes()` derive ratios from them.
- Each connection prints its totals to stderr when dropped, as `minip2p-quic diagnostics <id>: ...`, so a host can compare runs without reading them through the transport.
- `datagram_counters(&peer_id)` returns the `DatagramCounters` of every live transport bound with that identity, both address families together: datagrams and bytes the sockets actually sent or received, each GSO or GRO segment counted once. A datagram retained on `WouldBlock` counts once it leaves. Any thread can read them; `DatagramCounters::since` subtracts an earlier snapshot.

`minip2p-rs`'s `bench` feature enables this for the `endpoint_throughput` bench. An application enables it by naming the feature on its own `minip2p-quic` dependency.

## Authentication Notes

- QUIC handshakes require mutual TLS. Custom rustls verifiers check the peer inside the handshake: it must present exactly one certificate, that certificate must pass libp2p verification by `minip2p-tls`, and the TLS 1.3 CertificateVerify signature must check against the certificate's own key. A dial also requires the certificate to prove the `PeerId` it named.
- A rejected peer gets a TLS alert, which aborts the handshake on both ends, so `Connected` is never emitted. The local side reports `Error` (carrying the rustls error text) then `Closed`. minip2p releases on the earlier quiche engine closed with application codes `0x01`–`0x04` instead.
- Certificate validity is checked against the host's wall-clock time (`Now::unix_seconds` from the last poll, falling back to the system clock when absent), so a badly wrong clock makes peers' certificates look expired or not yet valid.
- `minip2p-tls` verifies Ed25519 and ECDSA P-256 host keys; secp256k1 and RSA peers are rejected.
- `IncomingConnection` is pre-auth and is emitted when the engine accepts an Initial, before the handshake completes. Treat `Connected` or `PeerIdentityVerified` as the authenticated connection signal.
