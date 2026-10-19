# minip2p-quic

Synchronous QUIC transport adapter for minip2p, on the [quinn-proto](https://github.com/quinn-rs/quinn) engine with [rustls](https://github.com/rustls/rustls) (`ring` provider) for libp2p TLS and [quinn-udp](https://crates.io/crates/quinn-udp) for socket I/O.

No async runtime required. quinn-proto owns no sockets and no clock: the adapter feeds it datagrams and a time sample, and sends what it produces. The host drives the transport by calling `poll(now)` with its own time sample.

## Features

- Implements `minip2p_transport::Transport` and the std `BlockingTransport` wait.
- One `QuicTransport` over one or two non-blocking UDP sockets, at most one per IP family, served by one quinn-proto endpoint. `QuicTransport::bind(config, &addrs)` binds one socket per socket address named, at most one IPv4 and one IPv6 (an IPv6 socket is IPv6-only). Each address is `/ip4|ip6/<ip>/udp/<port>/quic-v1`, served to libp2p peers, or `…/quic-v1/webtransport`, served to WebTransport clients ([ALPN dispatch](#alpn-dispatch-and-webtransport)); naming both shapes on one socket address serves both there; `QuicTransport::dual_stack(config)` binds an IPv4 and an IPv6 wildcard socket. Both return `QuicBindError` on failure: `InvalidLimit` (a `QuicLimits` field out of range, naming it), `InvalidAddress` and `AddressFamilies` are configuration mistakes caught before any socket is bound; `Certificate` (the typed `minip2p_tls::TlsError`) and `Tls` (naming the `QuicTlsStage` that failed) are TLS setup failures; `Socket` is the platform refusing a UDP socket, with its `IoErrorKind` (`AddrInUse`, say). Each transmit leaves from the socket of its destination's family. Every socket has its own connection namespace and retry queue; `QuicLimits::max_connections` counts across all of them.
- Connection lifecycle events (`IncomingConnection`, `Connected`, `PeerIdentityVerified`, `Closed`).
- Native QUIC stream operations: `open_stream`, `send_stream`, `close_stream_write`, `reset_stream`, `ack_stream`.
- Stream events (`StreamOpened`, `IncomingStream`, `StreamData`, `StreamWritable`, `StreamRemoteWriteClosed`, `StreamWriteStopped`, `StreamClosed`). Data always precedes the FIN, reset or `StreamClosed` of its stream, and nothing follows a stream's `StreamClosed`.
- Read backpressure (ADR 0012): the engine returns flow-control credit as bytes are read, so the transport stops reading a stream once it has delivered `QuicLimits::stream_receive_window` bytes that were not acknowledged with `ack_stream`. Acknowledging re-reads that stream at once, without waiting for another packet. Stream and connection windows are fixed at their initial size, so the engine buffers at most one more window behind the gate. A FIN or reset right behind a spent budget still surfaces. Each read is copied into a buffer of exactly its length, so delivered data never pins a larger packet allocation. A closed stream with unacknowledged bytes keeps its slot, and new peer streams past `max_streams_per_connection` are refused (stopped and reset, with no event) until it settles. The bound outlives the connection: an ended connection with unsettled streams keeps their counts and its slot against `max_connections` until they settle, and `ack_stream` and `reset_stream` still settle them after `Closed`, without credit or events, so close-and-reconnect churn cannot grow what a slow reader holds.
- Write backpressure (ADR 0012): `send_stream` takes what the engine accepts now plus what fits both the stream's queue (`QuicLimits::max_pending_bytes_per_stream`, 256 KiB) and the connection's (`max_pending_connection_bytes`, 1 MiB), whatever the peer's credit, and returns `TransportError::Full` with the exact unsent tail for the rest. Neither cap counts quinn's own send buffer. A stream stalled on the peer's credit therefore fills only its own share, and `control_stream_reserve_bytes` (256 KiB) of the connection cap is kept for streams marked with `Transport::set_control_stream`: the swarm marks its negotiation, ping and Identify streams, so application streams cannot starve them. `StreamWritable` fires for an armed stream once it can queue half the smaller of its stream cap and the connection cap it may fill (all of it for a control stream, all but the reserve otherwise; a control stream needs at most half a non-zero reserve, the room it may be left). The per-stream cap bounds each stalled stream, not their number: enough stalled streams can still fill the application share, though control streams keep their reserve. Queued bytes enter the engine round-robin, 64 KiB per stream per turn, from a cursor that persists between drains, so backlogged streams share scarce connection credit; while any stream has bytes queued, a new write queues behind them instead of going straight to the engine. `open_stream` succeeds below the local stream limit even while the peer has granted no stream credit: the stream's writes and FIN queue until the engine can open it.
- Stream errors stay stream-scoped: a peer's STOP_SENDING resets the stream's send half, drops its queued writes and emits `StreamWriteStopped` while the read half stays open; writes waiting on peer credit stay queued; any other engine stream error hit while draining closes only its connection, with a `Closed` whose reason is `Error`.
- Close semantics: every connection ends with one `Closed` carrying its `ConnectionCloseReason`: `Local` after `close` (or anything else ended on our side), `Remote { code }` for the peer's CONNECTION_CLOSE (its application or transport error code; minip2p closes with application code 0), `TimedOut` for an idle timeout (also while handshaking), and `Error(message)` for the rest: a stateless reset, a TLS rejection, a local protocol or stream failure. No separate `Error` event precedes it.
- Mutual libp2p TLS peer authentication inside the handshake (see [Authentication Notes](#authentication-notes)). `QuicNodeConfig` is identity-first: constructing a transport requires an Ed25519 host keypair.
- A `ConnectionToken` on the established endpoint: 32 bytes of TLS exporter output (label `minip2p quic connection token`, empty context), which both ends of one session derive identically. minip2p releases on the earlier quiche engine derived the token from connection IDs instead, so a mixed-version pair computes different tokens (ADR 0014).
- Dial and `send_datagram` accept `/ip4` and `/ip6` QUIC transport addresses only, of a family with a bound socket. The transport never resolves names, because a blocking lookup would stall every connection on the driver thread: a `/dns*` address is rejected with `TransportError::InvalidAddress`. The std `minip2p` `Endpoint` resolves `/dns*` candidates off its driver thread; direct transport users resolve names themselves first.
- `local_addresses()` reports each socket in the shapes it was bound with: `/…/quic-v1`, then `/…/quic-v1/webtransport/certhash/<k>/certhash/<k+1>` (the current and next [certificate periods](#certificate-rotation)). `listen` takes either shape of a bound socket (a WebTransport one with or without certhashes, which are ignored) and returns it with the current certhashes; a shape the socket was not bound with is `InvalidAddress`.
- Native WebTransport dialing is not implemented: `dial` refuses a WebTransport address with `TransportError::Unsupported`, pointing at the `/quic-v1` address. The Endpoint's connect treats that as one failed candidate and keeps racing the rest. `minip2p_webtransport::WebTransportClient` is the dialer, for browsers.
- QUIC deadlines are exposed through `Transport::next_deadline()` and processed by `poll()`; no async runtime or hidden timer thread is used. It owns no poll of its own: as a `PollSource` it registers a clone of each socket with the host's one shared readiness poll (a std `Swarm` attaches it when built), so an idle host blocks on both families and every other source at once. A host must still dispatch the poll's events to it: `dispatch` records that readiness arrived and keeps `next_deadline()` immediate until the next `poll()`, so a host that skips this transport's poll for a turn (a `TransportSet` handing over held-back events first) cannot park on an edge that will not come again. Every `poll()` reads every socket until `WouldBlock`, through the registered socket so mio re-arms readiness on every platform, and a receive batch cut off by its bound reports `next_deadline()` as immediate, as do buffered events, so calls made between polls -- `listen`, `open_stream`, and the stream operations -- never leave a host asleep on an undelivered event. Unattached (driven by a `SwarmCore` host), it behaves the same; only the wakeups are the host's to arrange.
- Quiet connections send an ack-eliciting packet at half `idle_timeout_ms` (15 s by default) so NAT bindings and the peer's idle timer stay warm without an application ping. A dead path still idle-times out, after roughly the keepalive interval plus the idle timeout.
- Only connections with work are serviced in a `poll`: those it routed datagrams to, those whose engine timer is due (kept in an ordered timer index), and those a previous service left unfinished. Each receive batch is handed to the engine first, and each serviced connection then sends its output once. Every stream or connection call also services its own connection, so its output leaves without waiting for the next poll.
- Each socket reads at most 128 logical datagrams per `poll`, so a packet flood cannot starve connection timers. A batch that hits the bound makes `next_deadline()` report `Deadline::IMMEDIATE`.
- Windows (ADR 0022): `QuicLimits::stream_receive_window`, `connection_receive_window` and `send_window` default to quinn's own: a 1,250,000-byte stream window, an unlimited connection window (`usize::MAX`, or any value past what QUIC can express, 2^62 - 1, is unlimited), and a 10,000,000-byte send window. Hosts raise or lower them by hand. With the connection window unlimited, one stalled stream cannot spend the credit the others need, but nothing bounds a connection's received data in aggregate except twice `max_streams_per_connection` (local and peer streams are limited separately) times two stream windows (one delivered and unacknowledged, one the engine buffers behind it). Memory is bounded by counts, windows and queues; there is no memory budget. Full and Writable stay per connection.
- Inbound admission, in order: on a socket that is not listening, nothing is accepted and nothing is sent in reply; at `max_connections` an Initial is ignored silently, before any Retry; with `require_address_validation` (the default), a stateless Retry validates the source address before any connection state is allocated. Retry tokens are valid for 10 s, and no NEW_TOKEN is issued, so Retry is the only validation path. Configurable limits bound connections, streams, queued bytes per stream and per connection, queued UDP datagrams, and idle time.

### Transport parameters

Every value the adapter relies on is set explicitly:

- stream receive window `QuicLimits::stream_receive_window` (1,250,000 bytes) and connection receive window `connection_receive_window` (unlimited), both fixed; send window `send_window` (10,000,000 bytes). These are quinn's own defaults (ADR 0022); the `endpoint_rtt` window sweeps in `minip2p-rs` measure other values on an emulated link (#361);
- `max_streams_per_connection` concurrent bidirectional streams, and no unidirectional streams (libp2p uses only bidirectional ones);
- QUIC DATAGRAM is not advertised;
- idle timeout `idle_timeout_ms` (0 is rejected, because QUIC reads it as "no timeout"), keepalive at half of it;
- TLS 1.3 only, ALPN `libp2p`, no session resumption.

A socket that also serves WebTransport ([ALPN dispatch](#alpn-dispatch-and-webtransport)) differs in two parameters, for every connection to it (the server config is chosen per socket, before ALPN): three peer unidirectional streams (HTTP/3's control and QPACK streams, RFC 9114 §6.2), and the QUIC DATAGRAM parameter with a 16 KiB receive buffer (Firefox requires it; received datagrams are drained and dropped). Its TLS offers ALPN `libp2p` and `h3`, or only `h3` on a socket bound for WebTransport alone. Other sockets keep the parameters above exactly.

quinn-proto's own defaults stand for the rest: CUBIC congestion control, path MTU discovery (from 1200 bytes, probing up; enabled only where the platform keeps datagrams from being fragmented), 8-byte connection IDs, and passive connection migration. A migrated connection keeps the `ConnectionEndpoint` of its handshake address.

## Basic usage

```rust
use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::Ed25519Keypair;
use minip2p_core::platform::{Clock, StdClock};
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
// its shared readiness poll and `next_deadline()` between polls.
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

- **Socket buffers.** `SO_SNDBUF` and `SO_RCVBUF` are raised toward a fixed 4 MiB, best effort and with no knob: a size the platform refuses is halved and retried, one it caps (Linux, at `net.core.wmem_max`/`rmem_max`) is kept as granted, and a size below the current one is never asked for (a Linux host whose default exceeds its `*mem_max` cap still ends up at the cap). The `diagnostics` feature reports what was granted.

- **Apple fast datapath.** On every Apple target, iOS included, quinn-udp's `fast-apple-datapath` sends and receives through the private `sendmsg_x`/`recvmsg_x`, batching up to 10 datagrams per send like GSO, and up to 32 per receive call. quinn-udp resolves both symbols through `dlsym` and falls back to `sendmsg`/`recvmsg` where either is missing. quinn-udp 0.6.3 does not report a short `sendmsg_x`, so a batch the socket only partly takes counts as sent (`DatagramCounters` included) and its tail is recovered as loss; the grown send buffer keeps this rare. Enabling it is the crate's only `unsafe` call. Apps distributed through the App Store take on the private-API review risk.
- **GSO.** One transmit carries up to 10 datagrams of one segment size, quinn's own cap; larger trains arrive as bursts a receiver's socket buffer drops. Where the platform refuses a segmented send (`EIO`/`EINVAL` on Linux), quinn-udp sends single datagrams from then on. The refused batch is treated as lost, and loss recovery resends it.
- **GRO and batched receives.** Where the platform has GRO, a receive call fills one buffer with a full GRO batch, which is split into its datagrams by stride. Elsewhere, a call offers quinn-udp's `BATCH_SIZE` slots (32 with `recvmmsg` or `recvmsg_x`; where a platform reads one datagram per call, it fills only the first), one datagram each, sized to the endpoint's maximum UDP payload; a larger datagram, which no peer honouring that advertised maximum sends, arrives truncated and is dropped. Either way, what one call read is copied into a single allocation that every datagram from it shares. Delivered stream data is copied out, but a chunk the engine still buffers (unread, or out of order) keeps that whole allocation alive while the engine counts only its own packet, so it can pin up to one call's worth: 32 datagrams, or one GRO batch of up to 64.
- **ECN** codepoints are read and set, and **packet info** gives the local address a datagram was sent to, so a reply leaves from that address.

Limits count logical datagrams, never transmits: `QuicLimits::max_pending_datagrams` bounds the individual UDP datagrams retained after `WouldBlock`, and the receive bound counts each segment of a GRO batch. Before each transmit the engine is asked for at most what the platform can segment and the retry queue could still keep; when the queue is full it is not asked for output at all. A transmit is retained only when every one of its datagrams fits, and a retained transmit never lets a later one overtake it. What one receive call read is always handled to the end, so a receive batch can overshoot its bound by less than one call's worth (a GRO batch, or up to 32 datagrams).

A hard send error drops that datagram as lost: loss recovery resends what mattered, and a path that stays dead ends in the idle timeout. Only a dial whose first flight the socket refuses outright fails at once. A receive error fails `poll()` with `TransportError::Io` (operation and `IoErrorKind`), and the events already queued are kept for the next call.

`send_datagram` is a plain single-datagram send from the socket of the target's family, for NAT hole punching (DCUtR): it leaves from the socket later QUIC packets will arrive on.

Dropping the transport sends every connection's CONNECTION_CLOSE at once, since nothing polls afterwards.

## Diagnostics

The off-by-default `diagnostics` feature compiles in counters for comparing fast and slow runs. Without it they do not exist and their recording hooks are empty.

- `QuicTransport::connection_diagnostics(id)` returns a live connection's `ConnectionDiagnostics`: datagrams routed to it, flushes (passes that asked the engine for output, from any trigger), and the engine's own figures from quinn's connection stats: UDP datagrams and bytes it produced (sent, or retained for a writable socket), packets it declared lost, the current congestion window and the smoothed RTT. `flushes_per_datagram()` and `average_datagram_bytes()` derive ratios from them.
- Each connection prints its totals to stderr when dropped, as `minip2p-quic diagnostics <id>: ...`, so a host can compare runs without reading them through the transport.
- `datagram_counters(&peer_id)` returns the `DatagramCounters` of every live transport bound with that identity, both address families together: datagrams and bytes the sockets actually sent or received, each GSO or GRO segment counted once, and the receive calls that read them. A datagram retained on `WouldBlock` counts once it leaves. Any thread can read them; `DatagramCounters::since` subtracts an earlier snapshot.
- `socket_buffers(&peer_id)` returns the `SocketBuffers` the OS granted that identity's sockets (the smallest per direction, since the first live transport with it was bound), as the OS reports them: Linux reports twice the size set.

`minip2p-rs`'s `bench` feature enables this for the `endpoint_throughput` bench. An application enables it by naming the feature on its own `minip2p-quic` dependency.

## Authentication Notes

- QUIC handshakes require mutual TLS for `libp2p` (on a WebTransport-serving socket, enforced once ALPN is known; see [ALPN dispatch](#alpn-dispatch-and-webtransport)). Custom rustls verifiers check the peer inside the handshake: it must present exactly one certificate, that certificate must pass libp2p verification by `minip2p-tls`, and the TLS 1.3 CertificateVerify signature must check against the certificate's own key. A dial also requires the certificate to prove the `PeerId` it named.
- A rejected peer gets a TLS alert, which aborts the handshake on both ends, so `Connected` is never emitted. The local side reports `Closed` with an `Error` reason carrying the rustls error text. minip2p releases on the earlier quiche engine closed with application codes `0x01`–`0x04` instead.
- Certificate validity is checked against the host's wall-clock time (`Now::unix_seconds` from the last poll, falling back to the system clock when absent), so a badly wrong clock makes peers' certificates look expired or not yet valid.
- `minip2p-tls` verifies Ed25519 and ECDSA P-256 host keys; secp256k1 and RSA peers are rejected.
- `IncomingConnection` is pre-auth and is emitted when the engine accepts an Initial, before the handshake completes. Treat `Connected` or `PeerIdentityVerified` as the authenticated connection signal.
- Stream events are gated on authentication: no peer stream is accepted before `Connected` (one opened in the same flight as the client's Finished waits in the engine and surfaces after `Connected`, or goes with a connection that fails). After a local `close` or a failed authentication, new peer streams are refused and data on existing ones is discarded, so only `Closed` follows. A refused bidirectional stream gets STOP_SENDING and RESET_STREAM; a peer's unidirectional stream gets STOP_SENDING only, since it has no local send half (quinn-proto asserts on resetting one).

## ALPN dispatch and WebTransport

A socket bound with a `/…/quic-v1/webtransport` address serves `h3`; nothing serves `h3` by default. On a socket bound with both shapes, each connection picks its protocol by ALPN, the server's order winning, so a client offering both gets `libp2p`; a socket bound for WebTransport alone offers only `h3`:

- The certificate is chosen by ALPN: a client offering `libp2p` gets the libp2p certificate, any other client the current WebTransport certificate (`minip2p_tls::webtransport`, for the current [period](#certificate-rotation); an X.509v3 ECDSA P-256 leaf without the libp2p extension, loaded through rustls's checked `CertifiedKey::from_der`). Its certhash is the first one the WebTransport address carries.
- Client certificates are optional on that socket, because browsers send none. A presented certificate is still fully verified inside the handshake. The libp2p requirement moves to the end of the handshake: a `libp2p` connection without a verified peer certificate is closed before any `Connected`.
- An `h3` connection runs a libp2p WebTransport session (draft-02) before it is reported; see [WebTransport sessions](#webtransport-sessions).
- Every connection to the socket carries the [two extra transport parameters](#transport-parameters); a libp2p peer that opens a unidirectional stream there gets STOP_SENDING and nothing is surfaced.

## Certificate rotation

WebTransport certificates rotate every 13-day period (`minip2p_tls::webtransport::PERIOD_SECS`), on the host's wall clock: each poll's `Now::unix_seconds`, or the system clock while the host supplies none (and at bind). During period `k` the listener presents certificate `k`, its addresses carry the certhashes of `k` and `k+1`, and its Noise extensions list `k-1`, `k` and `k+1`, so an address learned in the previous period still dials. Certificates derive from the host key, so a restarted node presents the same ones.

`next_deadline` includes the next period boundary. The first poll whose clock is in another period (a boundary, or a clock jump either way, with no stepwise catch-up) swaps the certificate the TLS resolver presents, recomputes the certhashes, bumps `local_addresses_revision`, and emits `Listening` for each listening WebTransport address in its new form. Live connections are unaffected: the certificate only matters during a handshake. The swarm turns those `Listening` events into one `SwarmEvent::ListenAddressesChanged`.

## WebTransport sessions

From QUIC's handshake on, an `h3` connection's endpoint reads `/…/quic-v1/webtransport` (a browser's address, without a certhash), so Identify's observed address and `active_inbound_connection_sources` never offer it to hole punching or NAT candidates, which take `is_quic_transport()` addresses only. Its session then runs inside the connection (`src/webtransport.rs`, on `minip2p-webtransport`'s codec):

1. The server opens its control stream with SETTINGS: draft-02's `ENABLE_WEBTRANSPORT` with extended CONNECT and HTTP datagrams, draft-13/14's `WT_MAX_SESSIONS` and `WT_INITIAL_MAX_*` (as webtransport-go sends them), and no QPACK settings, so peers use only the static table. It reads the client's control stream (SETTINGS first) and QPACK streams; push, WebTransport uni and unknown uni streams get STOP_SENDING.
2. The first request stream is the CONNECT. Once the client's SETTINGS offer WebTransport, `CONNECT` with `:protocol webtransport` to `/.well-known/libp2p-webtransport?type=noise` gets `:status 200`; a wrong path gets 404 and anything else 400, which finishes the CONNECT stream and closes the session the orderly way (below), so the status reaches the client.
3. The first stream with the session's `0x41` prefix runs Noise XX as responder; its extensions list the previous, current and next periods' certhashes. On completion the peer id is set, the connection token is the Noise handshake hash (which the client derives too), `Connected` and `PeerIdentityVerified` are emitted, and the Noise stream is finished. It is never surfaced.
4. Every later prefixed bidi stream surfaces as `IncomingStream`; one naming another session is refused. Stream prefixes stay internal: an inbound prefix is read a byte at a time before admission, so it never counts against the receive budget, and a local stream queues its prefix ahead of the caller's bytes, outside `send_room` and any `Full { unsent }`.

Prefixed streams that arrive before the session is authenticated -- the Noise stream racing the 200, or streams racing Noise -- are held, their data left in the engine, and admitted in order; more than four fail the connection with `H3_EXCESSIVE_LOAD`. HTTP/3 validation beyond the above, the pre-auth limits and handshake deadline are not implemented yet.

**Close.** A local `close` of an accepted session enters a Closing phase rather than closing QUIC at once (which would drop the capsule): it sends `CLOSE_WEBTRANSPORT_SESSION` (code 0) in a DATA frame, finishes the CONNECT stream and resets every open stream. QUIC then closes with `H3_NO_ERROR` once the client finishes or resets its side of the CONNECT stream, or after `max(3 × RTT, 500 ms)` capped at 2 s. A client's close capsule, CONNECT FIN or reset, or GOAWAY ends the session the same way: the server finishes its side and closes after the same wait, and `Closed` reports `Remote { code }` with the capsule's code (0 otherwise). A client's QUIC close with `H3_NO_ERROR` is `Remote { code: 0 }` too. During Closing no stream events surface and new client streams are refused; only the CONNECT stream is still read. `Closed` follows once QUIC drains, as for any connection.

**Stream error codes.** minip2p's reset and stop code 0 goes on the wire as WebTransport application error 0 (`0x52e4a40fa8db`). A client's STOP_SENDING code in the WebTransport range is reported in `StreamWriteStopped` as the WebTransport code it carries; codes outside the range pass through unchanged.

