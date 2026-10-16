# minip2p-tcp

`minip2p-tcp` is the libp2p TCP transport: multistream-select, Noise XX, and Yamux over an ordered byte stream, exposed as a regular minip2p `Transport`.

It owns no socket, no clock, and no executor. Byte streams come from a `TcpProvider`, and everything above that seam is portable:

```text
TcpTransport            connection + stream ids, the Transport contract
  -> SecureMuxSession   multistream-select, Noise XX, Yamux
  -> TcpProvider        sockets, listeners, name resolution
```

That split is the point: the same transport runs on hosted sockets and on an embedded network stack, and only the provider changes. `no_std + alloc`; disable default features and supply a provider and an `EntropySource`.

## Providers

`StdTcpProvider` is the hosted one: OS sockets driven by `mio`. It takes `/ip4` and `/ip6` addresses only and rejects `/dns*`, because a name lookup would block the driver thread; the std `minip2p` `Endpoint` resolves names off its driver, and direct users resolve them first. It owns no poll of its own: it is a `PollSource` that registers its listeners and sockets with the host's one shared readiness poll, which is what makes `TcpTransport` (which forwards `attach` and `dispatch` to it) a `BlockingTransport`, so an idle std swarm parks on TCP and every other source at once. Registration tokens are recycled once their socket is deregistered and are kept apart from `SocketHandle`s, which are never reused, so a stale event for a recycled token can at most mark the new socket possibly ready. After `dispatch` it reads each ready socket until `WouldBlock`, and work its per-poll budgets leave behind keeps `next_deadline()` immediate. Before it is attached, every poll treats every socket as possibly ready, so a host that only polls still makes progress. It disables Nagle's algorithm because delayed small writes add latency to the multiplexed protocol frames. It needs the `std` feature (on by default).

`SmoltcpTcpProvider` is the embedded one, over [smoltcp] — a TCP/IP stack, not an operating system. It needs the `smoltcp` feature and nothing else: the host builds the `Interface` and supplies the link, and this drives sockets on it. `/ip4` and `/ip6` only, since resolving a name is I/O it does not do.

smoltcp is timer-driven, so `next_deadline` matters more here than it does with readiness: honouring it is what lets a device sleep between packets instead of polling to find out nothing happened. A poll takes a bounded number of packets off the link and reports immediate when more are waiting, so a flood cannot hold one open on a host that has nothing to preempt it. Listeners are told apart by address as well as port, so two addresses may name one port; a wildcard is what takes a port outright, since it answers for every address on it. A wildcard listener reports every address the interface holds, and its address revision moves when the host changes them through the shared stack, so the swarm re-advertises without another `listen`.

Hosts with neither implement `TcpProvider` over their own stack. Nothing above the seam changes: the transport, the session, and the upgrade are the same code either way, and each provider is covered by its own suite — a virtual link for the transport's own behaviour, loopback sockets for `StdTcpProvider`, and a frame-queue link for `SmoltcpTcpProvider`.

[smoltcp]: https://docs.rs/smoltcp

## Writing a provider

A provider hands out ordered, reliable byte streams and reports what it observed through `TcpEvent`. It speaks `/tcp` multiaddrs rather than platform socket types, which is what keeps the transport portable — interpreting a `/dns*` host is a provider's job, because resolution is I/O. Both bundled providers reject names.

Three details are easy to get wrong, and the transport depends on all three:

- **Short writes are normal.** `send` returns how many leading bytes were accepted, and accepting none is valid. The transport keeps the remainder and retries; it never assumes a whole buffer went out.
- **`Connected` gates writability.** A handle from `connect` is not writable until its `TcpEvent::Connected` is polled.
- **`Closed` is terminal, and `abort` is silent.** A handle is never reused, and after `abort` the provider emits nothing further for it — the caller asked for the teardown and needs no confirmation.

Failures are a typed `TcpError`: `Address` for an address the provider cannot use, `Io { operation, kind, detail }` for a platform failure (a `TcpIoOperation` and a portable `IoErrorKind`, so `no_std` and hosted providers report the same kinds), `UnknownSocket`, and `Exhausted`. `TcpError` converts into `TransportError` (`Io` stays `TransportError::Io`), and a failed bind in `TcpTransport::listen` is `TransportError::ListenFailed { addr, kind, detail }`.

`TcpProvider`'s rustdoc has the full contract. `TcpEvent::Writable` is a hint rather than a requirement: the transport retries buffered writes on every `poll`, so a provider whose readiness reporting is coarse still drains.

## Backpressure

Reading is backpressured through Yamux (ADR 0012): a substream's window update is sent only for bytes acknowledged with `ack_stream`, flushed at once, so a reader that never acknowledges stalls its sender at one receive window. A closed substream with unacknowledged bytes keeps its slot until it settles, so stream churn cannot grow retained data past the stream limit times the window.

The transport pulls encrypted bytes from a connection's session only while that connection's outbound buffer is below `TcpConfig::max_buffered_send` (a soft limit: one pull may overshoot it by one encrypted frame), so a slow reader is backpressure, not a fault: stream writes fill Yamux's send caps and then return `TransportError::Full` with the unsent tail, and `StreamWritable` follows once Yamux has room again (ADR 0012). Pulling frames into the outbound buffer is what frees Yamux's caps, so it can fire while ciphertext still waits in that buffer for the socket. While the socket is still accepting, `next_deadline` reports immediate so a driver keeps coming back. Once it refuses everything, that becomes the point at which the stall turns fatal instead — claiming urgency against a socket taking nothing would spin a deadline-driven host for as long as the peer stayed silent. `TcpConfig::max_buffered_send` bounds how much may queue and `TcpConfig::send_stall_timeout_ms` how long the socket may accept nothing at all, so a peer that stops reading for good loses its connection rather than pinning memory.

## Poll cost

A `poll` costs what has work, not how many connections are open. The transport services only connections a provider event touched, ones with buffered bytes to retry, ones driven since the last poll, and ones whose authentication, keepalive, or stall deadline has come; deadlines sit in an ordered set, so `next_deadline` reads the earliest instead of walking every connection. `StdTcpProvider` likewise visits only sockets that `mio` reported readable or that are still connecting. The `readiness_poll` bench measures both: the provider with every socket or just one ready, and the transport with one upgraded connection or none active (`cargo bench -p minip2p-tcp --bench readiness_poll`).

## Limits

A connection costs a session — Noise state, a Yamux session, whatever is buffered — from the moment the byte stream comes up, which is well before the peer has proved who it is. `TcpConfig::max_connections` bounds how many exist at once: a dial past it fails the caller, and an inbound one is dropped where it stands, because nothing has been announced about it to report against. A connection that ends while some of its streams still hold delivered, unacknowledged bytes keeps its slot until they are acknowledged or abandoned (`ack_stream` and `reset_stream` still settle its streams after `Closed`), so reconnect churn against a slow reader stays bounded (ADR 0012); with every slot held, dials fail with `ResourceExhausted` and inbound connections are refused.

Every `TcpTransport` also has a TCP memory budget (ADR 0021), `TcpConfig::memory_budget_bytes`, covering all its listeners. It caps the transport's retained payload: queued sends (counted twice for slice pinning), receive windows, decoder backlogs and output backlogs. Container overhead, allocator slack, temporary copies and the provider's socket buffers are not counted.

- **Fixed part:** `TcpConfig::connection_reservation_bytes()` = `SecureMuxSession::fixed_reservation_bytes(&yamux)` (twice Yamux's total send cap, the session's write queue, its decoders and the control replies a peer may provoke) + `max_buffered_send` + one Noise message a pull may overshoot it by. Reserved from the dial or accept until teardown drops the session.
- **Per stream:** `TcpConfig::stream_reservation_bytes()` = the Yamux receive window, from open or admission until the stream settles: closed, and its delivered bytes acknowledged or abandoned, also after its connection ended.

What does not fit is refused, never queued: a dial or `open_stream` fails with `ResourceExhausted { resource: "TCP memory budget" }` (and Yamux's stream limit with `"Yamux streams"`), an inbound connection is aborted at accept like one past `max_connections`, and an inbound stream is reset. The session feeds provider reads to its decoders in batches of at most 64 KiB, so a provider handing over large reads cannot grow them past the fixed part. The defaults (2,432 KiB windows, 1 GiB) admit 68 connections with one stream each: 12.64 MiB fixed plus the window is 15 MiB. `TcpTransport::with_config` checks the limits (`TcpConfig::validate`) and returns `InvalidLimit` for a budget that cannot fit one connection and one stream; a zero `max_buffered_send` stays valid. `TcpTransport::memory_reserved()` reports what is reserved now.

A ceiling alone would not hold, though — a peer that completes the TCP handshake and then says nothing keeps its slot for as long as the socket lives, so a few silent peers could fill the ceiling and keep it full. `TcpConfig::handshake_timeout_ms` is what stops that, measured from the first `poll` that sees the connection rather than from the call that made it: the transport owns no clock, so between polls the only time it holds is the last poll's, and after an idle spell that is arbitrarily long ago.

## Identity

The upgrade authenticates both ends, so `Connected` always carries a verified peer id, plus the Noise handshake hash as its `ConnectionToken` — the same value on both ends. A dial additionally pins the expected identity from its `PeerAddr`: a remote that proves a different one fails the handshake instead of connecting.
