# minip2p-tcp

`minip2p-tcp` is the libp2p TCP transport: multistream-select, Noise XX, and
Yamux over an ordered byte stream, exposed as a regular minip2p `Transport`.

It owns no socket, no clock, and no executor. Byte streams come from a
`TcpProvider`, and everything above that seam is portable:

```text
TcpTransport            connection + stream ids, the Transport contract
  -> SecureMuxSession   multistream-select, Noise XX, Yamux
  -> TcpProvider        sockets, listeners, name resolution
```

That split is the point: the same transport runs on hosted sockets and on an
embedded network stack, and only the provider changes. `no_std + alloc`; disable
default features and supply a provider and an `EntropySource`.

## Providers

`StdTcpProvider` is the hosted one: OS sockets driven by `mio`, `/dns*`
resolution, and a real readiness wait. Implementing `BlockingTcpProvider` is
what makes `TcpTransport` a `BlockingTransport`, so an idle driver parks on the
sockets rather than polling on a timer. It disables Nagle's algorithm because
delayed small writes add latency to the multiplexed protocol frames. It needs
the `std` feature (on by default).

`SmoltcpTcpProvider` is the embedded one, over [smoltcp] — a TCP/IP stack, not
an operating system. It needs the `smoltcp` feature and nothing else: the host
builds the `Interface` and supplies the link, and this drives sockets on it.
`/ip4` and `/ip6` only, since resolving a name is I/O it does not do.

smoltcp is timer-driven, so `next_deadline` matters more here than it does with
readiness: honouring it is what lets a device sleep between packets instead of
polling to find out nothing happened. A poll takes a bounded number of packets
off the link and reports immediate when more are waiting, so a flood cannot hold
one open on a host that has nothing to preempt it. Listeners are told apart by
address as well as port, so two addresses may name one port; a wildcard is what
takes a port outright, since it answers for every address on it.

Hosts with neither implement `TcpProvider` over their own stack. Nothing above
the seam changes: the transport, the session, and the upgrade are the same code
either way, and each provider is covered by its own suite — a virtual link for
the transport's own behaviour, loopback sockets for `StdTcpProvider`, and a
frame-queue link for `SmoltcpTcpProvider`.

[smoltcp]: https://docs.rs/smoltcp

## Writing a provider

A provider hands out ordered, reliable byte streams and reports what it observed
through `TcpEvent`. It speaks `/tcp` multiaddrs rather than platform socket
types, which is what keeps the transport portable — interpreting a `/dns*` host
is a provider's job, because resolution is I/O.

Three details are easy to get wrong, and the transport depends on all three:

- **Short writes are normal.** `send` returns how many leading bytes were
  accepted, and accepting none is valid. The transport keeps the remainder and
  retries; it never assumes a whole buffer went out.
- **`Connected` gates writability.** A handle from `connect` is not writable
  until its `TcpEvent::Connected` is polled.
- **`Closed` is terminal, and `abort` is silent.** A handle is never reused, and
  after `abort` the provider emits nothing further for it — the caller asked for
  the teardown and needs no confirmation.

`TcpProvider`'s rustdoc has the full contract. `TcpEvent::Writable` is a hint
rather than a requirement: the transport retries buffered writes on every
`poll`, so a provider whose readiness reporting is coarse still drains.

## Backpressure

A session produces bytes whether or not the socket will take them, so the
transport buffers per connection. While the socket is still accepting,
`next_deadline` reports immediate so a driver keeps coming back. Once it refuses
everything, that becomes the point at which the stall turns fatal instead —
claiming urgency against a socket taking nothing would spin a deadline-driven
host for as long as the peer stayed silent. `TcpConfig::max_buffered_send`
bounds how much may queue and `TcpConfig::send_stall_timeout_ms` how long it may
sit there, so a peer that stops reading for good loses its connection rather
than pinning memory.

## Limits

A connection costs a session — Noise state, a Yamux session, whatever is
buffered — from the moment the byte stream comes up, which is well before the
peer has proved who it is. `TcpConfig::max_connections` bounds how many exist
at once: a dial past it fails the caller, and an inbound one is dropped where it
stands, because nothing has been announced about it to report against.

A ceiling alone would not hold, though — a peer that completes the TCP handshake
and then says nothing keeps its slot for as long as the socket lives, so a few
silent peers could fill the ceiling and keep it full.
`TcpConfig::handshake_timeout_ms` is what stops that, measured from the first
`poll` that sees the connection rather than from the call that made it: the
transport owns no clock, so between polls the only time it holds is the last
poll's, and after an idle spell that is arbitrarily long ago.

## Identity

The upgrade authenticates both ends, so `Connected` always carries a verified
peer id. A dial additionally pins the expected identity from its `PeerAddr`: a
remote that proves a different one fails the handshake instead of connecting.
