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

## Identity

The upgrade authenticates both ends, so `Connected` always carries a verified
peer id. A dial additionally pins the expected identity from its `PeerAddr`: a
remote that proves a different one fails the handshake instead of connecting.
