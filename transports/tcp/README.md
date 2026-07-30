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

`TcpProvider`'s rustdoc has the full contract. Providers that report writability
only coarsely still work: the transport retries buffered writes on every `poll`,
not only on `TcpEvent::Writable`.

## Backpressure

A session produces bytes whether or not the socket will take them, so the
transport buffers per connection. While anything is buffered, `next_deadline`
reports immediate, so a driver keeps coming back instead of sleeping. A peer that
stops reading altogether is bounded by `TcpConfig::max_buffered_send`, which
fails that connection rather than growing without limit.

## Identity

The upgrade authenticates both ends, so `Connected` always carries a verified
peer id. A dial additionally pins the expected identity from its `PeerAddr`: a
remote that proves a different one fails the handshake instead of connecting.
