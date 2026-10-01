# @minip2p/core

Platform-neutral TypeScript SDK for [minip2p](https://minip2p.com).

Applications normally install a platform package such as `@minip2p/react-native`, which provides the native backend and re-exports these public types. Adapter authors can implement the small contract from `@minip2p/core/backend`.

The API provides typed events, cancellable Promise operations, and `Stream` handles:

```ts
const path = await endpoint.connect(remoteAddress);
// Optional: wait for Identify when you need advertised protocols.
await endpoint.waitPeerReady(path.peerId);
const rttMs = await endpoint.ping(path.peerId);

const stream = await endpoint.openStream(path.peerId, "/example/files/1");
stream.write(new Uint8Array([1, 2, 3]));
stream.closeWrite();
```

Streams are async iterables. Iteration preserves chunk order, drains bytes buffered before a remote write half-close, and then ends quietly. Local shutdown, reset, peer disconnect, connection replacement, or driver failure rejects the iterator with its terminal error:

```ts
for await (const chunk of stream) {
  process(chunk);
}
```

`endpoint.events()` returns an async iterable of endpoint events. Each iterator has a bounded, drop-oldest buffer. It reports dropped events in-band as `queueOverflow` events. The default cap is 4096; pass `bufferCap` to change it or `signal` to end iteration on abort.

```ts
for await (const event of endpoint.events({ signal })) {
  if (event.type === "peerReady") {
    console.log(event.peerId);
  }
}
```

A peer holds one connection at a time. `connectionEstablished` and `connectionClosed` mark the peer connecting and disconnecting; when a newer connection takes the peer's slot, a single `connectionReplaced` (`{ peerId, old, new }`) stands in for both, the peer stays connected, and streams and pending opens on `old` end with `StreamClosedError`. `peerReady` carries the `connId` that completed Identify and fires once per connection. `waitPeerReady` follows the peer's current connection, so a stale `peerReady` for a replaced connection never resolves it; it resolves at once when `connectionInfo(peerId).readyProtocols` shows the current connection is already ready, and rejects with `PeerDisconnectedError` when that connection closes.

`connect` accepts a Connection target: a peer ID, one complete peer multiaddress, or a list of complete addresses naming one peer. For a Connection attempt, a timeout ends only the local wait (`cancelOnTimeout: true` opts into cancelling), an aborted `signal` cancels the attempt (the wait settles from its terminal), and a terminal lost to event overflow rejects with `ConnectResultLostError`. Waits never stop unrelated events from reaching other subscribers.

Use `endpoint.on("stream", handler)` to claim inbound streams. Operations accept `{ timeoutMs, signal }`; the default timeout is 65 seconds and `timeoutMs: 0` disables it. Both endpoints and streams implement `Symbol.dispose`, including the fallback used by `await using`; neither implements `Symbol.asyncDispose`.

Raw native unions, the `Minip2pBackend` adapter contract, `resolveEndpointConfig` (shared config defaults and validation), and `typedFfiError` (native `FfiError` variant name to typed SDK error) are available from `@minip2p/core/backend`.
