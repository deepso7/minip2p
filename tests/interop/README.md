# Live libp2p interoperability

The Go peer in `go-libp2p/` is an independent wire implementation used by an
opt-in minip2p integration test. Run it with:

```bash
just interop-go
```

The gate proves one real connection in the supported TCP stack:

```text
TCP -> multistream-select -> Noise XX -> Yamux
```

It then asserts the go-libp2p Identify snapshot and advertised echo protocol,
an explicit Ping round trip, and `/minip2p/interop/echo/1.0.0`. Minip2p dials
first and exchanges bytes on a locally initiated stream. That connection is
closed; the test requires a new inbound connection id before accepting a
remotely initiated echo stream from go-libp2p. This pins both handshake roles
and both stream directions against go-libp2p v0.48.0 rather than pairing
minip2p with itself.

The shape follows the process-oriented model of `@libp2p/interop`, but the
upstream package's current matrices cannot directly express this participant:
its node types are JS and Go, its stream suite requires key/security/muxer
combinations minip2p intentionally does not implement, and its transport list
does not include QUIC. Keeping this gate focused avoids treating unsupported
combinations as interoperability coverage.

The test is ignored by ordinary `cargo test` because it requires Go and owns a
separate Go module. Its dependencies are pinned in `go.mod` and `go.sum`.

## Still separate

QUIC interoperability needs its own live gate: the upstream interop package
does not currently cover QUIC; it covers TCP, WebTransport, and WebRTC Direct.
