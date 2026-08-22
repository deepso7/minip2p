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

## Circuit Relay v2 against rust-libp2p

Run `just interop-relay-rust` to start a minip2p TCP relay and two independent
rust-libp2p clients. The foreign Cargo project is outside the workspace and pins
`libp2p-relay` 0.22 at rust-libp2p commit
`170c3c81ddd80e7c58b0500563e00a09139e8545`; the audited Circuit Relay v2
specification commit is `6b6203ee6f62938ce67efdb33498173f475851c0`.

The gate requires a reservation, the relay's Identify HOP advertisement, HOP
CONNECT and STOP establishment, and successful ping traffic (bytes accepted in
both directions). It configures non-default duration and byte limits and asserts
that rust-libp2p decodes the exact values on RESERVE and both circuit legs.
Successful reservation proves rust-libp2p accepts minip2p's `voucher: None`.
The gate does not assert deliberate minip2p deviations as upstream parity. It
is ignored in ordinary tests because it downloads/builds the pinned foreign
implementation and owns loopback sockets.

Recorded environment/result: macOS arm64, Rust stable 1.91-compatible toolchain,
`just interop-relay-rust`: success (2026-08-20).

## Still separate

QUIC interoperability needs its own live gate: the upstream interop package
does not currently cover QUIC; it covers TCP, WebTransport, and WebRTC Direct.
