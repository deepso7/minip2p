# tests

Shared test code that lives outside any one crate. Each crate's own tests stay in the crate: inline `#[cfg(test)]` modules, `src/*_tests.rs`, and `tests/`.

## `interop/`

Interop against foreign libp2p implementations. Three local gates (go-libp2p over TCP, and the Circuit Relay v2 clients of rust-libp2p and go-libp2p) need Go or a network build, so they are `#[ignore]`d and run through `just interop-go`, `just interop-relay-rust` and `just interop-relay-go`; see [`interop/README.md`](interop/README.md). `unified-testing/` is the standalone TCP and QUIC app libp2p's external transport interop harnesses run; see its own README.

## `support/`

Helpers that crate tests compile in with `#[path = "…"]`, since they are not a crate:

| File | What it holds | Included by |
| --- | --- | --- |
| `endpoint.rs` | `NextEvent::next_event` over `Endpoint::wait`, and a check for a stranger's handshake failure. Timing rules for networked tests live in `.config/nextest.toml`. | `bulk_backpressure`, `discovery`, `mdns`, `nat`, `pubsub`, `reconnect_churn`, `relay_go_interop`, `relay_mesh`, `relay_rust_interop`, `relay_server`, `simultaneous_dial` and `webtransport` in `crates/minip2p/tests/` |
| `relay.rs` | A loopback Circuit Relay v2 service built from public `minip2p` APIs. | `crates/minip2p/src/std/nat_tests.rs`, `crates/minip2p/tests/nat.rs`, `crates/ffi/tests/relayed.rs`, `examples/chat/tests/chat.rs` |
| `relay_interop.rs` | Minip2p relays driven against a foreign relay client process. | `crates/minip2p/tests/relay_rust_interop.rs`, `relay_go_interop.rs` |
