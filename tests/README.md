# tests

Shared test code that lives outside any one crate. Each crate's own tests stay in the crate (`src/*_tests.rs` and `tests/`).

## `interop/`

Opt-in gates against foreign libp2p implementations: go-libp2p over TCP, and the Circuit Relay v2 clients of rust-libp2p and go-libp2p. They need Go or a network build, so they are `#[ignore]`d and run through `just interop-go`, `just interop-relay-rust` and `just interop-relay-go`. See [`interop/README.md`](interop/README.md).

## `support/`

Helpers that crate tests compile in with `#[path = "…"]`, since they are not a crate:

| File | What it holds | Included by |
| --- | --- | --- |
| `endpoint.rs` | `NextEvent::next_event` over `Endpoint::wait`, and a check for a stranger's handshake failure. Its header states the timing rules every networked test follows. | `crates/minip2p/tests/*` |
| `relay.rs` | A loopback Circuit Relay v2 service built from public `minip2p` APIs. | `crates/minip2p/src/std/nat_tests.rs`, `crates/minip2p/tests/nat.rs`, `crates/ffi/tests/relayed.rs`, `examples/chat/tests/chat.rs` |
| `relay_interop.rs` | Minip2p relays driven against a foreign relay client process. | `crates/minip2p/tests/relay_rust_interop.rs`, `relay_go_interop.rs` |
