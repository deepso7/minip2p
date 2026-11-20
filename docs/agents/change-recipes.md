# Change recipes

Where a cross-layer change lands, and the narrowest check that covers it. Finish with `just test` and `just clippy full`.

| Change | Touch | Check |
| --- | --- | --- |
| Endpoint capability or Cargo feature | The protocol crate; the feature in `crates/minip2p/Cargo.toml`; `Capabilities`, `validate` and `install` in `crates/minip2p/src/setup.rs`; its place in `Engine::drive` (`engine.rs`, whose order is load-bearing); setters on `std/builder.rs` and `portable/mod.rs`; a row in `scripts/run-feature-matrix.sh`, and `scripts/check-targets.sh` if it builds for no_std or has docs; `crates/ffi-core/src/config.rs` if bindings expose it. | `just matrix clippy <row>`, `just check-nostd` |
| `EndpointEvent` variant | `SwarmEvent` (`crates/swarm/src/events.rs`) if the swarm raises it; `EndpointEvent` (`crates/minip2p/src/portable/event_stream.rs`); `P2pEvent` and `convert_endpoint_event` (`crates/ffi-core/src/events.rs`); `P2pEvent` and the named event map in `bindings/ts/core/src/types.ts`; if it names a connection, the carry's elision rules (`crates/ffi-core/src/carry.rs`, `UNSEEN_CONNECTION_TAGS` in `bindings/ts/core/src/sdk.ts`); `pnpm rn:generate`, and `ENUM_FIELDS` in `bindings/ts/react-native/src/adapter.ts` if it carries a flat enum. | `cargo test -p minip2p-ffi-core`, `just bindings-check` |
| Binding method or config field | The `Endpoint` method (`crates/minip2p`); `P2pEndpoint` (`crates/ffi-core/src/endpoint.rs`) or `config.rs`; the forwarders in `crates/ffi/src/endpoint.rs`, `crates/nodejs/src/lib.rs`, and `crates/web/src/{host,wasm}.rs`; `Minip2pBackend` in `bindings/ts/core/src/backend.ts` and `sdk.ts`; the node, react-native and web adapters; `bindings/ts/test-fixtures/src/adapter-contract.ts`. | `just bindings-check`, `just check-wasm` |
