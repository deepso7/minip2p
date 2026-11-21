# Endpoint engine: ordering within a swarm-event batch, and what its drivers consume

The Endpoint engine in `minip2p-rs` (`engine.rs`: `ingest`, `close_stream_write`, `tick_mdns`; `setup.rs`) feeds each swarm event through several owners, and the order matters:

- **Punch refinement brackets the Connection engine.** The swarm reports a replaced connection's punch as `Direct`. `ingest` refines `old_path` before the event reaches NAT (which forgets `old`'s punch on this event) and `new_path` after (once NAT has recorded `new`'s punch).
- **The write queue sees every swarm event, claimed or not.** A connection a driver claims can still end streams the write queue holds bytes for, so `Writes::observe` runs regardless of `consumed`.
- **NAT output is routed after every event**, so Connection attempts see NAT output in step with the swarm event that caused it.
- **A FIN clears any pending writable.** No `StreamWritable` follows a FIN, so `close_stream_write` drops a waiting bare writer and any `StreamWritable` still queued for the stream; delivering it would tell the application to resend after the FIN.
- **mDNS on a shared transport re-ingests it.** The mDNS carrier drives the shared interface, which may have put bytes into a socket after the transport was serviced, so `tick_mdns` ingests the transport again.
- **Relay-server listener addresses are derived, and rejections are events.** `set_listener_addrs` is called with addresses from the bound transport at setup and on every address refresh; a rejected source keeps its previous addresses and the agent queues `AddrsRejected` (later `AddrsRestored`), drained with the next batch, so the returned error is dropped rather than failing setup or the drive.
- **DCUtR is registered only when the agent will run it** (`dcutr && !force_relay && platform.runs_dcutr`): a forced relay never upgrades.
- **Auto-NAT from discovery needs no server; explicit NAT does.** Only the NAT that discovery turns on goes without an AutoNAT server; an explicit `NatConfig` with none is rejected (`NatConfigError::NoServers`).

## NAT seeds its listen addresses only after a real listen

Setup gives `NatAgent::new` no listen addresses. The NAT host (`NatDriver`) starts with `listen_addrs_revision` at 0 and syncs the agent's listen addresses (`sync_listen_addrs`) only once a real `listen*` call (or `bind`, which already accepts on the QUIC socket) has bumped the transport's revision. Some transports report bound-but-not-listening sockets from `local_addresses`; syncing on an untouched revision would offer AutoNAT a dial-back address that drops packets. This matches a fresh runtime.

`tick` syncs the listen addresses before it checks whether the agent has due work, not after: the seed is what arms AutoNAT's probe timers, so gating it on a due deadline would keep the tick returning early forever.

## Outcomes the discovery driver ignores

In `crates/minip2p/src/discovery.rs`:

- **mDNS `Failed` and `Recovered` are not handled by the discovery book.** The engine reports mDNS health to the application itself (`EndpointEvent::MdnsFailed`), so the book only consumes peer observations and protocol violations.
- **A refused local publish of the signed beacon is dropped.** The beacon is periodic, so its next tick retries; queueing or reporting the refusal would only duplicate that.
