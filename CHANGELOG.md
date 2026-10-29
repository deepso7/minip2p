# Changelog

Breaking changes and their migrations. Release notes for each tag are generated on GitHub.

## Unreleased

### Relay server drives the swarm through `RelaySwarm` (#443)

`RelayServerAgent` now runs its commands on a borrowed swarm instead of emitting tokenized actions, as `NatAgent` does with `NatSwarm`. Breaking changes for direct `minip2p-relay-server` users (the `Endpoint` API is unchanged):

- **`handle_event(swarm, event, is_circuit, now)` and `handle_tick(swarm, now)`** take a `&mut impl RelaySwarm`, implemented for `SwarmCore`. A host on another swarm implements its six methods; `ack_stream` returns nothing, so absorb a stream already gone there.
- **`RelayServerAction`, `RelayServerToken`, `RelayServerSendError`, `poll_action`, `is_idle`, and the four `*_result` methods are gone.** Each command's result is applied before the call returns; a forwarding write refused as `DriverError::Full` is held until the stream's `StreamWritable`, as before.
- **`set_connection_addr` is gone.** The agent reads each new connection's remote address from `RelaySwarm::connection_remote_addr`.
- **STOP opens settle from swarm events.** Stop correlating them in the host: the agent settles each from its `StreamReady`, `StreamClosed`, or negotiation `SwarmEvent::Error` (claiming those events), and resets a STOP stream it gave up while it negotiated once it is ready. STOP readiness or acceptance exactly at the circuit's deadline now times the circuit out.

### NAT promotes relay bridges through `NatSwarm` (#442)

A bridged relay stream now goes straight to the host's circuit transport through the swarm seam instead of an action and a token round-trip. Breaking changes for direct `minip2p-nat` users (the `Endpoint` API is unchanged):

- **`NatSwarm::promote_bridge(BridgeHandoff, now_ms) -> Result<ConnectionId, PromoteError>`** is new. It defaults to resetting the bridge stream and refusing, so a host without circuits needs no change; a host that adopts bridges implements it with what it used to run for `PromoteBridge`. `BridgeHandoff` carries the fields the action did, minus the token.
- **`NatAction::PromoteBridge` and `NatAgent::promote_result` are gone.** Tails the agent held for the bridge are in `BridgeHandoff::unsent_data` when the call reaches the host.

### Endpoint builders record intent; Endpoint setup applies NAT defaults (#439)

The std, portable and smoltcp builders now only record what you configure. Endpoint setup picks every NAT default and merges the relay and AutoNAT lists, and every capability is checked at build. Breaking changes:

- **Renames and signature changes:**

  | Builder | Was | Now |
  | --- | --- | --- |
  | `PortableEndpointBuilder`, `SmoltcpEndpointBuilder` | `autonat(server)` | `autonat_server(server)` |
  | `PortableEndpointBuilder`, `SmoltcpEndpointBuilder` | `beacon_config(config)` | `discovery_config(config)` |
  | `PortableEndpointBuilder` | `connect_deadline_ms(u64)` | `connect_deadline(Duration)` |
  | `PortableEndpointBuilder` | `simultaneous_dial_window_ms(u64)` | `simultaneous_dial_window(Duration)` |
  | `SmoltcpEndpointBuilder` | (none) | `connect_deadline(Duration)`, `simultaneous_dial_window(Duration)` |
  | `EndpointBuilder` | `discovery_config(..) -> Result<Self, DiscoveryConfigError>` | `discovery_config(..) -> Self` |
  | `EndpointBuilder` | `peer_discovery_config(..) -> Result<Self, DiscoveryConfigError>` | `peer_discovery_config(..) -> Self` |
  | `EndpointBuilder` | `mdns_config(..) -> Result<Self, MdnsConfigError>` | `mdns_config(..) -> Self` |
  | `EndpointBuilder` | `relay_server_config(..) -> Result<Self, RelayServerConfigError>` | `relay_server_config(..) -> Self` |

  `Duration` is `core::time::Duration` (the same type as `std::time::Duration`). The std setters no longer validate eagerly: an invalid config fails `bind` with `BindError::Discovery`, `BindError::Mdns` or `BindError::RelayServer`, still before any socket opens. Drop the `?` / `.expect(..)` after those calls.

- **Portable and smoltcp `.relay(addr)` no longer forces relay-only.** `.relay` now means the same on every endpoint: a relay is a path raced against direct candidates, not a mode. Without `nat_config`, a portable endpoint with a relay runs the default policy with `dcutr = false`, so it now **reserves on the relay by default while reachability is not public, including while it is `Unknown`** (with or without AutoNAT servers). For the old behaviour, ask for it explicitly: `.nat_config(NatConfig { force_relay: true, reservation_policy: ReservationPolicy::Never, ..NatConfig::default() })` next to `.relay(addr)`.
- **`nat_config` is a base the list setters add to, in any order.** On portable and smoltcp, `.relay(a).nat_config(c)` used to drop `a`; now, as on std, the base keeps its policy and tuning fields as given, and its relay and AutoNAT lists come first, followed by the setters' addresses in call order, without exact repeats. A second `nat_config` call replaces the first, while `relay` and `autonat_server` add to each other. The merged config is what setup validates, so `.nat_config(NatConfig { force_relay: true, .. }).relay(a)` binds in either order.

### Endpoint setup: one place for capabilities (#432)

The std `Endpoint` and `PortableEndpoint` now validate, register and install capabilities through the same Endpoint setup, so a configuration behaves alike on both. Breaking changes:

- **Cargo features: one name per capability, the same on every platform.** `nat` and every `portable-*` name are gone:

  | Was                | Now                                |
  | ------------------ | ---------------------------------- |
  | `nat`              | `relay` (AutoNAT alone: `autonat`) |
  | `portable-autonat` | `autonat`                          |
  | `portable-relay`   | `relay`                            |
  | `portable-mdns`    | `mdns`                             |

  Features imply only what they depend on: `relay` implies `autonat`, `discovery` implies `pubsub`, and `mdns` brings the shared peer book. `mdns` and `discovery` no longer imply NAT or `std`; add `relay` (or `autonat`) to keep dialing discovered peers through the NAT connect race. `relay-server` no longer requires `std`, and the relay server runs on `PortableEndpoint` too (`PortableEndpointBuilder::relay_server`, `relay_server_config`, `PortableEndpoint::set_relay_server_accepting`). `std`, `quic`, `tcp` and `smoltcp` only choose platform adapters. With `mdns` compiled in, `PortableEndpoint` holds its carrier as a `Box<dyn MdnsIo>` and is not `Send`, now also in std builds.

- **Stricter std validation.** `EndpointBuilder::bind` runs the portable builder's NAT checks before any socket opens and reports them as `BindError::NatConfig(NatConfigError)`: an explicit NAT config with no relay and no AutoNAT server is refused (with no NAT config, discovery and mDNS turn NAT on for the peers they find), a reservation policy other than `Never` without a relay is refused, `force_relay` without a relay is refused (`NatConfigError::ForceRelayWithoutRelay`, on `PortableEndpoint` too; it used to be ignored, so connects dialed direct candidates), and relays with DCUtR on an endpoint built without `quic` are refused (set `NatConfig::dcutr = false` or `force_relay`). `PortableNatConfigError` is renamed `NatConfigError`.
- **`.autonat_server()` holds no reservation by default.** Without an explicit `nat_config` or a relay, the std endpoint's NAT config uses `ReservationPolicy::Never`, as portable `.autonat()` already did.
- **Protocols are advertised only when configured.** A capability's protocols are registered, and advertised through Identify, only when its configuration uses them: STOP and HOP-outbound with relays, DCUtR with relays on std with QUIC, AutoNAT with AutoNAT servers. A discovery- or mDNS-only std endpoint no longer advertises HOP, STOP or DCUtR.
- **Seeds come from the entropy source.** Gossipsub, mDNS and NAT jitter seeds are drawn from the endpoint's entropy source, never the clock or the keypair. A failing source fails the build: `BindError::Entropy` on std, `PortableBuildError::Entropy` on portable.
- **New error variants.** `BindError::Entropy`, `BindError::NatConfig` and `BindError::Discovery`; `PortableBuildError::RelayServer` and `PortableBuildError::RelayServerAnnounce`.
