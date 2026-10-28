# Changelog

Breaking changes and their migrations. Release notes for each tag are generated on GitHub.

## Unreleased

### Endpoint setup: one place for capabilities (#432)

The std `Endpoint` and `PortableEndpoint` now validate, register and install capabilities through the same Endpoint setup, so a configuration behaves alike on both. Breaking changes:

- **Cargo features: one name per capability, the same on every platform.** `nat` and every `portable-*` name are gone:

  | Was | Now |
  | --- | --- |
  | `nat` | `relay` (AutoNAT alone: `autonat`) |
  | `portable-autonat` | `autonat` |
  | `portable-relay` | `relay` |
  | `portable-mdns` | `mdns` |

  Features imply only what they depend on: `relay` implies `autonat`, `discovery` implies `pubsub`, and `mdns` brings the shared peer book. `mdns` and `discovery` no longer imply NAT or `std`; add `relay` (or `autonat`) to keep dialing discovered peers through the NAT connect race. `relay-server` no longer requires `std`, and the relay server runs on `PortableEndpoint` too (`PortableEndpointBuilder::relay_server`, `relay_server_config`, `PortableEndpoint::set_relay_server_accepting`). `std`, `quic`, `tcp` and `smoltcp` only choose platform adapters. With `mdns` compiled in, `PortableEndpoint` holds its carrier as a `Box<dyn MdnsIo>` and is not `Send`, now also in std builds.
- **Stricter std validation.** `EndpointBuilder::bind` runs the portable builder's NAT checks before any socket opens and reports them as `BindError::NatConfig(NatConfigError)`: an explicit NAT config with no relay and no AutoNAT server is refused (with no NAT config, discovery and mDNS turn NAT on for the peers they find), a reservation policy other than `Never` without a relay is refused, and relays with DCUtR on an endpoint built without `quic` are refused (set `NatConfig::dcutr = false` or `force_relay`). `PortableNatConfigError` is renamed `NatConfigError`.
- **`.autonat_server()` holds no reservation by default.** Without an explicit `nat_config` or a relay, the std endpoint's NAT config uses `ReservationPolicy::Never`, as portable `.autonat()` already did.
- **Protocols are advertised only when configured.** A capability's protocols are registered, and advertised through Identify, only when its configuration uses them: STOP and HOP-outbound with relays, DCUtR with relays on std with QUIC, AutoNAT with AutoNAT servers. A discovery- or mDNS-only std endpoint no longer advertises HOP, STOP or DCUtR.
- **Seeds come from the entropy source.** Gossipsub, mDNS and NAT jitter seeds are drawn from the endpoint's entropy source, never the clock or the keypair. A failing source fails the build: `BindError::Entropy` on std, `PortableBuildError::Entropy` on portable.
- **New error variants.** `BindError::Entropy`, `BindError::NatConfig` and `BindError::Discovery`; `PortableBuildError::RelayServer` and `PortableBuildError::RelayServerAnnounce`.
