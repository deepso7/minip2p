//! [`EndpointBuilder`]: one builder for every platform, like
//! [`Endpoint`](crate::Endpoint) itself (ADR 0029).
//!
//! The options every endpoint shares live in the non-generic
//! [`CommonBuilder`], so their setters are compiled once however many
//! platforms a program builds; the type parameter carries only what one
//! platform adds (`StdBuilderState`, [`PortableBuilderState`],
//! [`SmoltcpBuilderState`](crate::SmoltcpBuilderState)), and the methods
//! only that platform has are implemented on it.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;

use minip2p_core::platform::EntropySource;
use minip2p_identity::Ed25519Keypair;
use minip2p_swarm::{SwarmBuilder, SwarmCore, SwarmTimeouts};
use minip2p_transport::Transport;

#[cfg(feature = "discovery")]
use crate::BeaconConfig;
#[cfg(feature = "pubsub")]
use crate::GossipsubConfig;
#[cfg(feature = "autonat")]
use crate::NatConfig;
#[cfg(feature = "_peer-book")]
use crate::PeerDiscoveryConfig;
#[cfg(feature = "relay-server")]
use crate::RelayServerConfig;
use crate::engine::{Carrier, Engine};
use crate::portable::{DEFAULT_CONNECT_DEADLINE_MS, DriverError, StreamAcks};
use crate::protocols::ProtocolTable;
use crate::setup::Capabilities;
use crate::writes::WriteQueue;
#[cfg(feature = "autonat")]
use minip2p_core::PeerAddr;

/// The Identify `agentVersion` an endpoint advertises unless told otherwise.
pub(crate) const DEFAULT_AGENT_VERSION: &str = concat!("minip2p/", env!("CARGO_PKG_VERSION"));

/// Builder state every endpoint shares. Not generic, so the setters that
/// write it are compiled once however many platforms a program builds.
pub(crate) struct CommonBuilder {
    pub(crate) agent_version: String,
    pub(crate) timeouts: SwarmTimeouts,
    simultaneous_dial_window_ms: u64,
    connect_deadline_ms: u64,
    pub(crate) write_budget: usize,
    /// Application protocols, each once, in first-registration order: the
    /// order their handles number them in.
    protocols: Vec<String>,
    /// The registered protocols whose data the application acknowledges
    /// itself.
    manual_ack_protocols: Vec<String>,
    /// Capability intent for Endpoint setup, which applies the defaults.
    pub(crate) capabilities: Capabilities,
}

impl Default for CommonBuilder {
    fn default() -> Self {
        Self {
            agent_version: DEFAULT_AGENT_VERSION.to_string(),
            timeouts: SwarmTimeouts::default(),
            simultaneous_dial_window_ms: minip2p_swarm::SIMULTANEOUS_DIAL_WINDOW_MS,
            connect_deadline_ms: DEFAULT_CONNECT_DEADLINE_MS,
            write_budget: crate::DEFAULT_WRITE_BUDGET,
            protocols: Vec::new(),
            manual_ack_protocols: Vec::new(),
            capabilities: Capabilities::default(),
        }
    }
}

impl CommonBuilder {
    pub(crate) fn set_simultaneous_dial_window(&mut self, window: Duration) {
        self.simultaneous_dial_window_ms = duration_ms(window);
    }

    pub(crate) fn set_connect_deadline(&mut self, deadline: Duration) {
        self.connect_deadline_ms = duration_ms(deadline);
    }

    /// Registers an application protocol; a repeat keeps its first place.
    pub(crate) fn protocol(&mut self, protocol_id: String) {
        if !self.protocols.contains(&protocol_id) {
            self.protocols.push(protocol_id);
        }
    }

    /// Registers an application protocol whose data the application
    /// acknowledges itself.
    pub(crate) fn manual_ack_protocol(&mut self, protocol_id: String) {
        if !self.manual_ack_protocols.contains(&protocol_id) {
            self.manual_ack_protocols.push(protocol_id.clone());
        }
        self.protocol(protocol_id);
    }

    #[cfg(feature = "relay-server")]
    pub(crate) fn relay_server(&mut self, config: Option<RelayServerConfig>) {
        let setup =
            self.capabilities
                .relay_server
                .get_or_insert_with(|| crate::setup::RelayServerSetup {
                    config: RelayServerConfig::default(),
                    announce_addrs: Vec::new(),
                });
        if let Some(config) = config {
            setup.config = config;
        }
    }

    #[cfg(feature = "pubsub")]
    pub(crate) fn gossipsub(&mut self, config: Option<GossipsubConfig>) {
        match config {
            Some(config) => self.capabilities.gossipsub = Some(config),
            None => {
                self.capabilities
                    .gossipsub
                    .get_or_insert_with(GossipsubConfig::default);
            }
        }
    }

    #[cfg(feature = "discovery")]
    pub(crate) fn discovery(&mut self, config: BeaconConfig) {
        self.gossipsub(None);
        self.capabilities.beacon = Some(config);
    }

    /// The application protocols, in registration order.
    #[cfg(feature = "std")]
    pub(crate) fn protocols(&self) -> &[String] {
        &self.protocols
    }

    /// Splits the options into the swarm builder they configure for
    /// `keypair` and what the engine needs once that swarm is built, with
    /// protocol handles numbered in registration order. Take the
    /// capabilities out first; they go to Endpoint setup.
    pub(crate) fn into_parts(
        self,
        keypair: &Ed25519Keypair,
    ) -> Result<(SwarmBuilder, EngineParts), DriverError> {
        let mut acks = StreamAcks::default();
        for protocol in self.manual_ack_protocols {
            acks.set_manual(protocol, []);
        }
        let mut table = ProtocolTable::default();
        let mut swarm = SwarmBuilder::new(keypair)
            .agent_version(self.agent_version)
            .simultaneous_dial_window_ms(self.simultaneous_dial_window_ms)
            .timeouts(self.timeouts);
        for protocol in self.protocols {
            table.intern(&protocol)?;
            swarm = swarm.protocol(protocol);
        }
        let parts = EngineParts {
            connect_deadline_ms: self.connect_deadline_ms,
            write_budget: self.write_budget,
            acks,
            protocols: table,
        };
        Ok((swarm, parts))
    }
}

/// Builder for an [`Endpoint`](crate::Endpoint) on any platform.
///
/// `Endpoint::builder()` starts the std one, which binds its own sockets;
/// [`PortableEndpointBuilder::new`](crate::PortableEndpointBuilder::new)
/// starts one over a caller-supplied transport, entropy and clock, and its
/// `smoltcp` step one over an embedded smoltcp stack. The setters every
/// platform shares are below; each platform's own are on its state type.
#[cfg(feature = "std")]
pub struct EndpointBuilder<K = crate::StdBuilderState> {
    pub(crate) common: CommonBuilder,
    pub(crate) state: K,
}

/// Builder for an [`Endpoint`](crate::Endpoint) on any platform.
///
/// [`PortableEndpointBuilder::new`](crate::PortableEndpointBuilder::new)
/// starts one over a caller-supplied transport, entropy and clock, and its
/// `smoltcp` step one over an embedded smoltcp stack. The setters every
/// platform shares are below; each platform's own are on its state type.
#[cfg(not(feature = "std"))]
pub struct EndpointBuilder<K> {
    pub(crate) common: CommonBuilder,
    pub(crate) state: K,
}

impl<K> EndpointBuilder<K> {
    /// Overrides the Identify `agentVersion` string. Default
    /// `minip2p/<crate version>`.
    pub fn agent_version(mut self, value: impl Into<String>) -> Self {
        self.common.agent_version = value.into();
        self
    }

    /// Registers an application protocol before the endpoint starts. A
    /// repeat keeps the handle numbering of its first registration.
    ///
    /// Built-in ids ([`RESERVED_PROTOCOL_IDS`](crate::RESERVED_PROTOCOL_IDS))
    /// are reserved; registering one fails the build with
    /// [`SwarmError::ReservedProtocol`](crate::SwarmError::ReservedProtocol).
    pub fn protocol(mut self, protocol_id: impl Into<String>) -> Self {
        self.common.protocol(protocol_id.into());
        self
    }

    /// Registers an application protocol whose received data the
    /// application acknowledges itself, with
    /// [`Endpoint::stream_consumed`](crate::Endpoint::stream_consumed) (see
    /// [`Endpoint::add_manual_ack_protocol`](crate::Endpoint::add_manual_ack_protocol)).
    pub fn manual_ack_protocol(mut self, protocol_id: impl Into<String>) -> Self {
        self.common.manual_ack_protocol(protocol_id.into());
        self
    }

    /// Sets the Connection-attempt deadline. Default 30 seconds.
    pub fn connect_deadline(mut self, deadline: Duration) -> Self {
        self.common.set_connect_deadline(deadline);
        self
    }

    /// Sets how long a peer's new connection can lose a race to its current
    /// one. Default 5 seconds
    /// ([`SIMULTANEOUS_DIAL_WINDOW_MS`](minip2p_swarm::SIMULTANEOUS_DIAL_WINDOW_MS)).
    ///
    /// Both peers settle a race on their own, so they should use the same
    /// window. A shorter one lets a peer that reconnects after its old
    /// connection died silently get back in sooner, at the cost of settling
    /// slow candidate races less reliably.
    pub fn simultaneous_dial_window(mut self, window: Duration) -> Self {
        self.common.set_simultaneous_dial_window(window);
        self
    }

    /// Overrides the negotiation, first-Identify and ping deadlines
    /// (default [`SwarmTimeouts::default`]: 30 s, 30 s and 10 s). A zero
    /// deadline fails the build with
    /// [`SwarmError::ZeroTimeout`](crate::SwarmError::ZeroTimeout), on std
    /// before any socket is bound. See the crate README's deadline table for
    /// how they relate to the connect deadline and the transports' own
    /// deadlines.
    ///
    /// On a slow or loaded link, raise these together with
    /// [`connect_deadline`](Self::connect_deadline) and, on TCP,
    /// `TcpConfig::handshake_timeout_ms`.
    pub fn timeouts(mut self, timeouts: SwarmTimeouts) -> Self {
        self.common.timeouts = timeouts;
        self
    }

    /// Sets how many bytes [`Endpoint::send_stream`](crate::Endpoint::send_stream)
    /// may hold, across every stream, until their streams accept them.
    /// Default [`DEFAULT_WRITE_BUDGET`](crate::DEFAULT_WRITE_BUDGET) (8 MiB).
    ///
    /// A payload is admitted whole or not at all, so one larger than the
    /// budget always fails with [`SendError::TooLarge`](crate::SendError::TooLarge).
    /// `0` queues nothing: use
    /// [`Endpoint::try_send_stream`](crate::Endpoint::try_send_stream) and
    /// hold unsent tails yourself.
    pub fn write_budget(mut self, bytes: usize) -> Self {
        self.common.write_budget = bytes;
        self
    }

    /// Adds a relay, in preference order; each call adds one.
    ///
    /// A relay is a path, not a mode: connects still race direct candidates
    /// against a leg through the relay, upgrade a relayed connection with
    /// DCUtR where the endpoint runs it (std with QUIC), and reserve a slot
    /// on the relay for inbound connections while the endpoint is not known
    /// to be public. Without [`nat_config`](Self::nat_config), that is the
    /// default policy
    /// ([`ReservationPolicy::WhenPrivate`](crate::ReservationPolicy::WhenPrivate)).
    /// For relay-only connects set [`NatConfig::force_relay`].
    ///
    /// A portable endpoint needs a transport with circuit operations: build
    /// it with `build_with_circuits`.
    #[cfg(feature = "relay")]
    pub fn relay(mut self, relay: PeerAddr) -> Self {
        self.common.capabilities.relays.push(relay);
        self
    }

    /// Adds a trusted AutoNAT server used for reachability probing; each
    /// call adds one.
    ///
    /// Call once per server: a reachability verdict needs a quorum of
    /// distinct servers ([`NatConfig::confidence_threshold`], 3 by default),
    /// so with fewer reachable servers reachability stays Unknown. Without
    /// [`nat_config`](Self::nat_config) or a relay, the endpoint holds no
    /// reservation ([`ReservationPolicy::Never`](crate::ReservationPolicy::Never)).
    #[cfg(feature = "autonat")]
    pub fn autonat_server(mut self, server: PeerAddr) -> Self {
        self.common.capabilities.autonat_servers.push(server);
        self
    }

    /// Sets the base NAT configuration (timeouts, punch retries,
    /// reservation policy, …), kept as given. A second call replaces the
    /// first. Relays and AutoNAT servers added through `relay` /
    /// [`autonat_server`](Self::autonat_server) are appended to the
    /// config's own lists, in either call order, without exact repeats.
    ///
    /// Checked at build, after the merge (`BindError::NatConfig` on std,
    /// `PortableBuildError::NatConfig` otherwise): it needs a relay or an
    /// AutoNAT server, and a reservation policy other than `Never` or
    /// `force_relay` needs a relay. Only std with QUIC runs DCUtR, so a
    /// relay configuration elsewhere must set `dcutr = false` (direct
    /// candidates still race the relay leg) or `force_relay`. Without any
    /// NAT configuration, discovery and mDNS turn NAT on for the peers they
    /// find.
    #[cfg(feature = "autonat")]
    pub fn nat_config(mut self, config: NatConfig) -> Self {
        self.common.capabilities.nat = Some(config);
        self
    }

    /// Enables Circuit Relay v2 service with production-oriented defaults,
    /// keeping a config already given to
    /// [`relay_server_config`](Self::relay_server_config).
    ///
    /// The server announces the endpoint's concrete listener addresses and
    /// any public addresses AutoNAT confirms. Pause and resume admission
    /// with [`Endpoint::set_relay_server_accepting`](crate::Endpoint::set_relay_server_accepting);
    /// reservation, circuit, accounting and failure events arrive as
    /// [`EndpointEvent::RelayServer`](crate::EndpointEvent::RelayServer).
    #[cfg(feature = "relay-server")]
    pub fn relay_server(mut self) -> Self {
        self.common.relay_server(None);
        self
    }

    /// Enables Circuit Relay v2 service with custom limits, checked at
    /// build (naming the invalid field and why): a required value that is
    /// zero, or a duration the wire encoding cannot carry.
    #[cfg(feature = "relay-server")]
    pub fn relay_server_config(mut self, config: RelayServerConfig) -> Self {
        self.common.relay_server(Some(config));
        self
    }

    /// Enables pubsub with the default gossipsub configuration.
    ///
    /// Builder-time opt-in (rather than a lazy `subscribe`-time enable)
    /// because the gossipsub protocol ids must be in Identify's advertised
    /// set from the first handshake.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub(mut self) -> Self {
        self.common.gossipsub(None);
        self
    }

    /// Enables pubsub with an explicit gossipsub configuration. Invalid
    /// mesh relationships or zero bounds fail the build, on std before a
    /// socket is allocated.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub_config(mut self, config: GossipsubConfig) -> Self {
        self.common.gossipsub(Some(config));
        self
    }

    /// Enables signed pubsub peer discovery with interoperable defaults.
    /// Pubsub is enabled automatically.
    ///
    /// The discovery topic is driver-owned: subscribing to it again through
    /// [`Endpoint::subscribe`](crate::Endpoint::subscribe) is redundant, and
    /// its pubsub messages and subscription events are consumed before
    /// reaching the application.
    #[cfg(feature = "discovery")]
    pub fn discovery(mut self) -> Self {
        self.common.discovery(BeaconConfig::default());
        self
    }

    /// Enables discovery with an explicit beacon configuration, checked at
    /// build (on std before any socket opens). The configured topic is
    /// driver-owned, as with [`discovery`](Self::discovery).
    #[cfg(feature = "discovery")]
    pub fn discovery_config(mut self, config: BeaconConfig) -> Self {
        self.common.discovery(config);
        self
    }

    /// Overrides the shared bounded peer-book and automatic-dial policy,
    /// checked at build. It applies to every enabled discovery source.
    #[cfg(feature = "_peer-book")]
    pub fn peer_discovery_config(mut self, config: PeerDiscoveryConfig) -> Self {
        self.common.capabilities.peer_discovery = config;
        self
    }
}

/// What [`CommonBuilder::into_parts`] leaves for the engine.
pub(crate) struct EngineParts {
    connect_deadline_ms: u64,
    write_budget: usize,
    acks: StreamAcks,
    protocols: ProtocolTable,
}

impl EngineParts {
    /// The endpoint engine over `core`, the swarm built from the parts'
    /// swarm builder.
    pub(crate) fn engine<T: Transport, E: EntropySource, M: Carrier>(
        self,
        core: SwarmCore<T, E>,
    ) -> Engine<T, E, M> {
        let mut engine = Engine::new(core, self.connect_deadline_ms, self.acks);
        engine.writes = WriteQueue::new(self.write_budget);
        engine.protocols = self.protocols;
        engine
    }
}

/// Whole milliseconds in `duration`, saturating.
fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeat_registration_keeps_its_first_place() {
        let mut common = CommonBuilder::default();
        common.protocol("/a".into());
        common.manual_ack_protocol("/b".into());
        common.protocol("/a".into());
        common.manual_ack_protocol("/a".into());
        common.manual_ack_protocol("/b".into());
        assert_eq!(common.protocols, ["/a", "/b"]);
        assert_eq!(common.manual_ack_protocols, ["/b", "/a"]);
    }
}
