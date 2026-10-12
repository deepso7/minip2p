extern crate alloc;

#[cfg(feature = "portable-mdns")]
use alloc::boxed::Box;
#[cfg(feature = "smoltcp")]
use alloc::string::ToString;
use alloc::{string::String, vec::Vec};

pub use minip2p_core::{Bytes, Multiaddr, PeerAddr, PeerId, Protocol, TransportKind};
pub use minip2p_identity::Ed25519Keypair;
pub use minip2p_platform::{Deadline, EntropySource, Now, SharedEntropy};
pub use minip2p_swarm::{
    // Part of `EndpointEvent` / `SwarmEvent` public shapes (`Error`);
    // re-exported so portable callers can name them without a direct swarm
    // dependency.
    DriverError,
    IdentifyMessage,
    // How long an `open_stream` may negotiate before it fails.
    OUTBOUND_NEGOTIATION_TIMEOUT_MS,
    SwarmError,
    SwarmErrorKind,
    SwarmEvent,
    SwarmRuntimeError,
};
pub use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError};

pub(crate) mod connect;
pub use connect::{
    CandidateFailure, ConnectFailure, ConnectId, ConnectOutcome, ConnectTarget, ConnectTargetError,
    RelayFailure,
};
pub(crate) use connect::{DEFAULT_CONNECT_DEADLINE_MS, Expansion};
mod event_stream;
pub use event_stream::EndpointEvent;
mod stream_acks;
pub(crate) use stream_acks::StreamAcks;

#[cfg(feature = "portable-relay")]
pub use minip2p_circuit::CircuitTransport;
#[cfg(all(feature = "_discovery-driver", feature = "pubsub"))]
pub use minip2p_discovery::{BeaconConfig, DISCOVERY_TOPIC};
#[cfg(feature = "_discovery-driver")]
pub use minip2p_discovery::{
    DiscoveryConfigError, DiscoveryEvent, DiscoverySource, KnownPeer, PeerDiscoveryConfig,
};
#[cfg(feature = "_mdns-driver")]
pub use minip2p_mdns::{MdnsConfig, MdnsConfigError, MdnsError, MdnsEvent, MdnsIo};
#[cfg(feature = "smoltcp")]
pub use minip2p_mdns::{SmoltcpMdnsConfig, SmoltcpMdnsIo};
#[cfg(feature = "_nat-driver")]
pub use minip2p_nat::{
    NatConfig, NatError, NatEvent, Path, ReachabilityState, ReservationInfo, ReservationPolicy,
};
#[cfg(feature = "pubsub")]
pub use minip2p_pubsub::{
    GOSSIPSUB_PROTOCOL_IDS, GossipsubConfig, GossipsubConfigError, GossipsubEvent, PublishError,
    TopicError,
};
use minip2p_swarm::SwarmBuilder;
#[cfg(feature = "smoltcp")]
pub use minip2p_tcp::{SmoltcpConfig, SmoltcpStack, SmoltcpTcpProvider, smoltcp};
#[cfg(feature = "tcp")]
pub use minip2p_tcp::{TcpConfig, TcpProvider, TcpTransport};

#[cfg(feature = "_discovery-driver")]
use crate::discovery::DiscoveryDriver;
use crate::engine::Engine;
#[cfg(feature = "_circuit-driver")]
use crate::nat::CircuitOps;
#[cfg(feature = "portable-autonat")]
use crate::nat::NatDriver;
#[cfg(feature = "pubsub")]
use crate::pubsub::GossipsubDriver;

/// Portable endpoint entry point when the std `Endpoint` is not compiled.
///
/// Under `std`, the batteries-included endpoint exposes the same
/// [`Endpoint::portable`] constructor alongside `Endpoint::builder`.
#[cfg(not(feature = "std"))]
pub struct Endpoint;

#[cfg(not(feature = "std"))]
impl Endpoint {
    /// Starts portable endpoint configuration with explicit identity and entropy.
    pub fn portable<E: EntropySource>(
        identity: &Ed25519Keypair,
        entropy: E,
    ) -> PortableEndpointBuilder<E> {
        PortableEndpointBuilder::new(identity, entropy)
    }
}

/// The mDNS carrier a portable endpoint holds: any caller-owned `MdnsIo`.
#[cfg(feature = "portable-mdns")]
type PortableCarrier = Box<dyn MdnsIo>;
#[cfg(all(feature = "_mdns-driver", not(feature = "portable-mdns")))]
type PortableCarrier = NoMdns;
#[cfg(not(feature = "_mdns-driver"))]
type PortableCarrier = ();

/// The carrier of a portable endpoint built without `portable-mdns`, when the
/// std `mdns` feature still compiles the driver in. Uninhabited: such an
/// endpoint cannot run mDNS, and stays `Send`.
#[cfg(all(feature = "_mdns-driver", not(feature = "portable-mdns")))]
pub(crate) enum NoMdns {}

#[cfg(all(feature = "_mdns-driver", not(feature = "portable-mdns")))]
impl MdnsIo for NoMdns {
    fn interfaces(&self) -> &[minip2p_mdns::InterfaceSnapshot] {
        match *self {}
    }

    fn refresh(&mut self) -> Result<bool, MdnsError> {
        match *self {}
    }

    fn receive(&mut self, _: &mut [u8]) -> Result<Option<minip2p_mdns::MdnsDatagram>, MdnsError> {
        match *self {}
    }

    fn send(&mut self, _: &minip2p_mdns::MdnsAction) -> Result<(), MdnsError> {
        match *self {}
    }
}

/// Candidate expansion for portable endpoints: addresses are already
/// concrete, so expansion is the identity.
fn expand_concrete(addr: &PeerAddr) -> Expansion {
    Expansion::Ready(alloc::vec![addr.clone()])
}

/// Caller-driven endpoint over an injected transport and entropy source.
///
/// It is `Send` whenever its transport and entropy source are, unless
/// `portable-mdns` (or `smoltcp`, which enables it) is compiled in: the
/// carrier is then held as a `Box<dyn MdnsIo>`, which embedded carriers on a
/// shared stack are not. The std `mdns` feature alone does not affect it.
///
/// Portable entry point for embedded systems and deterministic event loops.
/// It performs no blocking and never reads a system clock. Callers drive it
/// with [`poll`](Self::poll) and may inspect
/// [`next_deadline`](Self::next_deadline) to decide how long their platform
/// loop can idle. Call [`shutdown`](Self::shutdown) to notify peers; there
/// is no `Drop` disconnect.
///
/// It runs the same engine and the same per-batch event order as the std
/// `Endpoint` (see [`EndpointEvent`]). Capabilities configured on
/// [`PortableEndpointBuilder`] (AutoNAT and relay, Gossipsub, signed
/// discovery, mDNS) report through their [`EndpointEvent`] variants. Every
/// dial goes through [`connect`](Self::connect).
///
/// # State snapshots
///
/// Getter-style snapshots ([`connected_peers`](Self::connected_peers),
/// [`is_peer_ready`](Self::is_peer_ready), [`peer_info`](Self::peer_info),
/// [`connection_id`](Self::connection_id),
/// [`connection_remote_addr`](Self::connection_remote_addr),
/// [`bound_addresses`](Self::bound_addresses)) do not drive the endpoint.
/// Separate getters are not one cross-getter atomic snapshot and may be ahead
/// of the Endpoint event stream (state changes before its corresponding event
/// is queued).
pub struct PortableEndpoint<T: Transport, E: EntropySource> {
    pub(crate) engine: Engine<T, E, PortableCarrier>,
}

/// Lightweight snapshot of portable endpoint state.
///
/// Aggregate counts only. Prefer the individual [State snapshot](PortableEndpoint#state-snapshots)
/// getters for peer and connection detail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableEndpointStats {
    /// Number of peers with an established transport connection.
    pub connected_peers: usize,
    /// Number of connected peers that completed Identify and are ready for
    /// application protocols.
    pub ready_peers: usize,
    /// Transport-bound local addresses (see [`PortableEndpoint::bound_addresses`]).
    pub bound_addresses: Vec<Multiaddr>,
}

impl<T: Transport, E: EntropySource> PortableEndpoint<T, E> {
    /// Returns this endpoint's peer ID.
    pub fn peer_id(&self) -> &PeerId {
        self.engine.core.local_peer_id()
    }

    /// Starts listening on a transport address.
    pub fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, DriverError> {
        self.engine.core.listen(address)
    }

    /// Starts listening on every address already bound by the transport.
    pub fn listen_all(&mut self) -> Result<Vec<PeerAddr>, DriverError> {
        self.engine.core.listen_on_bound_addrs()
    }

    /// Registers an application protocol for inbound and outbound negotiation.
    ///
    /// Built-in ids ([`minip2p_swarm::RESERVED_PROTOCOL_IDS`]) are rejected
    /// with [`SwarmError::ReservedProtocol`].
    pub fn add_protocol(&mut self, protocol_id: impl Into<String>) -> Result<(), DriverError> {
        Ok(self.engine.core.add_protocol(protocol_id)?)
    }

    /// Admits one Connection attempt. Sync errors: malformed target only.
    ///
    /// A [`PeerId`] target uses the discovery book's known addresses (when a
    /// book exists) and the configured relay when one exists. When neither a
    /// direct candidate nor a configured relay exists, the attempt settles
    /// [`ConnectFailure::NoUsableRoute`] through one terminal event.
    ///
    /// Every candidate is dialed immediately. Candidate completion order is
    /// not a public contract. The swarm still keeps a single connection per
    /// peer, chosen the same way on both sides when candidates race (see
    /// [`SIMULTANEOUS_DIAL_WINDOW_MS`](minip2p_swarm::SIMULTANEOUS_DIAL_WINDOW_MS)):
    /// a candidate that finishes after the winner may still replace it
    /// ([`EndpointEvent::ConnectionReplaced`]), so candidates that could still
    /// win stay open until that window ends. The attempt is settled at the first
    /// established connection the swarm keeps (including a simultaneous
    /// inbound), and the app sees any later hand-over as an ordinary
    /// connection event.
    #[expect(
        clippy::result_large_err,
        reason = "ConnectTargetError retains both peer identities for MixedPeers diagnostics."
    )]
    pub fn connect(
        &mut self,
        target: impl TryInto<ConnectTarget, Error: Into<ConnectTargetError>>,
        now: Now,
    ) -> Result<ConnectId, ConnectTargetError> {
        let target = target.try_into().map_err(Into::into)?;
        Ok(self.engine.connect(target, &mut expand_concrete, now))
    }

    /// Idempotent. Settled or unknown ids are a no-op. Never disconnects.
    ///
    /// Cancels the attempt's NAT relay leg too.
    pub fn cancel_connect(&mut self, id: ConnectId, now: Now) {
        self.engine.cancel_connect(id, now);
    }

    /// Returns peers with an established transport connection.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.engine.core.connected_peers()
    }

    /// Returns whether a peer completed Identify and is ready for application protocols.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.engine.core.is_peer_ready(peer_id)
    }

    /// Returns the peer's current connection and its Identify info once that
    /// connection is ready, as one coherent snapshot.
    pub fn peer_readiness(&self, peer_id: &PeerId) -> Option<(ConnectionId, &IdentifyMessage)> {
        self.engine.core.peer_readiness(peer_id)
    }

    /// Returns the latest Identify information received for a peer.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.engine.core.peer_info(peer_id)
    }

    /// Returns the active transport connection selected for `peer_id`.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connection_id(&self, peer_id: &PeerId) -> Option<ConnectionId> {
        self.engine.core.connection_id(peer_id)
    }

    /// Returns the remote transport address recorded for an exact connection.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connection_remote_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr> {
        self.engine.core.connection_remote_addr(conn_id)
    }

    /// Returns addresses currently bound on the local transport.
    ///
    /// These are what the sockets were given, not a signal that
    /// [`Self::listen`] / [`Self::listen_all`] has started accepting. The set
    /// can be non-empty before listening begins.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn bound_addresses(&self) -> Vec<Multiaddr> {
        self.engine.core.transport().local_addresses()
    }

    /// Sets externally validated addresses to advertise through Identify.
    ///
    /// Replaces the previous caller-set addresses; NAT contributions (relay
    /// circuits, confirmed public addresses) are kept and merged after them.
    pub fn set_external_addresses(&mut self, addresses: Vec<Multiaddr>) {
        self.engine.set_external_addresses(addresses);
    }

    /// Requests a ping using the caller's time sample.
    pub fn ping(&mut self, peer_id: &PeerId, now: Now) -> Result<(), DriverError> {
        self.engine.core.ping(peer_id, now.monotonic_ms)
    }

    /// Disconnects from a peer, aborting any dials still kept open for its
    /// simultaneous dial so none of them reconnects it.
    pub fn disconnect(&mut self, peer_id: &PeerId, now: Now) -> Result<(), DriverError> {
        self.engine.disconnect(peer_id, now)
    }

    /// Opens an outbound application stream and returns its connection and
    /// stream ids; later stream operations take both.
    pub fn open_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        now: Now,
    ) -> Result<(ConnectionId, StreamId), DriverError> {
        self.engine
            .core
            .open_stream(peer_id, protocol_id, now.monotonic_ms)
    }

    /// Sends bytes on an application stream named by its connection and
    /// stream ids; the peer is the connection's.
    ///
    /// Accepts as much as the stream can queue. [`DriverError::Full`] means
    /// a prefix may already have been accepted and only `unsent` is yours to
    /// resend after [`EndpointEvent::StreamWritable`]; a `?` on this call
    /// drops that tail. Fails with [`SwarmError::StreamNotFound`] if `conn_id`
    /// is no longer the connection holding the stream (or
    /// [`TransportError::ConnectionNotFound`](minip2p_transport::TransportError::ConnectionNotFound)
    /// once nothing names it), as do the other stream operations;
    /// [`DriverError::is_stream_gone`] covers both.
    pub fn send_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: impl Into<Bytes>,
        now: Now,
    ) -> Result<(), DriverError> {
        self.engine
            .send_stream(conn_id, stream_id, data.into(), now)
    }

    /// Half-closes the local write side of an application stream.
    pub fn close_stream_write(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        self.engine.close_stream_write(conn_id, stream_id, now)
    }

    /// Abruptly resets an application stream.
    pub fn reset_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        self.engine.reset_stream(conn_id, stream_id, now)
    }

    /// Resets a stream and removes all bookkeeping for it, including its
    /// events still queued in the endpoint (a failed [`Self::poll`] keeps
    /// them). A queued `StreamClosed` still counts as the stream existing.
    pub fn abandon_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        self.engine.abandon_stream(conn_id, stream_id, now)
    }

    /// Returns a lightweight aggregate of durable state without driving the endpoint.
    ///
    /// Prefer the individual State snapshot getters when you need peer or
    /// connection detail. Aggregate counts here are not atomic with those getters
    /// and may be ahead of the Endpoint event stream.
    pub fn stats(&self) -> PortableEndpointStats {
        let connected = self.engine.core.connected_peers();
        PortableEndpointStats {
            ready_peers: connected
                .iter()
                .filter(|peer_id| self.engine.core.is_peer_ready(peer_id))
                .count(),
            connected_peers: connected.len(),
            bound_addresses: self.bound_addresses(),
        }
    }

    /// Runs one drive batch with one host-supplied time sample and returns
    /// every queued Endpoint event.
    ///
    /// Events come in the per-batch order documented on [`EndpointEvent`].
    /// Returning an [`EndpointEvent::StreamData`] acknowledges its bytes
    /// (ADR 0012): a sender's receive budget is replenished as the
    /// application pulls its data, so polling less often slows the sender.
    ///
    /// An error discards nothing: events already queued come out of the next
    /// call, and [`Self::next_deadline`] is immediate until then.
    pub fn poll(&mut self, now: Now) -> Result<Vec<EndpointEvent>, DriverError> {
        self.engine.drive(now, &mut expand_concrete)?;
        Ok(self.engine.take_events())
    }

    /// Returns when the endpoint next needs to be polled: immediately while
    /// events wait to be returned, else the earliest transport, swarm,
    /// Connection-attempt, or capability timer.
    pub fn next_deadline(&self, now: Now) -> Option<Deadline> {
        self.engine.next_deadline(now)
    }

    /// Sends mDNS goodbyes, closes established peers, drives the endpoint
    /// once more, and consumes it.
    ///
    /// Returns the final Endpoint events, including capability events still
    /// queued (Gossipsub events still inside the agent too) and any a failed
    /// [`Self::poll`] left. Consuming `self` is intentional: dropping the
    /// transport releases listeners and in-progress connections as well as
    /// established ones. Every established peer is attempted even if an
    /// earlier step fails; the first error wins (mDNS, then a close, then
    /// the final drive).
    pub fn shutdown(mut self, now: Now) -> Result<Vec<EndpointEvent>, DriverError> {
        #[cfg(feature = "_mdns-driver")]
        let mut first_error = self.engine.shutdown_mdns(now).err();
        #[cfg(not(feature = "_mdns-driver"))]
        let mut first_error = None;
        for peer_id in self.engine.core.connected_peers() {
            if let Err(error) = self.engine.core.disconnect(&peer_id, now.monotonic_ms)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        let drove = self.engine.drive(now, &mut expand_concrete);
        #[cfg(feature = "pubsub")]
        {
            self.engine.collect_agent_events();
            self.engine.settle(now);
        }
        let events = self.engine.take_events();
        match (first_error, drove) {
            (Some(error), _) | (None, Err(error)) => Err(error),
            (None, Ok(())) => Ok(events),
        }
    }

    /// Returns the NAT-orchestrated path of `peer`'s current connection.
    ///
    /// It follows a Connection replacement to the new connection's origin
    /// and is gone once the peer disconnects. Connections NAT did not
    /// announce have no path, so this can return `None` while the peer is
    /// connected.
    #[cfg(feature = "portable-relay")]
    pub fn path(&self, peer: &PeerId) -> Option<Path> {
        self.engine.path(peer)
    }

    /// Returns the currently held relay reservation, when any.
    #[cfg(feature = "portable-relay")]
    pub fn active_reservation(&self) -> Option<ReservationInfo> {
        self.engine.active_reservation()
    }

    /// Returns the current AutoNAT reachability verdict
    /// ([`ReachabilityState::Unknown`] until a server exchange succeeds, or
    /// when NAT is not configured).
    #[cfg(feature = "portable-autonat")]
    pub fn reachability(&self) -> ReachabilityState {
        self.engine.reachability()
    }

    /// Subscribes to an application topic. Returns `Ok(false)` when already
    /// subscribed; [`crate::GossipsubError::NotEnabled`] unless Gossipsub
    /// was configured.
    #[cfg(feature = "pubsub")]
    pub fn subscribe(&mut self, topic: &str, now: Now) -> Result<bool, crate::GossipsubError> {
        self.engine.subscribe(topic, now)
    }

    /// Withdraws an application topic subscription. The configured
    /// discovery topic is reserved while discovery is enabled and returns
    /// [`crate::GossipsubError::DiscoveryTopicReserved`].
    #[cfg(feature = "pubsub")]
    pub fn unsubscribe(&mut self, topic: &str, now: Now) -> Result<bool, crate::GossipsubError> {
        self.engine.unsubscribe(topic, now)
    }

    /// Publishes one application message. The configured discovery topic is
    /// reserved while discovery is enabled and returns
    /// [`crate::GossipsubError::DiscoveryTopicReserved`].
    #[cfg(feature = "pubsub")]
    pub fn publish(
        &mut self,
        topic: &str,
        data: impl Into<Vec<u8>>,
        now: Now,
    ) -> Result<(), crate::GossipsubError> {
        self.engine.publish(topic, data.into(), now)
    }

    /// Returns the bounded peer book shared by mDNS and signed beacons;
    /// empty when neither is configured.
    #[cfg(feature = "_discovery-driver")]
    pub fn known_peers(&self) -> Vec<KnownPeer> {
        self.engine.known_peers()
    }
}

/// Failure while building a portable endpoint.
#[derive(Debug, thiserror::Error)]
pub enum PortableBuildError {
    /// The supplied entropy source failed.
    #[error(transparent)]
    Entropy(#[from] minip2p_platform::EntropyError),
    /// Swarm configuration was invalid (a reserved protocol id, say).
    #[error(transparent)]
    Swarm(#[from] SwarmError),
    /// A listen or transport operation failed.
    #[error(transparent)]
    Driver(#[from] DriverError),
    /// A listen address was not a valid multiaddress.
    #[error("invalid listen address {address}: {reason}")]
    ListenAddress { address: String, reason: String },
    /// The mDNS carrier could not be constructed.
    #[cfg(feature = "portable-mdns")]
    #[error(transparent)]
    Mdns(#[from] MdnsError),
    /// mDNS wire or scheduling policy was invalid.
    #[cfg(feature = "portable-mdns")]
    #[error(transparent)]
    MdnsConfig(#[from] MdnsConfigError),
    /// Gossipsub configuration was invalid.
    #[cfg(feature = "pubsub")]
    #[error(transparent)]
    Gossipsub(GossipsubConfigError),
    /// The reserved discovery topic was invalid.
    #[cfg(feature = "pubsub")]
    #[error(transparent)]
    Topic(#[from] TopicError),
    /// Signed-beacon or bounded peer-book policy was invalid.
    #[cfg(feature = "_discovery-driver")]
    #[error(transparent)]
    Discovery(#[from] DiscoveryConfigError),
    /// Portable NAT policy requested an unsupported path, or relay paths
    /// over a transport without circuit operations.
    #[cfg(feature = "portable-autonat")]
    #[error("invalid portable NAT config: {reason}")]
    NatConfig { reason: &'static str },
}

/// Builder for a [`PortableEndpoint`].
///
/// Base endpoint operations work over any [`Transport`]. Capabilities are
/// opt-in setters behind their Cargo features: AutoNAT and relay
/// (`portable-autonat`, `portable-relay`), Gossipsub and signed discovery
/// (`pubsub`), and mDNS (`portable-mdns`).
///
/// # Relay needs circuit operations
///
/// Relay paths turn a relay bridge into a connection, which takes circuit
/// operations from the transport. [`build`](Self::build) works over any
/// transport and refuses relay configuration with
/// `PortableBuildError::NatConfig`; wrap the transport in a
/// `CircuitTransport` and call `build_with_circuits` (feature
/// `portable-relay`) to run relays.
/// AutoNAT alone needs nothing from the transport.
pub struct PortableEndpointBuilder<E> {
    swarm: SwarmBuilder,
    #[cfg_attr(
        not(any(feature = "pubsub", feature = "smoltcp")),
        expect(
            dead_code,
            reason = "only Gossipsub, beacons, and smoltcp sign with it"
        )
    )]
    identity: Ed25519Keypair,
    entropy: E,
    connect_deadline_ms: u64,
    #[cfg(feature = "portable-autonat")]
    nat_config: Option<NatConfig>,
    #[cfg(feature = "pubsub")]
    gossipsub: Option<GossipsubConfig>,
    #[cfg(all(feature = "pubsub", feature = "_discovery-driver"))]
    beacon: Option<BeaconConfig>,
    #[cfg(feature = "_discovery-driver")]
    peer_discovery: PeerDiscoveryConfig,
    #[cfg(feature = "portable-mdns")]
    mdns: Option<(PortableCarrier, MdnsConfig)>,
}

impl<E: EntropySource> PortableEndpointBuilder<E> {
    /// Starts a builder with explicit identity and entropy.
    pub fn new(identity: &Ed25519Keypair, entropy: E) -> Self {
        Self {
            swarm: SwarmBuilder::new(identity),
            identity: identity.clone(),
            entropy,
            connect_deadline_ms: DEFAULT_CONNECT_DEADLINE_MS,
            #[cfg(feature = "portable-autonat")]
            nat_config: None,
            #[cfg(feature = "pubsub")]
            gossipsub: None,
            #[cfg(all(feature = "pubsub", feature = "_discovery-driver"))]
            beacon: None,
            #[cfg(feature = "_discovery-driver")]
            peer_discovery: PeerDiscoveryConfig::default(),
            #[cfg(feature = "portable-mdns")]
            mdns: None,
        }
    }

    /// Overrides the Identify agent-version string.
    pub fn agent_version(mut self, value: impl Into<String>) -> Self {
        self.swarm = self.swarm.agent_version(value);
        self
    }

    /// Registers an application stream protocol.
    pub fn protocol(mut self, protocol_id: impl Into<String>) -> Self {
        self.swarm = self.swarm.protocol(protocol_id);
        self
    }

    /// Sets how long, in milliseconds, a peer's new connection can lose a race
    /// to its current one. Default
    /// [`SIMULTANEOUS_DIAL_WINDOW_MS`](minip2p_swarm::SIMULTANEOUS_DIAL_WINDOW_MS);
    /// both peers should use the same window.
    pub fn simultaneous_dial_window_ms(mut self, ms: u64) -> Self {
        self.swarm = self.swarm.simultaneous_dial_window_ms(ms);
        self
    }

    /// Sets the Connection-attempt deadline in milliseconds. Default 30_000.
    pub fn connect_deadline_ms(mut self, ms: u64) -> Self {
        self.connect_deadline_ms = ms;
        self
    }

    /// Enables relay-only connectivity through one relay address.
    ///
    /// Needs a transport with circuit operations: build with
    /// `build_with_circuits`.
    #[cfg(feature = "portable-relay")]
    pub fn relay(mut self, relay: PeerAddr) -> Self {
        let mut config = match self.nat_config.take() {
            Some(config) => config,
            None => NatConfig {
                reservation_policy: ReservationPolicy::Never,
                ..NatConfig::default()
            },
        };
        config.relays.push(relay);
        config.force_relay = true;
        self.nat_config = Some(config);
        self
    }

    /// Enables AutoNAT probing through one trusted server.
    #[cfg(feature = "portable-autonat")]
    pub fn autonat(mut self, server: PeerAddr) -> Self {
        self.nat_config
            .get_or_insert_with(|| NatConfig {
                reservation_policy: ReservationPolicy::Never,
                ..NatConfig::default()
            })
            .autonat_servers
            .push(server);
        self
    }

    /// Enables portable NAT policy with explicit relay and AutoNAT settings.
    ///
    /// Relay configurations must set `force_relay`: portable endpoints do
    /// not run DCUtR. AutoNAT servers may be configured with or without
    /// relays.
    #[cfg(feature = "portable-autonat")]
    pub fn nat_config(mut self, config: NatConfig) -> Self {
        self.nat_config = Some(config);
        self
    }

    /// Enables pubsub with interoperable gossipsub defaults.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub(mut self) -> Self {
        self.gossipsub.get_or_insert_with(GossipsubConfig::default);
        self
    }

    /// Enables pubsub with an explicit gossipsub configuration, validated
    /// at build.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub_config(mut self, config: GossipsubConfig) -> Self {
        self.gossipsub = Some(config);
        self
    }

    /// Enables signed-beacon discovery. Pubsub is enabled automatically.
    #[cfg(all(feature = "pubsub", feature = "_discovery-driver"))]
    pub fn discovery(mut self) -> Self {
        self.gossipsub.get_or_insert_with(GossipsubConfig::default);
        self.beacon.get_or_insert_with(BeaconConfig::default);
        self
    }

    /// Enables signed-beacon discovery with explicit beacon policy.
    #[cfg(all(feature = "pubsub", feature = "_discovery-driver"))]
    pub fn beacon_config(mut self, config: BeaconConfig) -> Self {
        self.gossipsub.get_or_insert_with(GossipsubConfig::default);
        self.beacon = Some(config);
        self
    }

    /// Overrides the shared bounded peer-book and automatic-dial policy,
    /// validated at build. It applies to every enabled discovery source.
    #[cfg(feature = "_discovery-driver")]
    pub fn peer_discovery_config(mut self, config: PeerDiscoveryConfig) -> Self {
        self.peer_discovery = config;
        self
    }

    /// Enables mDNS over a caller-owned carrier.
    ///
    /// The endpoint owns the carrier from here on, so it must be `'static`;
    /// keep a handle to whatever it runs on (a cloned `SmoltcpStack`, say)
    /// to reconfigure it later. The mDNS seed comes from this builder's
    /// entropy. Peer-book and automatic-dial policy comes from
    /// [`Self::peer_discovery_config`]. The endpoint polls the transport
    /// again after each mDNS tick, in case the carrier shares its stack.
    #[cfg(feature = "portable-mdns")]
    pub fn mdns(mut self, io: impl MdnsIo + 'static, config: MdnsConfig) -> Self {
        self.mdns = Some((Box::new(io), config));
        self
    }

    /// Builds the endpoint over any transport. Relay configuration is
    /// refused here (see [Relay needs circuit operations](Self#relay-needs-circuit-operations)).
    pub fn build<T: Transport>(
        self,
        transport: T,
    ) -> Result<PortableEndpoint<T, E>, PortableBuildError> {
        self.assemble(
            transport,
            #[cfg(feature = "_circuit-driver")]
            None,
        )
    }

    /// Builds the endpoint over a [`CircuitTransport`], whose circuit
    /// operations let relay legs and reservations run.
    #[cfg(feature = "portable-relay")]
    pub fn build_with_circuits<T: Transport, R: EntropySource>(
        self,
        transport: CircuitTransport<T, R>,
    ) -> Result<PortableEndpoint<CircuitTransport<T, R>, E>, PortableBuildError> {
        self.assemble(transport, Some(CircuitOps::circuit_transport()))
    }

    #[cfg_attr(
        not(any(feature = "portable-autonat", feature = "pubsub")),
        expect(
            unused_mut,
            reason = "only capabilities add protocols while assembling"
        )
    )]
    fn assemble<T: Transport>(
        mut self,
        transport: T,
        #[cfg(feature = "_circuit-driver")] circuits: Option<CircuitOps<T>>,
    ) -> Result<PortableEndpoint<T, E>, PortableBuildError> {
        #[cfg(feature = "portable-autonat")]
        if let Some(config) = &self.nat_config {
            #[cfg(feature = "_circuit-driver")]
            let has_circuits = circuits.is_some();
            #[cfg(not(feature = "_circuit-driver"))]
            let has_circuits = false;
            validate_nat(config, has_circuits)?;
            if !config.autonat_servers.is_empty() {
                self.swarm = self.swarm.protocol(minip2p_nat::AUTONAT_PROTOCOL_ID);
            }
        }
        #[cfg(feature = "pubsub")]
        if let Some(config) = &self.gossipsub {
            config.validate().map_err(PortableBuildError::Gossipsub)?;
            for protocol in GOSSIPSUB_PROTOCOL_IDS {
                self.swarm = self.swarm.protocol(*protocol);
            }
        }
        #[cfg(feature = "_discovery-driver")]
        self.peer_discovery.validate()?;
        // The swarm owns the entropy from here on; capabilities draw from it.
        let core = self.swarm.build_core(transport, self.entropy)?;
        #[cfg_attr(
            not(any(
                feature = "portable-autonat",
                feature = "pubsub",
                feature = "_discovery-driver"
            )),
            expect(unused_mut, reason = "no capability to install")
        )]
        let mut engine = Engine::new(core, self.connect_deadline_ms, StreamAcks::default());

        #[cfg(feature = "portable-autonat")]
        if let Some(config) = self.nat_config {
            if !config.relays.is_empty() {
                engine
                    .core
                    .add_outbound_protocol(minip2p_nat::HOP_PROTOCOL_ID)?;
                engine
                    .core
                    .add_inbound_protocol(minip2p_nat::STOP_PROTOCOL_ID)?;
                engine
                    .core
                    .add_advertised_protocol(minip2p_nat::STOP_PROTOCOL_ID)?;
            }
            let relay_addrs = config
                .relays
                .iter()
                .map(|relay| (relay.peer_id().clone(), relay.transport().clone()))
                .collect();
            // The driver seeds the agent's listen addresses on its first turn.
            let agent = minip2p_nat::NatAgent::new(engine.core.local_peer_id().clone(), config);
            let driver = NatDriver::new(agent, relay_addrs, engine.core.entropy_mut());
            #[cfg(feature = "_circuit-driver")]
            let driver = match circuits {
                Some(circuits) => driver.with_circuits(circuits),
                None => driver,
            };
            engine.nat = Some(driver);
        }
        // Without portable NAT there is no relay to hand the operations to.
        #[cfg(all(feature = "_circuit-driver", not(feature = "portable-autonat")))]
        let _ = circuits;

        #[cfg(feature = "pubsub")]
        #[cfg_attr(
            not(feature = "_discovery-driver"),
            expect(unused_mut, reason = "only the beacon subscribes during assembly")
        )]
        let mut pubsub = match self.gossipsub {
            Some(config) => Some(
                minip2p_pubsub::GossipsubAgent::new(
                    self.identity.clone(),
                    config,
                    engine.core.entropy_mut().next_u64()?,
                    engine.core.entropy_mut().next_u64()?,
                )
                .map_err(PortableBuildError::Gossipsub)?,
            ),
            None => None,
        };
        #[cfg(all(feature = "pubsub", feature = "_discovery-driver"))]
        let beacon = self
            .beacon
            .map(|config| minip2p_discovery::BeaconAgent::new(self.identity.public_key(), config))
            .transpose()?;
        #[cfg(all(feature = "pubsub", feature = "_discovery-driver"))]
        if let (Some(pubsub), Some(beacon)) = (&mut pubsub, &beacon) {
            pubsub.subscribe(beacon.topic(), 0)?;
        }
        #[cfg(feature = "pubsub")]
        {
            engine.gossipsub = pubsub.map(GossipsubDriver::new);
        }

        #[cfg(feature = "portable-mdns")]
        if let Some((io, config)) = self.mdns {
            let mut seed = [0; 32];
            engine.core.entropy_mut().fill_bytes(&mut seed)?;
            let agent = minip2p_mdns::MdnsAgent::new(
                engine.core.local_peer_id().clone(),
                config.clone(),
                seed,
            )?;
            engine.set_mdns(minip2p_mdns::MdnsDriver::new(agent, io, &config), true);
        }

        #[cfg(feature = "_discovery-driver")]
        {
            #[cfg(feature = "pubsub")]
            let beacon_enabled = beacon.is_some();
            #[cfg(not(feature = "pubsub"))]
            let beacon_enabled = false;
            #[cfg(feature = "_mdns-driver")]
            let mdns_enabled = engine.has_mdns();
            #[cfg(not(feature = "_mdns-driver"))]
            let mdns_enabled = false;
            if beacon_enabled || mdns_enabled {
                let book = minip2p_discovery::PeerDiscoveryAgent::new(
                    engine.core.local_peer_id().clone(),
                    self.peer_discovery,
                )?;
                engine.discovery = Some(DiscoveryDriver::new(
                    book,
                    #[cfg(feature = "pubsub")]
                    beacon,
                ));
            }
        }
        Ok(PortableEndpoint { engine })
    }

    /// Selects the embedded smoltcp TCP backend over a host-configured stack.
    ///
    /// The TCP transport and the swarm share the entropy source, so the
    /// built endpoint holds it as a single-threaded [`SharedEntropy`], like
    /// the stack itself.
    #[cfg(feature = "smoltcp")]
    pub fn smoltcp<D: smoltcp::phy::Device>(
        self,
        stack: SmoltcpStack<D>,
    ) -> SmoltcpEndpointBuilder<D, E> {
        let entropy = SharedEntropy::new(self.entropy);
        SmoltcpEndpointBuilder {
            portable: PortableEndpointBuilder {
                swarm: self.swarm,
                identity: self.identity,
                entropy: entropy.clone(),
                connect_deadline_ms: self.connect_deadline_ms,
                #[cfg(feature = "portable-autonat")]
                nat_config: self.nat_config,
                #[cfg(feature = "pubsub")]
                gossipsub: self.gossipsub,
                #[cfg(feature = "pubsub")]
                beacon: self.beacon,
                peer_discovery: self.peer_discovery,
                mdns: self.mdns,
            },
            entropy,
            stack,
            tcp_config: TcpConfig::default(),
            provider_config: SmoltcpConfig::default(),
            listens: Vec::new(),
            mdns: None,
        }
    }
}

/// Rejects portable NAT policy that cannot run.
#[cfg(feature = "portable-autonat")]
fn validate_nat(config: &NatConfig, has_circuits: bool) -> Result<(), PortableBuildError> {
    let reason = if config.relays.is_empty() && config.autonat_servers.is_empty() {
        "at least one relay or AutoNAT server is required"
    } else if config.relays.is_empty() && config.reservation_policy != ReservationPolicy::Never {
        "relay reservation policy requires at least one relay address"
    } else if !config.relays.is_empty() && !config.force_relay {
        "portable relay requires force_relay = true; DCUtR is QUIC-only and portable endpoints do not run it"
    } else if !config.relays.is_empty() && cfg!(not(feature = "portable-relay")) {
        "relay addresses require the portable-relay feature"
    } else if !config.relays.is_empty() && !has_circuits {
        "relay addresses need circuit operations from the transport: wrap it in a CircuitTransport and build with build_with_circuits"
    } else {
        return Ok(());
    };
    Err(PortableBuildError::NatConfig { reason })
}

/// The transport a [`SmoltcpEndpointBuilder`] builds: TCP over smoltcp,
/// wrapped in a `CircuitTransport` with the `portable-relay` feature.
#[cfg(all(feature = "smoltcp", not(feature = "portable-relay")))]
pub type SmoltcpTransport<D, E> = TcpTransport<SmoltcpTcpProvider<D>, SharedEntropy<E>>;

/// The transport a [`SmoltcpEndpointBuilder`] builds: TCP over smoltcp,
/// wrapped in a [`CircuitTransport`] with the `portable-relay` feature.
#[cfg(all(feature = "smoltcp", feature = "portable-relay"))]
pub type SmoltcpTransport<D, E> =
    CircuitTransport<TcpTransport<SmoltcpTcpProvider<D>, SharedEntropy<E>>, SharedEntropy<E>>;

/// Embedded mDNS configuration.
#[cfg(feature = "smoltcp")]
struct EmbeddedMdnsConfig {
    mdns: MdnsConfig,
    carrier: SmoltcpMdnsConfig,
}

/// Builder for a [`PortableEndpoint`] over one shared smoltcp stack.
///
/// It installs TCP (and mDNS, when asked) on the stack and hands every
/// capability setter to the [`PortableEndpointBuilder`] it came from. Keep
/// a cloned [`SmoltcpStack`] from before `smoltcp(..)` to reconfigure the
/// interface later.
#[cfg(feature = "smoltcp")]
pub struct SmoltcpEndpointBuilder<D: smoltcp::phy::Device, E: EntropySource> {
    portable: PortableEndpointBuilder<SharedEntropy<E>>,
    /// Shared with the swarm, for the TCP (and circuit) transport.
    entropy: SharedEntropy<E>,
    stack: SmoltcpStack<D>,
    tcp_config: TcpConfig,
    provider_config: SmoltcpConfig,
    listens: Vec<String>,
    mdns: Option<EmbeddedMdnsConfig>,
}

#[cfg(feature = "smoltcp")]
impl<D: smoltcp::phy::Device, E: EntropySource> SmoltcpEndpointBuilder<D, E> {
    /// Overrides the Identify agent-version string.
    pub fn agent_version(mut self, value: impl Into<String>) -> Self {
        self.portable = self.portable.agent_version(value);
        self
    }

    /// Registers an application stream protocol.
    pub fn protocol(mut self, protocol_id: impl Into<String>) -> Self {
        self.portable = self.portable.protocol(protocol_id);
        self
    }

    /// Overrides secure-session and connection limits.
    pub fn tcp_config(mut self, config: TcpConfig) -> Self {
        self.tcp_config = config;
        self
    }

    /// Overrides smoltcp socket buffers, backlog, and provider limits.
    pub fn smoltcp_config(mut self, config: SmoltcpConfig) -> Self {
        self.provider_config = config;
        self
    }

    /// Adds a TCP listen multiaddress, validated when the endpoint is built.
    pub fn listen(mut self, address: impl Into<String>) -> Self {
        self.listens.push(address.into());
        self
    }

    /// Enables mDNS on the shared stack and bounded automatic local-peer
    /// discovery with defaults.
    pub fn mdns(self) -> Self {
        self.mdns_config(MdnsConfig::default())
    }

    /// Enables mDNS with explicit wire and scheduling policy.
    pub fn mdns_config(mut self, config: MdnsConfig) -> Self {
        self.mdns = Some(EmbeddedMdnsConfig {
            mdns: config,
            carrier: SmoltcpMdnsConfig::default(),
        });
        self
    }

    /// Overrides the mDNS UDP carrier buffers and enables mDNS when needed.
    pub fn mdns_carrier_config(mut self, config: SmoltcpMdnsConfig) -> Self {
        self.mdns
            .get_or_insert_with(|| EmbeddedMdnsConfig {
                mdns: MdnsConfig::default(),
                carrier: SmoltcpMdnsConfig::default(),
            })
            .carrier = config;
        self
    }

    /// Enables pubsub with interoperable gossipsub defaults.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub(mut self) -> Self {
        self.portable = self.portable.gossipsub();
        self
    }

    /// Enables pubsub with an explicit gossipsub configuration.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub_config(mut self, config: GossipsubConfig) -> Self {
        self.portable = self.portable.gossipsub_config(config);
        self
    }

    /// Enables signed-beacon discovery. Pubsub is enabled automatically.
    #[cfg(feature = "pubsub")]
    pub fn discovery(mut self) -> Self {
        self.portable = self.portable.discovery();
        self
    }

    /// Enables signed-beacon discovery with explicit beacon policy.
    #[cfg(feature = "pubsub")]
    pub fn beacon_config(mut self, config: BeaconConfig) -> Self {
        self.portable = self.portable.beacon_config(config);
        self
    }

    /// Overrides the shared bounded peer-book and automatic-dial policy.
    pub fn peer_discovery_config(mut self, config: PeerDiscoveryConfig) -> Self {
        self.portable = self.portable.peer_discovery_config(config);
        self
    }

    /// Enables relay-only connectivity through one relay address.
    #[cfg(feature = "portable-relay")]
    pub fn relay(mut self, relay: PeerAddr) -> Self {
        self.portable = self.portable.relay(relay);
        self
    }

    /// Enables portable AutoNAT probing through one trusted server.
    #[cfg(feature = "portable-autonat")]
    pub fn autonat(mut self, server: PeerAddr) -> Self {
        self.portable = self.portable.autonat(server);
        self
    }

    /// Enables portable NAT policy with explicit relay and AutoNAT settings.
    ///
    /// TCP relay configurations must set `force_relay`; UDP DCUtR remains
    /// unavailable. AutoNAT servers may be configured with or without relays.
    #[cfg(feature = "portable-autonat")]
    pub fn nat_config(mut self, config: NatConfig) -> Self {
        self.portable = self.portable.nat_config(config);
        self
    }

    /// Builds the endpoint: TCP (and mDNS) installed on the shared stack,
    /// every configured capability driven by one `poll`.
    pub fn build(
        self,
    ) -> Result<PortableEndpoint<SmoltcpTransport<D, E>, SharedEntropy<E>>, PortableBuildError>
    where
        D: 'static,
    {
        let Self {
            mut portable,
            entropy,
            stack,
            tcp_config,
            provider_config,
            listens,
            mdns,
        } = self;
        if let Some(config) = mdns {
            let io = SmoltcpMdnsIo::on_stack(stack.clone(), config.carrier)?;
            portable = portable.mdns(io, config.mdns);
        }
        let identity = portable.identity.clone();
        let transport = TcpTransport::with_config(
            SmoltcpTcpProvider::on_stack(stack, provider_config),
            identity.clone(),
            entropy.clone(),
            tcp_config,
        );
        #[cfg(feature = "portable-relay")]
        let mut endpoint =
            portable.build_with_circuits(CircuitTransport::new(transport, identity, entropy))?;
        #[cfg(not(feature = "portable-relay"))]
        let mut endpoint = {
            let _ = identity;
            drop(entropy);
            portable.build(transport)?
        };
        for address in listens {
            let parsed = address.parse::<Multiaddr>().map_err(|error| {
                PortableBuildError::ListenAddress {
                    address,
                    reason: error.to_string(),
                }
            })?;
            endpoint.listen(&parsed)?;
        }
        Ok(endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Endpoint;
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::Cell;
    use minip2p_platform::EntropyError;
    use minip2p_test_support::InMemoryTransport;
    use minip2p_transport::{ConnectionEndpoint, TransportEvent};

    struct NoopTransport;

    impl Transport for NoopTransport {
        fn ack_stream(
            &mut self,
            _: minip2p_transport::ConnectionId,
            _: minip2p_transport::StreamId,
            _: usize,
        ) -> Result<(), minip2p_transport::TransportError> {
            Ok(())
        }

        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            Err(TransportError::Unsupported { operation: "dial" })
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            Err(TransportError::Unsupported {
                operation: "listen",
            })
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            Err(TransportError::Unsupported {
                operation: "open stream",
            })
        }

        fn send_stream(
            &mut self,
            _: ConnectionId,
            _: StreamId,
            _: minip2p_core::Bytes,
        ) -> Result<(), TransportError> {
            Err(TransportError::Unsupported {
                operation: "send stream",
            })
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            Err(TransportError::Unsupported {
                operation: "close stream write",
            })
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            Err(TransportError::Unsupported {
                operation: "reset stream",
            })
        }

        fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
            Err(TransportError::Unsupported {
                operation: "close connection",
            })
        }

        fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(Vec::new())
        }
    }

    struct ZeroEntropy;

    impl EntropySource for ZeroEntropy {
        fn fill_bytes(&mut self, output: &mut [u8]) -> Result<(), EntropyError> {
            output.fill(0);
            Ok(())
        }
    }

    struct RecordingTransport {
        events: Vec<TransportEvent>,
        local_address: Multiaddr,
        next_stream_id: u64,
        closed: Rc<Cell<bool>>,
    }

    impl Transport for RecordingTransport {
        fn ack_stream(
            &mut self,
            _: minip2p_transport::ConnectionId,
            _: minip2p_transport::StreamId,
            _: usize,
        ) -> Result<(), minip2p_transport::TransportError> {
            Ok(())
        }

        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            Err(TransportError::Unsupported { operation: "dial" })
        }

        fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, TransportError> {
            Ok(address.clone())
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            self.next_stream_id += 1;
            Ok(StreamId::new(self.next_stream_id))
        }

        fn send_stream(
            &mut self,
            _: ConnectionId,
            _: StreamId,
            _: minip2p_core::Bytes,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            Ok(())
        }

        fn close(&mut self, id: ConnectionId) -> Result<(), TransportError> {
            self.closed.set(true);
            self.events.push(TransportEvent::Closed { id });
            Ok(())
        }

        fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
            Ok(core::mem::take(&mut self.events))
        }

        fn local_addresses(&self) -> Vec<Multiaddr> {
            vec![self.local_address.clone()]
        }
    }

    /// An mDNS carrier with no interfaces whose driving fails, as a stack
    /// that has gone away does.
    #[cfg(feature = "portable-mdns")]
    struct BrokenMdns;

    #[cfg(feature = "portable-mdns")]
    impl MdnsIo for BrokenMdns {
        fn interfaces(&self) -> &[minip2p_mdns::InterfaceSnapshot] {
            &[]
        }
        fn refresh(&mut self) -> Result<bool, MdnsError> {
            Ok(false)
        }
        fn receive(
            &mut self,
            _: &mut [u8],
        ) -> Result<Option<minip2p_mdns::MdnsDatagram>, MdnsError> {
            Ok(None)
        }
        fn send(&mut self, _: &minip2p_mdns::MdnsAction) -> Result<(), MdnsError> {
            Ok(())
        }
        fn poll(&mut self, _: u64) -> Result<(), MdnsError> {
            Err(MdnsError::Io {
                operation: "poll",
                reason: "stack gone".into(),
            })
        }
    }

    /// A stream whose close is still queued in the endpoint is gone from
    /// the swarm, yet abandoning it drops every queued event for it.
    #[cfg(feature = "portable-mdns")]
    #[test]
    fn abandoning_a_stream_closed_in_held_events_drops_them() {
        let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
        let mut endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .mdns(BrokenMdns, MdnsConfig::default())
            .build(NoopTransport)
            .expect("mdns endpoint");
        let peer = Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();
        let (conn_id, stream_id) = (ConnectionId::new(1), StreamId::new(3));
        let other = EndpointEvent::ConnectionClosed {
            peer_id: peer.clone(),
            conn_id: ConnectionId::new(2),
        };
        endpoint.engine.events.extend([
            EndpointEvent::StreamData {
                peer_id: peer.clone(),
                conn_id,
                stream_id,
                data: minip2p_core::Bytes::from_static(b"late"),
            },
            EndpointEvent::StreamClosed {
                peer_id: peer.clone(),
                conn_id,
                stream_id,
            },
            other,
        ]);
        endpoint
            .abandon_stream(conn_id, stream_id, Now::from_millis(0))
            .expect("a held close proves the stream");
        assert!(
            matches!(
                endpoint.engine.events.make_contiguous(),
                [EndpointEvent::ConnectionClosed { conn_id, .. }] if *conn_id == ConnectionId::new(2)
            ),
            "{:?}",
            endpoint.engine.events
        );
    }

    /// A failed mDNS tick keeps the events the batch already queued: the
    /// deadline turns immediate, and the next poll returns them.
    #[cfg(feature = "portable-mdns")]
    #[test]
    fn a_failed_mdns_poll_keeps_its_collected_events_for_the_next() {
        let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
        let mut endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .mdns(BrokenMdns, MdnsConfig::default())
            .build(NoopTransport)
            .expect("mdns endpoint");
        let peer = Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();
        let target = PeerAddr::new(
            <Multiaddr as core::str::FromStr>::from_str("/ip4/192.0.2.1/tcp/4001").expect("addr"),
            peer,
        )
        .expect("peer addr");
        // The transport refuses the dial, so the attempt settles on the
        // endpoint pass that runs before the mDNS tick fails.
        let id = endpoint
            .connect(target, Now::from_millis(0))
            .expect("admitted");

        endpoint
            .poll(Now::from_millis(1))
            .expect_err("the carrier fails");
        assert_eq!(
            endpoint.next_deadline(Now::from_millis(1)),
            Some(Deadline::IMMEDIATE)
        );
        let events = endpoint.poll(Now::from_millis(2)).expect("poll");
        assert!(
            events.iter().any(|event| matches!(
                event,
                EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == id
            )),
            "{events:?}"
        );
    }

    #[test]
    fn portable_builder_constructs_a_protocol_ready_endpoint() {
        let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
        let mut endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .protocol("/example/1.0.0")
            .build(NoopTransport)
            .expect("portable endpoint configuration is valid");
        let remote = Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();

        assert_eq!(endpoint.peer_id(), &identity.peer_id());
        let now = Now::from_millis(0);
        assert!(matches!(
            endpoint.open_stream(&remote, "/example/1.0.0", now),
            Err(DriverError::Swarm(SwarmError::NotConnected { .. }))
        ));
        assert!(matches!(
            endpoint.open_stream(&remote, "/missing/1.0.0", now),
            Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
        ));

        let error = Endpoint::portable(&identity, ZeroEntropy)
            .protocol(minip2p_swarm::RESERVED_PROTOCOL_IDS[0])
            .build(NoopTransport)
            .err()
            .expect("reserved protocols must be rejected");
        assert!(matches!(
            error,
            PortableBuildError::Swarm(SwarmError::ReservedProtocol { .. })
        ));
    }

    #[test]
    fn portable_stats_count_identify_ready_peers() {
        let a_identity = Ed25519Keypair::from_secret_key_bytes([11; 32]);
        let b_identity = Ed25519Keypair::from_secret_key_bytes([12; 32]);
        let (a_transport, b_transport) =
            InMemoryTransport::pair(a_identity.peer_id(), b_identity.peer_id());
        let mut a = Endpoint::portable(&a_identity, ZeroEntropy)
            .build(a_transport)
            .expect("a endpoint configuration is valid");
        let mut b = Endpoint::portable(&b_identity, ZeroEntropy)
            .build(b_transport)
            .expect("b endpoint configuration is valid");

        for now_ms in 0..64 {
            a.poll(Now::from_millis(now_ms)).expect("drive a");
            b.poll(Now::from_millis(now_ms)).expect("drive b");
            if a.is_peer_ready(&b_identity.peer_id()) && b.is_peer_ready(&a_identity.peer_id()) {
                break;
            }
        }

        assert_eq!(a.stats().connected_peers, 1);
        assert_eq!(a.stats().ready_peers, 1);
        assert_eq!(b.stats().connected_peers, 1);
        assert_eq!(b.stats().ready_peers, 1);
        assert!(
            a.connection_id(&b_identity.peer_id()).is_some(),
            "connection id is visible through the State getter"
        );
        assert!(!a.bound_addresses().is_empty());
    }

    #[test]
    fn portable_connect_settles_when_the_peer_is_already_connected() {
        let a_identity = Ed25519Keypair::from_secret_key_bytes([21; 32]);
        let b_identity = Ed25519Keypair::from_secret_key_bytes([22; 32]);
        let (a_transport, b_transport) =
            InMemoryTransport::pair(a_identity.peer_id(), b_identity.peer_id());
        let mut a = Endpoint::portable(&a_identity, ZeroEntropy)
            .build(a_transport)
            .expect("a endpoint configuration is valid");
        let mut b = Endpoint::portable(&b_identity, ZeroEntropy)
            .build(b_transport)
            .expect("b endpoint configuration is valid");

        for now_ms in 0..64 {
            a.poll(Now::from_millis(now_ms)).expect("drive a");
            b.poll(Now::from_millis(now_ms)).expect("drive b");
            if a.connection_id(&b_identity.peer_id()).is_some() {
                break;
            }
        }
        let conn_id = a
            .connection_id(&b_identity.peer_id())
            .expect("pair is connected");
        let target = PeerAddr::new(
            "/ip4/192.0.2.2/udp/4002/quic-v1".parse().expect("address"),
            b_identity.peer_id(),
        )
        .expect("peer addr");
        let id = a
            .connect(target, Now::from_millis(80))
            .expect("connect admitted");
        let events = a.poll(Now::from_millis(80)).expect("drain settled");
        assert!(events.iter().any(|event| matches!(
            event,
            EndpointEvent::ConnectSettled {
                connect_id,
                outcome: ConnectOutcome::Connected { conn_id: settled },
                ..
            } if *connect_id == id && *settled == conn_id
        )));
    }

    #[test]
    fn portable_shutdown_closes_established_peers_and_releases_the_endpoint() {
        let identity = Ed25519Keypair::from_secret_key_bytes([9; 32]);
        let remote = Ed25519Keypair::from_secret_key_bytes([10; 32]).peer_id();
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().expect("address");
        let conn_id = ConnectionId::new(1);
        let closed = Rc::new(Cell::new(false));
        let transport = RecordingTransport {
            events: vec![TransportEvent::Connected {
                id: conn_id,
                endpoint: ConnectionEndpoint::with_peer_id(address.clone(), remote.clone()),
            }],
            local_address: address.clone(),
            next_stream_id: 0,
            closed: closed.clone(),
        };
        let mut endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .build(transport)
            .expect("portable endpoint configuration is valid");

        endpoint
            .poll(Now::from_millis(1))
            .expect("connection event is accepted");
        assert_eq!(
            endpoint.stats(),
            PortableEndpointStats {
                connected_peers: 1,
                ready_peers: 0,
                bound_addresses: vec![address],
            }
        );

        let events = endpoint
            .shutdown(Now::from_millis(2))
            .expect("shutdown succeeds");
        assert!(
            closed.get(),
            "the established transport connection was closed"
        );
        assert!(events.iter().any(|event| matches!(
            event,
            EndpointEvent::ConnectionClosed { peer_id, conn_id: closed_id, .. }
                if peer_id == &remote && closed_id == &conn_id
        )));
    }

    #[cfg(all(feature = "smoltcp", feature = "pubsub"))]
    #[test]
    fn smoltcp_shutdown_returns_gossipsub_events_still_in_the_agent() {
        use minip2p_pubsub::{GossipsubEvent, MESHSUB_PROTOCOL_ID_V11, Rpc, SubOpts, encode_frame};
        use smoltcp::iface::{Config, Interface};
        use smoltcp::phy::{Loopback, Medium};
        use smoltcp::wire::HardwareAddress;

        let identity = Ed25519Keypair::from_secret_key_bytes([70; 32]);
        let mut device = Loopback::new(Medium::Ip);
        let interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            smoltcp::time::Instant::from_millis(0),
        );
        let mut endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .smoltcp(SmoltcpStack::new(device, interface))
            .gossipsub()
            .build()
            .expect("embedded endpoint builds");

        // An inbound meshsub stream carrying a subscribe leaves
        // `PeerSubscribed` in the agent; nothing has polled it out yet.
        let peer = Ed25519Keypair::from_secret_key_bytes([71; 32]).peer_id();
        let (conn_id, stream_id) = (ConnectionId::new(1), StreamId::new(1));
        let agent = &mut endpoint.engine.gossipsub.as_mut().expect("gossipsub").agent;
        assert!(agent.handle_event(
            &SwarmEvent::StreamReady {
                peer_id: peer.clone(),
                conn_id,
                stream_id,
                protocol_id: MESHSUB_PROTOCOL_ID_V11.into(),
                initiated_locally: false,
            },
            0,
        ));
        let rpc = Rpc {
            subscriptions: vec![SubOpts {
                subscribe: Some(true),
                topic_id: Some("still-in-agent".into()),
            }],
            publish: Vec::new(),
            control: None,
        };
        assert!(agent.handle_event(
            &SwarmEvent::StreamData {
                peer_id: peer.clone(),
                conn_id,
                stream_id,
                data: Bytes::from(encode_frame(&rpc.encode())),
            },
            0,
        ));

        let events = endpoint.shutdown(Now::from_millis(0)).expect("shutdown");
        assert!(
            events.iter().any(|event| matches!(
                event,
                EndpointEvent::Gossipsub(GossipsubEvent::PeerSubscribed {
                    peer: returned,
                    topic,
                }) if returned == &peer && topic == "still-in-agent"
            )),
            "shutdown dropped a Gossipsub event still in the agent: {events:?}"
        );
    }
}
