extern crate alloc;

#[cfg(feature = "portable-mdns")]
use alloc::collections::BTreeMap;
#[cfg(all(feature = "smoltcp", feature = "pubsub"))]
use alloc::collections::VecDeque;
#[cfg(feature = "portable-mdns")]
use alloc::string::ToString;
use alloc::{string::String, vec::Vec};

pub use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol, TransportKind};
pub use minip2p_identity::Ed25519Keypair;
pub use minip2p_platform::{Deadline as PollDeadline, EntropySource, Now, SharedEntropy};
pub use minip2p_swarm::{
    DriverError, IdentifyMessage, SwarmBuilder, SwarmError, SwarmEvent, SwarmRuntime,
};
pub use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError};

#[cfg(feature = "portable-mdns")]
pub use minip2p_discovery::{
    BeaconConfig, DiscoveryEvent, DiscoverySource, KnownPeer, PeerDiscoveryConfig,
};
#[cfg(feature = "portable-mdns")]
pub use minip2p_mdns::{MdnsConfig, MdnsConfigError, MdnsError, MdnsEvent, MdnsIo};
#[cfg(feature = "smoltcp")]
pub use minip2p_mdns::{SmoltcpMdnsConfig, SmoltcpMdnsIo};
#[cfg(all(feature = "portable-autonat", not(feature = "nat")))]
pub use minip2p_nat::{
    ConnectId, NatConfig, NatEvent, Path, ReachabilityState, ReservationInfo, ReservationPolicy,
};
#[cfg(all(feature = "pubsub", not(feature = "std")))]
pub use minip2p_pubsub::{
    FloodsubConfig, GossipsubConfig, PublishError, PubsubConfig, PubsubConfigError, PubsubEvent,
    TopicError,
};
#[cfg(feature = "smoltcp")]
pub use minip2p_tcp::{SmoltcpConfig, SmoltcpStack, SmoltcpTcpProvider, smoltcp};
#[cfg(feature = "tcp")]
pub use minip2p_tcp::{TcpConfig, TcpProvider, TcpTransport};

#[cfg(feature = "portable-autonat")]
mod nat;

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

/// Caller-driven endpoint over an injected transport and entropy source.
///
/// Portable entry point for embedded systems and deterministic event loops.
/// It performs no blocking and never reads a system clock. Callers drive it
/// with [`poll`](Self::poll) and may inspect
/// [`next_deadline`](Self::next_deadline) to decide how long their platform
/// loop can idle.
///
/// Call [`shutdown`](Self::shutdown) to notify established peers before the
/// endpoint is dropped. There is no `Drop` disconnect: this type offers
/// [`into_runtime`](Self::into_runtime), and `Drop` cannot `poll` without a
/// caller [`Now`]. Transport destructors still close leftover sockets.
pub struct PortableEndpoint<T: Transport, E: EntropySource> {
    runtime: SwarmRuntime<T, E>,
}

/// Lightweight snapshot of portable endpoint state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableEndpointStats {
    /// Number of peers with an established transport connection.
    pub connected_peers: usize,
    /// Number of connected peers that completed Identify and are ready for
    /// application protocols.
    pub ready_peers: usize,
    /// Addresses currently exposed by the transport as listening locally.
    pub listen_addresses: Vec<Multiaddr>,
}

impl<T: Transport, E: EntropySource> PortableEndpoint<T, E> {
    /// Returns this endpoint's peer ID.
    pub fn peer_id(&self) -> &PeerId {
        self.runtime.local_peer_id()
    }

    /// Returns the underlying caller-driven runtime.
    pub fn runtime(&self) -> &SwarmRuntime<T, E> {
        &self.runtime
    }

    /// Returns mutable access to the underlying caller-driven runtime.
    pub fn runtime_mut(&mut self) -> &mut SwarmRuntime<T, E> {
        &mut self.runtime
    }

    /// Consumes the endpoint and returns its underlying runtime.
    pub fn into_runtime(self) -> SwarmRuntime<T, E> {
        self.runtime
    }

    /// Starts listening on a transport address.
    pub fn listen(&mut self, address: &Multiaddr) -> Result<Multiaddr, DriverError> {
        self.runtime.listen(address)
    }

    /// Starts listening on every address already bound by the transport.
    pub fn listen_all(&mut self) -> Result<Vec<PeerAddr>, DriverError> {
        self.runtime.listen_on_bound_addrs()
    }

    /// Starts dialing a peer address.
    pub fn dial(&mut self, address: &PeerAddr) -> Result<ConnectionId, DriverError> {
        self.runtime.dial(address)
    }

    /// Returns peers with an established transport connection.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.runtime.connected_peers()
    }

    /// Returns whether a peer completed Identify and is ready for application protocols.
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.runtime.is_peer_ready(peer_id)
    }

    /// Returns the latest Identify information received for a peer.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.runtime.peer_info(peer_id)
    }

    /// Sets externally validated addresses to advertise through Identify.
    pub fn set_external_addresses(&mut self, addresses: Vec<Multiaddr>) {
        self.runtime.set_external_addresses(addresses);
    }

    /// Requests a ping using the caller's time sample.
    pub fn ping(&mut self, peer_id: &PeerId, now: Now) -> Result<(), DriverError> {
        self.runtime.ping(peer_id, now.monotonic_ms)
    }

    /// Disconnects from a peer.
    pub fn disconnect(&mut self, peer_id: &PeerId, now: Now) -> Result<(), DriverError> {
        self.runtime.disconnect(peer_id, now.monotonic_ms)
    }

    /// Opens an outbound application stream.
    pub fn open_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        now: Now,
    ) -> Result<StreamId, DriverError> {
        self.runtime
            .open_stream(peer_id, protocol_id, now.monotonic_ms)
    }

    /// Sends bytes on an application stream.
    pub fn send_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: Vec<u8>,
        now: Now,
    ) -> Result<(), DriverError> {
        self.runtime
            .send_stream(peer_id, stream_id, data, now.monotonic_ms)
    }

    /// Half-closes the local write side of an application stream.
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        self.runtime
            .close_stream_write(peer_id, stream_id, now.monotonic_ms)
    }

    /// Abruptly resets an application stream.
    pub fn reset_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        self.runtime
            .reset_stream(peer_id, stream_id, now.monotonic_ms)
    }

    /// Resets a stream and removes all swarm bookkeeping for it.
    pub fn abandon_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        self.runtime
            .abandon_stream(peer_id, stream_id, now.monotonic_ms)
    }

    /// Returns a lightweight state snapshot without driving the endpoint.
    pub fn stats(&self) -> PortableEndpointStats {
        let connected = self.runtime.connected_peers();
        PortableEndpointStats {
            ready_peers: connected
                .iter()
                .filter(|peer_id| self.runtime.is_peer_ready(peer_id))
                .count(),
            connected_peers: connected.len(),
            listen_addresses: self.runtime.transport().local_addresses(),
        }
    }

    /// Advances transport and protocol state using one host-supplied time sample.
    pub fn poll(&mut self, now: Now) -> Result<alloc::vec::Vec<SwarmEvent>, DriverError> {
        self.runtime.poll(now)
    }

    /// Returns when the endpoint next needs to be polled.
    pub fn next_deadline(&self, now: Now) -> Option<PollDeadline> {
        self.runtime.next_deadline(now)
    }

    /// Gracefully closes established peers, drives the resulting actions once,
    /// and consumes the endpoint.
    ///
    /// Consuming `self` is intentional: after the final drive, dropping the
    /// transport releases listeners and in-progress connections as well as
    /// established ones. Every established peer is attempted even if an
    /// earlier close fails. The first close error wins over a later poll error.
    ///
    /// Portable endpoints do not implement `Drop` close: [`Self::into_runtime`]
    /// moves the runtime out, and `Drop` cannot `poll` without a caller
    /// `Now`. Call `shutdown` before dropping when peers should be notified.
    /// Transport `Drop` still closes leftover TCP sockets. QUIC is std-only;
    /// the std `Endpoint` `close`/`Drop` path covers that case.
    /// Neither this nor std `Drop` can notify a peer after `kill -9` or a
    /// hard partition — those wait for the transport idle timeout.
    pub fn shutdown(mut self, now: Now) -> Result<Vec<SwarmEvent>, DriverError> {
        let mut first_error = None;
        for peer_id in self.runtime.connected_peers() {
            if let Err(error) = self.runtime.disconnect(&peer_id, now.monotonic_ms)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        let events = self.runtime.poll(now);
        match first_error {
            Some(error) => Err(error),
            None => events,
        }
    }

    /// Adds caller-driven mDNS discovery to this portable endpoint.
    #[cfg(feature = "portable-mdns")]
    pub fn with_mdns<I: MdnsIo>(
        self,
        io: I,
        config: MdnsConfig,
        seed: [u8; 32],
    ) -> Result<PortableMdnsEndpoint<T, E, I>, PortableMdnsConfigError> {
        self.with_mdns_config(io, config, PeerDiscoveryConfig::default(), seed)
    }

    /// Adds mDNS with explicit bounded peer-book and automatic-dial policy.
    #[cfg(feature = "portable-mdns")]
    pub fn with_mdns_config<I: MdnsIo>(
        self,
        io: I,
        mdns_config: MdnsConfig,
        discovery_config: PeerDiscoveryConfig,
        seed: [u8; 32],
    ) -> Result<PortableMdnsEndpoint<T, E, I>, PortableMdnsConfigError> {
        let agent =
            minip2p_mdns::MdnsAgent::new(self.peer_id().clone(), mdns_config.clone(), seed)?;
        let local_peer_id = self.peer_id().clone();
        Ok(PortableMdnsEndpoint {
            endpoint: self,
            mdns: minip2p_mdns::MdnsDriver::new(agent, io, &mdns_config),
            discovery: minip2p_discovery::PeerDiscoveryAgent::new(local_peer_id, discovery_config)?,
            active_dials: BTreeMap::new(),
        })
    }
}

/// Invalid portable mDNS or peer-discovery configuration.
#[cfg(feature = "portable-mdns")]
#[derive(Debug)]
pub enum PortableMdnsConfigError {
    /// Invalid mDNS wire or scheduling policy.
    Mdns(MdnsConfigError),
    /// Invalid bounded peer-book or automatic-dial policy.
    Discovery(minip2p_discovery::DiscoveryConfigError),
}

#[cfg(feature = "portable-mdns")]
impl From<MdnsConfigError> for PortableMdnsConfigError {
    fn from(error: MdnsConfigError) -> Self {
        Self::Mdns(error)
    }
}

#[cfg(feature = "portable-mdns")]
impl From<minip2p_discovery::DiscoveryConfigError> for PortableMdnsConfigError {
    fn from(error: minip2p_discovery::DiscoveryConfigError) -> Self {
        Self::Discovery(error)
    }
}

#[cfg(feature = "portable-mdns")]
impl core::fmt::Display for PortableMdnsConfigError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Mdns(error) => error.fmt(formatter),
            Self::Discovery(error) => error.fmt(formatter),
        }
    }
}

/// Event produced by a portable endpoint with mDNS enabled.
#[cfg(feature = "portable-mdns")]
#[derive(Clone, Debug)]
pub enum PortableMdnsEvent {
    /// Ordinary endpoint protocol or connection progress.
    Endpoint(SwarmEvent),
    /// Bounded peer-book and automatic-dial observation.
    Discovery(DiscoveryEvent),
}

/// Portable endpoint composed with an injected mDNS carrier.
#[cfg(feature = "portable-mdns")]
pub struct PortableMdnsEndpoint<T: Transport, E: EntropySource, I: MdnsIo> {
    endpoint: PortableEndpoint<T, E>,
    mdns: minip2p_mdns::MdnsDriver<I>,
    discovery: minip2p_discovery::PeerDiscoveryAgent,
    active_dials: BTreeMap<PeerId, ConnectionId>,
}

#[cfg(feature = "portable-mdns")]
impl<T: Transport, E: EntropySource, I: MdnsIo> core::ops::Deref for PortableMdnsEndpoint<T, E, I> {
    type Target = PortableEndpoint<T, E>;

    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}

#[cfg(feature = "portable-mdns")]
impl<T: Transport, E: EntropySource, I: MdnsIo> core::ops::DerefMut
    for PortableMdnsEndpoint<T, E, I>
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.endpoint
    }
}

#[cfg(feature = "portable-mdns")]
impl<T: Transport, E: EntropySource, I: MdnsIo> PortableMdnsEndpoint<T, E, I> {
    /// Returns the bounded, TTL-aware peer book populated by mDNS.
    pub fn known_peers(&self) -> Vec<KnownPeer> {
        self.discovery.known_peers()
    }

    /// Borrows the mDNS carrier, or `None` after it has stopped.
    pub fn mdns_io(&self) -> Option<&I> {
        self.mdns.io()
    }

    /// Mutably borrows the mDNS carrier for platform reconfiguration.
    pub fn mdns_io_mut(&mut self) -> Option<&mut I> {
        self.mdns.io_mut()
    }

    /// Advances the endpoint, mDNS carrier, and automatic local-peer dialing.
    pub fn poll(&mut self, now: Now) -> Result<Vec<PortableMdnsEvent>, PortableMdnsError> {
        let mut events = Vec::new();
        self.poll_endpoint(now, &mut events)?;

        let local_addrs = self.endpoint.stats().listen_addresses;
        self.mdns.tick(now.monotonic_ms, &local_addrs)?;
        // The mDNS carrier drives the shared interface. That may place TCP
        // bytes into a socket after the transport was serviced above, so run
        // the endpoint once more before computing a sleep deadline.
        self.poll_endpoint(now, &mut events)?;
        while let Some(event) = self.mdns.poll_event() {
            match event {
                MdnsEvent::PeerObserved { peer, addrs } => {
                    self.discovery.observe_mdns(peer, addrs, now.monotonic_ms);
                }
                MdnsEvent::ProtocolViolation { peer, reason } => {
                    self.discovery.report_violation(
                        peer,
                        minip2p_discovery::DiscoverySource::Mdns,
                        &reason,
                    );
                }
            }
        }
        self.discovery.handle_tick(now.monotonic_ms);
        self.drive_discovery_actions(now)?;
        while let Some(event) = self.discovery.poll_event() {
            events.push(PortableMdnsEvent::Discovery(event));
        }
        Ok(events)
    }

    fn poll_endpoint(
        &mut self,
        now: Now,
        events: &mut Vec<PortableMdnsEvent>,
    ) -> Result<(), DriverError> {
        for event in self.endpoint.poll(now)? {
            match &event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    self.active_dials.remove(peer_id);
                    self.discovery.dial_succeeded(peer_id, now.monotonic_ms);
                    self.discovery.peer_connected(peer_id, now.monotonic_ms);
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    self.discovery.peer_disconnected(peer_id, now.monotonic_ms);
                }
                SwarmEvent::Error(error) => {
                    if let Some(peer_id) = remove_failed_autodial(
                        &mut self.active_dials,
                        error.peer_id.as_ref(),
                        error.conn_id,
                    ) {
                        self.discovery
                            .dial_failed(&peer_id, &error.detail, now.monotonic_ms);
                    }
                }
                _ => {}
            }
            events.push(PortableMdnsEvent::Endpoint(event));
        }
        Ok(())
    }

    /// Returns the earliest endpoint or mDNS deadline.
    pub fn next_deadline(&self, now: Now) -> Option<PollDeadline> {
        let mdns = self
            .mdns
            .next_timeout(now.monotonic_ms)
            .map(|timeout| PollDeadline::from_millis(now.monotonic_ms.saturating_add(timeout)));
        let discovery = self
            .discovery
            .next_timeout(now.monotonic_ms)
            .map(|timeout| PollDeadline::from_millis(now.monotonic_ms.saturating_add(timeout)));
        PollDeadline::earliest_opt(
            PollDeadline::earliest_opt(self.endpoint.next_deadline(now), mdns),
            discovery,
        )
    }

    /// Sends mDNS goodbyes, closes peers, and consumes the composed endpoint.
    pub fn shutdown(mut self, now: Now) -> Result<Vec<PortableMdnsEvent>, PortableMdnsError> {
        self.mdns.shutdown(now.monotonic_ms)?;
        Ok(self
            .endpoint
            .shutdown(now)?
            .into_iter()
            .map(PortableMdnsEvent::Endpoint)
            .collect())
    }

    fn drive_discovery_actions(&mut self, now: Now) -> Result<(), PortableMdnsError> {
        while let Some(action) = self.discovery.poll_action() {
            match action {
                minip2p_discovery::DiscoveryAction::Dial { peer, addrs, .. } => {
                    let mut started = None;
                    let mut last_error = None;
                    for address in addrs {
                        let Ok(target) = PeerAddr::new(address, peer.clone()) else {
                            continue;
                        };
                        match self.endpoint.dial(&target) {
                            Ok(connection) => {
                                started = Some(connection);
                                break;
                            }
                            Err(error) => last_error = Some(error),
                        }
                    }
                    if let Some(connection) = started {
                        self.active_dials.insert(peer, connection);
                    } else {
                        let reason = last_error
                            .map(|error| error.to_string())
                            .unwrap_or_else(|| "mDNS supplied no dialable address".into());
                        self.discovery.dial_failed(&peer, &reason, now.monotonic_ms);
                    }
                }
                minip2p_discovery::DiscoveryAction::CancelDial { peer } => {
                    if let Some(connection) = self.active_dials.remove(&peer) {
                        let close = self
                            .endpoint
                            .runtime_mut()
                            .transport_mut()
                            .close(connection);
                        match close {
                            Ok(())
                            | Err(
                                TransportError::ConnectionNotFound { .. }
                                | TransportError::InvalidState { .. },
                            ) => {}
                            Err(error) => return Err(DriverError::from(error).into()),
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "portable-mdns")]
fn remove_failed_autodial(
    active: &mut BTreeMap<PeerId, ConnectionId>,
    peer_id: Option<&PeerId>,
    connection: Option<ConnectionId>,
) -> Option<PeerId> {
    let peer = peer_id
        .filter(|peer| active.contains_key(*peer))
        .cloned()
        .or_else(|| {
            connection.and_then(|failed| {
                active
                    .iter()
                    .find_map(|(peer, current)| (*current == failed).then(|| peer.clone()))
            })
        })?;
    active.remove(&peer);
    Some(peer)
}

/// Failure while driving a portable endpoint with mDNS.
#[cfg(feature = "portable-mdns")]
#[derive(Debug)]
pub enum PortableMdnsError {
    /// Endpoint transport or swarm failure.
    Endpoint(DriverError),
    /// mDNS carrier failure.
    Mdns(MdnsError),
}

#[cfg(feature = "portable-mdns")]
impl From<DriverError> for PortableMdnsError {
    fn from(error: DriverError) -> Self {
        Self::Endpoint(error)
    }
}

#[cfg(feature = "portable-mdns")]
impl From<MdnsError> for PortableMdnsError {
    fn from(error: MdnsError) -> Self {
        Self::Mdns(error)
    }
}

#[cfg(feature = "portable-mdns")]
impl core::fmt::Display for PortableMdnsError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Endpoint(error) => error.fmt(formatter),
            Self::Mdns(error) => error.fmt(formatter),
        }
    }
}

/// Builder for a [`PortableEndpoint`].
pub struct PortableEndpointBuilder<E> {
    swarm: SwarmBuilder,
    #[cfg(feature = "smoltcp")]
    identity: Ed25519Keypair,
    entropy: E,
}

impl<E: EntropySource> PortableEndpointBuilder<E> {
    /// Starts a builder with explicit identity and entropy.
    pub fn new(identity: &Ed25519Keypair, entropy: E) -> Self {
        Self {
            swarm: SwarmBuilder::new(identity),
            #[cfg(feature = "smoltcp")]
            identity: identity.clone(),
            entropy,
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

    /// Builds the portable endpoint over a caller-provided transport.
    pub fn build<T: Transport>(self, transport: T) -> Result<PortableEndpoint<T, E>, SwarmError> {
        Ok(PortableEndpoint {
            runtime: self.swarm.build_runtime(transport, self.entropy)?,
        })
    }

    /// Selects the embedded smoltcp TCP backend over a host-configured stack.
    #[cfg(feature = "smoltcp")]
    pub fn smoltcp<D: smoltcp::phy::Device>(
        self,
        stack: SmoltcpStack<D>,
    ) -> SmoltcpEndpointBuilder<D, E> {
        SmoltcpEndpointBuilder {
            swarm: self.swarm,
            identity: self.identity,
            entropy: SharedEntropy::new(self.entropy),
            stack,
            tcp_config: TcpConfig::default(),
            provider_config: SmoltcpConfig::default(),
            listens: Vec::new(),
            mdns: None,
            #[cfg(feature = "pubsub")]
            pubsub: None,
            #[cfg(feature = "pubsub")]
            beacon: None,
            #[cfg(feature = "portable-autonat")]
            nat_config: None,
            discovery: PeerDiscoveryConfig::default(),
        }
    }
}

/// Embedded mDNS and peer-discovery configuration.
#[cfg(feature = "smoltcp")]
struct EmbeddedMdnsConfig {
    mdns: MdnsConfig,
    carrier: SmoltcpMdnsConfig,
}

/// Specialized builder for a portable endpoint over one shared smoltcp stack.
#[cfg(feature = "smoltcp")]
pub struct SmoltcpEndpointBuilder<D: smoltcp::phy::Device, E: EntropySource> {
    swarm: SwarmBuilder,
    identity: Ed25519Keypair,
    entropy: SharedEntropy<E>,
    stack: SmoltcpStack<D>,
    tcp_config: TcpConfig,
    provider_config: SmoltcpConfig,
    listens: Vec<String>,
    mdns: Option<EmbeddedMdnsConfig>,
    #[cfg(feature = "pubsub")]
    pubsub: Option<PubsubConfig>,
    #[cfg(feature = "pubsub")]
    beacon: Option<BeaconConfig>,
    #[cfg(feature = "portable-autonat")]
    nat_config: Option<minip2p_nat::NatConfig>,
    discovery: PeerDiscoveryConfig,
}

#[cfg(feature = "smoltcp")]
type SmoltcpTcpTransport<D, E> = TcpTransport<SmoltcpTcpProvider<D>, SharedEntropy<E>>;

#[cfg(all(feature = "smoltcp", not(feature = "portable-relay")))]
type SmoltcpComposedTransport<D, E> = SmoltcpTcpTransport<D, E>;

#[cfg(feature = "portable-relay")]
type SmoltcpComposedTransport<D, E> =
    minip2p_circuit::CircuitTransport<SmoltcpTcpTransport<D, E>, SharedEntropy<E>>;

/// Caller-driven endpoint over one shared smoltcp stack.
#[cfg(feature = "smoltcp")]
pub struct SmoltcpEndpoint<D: smoltcp::phy::Device, E: EntropySource> {
    endpoint: PortableEndpoint<SmoltcpComposedTransport<D, E>, SharedEntropy<E>>,
    mdns: Option<minip2p_mdns::MdnsDriver<SmoltcpMdnsIo<D>>>,
    #[cfg(feature = "pubsub")]
    pubsub: Option<minip2p_pubsub::PubsubAgent>,
    #[cfg(feature = "pubsub")]
    pending_pubsub_events: VecDeque<PubsubEvent>,
    #[cfg(feature = "pubsub")]
    beacon: Option<minip2p_discovery::BeaconAgent>,
    #[cfg(feature = "portable-autonat")]
    nat: Option<nat::PortableNatDriver>,
    discovery: Option<minip2p_discovery::PeerDiscoveryAgent>,
    active_dials: BTreeMap<PeerId, ConnectionId>,
}

/// Event emitted by the composed embedded endpoint.
#[cfg(feature = "smoltcp")]
#[derive(Clone, Debug)]
pub enum SmoltcpEvent {
    /// Ordinary connection, Identify, Ping, or application-stream progress.
    Endpoint(SwarmEvent),
    /// Application-visible pubsub progress.
    #[cfg(feature = "pubsub")]
    Pubsub(PubsubEvent),
    /// Relay reservation, circuit-path, or reachability progress.
    #[cfg(feature = "portable-autonat")]
    Nat(minip2p_nat::NatEvent),
    /// A change or violation from the shared discovery book.
    Discovery(DiscoveryEvent),
}

#[cfg(feature = "smoltcp")]
impl<D: smoltcp::phy::Device, E: EntropySource> core::ops::Deref for SmoltcpEndpoint<D, E> {
    type Target = PortableEndpoint<SmoltcpComposedTransport<D, E>, SharedEntropy<E>>;

    fn deref(&self) -> &Self::Target {
        &self.endpoint
    }
}

#[cfg(feature = "smoltcp")]
impl<D: smoltcp::phy::Device, E: EntropySource> core::ops::DerefMut for SmoltcpEndpoint<D, E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.endpoint
    }
}

#[cfg(feature = "smoltcp")]
impl<D: smoltcp::phy::Device, E: EntropySource> SmoltcpEndpoint<D, E> {
    /// Starts a relay-only connection attempt toward `peer`.
    #[cfg(feature = "portable-relay")]
    pub fn connect_relay(
        &mut self,
        peer: &PeerId,
        now: Now,
    ) -> Result<minip2p_nat::ConnectId, SmoltcpRelayError> {
        let nat = self.nat.as_mut().ok_or(SmoltcpRelayError::NotEnabled)?;
        if !nat.relay_enabled() {
            return Err(SmoltcpRelayError::NotEnabled);
        }
        let id = nat.connect(peer.clone(), now);
        nat.pump(&mut self.endpoint, now);
        Ok(id)
    }

    /// Cancels one relay connection attempt.
    #[cfg(feature = "portable-relay")]
    pub fn cancel_connect(&mut self, id: minip2p_nat::ConnectId, now: Now) {
        if let Some(nat) = self.nat.as_mut() {
            nat.cancel(id, now);
            nat.pump(&mut self.endpoint, now);
        }
    }

    /// Returns the latest NAT-orchestrated path to `peer`.
    #[cfg(feature = "portable-relay")]
    pub fn path(&self, peer: &PeerId) -> Option<minip2p_nat::Path> {
        self.nat.as_ref().and_then(|nat| nat.path(peer))
    }

    /// Returns the currently held relay reservation, when any.
    #[cfg(feature = "portable-relay")]
    pub fn active_reservation(&self) -> Option<minip2p_nat::ReservationInfo> {
        self.nat
            .as_ref()
            .and_then(nat::PortableNatDriver::active_reservation)
    }

    /// Returns the current portable AutoNAT reachability verdict.
    #[cfg(feature = "portable-autonat")]
    pub fn reachability(&self) -> minip2p_nat::ReachabilityState {
        self.nat
            .as_ref()
            .map(|nat| nat.agent.reachability())
            .unwrap_or_default()
    }

    /// Subscribes to an application topic.
    #[cfg(feature = "pubsub")]
    pub fn subscribe(&mut self, topic: &str, now: Now) -> Result<bool, SmoltcpPubsubError> {
        let agent = self.pubsub.as_mut().ok_or(SmoltcpPubsubError::NotEnabled)?;
        let subscribed = agent.subscribe(topic, now.monotonic_ms)?;
        pump_embedded_pubsub(agent, &mut self.endpoint, now);
        collect_embedded_pubsub_events(agent, &mut self.pending_pubsub_events);
        Ok(subscribed)
    }

    /// Withdraws an application topic subscription.
    #[cfg(feature = "pubsub")]
    pub fn unsubscribe(&mut self, topic: &str, now: Now) -> Result<bool, SmoltcpPubsubError> {
        if self
            .beacon
            .as_ref()
            .is_some_and(|beacon| beacon.topic() == topic)
        {
            return Err(SmoltcpPubsubError::DiscoveryTopicReserved);
        }
        let agent = self.pubsub.as_mut().ok_or(SmoltcpPubsubError::NotEnabled)?;
        let removed = agent.unsubscribe(topic, now.monotonic_ms);
        pump_embedded_pubsub(agent, &mut self.endpoint, now);
        collect_embedded_pubsub_events(agent, &mut self.pending_pubsub_events);
        Ok(removed)
    }

    /// Publishes one application message.
    #[cfg(feature = "pubsub")]
    pub fn publish(
        &mut self,
        topic: &str,
        data: impl Into<Vec<u8>>,
        now: Now,
    ) -> Result<(), SmoltcpPubsubError> {
        if self
            .beacon
            .as_ref()
            .is_some_and(|beacon| beacon.topic() == topic)
        {
            return Err(SmoltcpPubsubError::DiscoveryTopicReserved);
        }
        let agent = self.pubsub.as_mut().ok_or(SmoltcpPubsubError::NotEnabled)?;
        agent.publish(topic, data.into(), now.monotonic_ms)?;
        pump_embedded_pubsub(agent, &mut self.endpoint, now);
        collect_embedded_pubsub_events(agent, &mut self.pending_pubsub_events);
        Ok(())
    }

    /// Returns the bounded peer book shared by mDNS and signed beacons.
    pub fn known_peers(&self) -> Vec<KnownPeer> {
        self.discovery
            .as_ref()
            .map(minip2p_discovery::PeerDiscoveryAgent::known_peers)
            .unwrap_or_default()
    }

    /// Advances TCP and every configured embedded service once.
    pub fn poll(&mut self, now: Now) -> Result<Vec<SmoltcpEvent>, SmoltcpDriveError> {
        let mut output = Vec::new();
        self.poll_swarm(now, &mut output)?;
        if let Some(mdns) = self.mdns.as_mut() {
            mdns.tick(now.monotonic_ms, &self.endpoint.stats().listen_addresses)?;
        }
        if self.mdns.is_some() {
            self.poll_swarm(now, &mut output)?;
        }
        if let Some(mdns) = self.mdns.as_mut() {
            while let Some(event) = mdns.poll_event() {
                if let Some(discovery) = self.discovery.as_mut() {
                    match event {
                        MdnsEvent::PeerObserved { peer, addrs } => {
                            discovery.observe_mdns(peer, addrs, now.monotonic_ms);
                        }
                        MdnsEvent::ProtocolViolation { peer, reason } => discovery
                            .report_violation(
                                peer,
                                minip2p_discovery::DiscoverySource::Mdns,
                                &reason,
                            ),
                    }
                }
            }
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.pubsub.as_mut() {
            if pubsub.next_timeout(now.monotonic_ms) == Some(0) {
                pubsub.handle_tick(now.monotonic_ms);
            }
            pump_embedded_pubsub(pubsub, &mut self.endpoint, now);
        }
        #[cfg(feature = "pubsub")]
        self.drive_beacon(now, &mut output);
        #[cfg(feature = "portable-autonat")]
        if let Some(nat) = self.nat.as_mut() {
            nat.tick(&mut self.endpoint, now);
            while let Some(event) = nat.events.pop_front() {
                output.push(SmoltcpEvent::Nat(event));
            }
        }
        if let Some(discovery) = self.discovery.as_mut()
            && discovery.next_timeout(now.monotonic_ms) == Some(0)
        {
            discovery.handle_tick(now.monotonic_ms);
        }
        self.drive_discovery_actions(now)?;
        if let Some(discovery) = self.discovery.as_mut() {
            while let Some(event) = discovery.poll_event() {
                output.push(SmoltcpEvent::Discovery(event));
            }
        }
        Ok(output)
    }

    fn poll_swarm(&mut self, now: Now, output: &mut Vec<SmoltcpEvent>) -> Result<(), DriverError> {
        for event in self.endpoint.poll(now)? {
            if let Some(discovery) = self.discovery.as_mut() {
                match &event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        self.active_dials.remove(peer_id);
                        discovery.dial_succeeded(peer_id, now.monotonic_ms);
                        discovery.peer_connected(peer_id, now.monotonic_ms);
                    }
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        discovery.peer_disconnected(peer_id, now.monotonic_ms);
                    }
                    SwarmEvent::Error(error) => {
                        if let Some(peer) = remove_failed_autodial(
                            &mut self.active_dials,
                            error.peer_id.as_ref(),
                            error.conn_id,
                        ) {
                            discovery.dial_failed(&peer, &error.detail, now.monotonic_ms);
                        }
                    }
                    _ => {}
                }
            }
            #[cfg(feature = "portable-autonat")]
            let claimed = self
                .nat
                .as_mut()
                .is_some_and(|nat| nat.ingest(&event, &mut self.endpoint, now));
            #[cfg(not(feature = "portable-autonat"))]
            let claimed = false;
            #[cfg(feature = "pubsub")]
            let claimed = claimed
                || self
                    .pubsub
                    .as_mut()
                    .is_some_and(|agent| agent.handle_event(&event, now.monotonic_ms));
            #[cfg(feature = "pubsub")]
            if let Some(agent) = self.pubsub.as_mut() {
                pump_embedded_pubsub(agent, &mut self.endpoint, now);
            }
            if !claimed {
                output.push(SmoltcpEvent::Endpoint(event));
            }
        }
        Ok(())
    }

    #[cfg(feature = "pubsub")]
    fn drive_beacon(&mut self, now: Now, output: &mut Vec<SmoltcpEvent>) {
        let Some(beacon) = self.beacon.as_mut() else {
            if let Some(pubsub) = self.pubsub.as_mut() {
                collect_embedded_pubsub_events(pubsub, &mut self.pending_pubsub_events);
            }
            output.extend(
                self.pending_pubsub_events
                    .drain(..)
                    .map(SmoltcpEvent::Pubsub),
            );
            return;
        };
        beacon.set_local_addrs(&self.endpoint.stats().listen_addresses, now.monotonic_ms);
        if beacon.next_timeout(now.monotonic_ms) == Some(0) {
            beacon.handle_tick(now.monotonic_ms);
        }
        if let Some(pubsub) = self.pubsub.as_mut() {
            collect_embedded_pubsub_events(pubsub, &mut self.pending_pubsub_events);
            while let Some(event) = self.pending_pubsub_events.pop_front() {
                let consumed = match &event {
                    PubsubEvent::Message {
                        from,
                        topics,
                        data,
                        signed,
                        ..
                    } if topics.iter().any(|topic| topic == beacon.topic()) => {
                        beacon.handle_beacon(from, data, *signed);
                        true
                    }
                    PubsubEvent::PeerSubscribed { topic, .. }
                    | PubsubEvent::PeerUnsubscribed { topic, .. }
                        if topic == beacon.topic() =>
                    {
                        true
                    }
                    _ => false,
                };
                if !consumed {
                    output.push(SmoltcpEvent::Pubsub(event));
                }
            }
            while let Some(minip2p_discovery::BeaconAction::PublishBeacon { topic, payload }) =
                beacon.poll_action()
            {
                // Beacon publication is best-effort, matching the hosted
                // driver. Backpressure must not discard events already
                // collected by this poll; the next interval announces again.
                if pubsub.publish(&topic, payload, now.monotonic_ms).is_ok() {
                    pump_embedded_pubsub(pubsub, &mut self.endpoint, now);
                }
            }
            collect_embedded_pubsub_events(pubsub, &mut self.pending_pubsub_events);
            while let Some(event) = self.pending_pubsub_events.pop_front() {
                output.push(SmoltcpEvent::Pubsub(event));
            }
        }
        if let Some(discovery) = self.discovery.as_mut() {
            while let Some(event) = beacon.poll_event() {
                match event {
                    minip2p_discovery::BeaconEvent::Observation(observation) => {
                        discovery.observe_beacon(observation, now.monotonic_ms);
                    }
                    minip2p_discovery::BeaconEvent::ProtocolViolation { peer, reason } => {
                        discovery.report_violation(
                            Some(peer),
                            minip2p_discovery::DiscoverySource::SignedBeacon,
                            &reason,
                        );
                    }
                }
            }
        }
    }

    fn drive_discovery_actions(&mut self, now: Now) -> Result<(), DriverError> {
        let Some(discovery) = self.discovery.as_mut() else {
            return Ok(());
        };
        while let Some(action) = discovery.poll_action() {
            match action {
                minip2p_discovery::DiscoveryAction::Dial { peer, addrs, .. } => {
                    let mut started = None;
                    let mut last_error = None;
                    for address in addrs {
                        let Ok(target) = PeerAddr::new(address, peer.clone()) else {
                            continue;
                        };
                        match self.endpoint.dial(&target) {
                            Ok(connection) => {
                                started = Some(connection);
                                break;
                            }
                            Err(error) => last_error = Some(error),
                        }
                    }
                    if let Some(connection) = started {
                        self.active_dials.insert(peer, connection);
                    } else {
                        let reason = last_error
                            .map(|error| error.to_string())
                            .unwrap_or_else(|| "discovery supplied no dialable address".into());
                        discovery.dial_failed(&peer, &reason, now.monotonic_ms);
                    }
                }
                minip2p_discovery::DiscoveryAction::CancelDial { peer } => {
                    if let Some(connection) = self.active_dials.remove(&peer) {
                        match self
                            .endpoint
                            .runtime_mut()
                            .transport_mut()
                            .close(connection)
                        {
                            Ok(())
                            | Err(
                                TransportError::ConnectionNotFound { .. }
                                | TransportError::InvalidState { .. },
                            ) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Returns the earliest deadline across TCP and configured services.
    pub fn next_deadline(&self, now: Now) -> Option<PollDeadline> {
        let mut deadline = self.endpoint.next_deadline(now);
        let mut timeouts = Vec::new();
        timeouts.extend(
            self.mdns
                .as_ref()
                .and_then(|agent| agent.next_timeout(now.monotonic_ms)),
        );
        #[cfg(feature = "pubsub")]
        {
            if !self.pending_pubsub_events.is_empty() {
                deadline = PollDeadline::earliest_opt(deadline, Some(PollDeadline::IMMEDIATE));
            }
            timeouts.extend(
                self.pubsub
                    .as_ref()
                    .and_then(|agent| agent.next_timeout(now.monotonic_ms)),
            );
            timeouts.extend(
                self.beacon
                    .as_ref()
                    .and_then(|agent| agent.next_timeout(now.monotonic_ms)),
            );
        }
        #[cfg(feature = "portable-autonat")]
        if let Some(nat) = self.nat.as_ref()
            && let Some(timeout) = nat.agent.next_timeout(now.monotonic_ms)
        {
            deadline = PollDeadline::earliest_opt(
                deadline,
                Some(PollDeadline::from_millis(
                    now.monotonic_ms.saturating_add(timeout),
                )),
            );
            if !nat.events.is_empty() {
                deadline = PollDeadline::earliest_opt(deadline, Some(PollDeadline::IMMEDIATE));
            }
        }
        timeouts.extend(
            self.discovery
                .as_ref()
                .and_then(|agent| agent.next_timeout(now.monotonic_ms)),
        );
        for timeout in timeouts {
            deadline = PollDeadline::earliest_opt(
                deadline,
                Some(PollDeadline::from_millis(
                    now.monotonic_ms.saturating_add(timeout),
                )),
            );
        }
        deadline
    }

    /// Sends an mDNS goodbye when enabled, closes peers, and consumes the endpoint.
    pub fn shutdown(mut self, now: Now) -> Result<Vec<SmoltcpEvent>, SmoltcpDriveError> {
        if let Some(mdns) = self.mdns.as_mut() {
            mdns.shutdown(now.monotonic_ms)?;
        }
        Ok(self
            .endpoint
            .shutdown(now)?
            .into_iter()
            .map(SmoltcpEvent::Endpoint)
            .collect())
    }
}

#[cfg(feature = "smoltcp")]
#[cfg(feature = "pubsub")]
fn pump_embedded_pubsub<D: smoltcp::phy::Device, E: EntropySource>(
    agent: &mut minip2p_pubsub::PubsubAgent,
    endpoint: &mut PortableEndpoint<SmoltcpComposedTransport<D, E>, SharedEntropy<E>>,
    now: Now,
) {
    while let Some(action) = agent.poll_action() {
        match action {
            minip2p_pubsub::PubsubAction::OpenStream {
                token,
                peer,
                protocol_id,
            } => {
                let result = endpoint
                    .open_stream(&peer, &protocol_id, now)
                    .map_err(|e| e.to_string());
                agent.stream_open_result(&peer, token, result, now.monotonic_ms);
            }
            minip2p_pubsub::PubsubAction::SendStream {
                token,
                peer,
                stream_id,
                data,
            } => {
                let result = endpoint
                    .send_stream(&peer, stream_id, data, now)
                    .map_err(|e| e.to_string());
                agent.send_result(&peer, stream_id, token, result, now.monotonic_ms);
            }
            minip2p_pubsub::PubsubAction::CloseStreamWrite { peer, stream_id } => {
                let _ = endpoint.close_stream_write(&peer, stream_id, now);
            }
            minip2p_pubsub::PubsubAction::ResetStream { peer, stream_id } => {
                let _ = endpoint.reset_stream(&peer, stream_id, now);
            }
        }
    }
}

#[cfg(all(feature = "smoltcp", feature = "pubsub"))]
fn collect_embedded_pubsub_events(
    agent: &mut minip2p_pubsub::PubsubAgent,
    pending: &mut VecDeque<PubsubEvent>,
) {
    while let Some(event) = agent.poll_event() {
        pending.push_back(event);
    }
}

#[cfg(feature = "smoltcp")]
impl<D: smoltcp::phy::Device, E: EntropySource> SmoltcpEndpointBuilder<D, E> {
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

    /// Enables mDNS and bounded automatic local-peer discovery with defaults.
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
    pub fn pubsub(mut self) -> Self {
        self.pubsub.get_or_insert_with(PubsubConfig::default);
        self
    }

    /// Enables pubsub with an explicit gossipsub or floodsub configuration.
    #[cfg(feature = "pubsub")]
    pub fn pubsub_config(mut self, config: impl Into<PubsubConfig>) -> Self {
        self.pubsub = Some(config.into());
        self
    }

    /// Enables signed-beacon discovery. Pubsub is enabled automatically.
    #[cfg(feature = "pubsub")]
    pub fn discovery(mut self) -> Self {
        self.pubsub.get_or_insert_with(PubsubConfig::default);
        self.beacon.get_or_insert_with(BeaconConfig::default);
        self
    }

    /// Enables signed-beacon discovery with explicit beacon policy.
    #[cfg(feature = "pubsub")]
    pub fn beacon_config(mut self, config: BeaconConfig) -> Self {
        self.pubsub.get_or_insert_with(PubsubConfig::default);
        self.beacon = Some(config);
        self
    }

    /// Overrides the shared bounded peer-book and automatic-dial policy.
    pub fn discovery_config(mut self, config: PeerDiscoveryConfig) -> Self {
        self.discovery = config;
        self
    }

    /// Enables relay-only connectivity through one relay address.
    #[cfg(feature = "portable-relay")]
    pub fn relay(mut self, relay: PeerAddr) -> Self {
        let mut config = match self.nat_config.take() {
            Some(config) => config,
            None => minip2p_nat::NatConfig {
                reservation_policy: minip2p_nat::ReservationPolicy::Never,
                ..minip2p_nat::NatConfig::default()
            },
        };
        config.relays.push(relay);
        config.force_relay = true;
        self.nat_config = Some(config);
        self
    }

    /// Enables portable AutoNAT probing through one trusted server.
    #[cfg(feature = "portable-autonat")]
    pub fn autonat(mut self, server: PeerAddr) -> Self {
        self.nat_config
            .get_or_insert_with(|| minip2p_nat::NatConfig {
                reservation_policy: minip2p_nat::ReservationPolicy::Never,
                ..minip2p_nat::NatConfig::default()
            })
            .autonat_servers
            .push(server);
        self
    }

    /// Enables portable NAT policy with explicit relay and AutoNAT settings.
    ///
    /// TCP relay configurations must set `force_relay`; UDP DCUtR remains
    /// unavailable. AutoNAT servers may be configured with or without relays.
    #[cfg(feature = "portable-autonat")]
    pub fn portable_nat_config(mut self, config: minip2p_nat::NatConfig) -> Self {
        self.nat_config = Some(config);
        self
    }

    /// Enables portable relay orchestration with explicit policy.
    ///
    /// This is an alias for [`Self::portable_nat_config`] available with the
    /// relay feature.
    #[cfg(feature = "portable-relay")]
    pub fn relay_config(mut self, config: minip2p_nat::NatConfig) -> Self {
        self.nat_config = Some(config);
        self
    }

    /// Builds the configured endpoint. Optional services share one event loop.
    pub fn build(mut self) -> Result<SmoltcpEndpoint<D, E>, SmoltcpBuildError> {
        #[cfg(feature = "portable-autonat")]
        if let Some(config) = &self.nat_config {
            if config.relays.is_empty() && config.autonat_servers.is_empty() {
                return Err(SmoltcpBuildError::NatConfig {
                    reason: "at least one relay or AutoNAT server is required",
                });
            }
            if config.relays.is_empty()
                && config.reservation_policy != minip2p_nat::ReservationPolicy::Never
            {
                return Err(SmoltcpBuildError::NatConfig {
                    reason: "relay reservation policy requires at least one relay address",
                });
            }
            if !config.relays.is_empty() && !config.force_relay {
                return Err(SmoltcpBuildError::NatConfig {
                    reason: "portable TCP relay requires force_relay = true; DCUtR is QUIC-only",
                });
            }
            #[cfg(not(feature = "portable-relay"))]
            if !config.relays.is_empty() {
                return Err(SmoltcpBuildError::NatConfig {
                    reason: "relay addresses require the portable-relay feature",
                });
            }
            if !config.relays.is_empty() {
                for protocol in [minip2p_nat::HOP_PROTOCOL_ID, minip2p_nat::STOP_PROTOCOL_ID] {
                    self.swarm = self.swarm.protocol(protocol);
                }
            }
            if !config.autonat_servers.is_empty() {
                self.swarm = self.swarm.protocol(minip2p_nat::AUTONAT_PROTOCOL_ID);
            }
        }
        #[cfg(feature = "pubsub")]
        if let Some(config) = &self.pubsub {
            for protocol in config.protocol_ids() {
                self.swarm = self.swarm.protocol(*protocol);
            }
        }
        let transport = TcpTransport::with_config(
            SmoltcpTcpProvider::on_stack(self.stack.clone(), self.provider_config),
            self.identity.clone(),
            self.entropy.clone(),
            self.tcp_config,
        );
        #[cfg(feature = "portable-relay")]
        let transport = minip2p_circuit::CircuitTransport::new(
            transport,
            self.identity.clone(),
            self.entropy.clone(),
        );
        let mut endpoint = PortableEndpoint {
            runtime: self.swarm.build_runtime(transport, self.entropy.clone())?,
        };
        for address in self.listens {
            let parsed =
                address
                    .parse::<Multiaddr>()
                    .map_err(|error| SmoltcpBuildError::ListenAddress {
                        address,
                        reason: error.to_string(),
                    })?;
            endpoint.listen(&parsed)?;
        }
        let mdns = if let Some(config) = self.mdns {
            let mut seed = [0; 32];
            self.entropy.fill_bytes(&mut seed)?;
            let io = SmoltcpMdnsIo::on_stack(self.stack, config.carrier)?;
            let agent =
                minip2p_mdns::MdnsAgent::new(endpoint.peer_id().clone(), config.mdns.clone(), seed)
                    .map_err(|error| {
                        SmoltcpBuildError::MdnsConfig(PortableMdnsConfigError::Mdns(error))
                    })?;
            Some(minip2p_mdns::MdnsDriver::new(agent, io, &config.mdns))
        } else {
            None
        };
        #[cfg(feature = "pubsub")]
        let mut pubsub = self
            .pubsub
            .map(|config| {
                minip2p_pubsub::PubsubAgent::new(
                    self.identity.clone(),
                    config,
                    self.entropy.next_u64()?,
                    self.entropy.next_u64()?,
                )
                .map_err(SmoltcpBuildError::Pubsub)
            })
            .transpose()?;
        #[cfg(feature = "pubsub")]
        let beacon = self
            .beacon
            .map(|config| minip2p_discovery::BeaconAgent::new(self.identity.public_key(), config))
            .transpose()?;
        #[cfg(feature = "pubsub")]
        if let (Some(pubsub), Some(beacon)) = (&mut pubsub, &beacon) {
            pubsub.subscribe(beacon.topic(), 0)?;
        }
        #[cfg(feature = "pubsub")]
        let discovery_enabled = mdns.is_some() || beacon.is_some();
        #[cfg(not(feature = "pubsub"))]
        let discovery_enabled = mdns.is_some();
        let discovery = if discovery_enabled {
            Some(minip2p_discovery::PeerDiscoveryAgent::new(
                endpoint.peer_id().clone(),
                self.discovery,
            )?)
        } else {
            None
        };
        #[cfg(feature = "portable-autonat")]
        let nat = self.nat_config.map(|config| {
            let relay_addrs = config
                .relays
                .iter()
                .map(|relay| (relay.peer_id().clone(), relay.transport().clone()))
                .collect();
            nat::PortableNatDriver::new(
                minip2p_nat::NatAgent::new(endpoint.peer_id().clone(), config),
                relay_addrs,
            )
        });
        Ok(SmoltcpEndpoint {
            endpoint,
            mdns,
            #[cfg(feature = "pubsub")]
            pubsub,
            #[cfg(feature = "pubsub")]
            pending_pubsub_events: VecDeque::new(),
            #[cfg(feature = "pubsub")]
            beacon,
            #[cfg(feature = "portable-autonat")]
            nat,
            discovery,
            active_dials: BTreeMap::new(),
        })
    }
}

/// Failure while constructing a specialized smoltcp endpoint.
#[cfg(feature = "smoltcp")]
#[derive(Debug)]
pub enum SmoltcpBuildError {
    /// The supplied entropy source failed.
    Entropy(minip2p_platform::EntropyError),
    /// Portable swarm configuration was invalid.
    Swarm(SwarmError),
    /// A listen or transport operation failed.
    Driver(DriverError),
    /// A listen address was not a valid multiaddress.
    ListenAddress { address: String, reason: String },
    /// The mDNS carrier could not be constructed.
    Mdns(MdnsError),
    /// mDNS or bounded discovery policy was invalid.
    MdnsConfig(PortableMdnsConfigError),
    /// Pubsub routing policy was invalid.
    #[cfg(feature = "pubsub")]
    Pubsub(PubsubConfigError),
    /// The reserved discovery topic was invalid.
    #[cfg(feature = "pubsub")]
    Topic(TopicError),
    /// Signed-beacon or bounded discovery policy was invalid.
    Discovery(minip2p_discovery::DiscoveryConfigError),
    /// Portable NAT policy requested an unsupported path.
    #[cfg(feature = "portable-autonat")]
    NatConfig { reason: &'static str },
}

#[cfg(feature = "smoltcp")]
impl From<minip2p_platform::EntropyError> for SmoltcpBuildError {
    fn from(error: minip2p_platform::EntropyError) -> Self {
        Self::Entropy(error)
    }
}
#[cfg(feature = "smoltcp")]
impl From<SwarmError> for SmoltcpBuildError {
    fn from(error: SwarmError) -> Self {
        Self::Swarm(error)
    }
}
#[cfg(feature = "smoltcp")]
impl From<DriverError> for SmoltcpBuildError {
    fn from(error: DriverError) -> Self {
        Self::Driver(error)
    }
}
#[cfg(feature = "smoltcp")]
impl From<MdnsError> for SmoltcpBuildError {
    fn from(error: MdnsError) -> Self {
        Self::Mdns(error)
    }
}
#[cfg(feature = "smoltcp")]
impl From<PortableMdnsConfigError> for SmoltcpBuildError {
    fn from(error: PortableMdnsConfigError) -> Self {
        Self::MdnsConfig(error)
    }
}
#[cfg(feature = "smoltcp")]
#[cfg(feature = "pubsub")]
impl From<TopicError> for SmoltcpBuildError {
    fn from(error: TopicError) -> Self {
        Self::Topic(error)
    }
}
#[cfg(feature = "smoltcp")]
impl From<minip2p_discovery::DiscoveryConfigError> for SmoltcpBuildError {
    fn from(error: minip2p_discovery::DiscoveryConfigError) -> Self {
        Self::Discovery(error)
    }
}

#[cfg(feature = "smoltcp")]
impl core::fmt::Display for SmoltcpBuildError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Entropy(error) => error.fmt(formatter),
            Self::Swarm(error) => error.fmt(formatter),
            Self::Driver(error) => error.fmt(formatter),
            Self::ListenAddress { address, reason } => {
                write!(
                    formatter,
                    "invalid smoltcp listen address {address}: {reason}"
                )
            }
            Self::Mdns(error) => error.fmt(formatter),
            Self::MdnsConfig(error) => error.fmt(formatter),
            #[cfg(feature = "pubsub")]
            Self::Pubsub(error) => error.fmt(formatter),
            #[cfg(feature = "pubsub")]
            Self::Topic(error) => error.fmt(formatter),
            Self::Discovery(error) => error.fmt(formatter),
            #[cfg(feature = "portable-autonat")]
            Self::NatConfig { reason } => {
                write!(formatter, "invalid portable NAT config: {reason}")
            }
        }
    }
}

/// Failure while driving the composed smoltcp endpoint.
#[cfg(feature = "smoltcp")]
#[derive(Debug)]
pub enum SmoltcpDriveError {
    /// TCP or swarm progress failed.
    Endpoint(DriverError),
    /// The mDNS carrier failed.
    Mdns(MdnsError),
}

#[cfg(feature = "smoltcp")]
impl From<DriverError> for SmoltcpDriveError {
    fn from(error: DriverError) -> Self {
        Self::Endpoint(error)
    }
}
#[cfg(feature = "smoltcp")]
impl From<MdnsError> for SmoltcpDriveError {
    fn from(error: MdnsError) -> Self {
        Self::Mdns(error)
    }
}
#[cfg(feature = "smoltcp")]
impl core::fmt::Display for SmoltcpDriveError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Endpoint(error) => error.fmt(formatter),
            Self::Mdns(error) => error.fmt(formatter),
        }
    }
}

/// Failure from a portable relay operation.
#[cfg(feature = "portable-relay")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SmoltcpRelayError {
    /// No relay policy was selected on the builder.
    NotEnabled,
}

#[cfg(feature = "portable-relay")]
impl core::fmt::Display for SmoltcpRelayError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotEnabled => write!(formatter, "relay is not enabled; call .relay()"),
        }
    }
}

/// Failure from an embedded pubsub operation.
#[cfg(all(feature = "smoltcp", feature = "pubsub"))]
#[derive(Debug, Eq, PartialEq)]
pub enum SmoltcpPubsubError {
    /// `.pubsub()` or `.discovery()` was not selected on the builder.
    NotEnabled,
    /// Signed discovery owns this subscription.
    DiscoveryTopicReserved,
    /// The topic was invalid.
    Topic(TopicError),
    /// The message could not be queued.
    Publish(PublishError),
}

#[cfg(all(feature = "smoltcp", feature = "pubsub"))]
impl From<TopicError> for SmoltcpPubsubError {
    fn from(error: TopicError) -> Self {
        Self::Topic(error)
    }
}
#[cfg(all(feature = "smoltcp", feature = "pubsub"))]
impl From<PublishError> for SmoltcpPubsubError {
    fn from(error: PublishError) -> Self {
        Self::Publish(error)
    }
}
#[cfg(all(feature = "smoltcp", feature = "pubsub"))]
impl core::fmt::Display for SmoltcpPubsubError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotEnabled => write!(
                formatter,
                "pubsub is not enabled; call .pubsub() or .discovery()"
            ),
            Self::DiscoveryTopicReserved => {
                write!(formatter, "signed discovery owns this topic subscription")
            }
            Self::Topic(error) => error.fmt(formatter),
            Self::Publish(error) => error.fmt(formatter),
        }
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
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            unreachable!()
        }

        fn listen(&mut self, _: &Multiaddr) -> Result<Multiaddr, TransportError> {
            unreachable!()
        }

        fn open_stream(&mut self, _: ConnectionId) -> Result<StreamId, TransportError> {
            unreachable!()
        }

        fn send_stream(
            &mut self,
            _: ConnectionId,
            _: StreamId,
            _: Vec<u8>,
        ) -> Result<(), TransportError> {
            unreachable!()
        }

        fn close_stream_write(
            &mut self,
            _: ConnectionId,
            _: StreamId,
        ) -> Result<(), TransportError> {
            unreachable!()
        }

        fn reset_stream(&mut self, _: ConnectionId, _: StreamId) -> Result<(), TransportError> {
            unreachable!()
        }

        fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
            unreachable!()
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
        fn dial(&mut self, _: &PeerAddr) -> Result<ConnectionId, TransportError> {
            unreachable!()
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
            _: Vec<u8>,
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

    #[test]
    fn portable_builder_constructs_a_protocol_ready_endpoint() {
        let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
        let mut endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .protocol("/example/1.0.0")
            .build(NoopTransport)
            .expect("portable endpoint configuration is valid");
        let remote = Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();

        assert_eq!(endpoint.peer_id(), &identity.peer_id());
        assert!(matches!(
            endpoint
                .runtime_mut()
                .open_stream(&remote, "/example/1.0.0", 0),
            Err(DriverError::Swarm(SwarmError::NotConnected { .. }))
        ));
        assert!(matches!(
            endpoint
                .runtime_mut()
                .open_stream(&remote, "/missing/1.0.0", 0),
            Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
        ));

        let error = Endpoint::portable(&identity, ZeroEntropy)
            .protocol(minip2p_swarm::RESERVED_PROTOCOL_IDS[0])
            .build(NoopTransport)
            .err()
            .expect("reserved protocols must be rejected");
        assert!(matches!(error, SwarmError::ReservedProtocol { .. }));
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
                listen_addresses: vec![address],
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
            SwarmEvent::ConnectionClosed { peer_id, conn_id: closed_id }
                if peer_id == &remote && closed_id == &conn_id
        )));
    }

    #[cfg(feature = "portable-mdns")]
    #[test]
    fn failed_autodial_is_correlated_by_connection_without_a_peer_id() {
        let peer = Ed25519Keypair::from_secret_key_bytes([42; 32]).peer_id();
        let connection = ConnectionId::new(77);
        let mut active = BTreeMap::from([(peer.clone(), connection)]);

        assert_eq!(
            remove_failed_autodial(&mut active, None, Some(connection)),
            Some(peer)
        );
        assert!(active.is_empty(), "a failed dial must become retryable");
    }
}
