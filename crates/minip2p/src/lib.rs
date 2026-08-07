//! Portable and std application-facing APIs for minip2p.
//!
//! [`PortableEndpoint`] is the `no_std + alloc`, caller-driven facade. It
//! owns a transport and protocol runtime but no clock, executor, sockets, or
//! operating-system entropy source. The host passes one [`Now`] sample to
//! each [`PortableEndpoint::poll`] call.
//!
//! With the default `std` and `quic` features, the batteries-included
//! [`Endpoint`] and `EndpointBuilder` APIs remain available for OS programs.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "portable-mdns")]
use alloc::collections::BTreeMap;
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
pub use minip2p_discovery::{DiscoveryEvent, KnownPeer, PeerDiscoveryConfig};
#[cfg(feature = "portable-mdns")]
pub use minip2p_mdns::{MdnsConfig, MdnsConfigError, MdnsError, MdnsEvent, MdnsIo};
#[cfg(feature = "smoltcp")]
pub use minip2p_mdns::{SmoltcpMdnsConfig, SmoltcpMdnsIo};
#[cfg(feature = "smoltcp")]
pub use minip2p_tcp::{SmoltcpConfig, SmoltcpStack, SmoltcpTcpProvider, smoltcp};
#[cfg(feature = "tcp")]
pub use minip2p_tcp::{TcpConfig, TcpProvider, TcpTransport};

#[cfg(feature = "std")]
mod std_endpoint;
#[cfg(feature = "std")]
pub use std_endpoint::*;

/// Portable endpoint entry point when the std facade is not compiled.
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
/// This is the portable facade for embedded systems and deterministic event
/// loops. It performs no blocking and never reads a system clock. Callers
/// drive it with [`poll`](Self::poll) and may inspect
/// [`next_deadline`](Self::next_deadline) to decide how long their platform
/// loop can idle.
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

    /// Consumes the facade and returns its underlying runtime.
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
    ) -> SmoltcpEndpointBuilder<D, E, MdnsDisabled> {
        SmoltcpEndpointBuilder {
            swarm: self.swarm,
            identity: self.identity,
            entropy: SharedEntropy::new(self.entropy),
            stack,
            tcp_config: TcpConfig::default(),
            provider_config: SmoltcpConfig::default(),
            listens: Vec::new(),
            mdns: MdnsDisabled,
        }
    }
}

/// Type-state marker for an embedded endpoint without mDNS.
#[cfg(feature = "smoltcp")]
pub struct MdnsDisabled;

/// Embedded mDNS and peer-discovery configuration.
#[cfg(feature = "smoltcp")]
pub struct MdnsEnabled {
    mdns: MdnsConfig,
    carrier: SmoltcpMdnsConfig,
    discovery: PeerDiscoveryConfig,
}

/// Specialized builder for a portable endpoint over one shared smoltcp stack.
#[cfg(feature = "smoltcp")]
pub struct SmoltcpEndpointBuilder<D: smoltcp::phy::Device, E: EntropySource, M> {
    swarm: SwarmBuilder,
    identity: Ed25519Keypair,
    entropy: SharedEntropy<E>,
    stack: SmoltcpStack<D>,
    tcp_config: TcpConfig,
    provider_config: SmoltcpConfig,
    listens: Vec<String>,
    mdns: M,
}

/// TCP-only endpoint produced by the specialized smoltcp builder.
#[cfg(feature = "smoltcp")]
pub type SmoltcpEndpoint<D, E> =
    PortableEndpoint<TcpTransport<SmoltcpTcpProvider<D>, SharedEntropy<E>>, SharedEntropy<E>>;

/// TCP and mDNS endpoint produced by the specialized smoltcp builder.
#[cfg(feature = "smoltcp")]
pub type SmoltcpMdnsEndpoint<D, E> = PortableMdnsEndpoint<
    TcpTransport<SmoltcpTcpProvider<D>, SharedEntropy<E>>,
    SharedEntropy<E>,
    SmoltcpMdnsIo<D>,
>;

#[cfg(feature = "smoltcp")]
type SmoltcpBuildParts<D, E, M> = (SmoltcpEndpoint<D, E>, SmoltcpStack<D>, M);

#[cfg(feature = "smoltcp")]
impl<D: smoltcp::phy::Device, E: EntropySource, M> SmoltcpEndpointBuilder<D, E, M> {
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

    fn build_endpoint(self) -> Result<SmoltcpBuildParts<D, E, M>, SmoltcpBuildError> {
        let transport = TcpTransport::with_config(
            SmoltcpTcpProvider::on_stack(self.stack.clone(), self.provider_config),
            self.identity,
            self.entropy.clone(),
            self.tcp_config,
        );
        let mut endpoint = PortableEndpoint {
            runtime: self.swarm.build_runtime(transport, self.entropy)?,
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
        Ok((endpoint, self.stack, self.mdns))
    }
}

#[cfg(feature = "smoltcp")]
impl<D: smoltcp::phy::Device, E: EntropySource> SmoltcpEndpointBuilder<D, E, MdnsDisabled> {
    /// Enables mDNS and bounded automatic local-peer discovery with defaults.
    pub fn mdns(self) -> SmoltcpEndpointBuilder<D, E, MdnsEnabled> {
        self.mdns_config(MdnsConfig::default())
    }

    /// Enables mDNS with explicit wire and scheduling policy.
    pub fn mdns_config(self, config: MdnsConfig) -> SmoltcpEndpointBuilder<D, E, MdnsEnabled> {
        SmoltcpEndpointBuilder {
            swarm: self.swarm,
            identity: self.identity,
            entropy: self.entropy,
            stack: self.stack,
            tcp_config: self.tcp_config,
            provider_config: self.provider_config,
            listens: self.listens,
            mdns: MdnsEnabled {
                mdns: config,
                carrier: SmoltcpMdnsConfig::default(),
                discovery: PeerDiscoveryConfig::default(),
            },
        }
    }

    /// Builds a TCP-only portable endpoint.
    pub fn build(self) -> Result<SmoltcpEndpoint<D, E>, SmoltcpBuildError> {
        self.build_endpoint().map(|(endpoint, _, _)| endpoint)
    }
}

#[cfg(feature = "smoltcp")]
impl<D: smoltcp::phy::Device, E: EntropySource> SmoltcpEndpointBuilder<D, E, MdnsEnabled> {
    /// Overrides the mDNS UDP carrier buffers and enabled address families.
    pub fn mdns_carrier_config(mut self, config: SmoltcpMdnsConfig) -> Self {
        self.mdns.carrier = config;
        self
    }

    /// Overrides bounded peer-book and automatic-dial policy.
    pub fn discovery_config(mut self, config: PeerDiscoveryConfig) -> Self {
        self.mdns.discovery = config;
        self
    }

    /// Builds a TCP endpoint with mDNS over the same smoltcp stack.
    pub fn build(mut self) -> Result<SmoltcpMdnsEndpoint<D, E>, SmoltcpBuildError> {
        let mut seed = [0; 32];
        self.entropy.fill_bytes(&mut seed)?;
        let (endpoint, stack, mdns) = self.build_endpoint()?;
        let io = SmoltcpMdnsIo::on_stack(stack, mdns.carrier)?;
        Ok(endpoint.with_mdns_config(io, mdns.mdns, mdns.discovery, seed)?)
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
