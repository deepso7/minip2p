extern crate alloc;

#[cfg(feature = "mdns")]
use alloc::boxed::Box;
use alloc::{string::String, vec::Vec};

pub use minip2p_core::platform::{Deadline, EntropySource, IoErrorKind, Now, SharedEntropy};
pub use minip2p_core::{
    Bytes, Multiaddr, MultiaddrError, Path, PeerAddr, PeerAddrError, PeerId, Protocol,
    TransportKind,
};
pub use minip2p_identity::Ed25519Keypair;
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
pub use minip2p_transport::{
    ConnectionCloseReason, ConnectionId, InvalidLimit, StreamId, Transport, TransportError,
};

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

#[cfg(feature = "relay")]
pub use minip2p_circuit::CircuitLimits;
#[cfg(feature = "relay")]
pub use minip2p_circuit::CircuitTransport;
#[cfg(feature = "discovery")]
pub use minip2p_discovery::{BeaconConfig, DISCOVERY_TOPIC};
#[cfg(feature = "_peer-book")]
pub use minip2p_discovery::{
    DiscoveryConfigError, DiscoveryEvent, DiscoverySource, KnownPeer, PeerDiscoveryConfig,
};
#[cfg(feature = "mdns")]
pub use minip2p_mdns::{
    MDNS_FAILURE_RETRY, MdnsConfig, MdnsConfigError, MdnsError, MdnsEvent, MdnsIo, MdnsIoOperation,
};
#[cfg(feature = "smoltcp")]
pub use minip2p_mdns::{SmoltcpMdnsConfig, SmoltcpMdnsIo};
#[cfg(feature = "autonat")]
pub use minip2p_nat::{
    NatConfig, NatError, NatEvent, ReachabilityState, RelayStage, ReservationInfo,
    ReservationPolicy, UpgradeStop,
};
#[cfg(feature = "pubsub")]
pub use minip2p_pubsub::{
    GOSSIPSUB_PROTOCOL_IDS, GossipsubConfig, GossipsubConfigError, GossipsubEvent, PublishError,
    TopicError,
};
#[cfg(feature = "relay-server")]
pub use minip2p_relay_server::{
    CircuitByteCounts, CircuitCloseReason, CircuitDirection, CircuitLeg, RateLimit,
    RelayServerAddrSource, RelayServerAddressError, RelayServerAddressErrorKind, RelayServerConfig,
    RelayServerConfigError, RelayServerConfigErrorKind, RelayServerEvent, RelayServerRuntimeError,
    RelayServerRuntimeErrorKind, ReservationCloseReason, Status,
};
/// Yamux limits, set per connection through `TcpConfig::yamux` and
/// `CircuitLimits::yamux`.
#[cfg(any(feature = "tcp", feature = "relay"))]
pub use minip2p_secure_mux::YamuxConfig;
use minip2p_swarm::SwarmBuilder;
#[cfg(feature = "smoltcp")]
pub use minip2p_tcp::{SmoltcpConfig, SmoltcpStack, SmoltcpTcpProvider, smoltcp};
#[cfg(feature = "tcp")]
pub use minip2p_tcp::{TcpConfig, TcpProvider, TcpTransport};

use crate::engine::Engine;
#[cfg(feature = "relay")]
use crate::nat::CircuitOps;
#[cfg(feature = "autonat")]
use crate::setup::NatConfigError;
use crate::setup::{self, Capabilities, Platform, SetupError};

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
#[cfg(feature = "mdns")]
type PortableCarrier = Box<dyn MdnsIo>;
#[cfg(not(feature = "mdns"))]
type PortableCarrier = ();

/// What a portable endpoint offers its capabilities: no DCUtR, circuit
/// operations only over a `CircuitTransport`, and an mDNS carrier that may
/// share the transport's stack.
fn portable_platform(has_circuits: bool) -> Platform {
    Platform {
        runs_dcutr: false,
        has_circuits,
        mdns_shares_transport: true,
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
/// `mdns` (or `smoltcp`, which enables it) is compiled in: the carrier is
/// then held as a `Box<dyn MdnsIo>`, which embedded carriers on a shared
/// stack are not.
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
/// [`PortableEndpointBuilder`] (AutoNAT and relay, the relay server,
/// Gossipsub, signed discovery, mDNS) report through their [`EndpointEvent`]
/// variants. Every
/// dial goes through [`connect`](Self::connect).
///
/// # State snapshots
///
/// Getter-style snapshots ([`connected_peers`](Self::connected_peers),
/// [`is_peer_ready`](Self::is_peer_ready), [`peer_info`](Self::peer_info),
/// [`connection_id`](Self::connection_id),
/// [`connection_remote_addr`](Self::connection_remote_addr),
/// [`connection_info`](Self::connection_info), [`path`](Self::path),
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

/// A snapshot of one established connection, from
/// [`PortableEndpoint::connection_info`] or the std `Endpoint`'s.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    /// The peer on the other end.
    pub peer_id: PeerId,
    /// The connection this describes.
    pub conn_id: ConnectionId,
    /// The remote transport address the transport reported for it; a circuit
    /// reports `/p2p/<relay>/p2p-circuit`.
    pub remote_addr: Multiaddr,
    /// How the connection was made.
    pub path: Path,
    /// The protocols the peer advertised through Identify on this
    /// connection: `None` until it is identified (its
    /// [`EndpointEvent::PeerReady`]), which is distinct from `Some` of an
    /// empty list.
    pub ready_protocols: Option<Vec<String>>,
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

    /// Registers an application protocol whose received data the caller
    /// acknowledges itself, with [`Self::stream_consumed`], instead of as
    /// [`Self::poll`] returns it.
    ///
    /// Otherwise like [`Self::add_protocol`]. A host that hands bytes on to
    /// a reader which may hold them (a foreign runtime's stream queue) uses
    /// it, so the sender waits until they are really consumed (ADR 0012).
    /// Streams that became ready before this call keep the acknowledgement
    /// they had.
    pub fn add_manual_ack_protocol(
        &mut self,
        protocol_id: impl Into<String>,
    ) -> Result<(), DriverError> {
        self.engine.add_manual_ack_protocol(protocol_id.into())
    }

    /// Acknowledges `bytes` of a manual-acknowledgement stream's received
    /// data as consumed, replenishing its receive budget (ADR 0012).
    ///
    /// The same contract as the std `Endpoint::stream_consumed`: more than
    /// the stream's unacknowledged bytes fails with
    /// [`TransportError::AckExceedsDelivered`](minip2p_transport::TransportError::AckExceedsDelivered),
    /// a closed stream (also on an ended connection) releases its bytes, and
    /// a settled or unknown stream is a no-op.
    pub fn stream_consumed(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), DriverError> {
        self.engine.core.ack_stream(conn_id, stream_id, bytes)
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
    ///
    /// Connecting to a peer that is already connected reuses that
    /// connection: the attempt settles at once with the current connection,
    /// and the addresses passed are not dialed.
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

    /// Returns the [`Path`] of `peer`'s established connection; `None` only
    /// while the peer is not connected.
    ///
    /// See [`Self::connection_info`].
    pub fn path(&self, peer: &PeerId) -> Option<Path> {
        self.engine.path(peer)
    }

    /// Returns a snapshot of the established connection `conn_id`: its peer,
    /// remote address, [`Path`], and Identify protocols once ready.
    ///
    /// `None` for a pending, replaced, or closed connection. A connection's
    /// path is [`Path::Relayed`] for a circuit, [`Path::Direct`] for a direct
    /// connection we dialed or accepted, or [`Path::Punched`] once NAT
    /// reports its hole punch produced it. A Connection replacement's new
    /// connection has its own path.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connection_info(&self, conn_id: ConnectionId) -> Option<ConnectionInfo> {
        self.engine.connection_info(conn_id)
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
    /// earlier step fails; the first error wins (a close, then the final
    /// drive). mDNS goodbyes are best effort: one that could not be sent is
    /// an [`EndpointEvent::MdnsFailed`] among the returned events, not an
    /// error.
    pub fn shutdown(mut self, now: Now) -> Result<Vec<EndpointEvent>, DriverError> {
        // The failure is queued as an event too.
        #[cfg(feature = "mdns")]
        drop(self.engine.shutdown_mdns(now));
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

    /// Pauses or resumes admission of new relay reservations and circuits.
    ///
    /// Existing reservations and circuits remain active, and HOP remains
    /// advertised while admission is paused.
    #[cfg(feature = "relay-server")]
    #[expect(
        clippy::result_large_err,
        reason = "The error type retains a rejected address for the announce control."
    )]
    pub fn set_relay_server_accepting(
        &mut self,
        accepting: bool,
    ) -> Result<(), crate::RelayServerControlError> {
        let relay_server = self
            .engine
            .relay_server
            .as_mut()
            .ok_or(crate::RelayServerControlError::NotConfigured)?;
        relay_server.agent.set_accepting(accepting);
        Ok(())
    }

    /// Returns the currently held relay reservation, when any.
    #[cfg(feature = "relay")]
    pub fn active_reservation(&self) -> Option<ReservationInfo> {
        self.engine.active_reservation()
    }

    /// Returns the current AutoNAT reachability verdict
    /// ([`ReachabilityState::Unknown`] until a server exchange succeeds, or
    /// when NAT is not configured).
    #[cfg(feature = "autonat")]
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
    #[cfg(feature = "_peer-book")]
    pub fn known_peers(&self) -> Vec<KnownPeer> {
        self.engine.known_peers()
    }
}

/// Failure while building a portable endpoint.
#[derive(Debug, thiserror::Error)]
pub enum PortableBuildError {
    /// The supplied entropy source failed.
    #[error(transparent)]
    Entropy(#[from] minip2p_core::platform::EntropyError),
    /// Swarm configuration was invalid (a reserved protocol id, say).
    #[error(transparent)]
    Swarm(#[from] SwarmError),
    /// A listen or transport operation failed.
    #[error(transparent)]
    Driver(#[from] DriverError),
    /// A listen address was not a valid multiaddress.
    #[error("invalid listen address `{address}`: {error}")]
    ListenAddress {
        /// The address as given.
        address: String,
        /// Why it does not parse.
        error: minip2p_core::MultiaddrError,
    },
    /// The mDNS carrier could not be constructed.
    #[cfg(feature = "mdns")]
    #[error(transparent)]
    Mdns(#[from] MdnsError),
    /// mDNS wire or scheduling policy was invalid.
    #[cfg(feature = "mdns")]
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
    #[cfg(feature = "_peer-book")]
    #[error(transparent)]
    Discovery(#[from] DiscoveryConfigError),
    /// NAT policy that cannot run on this endpoint: no servers, a
    /// reservation without a relay, or relays it cannot use.
    #[cfg(feature = "autonat")]
    #[error("invalid NAT config: {0}")]
    NatConfig(NatConfigError),
    /// The relay server's configuration is invalid.
    #[cfg(feature = "relay-server")]
    #[error("relay-server configuration: {0}")]
    RelayServer(RelayServerConfigError),
    /// A relay-server announce address does not fit this endpoint's
    /// identity.
    #[cfg(feature = "relay-server")]
    #[error("relay-server announce address: {0}")]
    RelayServerAnnounce(alloc::boxed::Box<RelayServerAddressError>),
    /// A transport limit cannot work ([`TcpConfig::validate`], or
    /// [`CircuitLimits::validate`] with the `relay` feature).
    #[error(transparent)]
    InvalidLimit(#[from] InvalidLimit),
}

impl From<SetupError> for PortableBuildError {
    fn from(error: SetupError) -> Self {
        match error {
            SetupError::Entropy(error) => Self::Entropy(error),
            SetupError::Swarm(error) => Self::Swarm(error),
            #[cfg(feature = "autonat")]
            SetupError::NatConfig(error) => Self::NatConfig(error),
            #[cfg(feature = "pubsub")]
            SetupError::Gossipsub(error) => Self::Gossipsub(error),
            #[cfg(feature = "discovery")]
            SetupError::Topic(error) => Self::Topic(error),
            #[cfg(feature = "_peer-book")]
            SetupError::Discovery(error) => Self::Discovery(error),
            #[cfg(feature = "mdns")]
            SetupError::Mdns(error) => Self::MdnsConfig(error),
            #[cfg(feature = "relay-server")]
            SetupError::RelayServer(error) => Self::RelayServer(error),
            #[cfg(feature = "relay-server")]
            SetupError::RelayServerAnnounce(error) => Self::RelayServerAnnounce(error),
        }
    }
}

/// Builder for a [`PortableEndpoint`].
///
/// Base endpoint operations work over any [`Transport`]. Capabilities are
/// opt-in setters behind their Cargo features: AutoNAT and relay
/// (`autonat`, `relay`), the relay server (`relay-server`), Gossipsub
/// (`pubsub`), signed discovery (`discovery`), and mDNS (`mdns`).
///
/// # Relay needs circuit operations
///
/// Relay paths turn a relay bridge into a connection, which takes circuit
/// operations from the transport. [`build`](Self::build) works over any
/// transport and refuses relay configuration with
/// `PortableBuildError::NatConfig`; wrap the transport in a
/// `CircuitTransport` and call `build_with_circuits` (feature `relay`) to
/// run relays. AutoNAT alone needs nothing from the transport.
pub struct PortableEndpointBuilder<E> {
    swarm: SwarmBuilder,
    identity: Ed25519Keypair,
    entropy: E,
    connect_deadline_ms: u64,
    capabilities: Capabilities,
    /// The carrier [`Self::mdns`] hands over with `capabilities.mdns`.
    #[cfg(feature = "mdns")]
    mdns_io: Option<PortableCarrier>,
}

impl<E: EntropySource> PortableEndpointBuilder<E> {
    /// Starts a builder with explicit identity and entropy.
    pub fn new(identity: &Ed25519Keypair, entropy: E) -> Self {
        Self {
            swarm: SwarmBuilder::new(identity),
            identity: identity.clone(),
            entropy,
            connect_deadline_ms: DEFAULT_CONNECT_DEADLINE_MS,
            capabilities: Capabilities::default(),
            #[cfg(feature = "mdns")]
            mdns_io: None,
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
    #[cfg(feature = "relay")]
    pub fn relay(mut self, relay: PeerAddr) -> Self {
        let config = self.nat_or_default();
        config.relays.push(relay);
        config.force_relay = true;
        self
    }

    /// Adds a trusted AutoNAT server, enabling probing.
    ///
    /// Call once per server: a reachability verdict needs a quorum of
    /// distinct servers ([`NatConfig::confidence_threshold`], 3 by default),
    /// so with fewer reachable servers reachability stays Unknown.
    #[cfg(feature = "autonat")]
    pub fn autonat(mut self, server: PeerAddr) -> Self {
        self.nat_or_default().autonat_servers.push(server);
        self
    }

    /// The NAT configuration the setters add to; a fresh one holds no
    /// reservation.
    #[cfg(feature = "autonat")]
    fn nat_or_default(&mut self) -> &mut NatConfig {
        self.capabilities
            .nat
            .get_or_insert_with(setup::no_reservation_nat)
    }

    /// Enables NAT policy with explicit relay and AutoNAT settings.
    ///
    /// Relay configurations must set `dcutr = false` (direct candidates
    /// still race the relay leg) or `force_relay` (relay only): portable
    /// endpoints do not run DCUtR. AutoNAT servers may be configured with or
    /// without relays.
    #[cfg(feature = "autonat")]
    pub fn nat_config(mut self, config: NatConfig) -> Self {
        self.capabilities.nat = Some(config);
        self
    }

    /// Enables Circuit Relay v2 service with production-oriented defaults.
    ///
    /// The server announces the transport's concrete listener addresses
    /// and any public addresses AutoNAT confirms. Pause and resume admission
    /// with [`PortableEndpoint::set_relay_server_accepting`]; its events
    /// arrive as [`EndpointEvent::RelayServer`].
    #[cfg(feature = "relay-server")]
    pub fn relay_server(self) -> Self {
        self.relay_server_config(RelayServerConfig::default())
    }

    /// Enables Circuit Relay v2 service with custom limits, validated at
    /// build.
    #[cfg(feature = "relay-server")]
    pub fn relay_server_config(mut self, config: RelayServerConfig) -> Self {
        self.capabilities.relay_server = Some(setup::RelayServerSetup {
            config,
            announce_addrs: Vec::new(),
        });
        self
    }

    /// Enables pubsub with interoperable gossipsub defaults.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub(mut self) -> Self {
        self.capabilities
            .gossipsub
            .get_or_insert_with(GossipsubConfig::default);
        self
    }

    /// Enables pubsub with an explicit gossipsub configuration, validated
    /// at build.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub_config(mut self, config: GossipsubConfig) -> Self {
        self.capabilities.gossipsub = Some(config);
        self
    }

    /// Enables signed-beacon discovery. Pubsub is enabled automatically.
    #[cfg(feature = "discovery")]
    pub fn discovery(self) -> Self {
        self.beacon_config(BeaconConfig::default())
    }

    /// Enables signed-beacon discovery with explicit beacon policy.
    #[cfg(feature = "discovery")]
    pub fn beacon_config(mut self, config: BeaconConfig) -> Self {
        self.capabilities
            .gossipsub
            .get_or_insert_with(GossipsubConfig::default);
        self.capabilities.beacon = Some(config);
        self
    }

    /// Overrides the shared bounded peer-book and automatic-dial policy,
    /// validated at build. It applies to every enabled discovery source.
    #[cfg(feature = "_peer-book")]
    pub fn peer_discovery_config(mut self, config: PeerDiscoveryConfig) -> Self {
        self.capabilities.peer_discovery = config;
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
    #[cfg(feature = "mdns")]
    pub fn mdns(mut self, io: impl MdnsIo + 'static, config: MdnsConfig) -> Self {
        self.mdns_io = Some(Box::new(io));
        self.capabilities.mdns = Some(config);
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
            #[cfg(feature = "relay")]
            None,
        )
    }

    /// Builds the endpoint over a [`CircuitTransport`], whose circuit
    /// operations let relay legs and reservations run.
    #[cfg(feature = "relay")]
    pub fn build_with_circuits<T: Transport, R: EntropySource>(
        self,
        transport: CircuitTransport<T, R>,
    ) -> Result<PortableEndpoint<CircuitTransport<T, R>, E>, PortableBuildError> {
        self.assemble(transport, Some(CircuitOps::circuit_transport()))
    }

    /// Validates the capabilities, builds the swarm over `transport`, and
    /// installs them through Endpoint setup.
    fn assemble<T: Transport>(
        self,
        transport: T,
        #[cfg(feature = "relay")] circuits: Option<CircuitOps<T>>,
    ) -> Result<PortableEndpoint<T, E>, PortableBuildError> {
        #[cfg(feature = "relay")]
        let has_circuits = circuits.is_some();
        #[cfg(not(feature = "relay"))]
        let has_circuits = false;
        let validated = setup::validate(
            self.capabilities,
            portable_platform(has_circuits),
            &self.identity.peer_id(),
        )?;
        // The swarm owns the entropy from here on; capabilities draw from it.
        let core = self.swarm.build_core(transport, self.entropy)?;
        let mut engine = Engine::new(core, self.connect_deadline_ms, StreamAcks::default());
        setup::install(
            &mut engine,
            validated,
            &self.identity,
            #[cfg(feature = "relay")]
            circuits,
            #[cfg(feature = "mdns")]
            self.mdns_io,
        )?;
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
                capabilities: self.capabilities,
                mdns_io: self.mdns_io,
            },
            entropy,
            stack,
            tcp_config: TcpConfig::default(),
            #[cfg(feature = "relay")]
            circuit_limits: CircuitLimits::default(),
            provider_config: SmoltcpConfig::default(),
            listens: Vec::new(),
            mdns: None,
        }
    }
}

/// The transport a [`SmoltcpEndpointBuilder`] builds: TCP over smoltcp,
/// wrapped in a `CircuitTransport` with the `relay` feature.
#[cfg(all(feature = "smoltcp", not(feature = "relay")))]
pub type SmoltcpTransport<D, E> = TcpTransport<SmoltcpTcpProvider<D>, SharedEntropy<E>>;

/// The transport a [`SmoltcpEndpointBuilder`] builds: TCP over smoltcp,
/// wrapped in a [`CircuitTransport`] with the `relay` feature.
#[cfg(all(feature = "smoltcp", feature = "relay"))]
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
    #[cfg(feature = "relay")]
    circuit_limits: CircuitLimits,
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

    /// Overrides secure-session and connection limits. Checked when the
    /// endpoint is built.
    pub fn tcp_config(mut self, config: TcpConfig) -> Self {
        self.tcp_config = config;
        self
    }

    /// Overrides the relay circuits' Yamux limits. Checked when the endpoint
    /// is built.
    #[cfg(feature = "relay")]
    pub fn circuit_limits(mut self, limits: CircuitLimits) -> Self {
        self.circuit_limits = limits;
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
    #[cfg(feature = "discovery")]
    pub fn discovery(mut self) -> Self {
        self.portable = self.portable.discovery();
        self
    }

    /// Enables signed-beacon discovery with explicit beacon policy.
    #[cfg(feature = "discovery")]
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
    #[cfg(feature = "relay")]
    pub fn relay(mut self, relay: PeerAddr) -> Self {
        self.portable = self.portable.relay(relay);
        self
    }

    /// Enables Circuit Relay v2 service with production-oriented defaults.
    #[cfg(feature = "relay-server")]
    pub fn relay_server(mut self) -> Self {
        self.portable = self.portable.relay_server();
        self
    }

    /// Enables Circuit Relay v2 service with custom limits, validated at
    /// build.
    #[cfg(feature = "relay-server")]
    pub fn relay_server_config(mut self, config: RelayServerConfig) -> Self {
        self.portable = self.portable.relay_server_config(config);
        self
    }

    /// Adds a trusted AutoNAT server, enabling probing.
    ///
    /// Call once per server: a reachability verdict needs a quorum of
    /// distinct servers ([`NatConfig::confidence_threshold`], 3 by default),
    /// so with fewer reachable servers reachability stays Unknown.
    #[cfg(feature = "autonat")]
    pub fn autonat(mut self, server: PeerAddr) -> Self {
        self.portable = self.portable.autonat(server);
        self
    }

    /// Enables NAT policy with explicit relay and AutoNAT settings.
    ///
    /// TCP relay configurations must set `dcutr = false` or `force_relay`;
    /// UDP DCUtR remains unavailable. AutoNAT servers may be configured with
    /// or without relays.
    #[cfg(feature = "autonat")]
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
            #[cfg(feature = "relay")]
            circuit_limits,
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
        )?;
        #[cfg(feature = "relay")]
        let mut endpoint = portable.build_with_circuits(CircuitTransport::with_limits(
            transport,
            identity,
            entropy,
            circuit_limits,
        )?)?;
        #[cfg(not(feature = "relay"))]
        let mut endpoint = {
            let _ = identity;
            drop(entropy);
            portable.build(transport)?
        };
        for address in listens {
            let parsed = match address.parse::<Multiaddr>() {
                Ok(parsed) => parsed,
                Err(error) => return Err(PortableBuildError::ListenAddress { address, error }),
            };
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
    use minip2p_core::platform::EntropyError;
    use minip2p_test_support::InMemoryTransport;
    use minip2p_transport::{ConnectionEndpoint, ConnectionNamespace, TransportEvent};

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
            self.events.push(TransportEvent::Closed {
                id,
                reason: ConnectionCloseReason::Local,
            });
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
    #[cfg(feature = "mdns")]
    struct BrokenMdns;

    #[cfg(feature = "mdns")]
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
            Err(MdnsError::io(
                MdnsIoOperation::Poll,
                minip2p_core::platform::IoErrorKind::NotConnected,
                None,
                "stack gone",
            ))
        }
    }

    /// A stream whose close is still queued in the endpoint is gone from
    /// the swarm, yet abandoning it drops every queued event for it.
    #[cfg(feature = "mdns")]
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
            reason: ConnectionCloseReason::Local,
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

    /// A failing mDNS carrier never fails the poll: the failure is one
    /// capability event, reported once, and the rest of the batch (here an
    /// attempt's terminal) is unaffected.
    #[cfg(feature = "mdns")]
    #[test]
    fn a_failing_mdns_carrier_is_an_event_not_a_poll_error() {
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
        // The transport refuses the dial, so the attempt settles at once.
        let id = endpoint
            .connect(target, Now::from_millis(0))
            .expect("admitted");

        let events = endpoint.poll(Now::from_millis(1)).expect("poll");
        let failures = |events: &[EndpointEvent]| {
            events
                .iter()
                .filter(|event| {
                    matches!(
                        event,
                        EndpointEvent::MdnsFailed {
                            error: MdnsError::Io {
                                operation: MdnsIoOperation::Poll,
                                ..
                            }
                        }
                    )
                })
                .count()
        };
        assert_eq!(failures(&events), 1, "{events:?}");
        assert!(
            events.iter().any(|event| matches!(
                event,
                EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == id
            )),
            "{events:?}"
        );
        // The retry fails the same way: still running, nothing new to report.
        let retried = endpoint
            .poll(Now::from_millis(1 + MDNS_FAILURE_RETRY))
            .expect("poll");
        assert_eq!(failures(&retried), 0, "{retried:?}");
    }

    /// Goodbyes are best effort: one that cannot be sent is a final
    /// `MdnsFailed` among the shutdown's events, not a shutdown error.
    #[cfg(feature = "mdns")]
    #[test]
    fn a_failed_goodbye_is_an_event_from_shutdown() {
        let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
        let endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .mdns(BrokenMdns, MdnsConfig::default())
            .build(NoopTransport)
            .expect("mdns endpoint");
        let events = endpoint
            .shutdown(Now::from_millis(0))
            .expect("goodbyes are best effort");
        assert!(
            events
                .iter()
                .any(|event| matches!(event, EndpointEvent::MdnsFailed { .. })),
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

    /// A circuit is Relayed through the relay its address names; the direct
    /// connection that replaces it is Direct, inheriting nothing; pending,
    /// replaced, and closed connections have no info.
    #[test]
    fn every_established_connection_has_its_own_path() {
        let identity = Ed25519Keypair::from_secret_key_bytes([31; 32]);
        let peer = Ed25519Keypair::from_secret_key_bytes([32; 32]).peer_id();
        let relay = Ed25519Keypair::from_secret_key_bytes([33; 32]).peer_id();
        let circuit = ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 1).expect("id");
        let circuit_addr =
            Multiaddr::from_protocols(vec![Protocol::P2p(relay.clone()), Protocol::P2pCircuit]);
        let direct = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("id");
        let direct_addr: Multiaddr = "/ip4/192.0.2.7/tcp/4001".parse().expect("address");
        let transport = RecordingTransport {
            events: vec![
                TransportEvent::Connected {
                    id: circuit,
                    endpoint: ConnectionEndpoint::with_peer_id(circuit_addr.clone(), peer.clone()),
                },
                TransportEvent::IncomingConnection {
                    id: direct,
                    endpoint: ConnectionEndpoint::new(direct_addr.clone()),
                },
            ],
            local_address: direct_addr.clone(),
            next_stream_id: 0,
            closed: Rc::new(Cell::new(false)),
        };
        let mut endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .build(transport)
            .expect("endpoint configuration is valid");
        endpoint.poll(Now::from_millis(0)).expect("poll");

        assert_eq!(
            endpoint.connection_info(circuit),
            Some(ConnectionInfo {
                peer_id: peer.clone(),
                conn_id: circuit,
                remote_addr: circuit_addr,
                path: Path::Relayed { relay },
                ready_protocols: None,
            })
        );
        assert_eq!(
            endpoint.connection_info(direct),
            None,
            "a pending handshake"
        );

        // The accepted direct connection identifies the peer and replaces
        // the circuit.
        endpoint
            .engine
            .core
            .transport_mut()
            .events
            .push(TransportEvent::Connected {
                id: direct,
                endpoint: ConnectionEndpoint::with_peer_id(direct_addr, peer.clone()),
            });
        endpoint.poll(Now::from_millis(1)).expect("poll");
        assert_eq!(endpoint.connection_info(circuit), None, "replaced");
        assert_eq!(
            endpoint.connection_info(direct).map(|info| info.path),
            Some(Path::Direct)
        );
        assert_eq!(endpoint.path(&peer), Some(Path::Direct));

        endpoint
            .engine
            .core
            .transport_mut()
            .events
            .push(TransportEvent::Closed {
                id: direct,
                reason: ConnectionCloseReason::Local,
            });
        endpoint.poll(Now::from_millis(2)).expect("poll");
        assert_eq!(endpoint.connection_info(direct), None, "closed");
        assert_eq!(endpoint.path(&peer), None);
    }

    /// A Connected terminal names the path it settled on, even when that
    /// connection is replaced before the application reads the terminal.
    #[test]
    fn a_settled_attempt_keeps_its_path_after_the_connection_is_replaced() {
        let identity = Ed25519Keypair::from_secret_key_bytes([36; 32]);
        let peer = Ed25519Keypair::from_secret_key_bytes([37; 32]).peer_id();
        let relay = Ed25519Keypair::from_secret_key_bytes([38; 32]).peer_id();
        let circuit = ConnectionId::namespaced(ConnectionNamespace::CIRCUIT, 1).expect("id");
        let circuit_addr =
            Multiaddr::from_protocols(vec![Protocol::P2p(relay.clone()), Protocol::P2pCircuit]);
        let direct = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("id");
        let direct_addr: Multiaddr = "/ip4/192.0.2.8/tcp/4001".parse().expect("address");
        let transport = RecordingTransport {
            events: vec![TransportEvent::Connected {
                id: circuit,
                endpoint: ConnectionEndpoint::with_peer_id(circuit_addr, peer.clone()),
            }],
            local_address: direct_addr.clone(),
            next_stream_id: 0,
            closed: Rc::new(Cell::new(false)),
        };
        let mut endpoint = Endpoint::portable(&identity, ZeroEntropy)
            .build(transport)
            .expect("endpoint configuration is valid");
        endpoint.poll(Now::from_millis(0)).expect("poll");

        // Settles at once on the circuit; a direct connection replaces it
        // before the terminal is read.
        let target = PeerAddr::new(direct_addr.clone(), peer.clone()).expect("peer addr");
        let id = endpoint
            .connect(target, Now::from_millis(1))
            .expect("connect admitted");
        endpoint
            .engine
            .core
            .transport_mut()
            .events
            .push(TransportEvent::Connected {
                id: direct,
                endpoint: ConnectionEndpoint::with_peer_id(direct_addr, peer.clone()),
            });
        let events = endpoint.poll(Now::from_millis(2)).expect("poll");

        assert_eq!(endpoint.connection_info(circuit), None, "replaced");
        let settled = events.iter().find_map(|event| match event {
            EndpointEvent::ConnectSettled {
                connect_id,
                outcome,
                ..
            } if *connect_id == id => Some(outcome),
            _ => None,
        });
        assert_eq!(
            settled,
            Some(&ConnectOutcome::Connected {
                conn_id: circuit,
                path: Path::Relayed { relay },
            }),
            "{events:?}"
        );
    }

    /// `ready_protocols` is `None` until the connection is identified, then
    /// the protocols the peer advertised on it.
    #[test]
    fn connection_info_reports_protocols_once_identified() {
        let a_identity = Ed25519Keypair::from_secret_key_bytes([34; 32]);
        let b_identity = Ed25519Keypair::from_secret_key_bytes([35; 32]);
        let (a_transport, b_transport) =
            InMemoryTransport::pair(a_identity.peer_id(), b_identity.peer_id());
        let conn_id = a_transport.connection_id();
        let mut a = Endpoint::portable(&a_identity, ZeroEntropy)
            .build(a_transport)
            .expect("a endpoint configuration is valid");
        let mut b = Endpoint::portable(&b_identity, ZeroEntropy)
            .protocol("/app/1")
            .build(b_transport)
            .expect("b endpoint configuration is valid");

        a.poll(Now::from_millis(0)).expect("drive a");
        let info = a.connection_info(conn_id).expect("established");
        assert_eq!(info.path, Path::Direct);
        assert_eq!(info.ready_protocols, None, "not identified yet");

        for now_ms in 1..64 {
            b.poll(Now::from_millis(now_ms)).expect("drive b");
            a.poll(Now::from_millis(now_ms)).expect("drive a");
            if a.is_peer_ready(&b_identity.peer_id()) {
                break;
            }
        }
        let protocols = a
            .connection_info(conn_id)
            .and_then(|info| info.ready_protocols)
            .expect("identified");
        assert!(protocols.iter().any(|protocol| protocol == "/app/1"));
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
                outcome: ConnectOutcome::Connected { conn_id: settled, .. },
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
