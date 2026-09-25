//! Application-facing `Endpoint` API for minip2p.
//!
//! This crate is the ergonomic std entrypoint. It composes the lower-level
//! crates without hiding them: protocol crates and `SwarmCore` remain the
//! Sans-I/O / `no_std + alloc` surface, while [`Endpoint`] gives applications a
//! small batteries-included API for identity, transports, listen/dial, ping,
//! and event polling.
//!
//! # Transports
//!
//! Prefer address-shaped listening: pass complete multiaddresses to
//! [`EndpointBuilder::listen_on`] (or [`EndpointBuilder::listen_default`] for
//! dual-stack QUIC) and call [`EndpointBuilder::bind`]. The builder infers
//! QUIC vs TCP from each address and groups compatible IPv4/IPv6 listeners
//! onto one transport per shape.
//!
//! Dial routing is address-shaped too: a `/udp/…/quic-v1` candidate is
//! reached over QUIC and a `/tcp` one over TCP.
//!
//! With the `pubsub` feature, `EndpointBuilder::gossipsub` enables gossipsub
//! and `EndpointBuilder::gossipsub_config` tunes it with a `GossipsubConfig`.
//!
//! The `nat` feature exposes relay, AutoNAT, and DCUtR coordination. The
//! `discovery` feature includes `nat` and `pubsub`, adding signed presence
//! beacons plus a bounded peer book. The `mdns` feature includes `nat` but not
//! `pubsub`, and adds caller-driven local-link multicast discovery. Enable
//! both discovery sources to feed one shared peer book and automatic-dial
//! state. Cargo features expose these APIs; the corresponding builder methods
//! activate their drivers.
//!
//! The independent std-only `relay-server` feature enables the three-line
//! `Endpoint::builder().relay_server().listen_on(…)?.bind()` hosting path. Relay-only
//! endpoints advertise inbound HOP and open outbound STOP; NAT-only endpoints
//! install the trusted client roles, and combined endpoints compose both.

mod dial;
#[cfg(feature = "mdns")]
mod mdns;
#[cfg(all(test, feature = "nat", feature = "quic"))]
mod nat_tests;
#[cfg(feature = "nat")]
type NatDriver = crate::nat::NatDriver<minip2p_platform::StdEntropy>;
#[cfg(feature = "relay-server")]
mod relay_server;

#[cfg(feature = "pubsub")]
use crate::GossipsubError;
#[cfg(any(feature = "discovery", feature = "mdns"))]
use crate::discovery::{DiscoveryDriver, resolve_book_candidates};
#[cfg(feature = "nat")]
use crate::portable::connect::cancel_attempt;
use crate::portable::connect::{ConnectAdmission, admit_connect};
#[cfg(feature = "pubsub")]
use crate::pubsub::GossipsubDriver;
use minip2p_core::Multiaddr;
#[cfg(any(feature = "quic", feature = "tcp", feature = "relay-server"))]
use minip2p_core::Protocol;
#[cfg(any(feature = "quic", feature = "tcp"))]
use minip2p_core::TransportKind;
use minip2p_core::{PeerAddr, PeerId};
#[cfg(all(any(feature = "discovery", feature = "mdns"), feature = "smoltcp"))]
#[expect(
    unused_imports,
    reason = "The portable mDNS build re-exports this std API type without using it internally."
)]
pub use minip2p_discovery::DiscoverySource;
#[cfg(all(any(feature = "discovery", feature = "mdns"), not(feature = "smoltcp")))]
pub use minip2p_discovery::DiscoverySource;
#[cfg(feature = "discovery")]
pub use minip2p_discovery::{BeaconConfig, DISCOVERY_TOPIC};
#[cfg(any(feature = "discovery", feature = "mdns"))]
pub use minip2p_discovery::{DiscoveryConfigError, DiscoveryEvent, KnownPeer, PeerDiscoveryConfig};
pub use minip2p_identify::IdentifyMessage;
pub use minip2p_identity::Ed25519Keypair;
#[cfg(feature = "mdns")]
pub use minip2p_mdns::{MdnsConfig, MdnsConfigError};
#[cfg(feature = "nat")]
pub use minip2p_nat::{
    NatConfig, NatError, NatEvent, Path, ReachabilityState, ReservationInfo, ReservationPolicy,
};
#[cfg(feature = "tcp")]
use minip2p_platform::StdEntropy;
#[cfg(feature = "pubsub")]
pub use minip2p_pubsub::{
    GOSSIPSUB_PROTOCOL_IDS, GossipsubConfig, GossipsubConfigError, GossipsubEvent,
    MESHSUB_PROTOCOL_ID_V10, MESHSUB_PROTOCOL_ID_V11, PublishError, TopicError,
};
#[cfg(feature = "quic")]
pub use minip2p_quic::QuicLimits;
#[cfg(feature = "quic")]
use minip2p_quic::{QuicEndpoint, QuicNodeConfig};
#[cfg(feature = "relay-server")]
pub use minip2p_relay_server::{
    CircuitByteCounts, CircuitCloseReason, CircuitDirection, CircuitLeg, RateLimit,
    RelayServerAddressError, RelayServerAddressErrorKind, RelayServerConfig,
    RelayServerConfigError, RelayServerConfigErrorKind, RelayServerEvent, RelayServerRuntimeError,
    RelayServerRuntimeErrorKind, ReservationCloseReason, Status,
};
use minip2p_swarm::SwarmBuilder;
pub use minip2p_swarm::{
    Deadline, DriverError as Error, PollNext, RESERVED_PROTOCOL_IDS, RUN_UNTIL_SKIP_LIMIT, Swarm,
    SwarmError, SwarmEvent,
};
#[cfg(feature = "tcp")]
use minip2p_tcp::{StdTcpProvider, TcpConfig, TcpTransport};
#[cfg(any(feature = "quic", feature = "tcp"))]
use minip2p_transport::ConnectionNamespace;
use minip2p_transport::Transport;
pub use minip2p_transport::{ConnectionId, StreamId, TransportError, TransportSet, WaitHandle};
#[cfg(any(feature = "quic", feature = "tcp"))]
use std::str::FromStr;

use crate::portable::{ConnectEngine, DEFAULT_CONNECT_DEADLINE_MS};
use crate::{ConnectId, ConnectTarget, ConnectTargetError, EndpointEvent};

/// Why one blocking [`Endpoint::wait`] returned.
///
/// Deadline and interruption are control outcomes, not additional event
/// sources. Enabled capabilities deliver their output as [`EndpointEvent`]
/// variants inside [`Self::Event`](EndpointWaitOutcome::Event).
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "EndpointEvent ownership avoids a heap allocation on the ready path."
)]
#[must_use = "handle the wait outcome; an EndpointEvent has been removed from the endpoint"]
pub enum EndpointWaitOutcome {
    /// An application event from the Endpoint event stream.
    ///
    /// The event has been removed from the endpoint and belongs to the caller.
    Event(EndpointEvent),
    /// The caller's deadline elapsed without an application event.
    Deadline,
    /// The transport wait was interrupted by an external wait handle.
    Interrupted,
}

const DEFAULT_AGENT_VERSION: &str = concat!("minip2p/", env!("CARGO_PKG_VERSION"));

#[cfg(feature = "relay-server")]
const RELAY_HOP_PROTOCOL_ID: &str = "/libp2p/circuit/relay/0.2.0/hop";
#[cfg(feature = "relay-server")]
const RELAY_STOP_PROTOCOL_ID: &str = "/libp2p/circuit/relay/0.2.0/stop";

/// Relay announce-address validation failure while building an endpoint.
#[cfg(feature = "relay-server")]
#[derive(Debug)]
pub enum RelayServerAnnounceError {
    /// The temporary validator could not be constructed from its configuration.
    Config(RelayServerConfigError),
    /// An announce address is invalid for the relay identity.
    Address(RelayServerAddressError),
}

#[cfg(feature = "relay-server")]
impl From<RelayServerConfigError> for RelayServerAnnounceError {
    fn from(error: RelayServerConfigError) -> Self {
        Self::Config(error)
    }
}

#[cfg(feature = "relay-server")]
impl From<RelayServerAddressError> for RelayServerAnnounceError {
    fn from(error: RelayServerAddressError) -> Self {
        Self::Address(error)
    }
}

#[cfg(feature = "relay-server")]
impl core::fmt::Display for RelayServerAnnounceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(error) => error.fmt(formatter),
            Self::Address(error) => error.fmt(formatter),
        }
    }
}

#[cfg(feature = "relay-server")]
impl std::error::Error for RelayServerAnnounceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Address(error) => Some(error),
        }
    }
}

/// Synchronous relay-server runtime control failure.
#[cfg(feature = "relay-server")]
#[derive(Debug)]
pub enum RelayServerControlError {
    /// This endpoint was not built with relay-server enablement.
    NotConfigured,
    /// The complete replacement contained an invalid address and was not applied.
    InvalidAddress(RelayServerAddressError),
}

#[cfg(feature = "relay-server")]
impl core::fmt::Display for RelayServerControlError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotConfigured => formatter.write_str("relay server is not configured"),
            Self::InvalidAddress(error) => {
                write!(formatter, "invalid relay-server address: {error}")
            }
        }
    }
}

#[cfg(feature = "relay-server")]
impl std::error::Error for RelayServerControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAddress(error) => Some(error),
            Self::NotConfigured => None,
        }
    }
}

/// Transport used by [`Endpoint`]. With NAT enabled, relay bridges are
/// promoted into ordinary Noise/Yamux connections by `CircuitTransport`.
///
/// The endpoint always holds a [`TransportSet`], even with one member in it:
/// what an address is dialed over is then a routing decision the set makes
/// from the address itself, and adding a second transport changes nothing
/// above this line.
#[cfg(feature = "nat")]
pub type EndpointTransport =
    minip2p_circuit::CircuitTransport<TransportSet, minip2p_platform::StdEntropy>;

/// Transport used by [`Endpoint`] when NAT traversal is not compiled in.
#[cfg(not(feature = "nat"))]
pub type EndpointTransport = TransportSet;

/// Concrete swarm type owned by [`Endpoint`].
pub type EndpointSwarm = Swarm<EndpointTransport>;

/// App-facing minip2p endpoint over the transports it was asked to bind.
///
/// `Endpoint` owns identity, transports, and the std swarm driver. It has one
/// Connection-attempt entry point, [`connect`](Self::connect), and one ordered
/// Endpoint event stream, read with [`wait`](Self::wait) (blocking) or
/// [`poll`](Self::poll) (non-blocking). Every enabled capability (NAT,
/// Gossipsub, Discovery, relay-server) delivers its output once, as an
/// [`EndpointEvent`] variant on that stream. `poll` and `wait` finish each
/// swarm event before the next one: that swarm event, then capability events
/// in relay-server, NAT, Gossipsub, Discovery order, then Connection-attempt
/// terminals.
///
/// Applications correlate events by the IDs they carry (a [`ConnectId`], a
/// [`ConnectionId`], a [`StreamId`]) and dispatch unrelated events while they
/// wait for a particular one; see [`wait`](Self::wait) for the canonical loop.
///
/// Raw Transport dials bypass Connection-attempt policy and belong to the
/// lower-level swarm: borrow it with [`Endpoint::swarm_mut`] when that is
/// really what you want.
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
///
/// QUIC, TCP, or both, chosen by the addresses passed to
/// [`EndpointBuilder::listen_on`]. They live behind one [`TransportSet`],
/// which routes each address to the transport that serves its shape, so
/// nothing here or above changes with the second one: [`connect`](Self::connect)
/// takes the same complete peer addresses, [`listen`](Self::listen) arms every
/// bound address, and the events are the same events.
///
/// With the `nat` cargo feature and a NAT configuration
/// (`EndpointBuilder::relay` / `EndpointBuilder::nat_config`), `connect`
/// races direct candidates against a relay leg. Path transitions arrive as
/// [`EndpointEvent::Nat`]; the attempt's outcome is its
/// [`EndpointEvent::ConnectSettled`].
///
/// [`close`](Self::close) or drop disconnects established peers so a listener
/// is not left on the QUIC idle timeout. Neither path helps after `kill -9`
/// or a hard partition.
pub struct Endpoint {
    swarm: EndpointSwarm,
    connect: ConnectEngine,
    #[cfg(feature = "relay-server")]
    relay_server: Option<relay_server::RelayServerDriver>,
    #[cfg(feature = "nat")]
    nat: Option<NatDriver>,
    #[cfg(feature = "pubsub")]
    gossipsub: Option<GossipsubDriver>,
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    discovery: Option<DiscoveryDriver>,
    #[cfg(feature = "mdns")]
    mdns: Option<mdns::MdnsDriver>,
    /// The Endpoint event stream's queue: events produced by a step beyond
    /// the one returned.
    pending_events: std::collections::VecDeque<EndpointEvent>,
    #[cfg(any(feature = "nat", feature = "relay-server"))]
    caller_external_addresses: Vec<Multiaddr>,
    #[cfg(any(feature = "nat", feature = "relay-server"))]
    external_addresses_revision: u64,
}

impl Endpoint {
    /// Starts portable endpoint configuration with explicit identity and entropy.
    ///
    /// This constructs the same caller-driven, transport-generic endpoint as
    /// a `no_std` build; the std [`Endpoint::builder`] remains unchanged.
    pub fn portable<E: minip2p_platform::EntropySource>(
        identity: &Ed25519Keypair,
        entropy: E,
    ) -> crate::PortableEndpointBuilder<E> {
        crate::PortableEndpointBuilder::new(identity, entropy)
    }

    /// Returns a cloneable handle that can interrupt a blocking endpoint wait
    /// from another thread.
    ///
    /// Taken through the transport trait rather than the concrete QUIC
    /// endpoint, so it stays correct once the endpoint drives more than one
    /// transport.
    pub fn wait_handle(&self) -> WaitHandle {
        minip2p_transport::BlockingTransport::wait_handle(self.swarm.transport())
    }

    /// Starts building an endpoint.
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::default()
    }

    /// Returns this node's peer id.
    pub fn peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Starts listening on every bound address and returns the first.
    ///
    /// Every one of them, not only the address returned: an endpoint that
    /// bound two transports would otherwise report a listen success while one
    /// of them accepted nothing, and which one that was would depend on the
    /// order the sockets happened to be asked for. Use
    /// [`listen_all`](Self::listen_all) to see them all.
    pub fn listen(&mut self) -> Result<PeerAddr, Error> {
        let mut addrs = self.listen_all()?;
        // `listen_all` fails rather than return nothing, so there is one here.
        addrs.drain(..).next().ok_or(Error::Invariant {
            reason: "a successful listen reported no address",
        })
    }

    /// Starts listening on all transport-bound addresses.
    pub fn listen_all(&mut self) -> Result<Vec<PeerAddr>, Error> {
        let addrs = self.swarm.listen_on_bound_addrs()?;
        Ok(addrs)
    }

    /// Admits one Connection attempt and returns its [`ConnectId`].
    ///
    /// `target` is a [`PeerId`], one complete peer address such as
    /// `/ip4/192.0.2.7/udp/4001/quic-v1/p2p/12D3KooW…`, or a non-empty list of
    /// complete peer addresses that all name the same peer. Synchronous errors
    /// are malformed targets only; everything else, including "no usable
    /// route", arrives later as the attempt's one
    /// [`EndpointEvent::ConnectSettled`].
    ///
    /// A [`PeerId`] target uses the discovery book's known addresses (when a
    /// book exists) and the configured relay when one exists and `force_relay`
    /// / the dial source permit. When neither a direct candidate nor a
    /// configured relay exists, the attempt settles
    /// [`crate::ConnectFailure::NoUsableRoute`] through one terminal event.
    ///
    /// Every candidate is DNS-expanded and dialed immediately. Candidate
    /// completion order is not a public contract. The swarm still keeps a
    /// single connection per peer: a race loser that finishes after the winner
    /// may supersede it (`ConnectionClosed { Superseded }` then a new
    /// `ConnectionEstablished`). The attempt is already settled at the first
    /// established connection (including a simultaneous inbound), and the app
    /// sees those as ordinary connection events.
    ///
    /// Candidates may name the IP family explicitly (`/ip4`, `/ip6`); a
    /// `/dns` candidate is resolved and dialed over every family it answers
    /// with.
    #[expect(
        clippy::result_large_err,
        reason = "ConnectTargetError retains both peer identities for MixedPeers diagnostics."
    )]
    pub fn connect(
        &mut self,
        target: impl TryInto<ConnectTarget, Error: Into<ConnectTargetError>>,
    ) -> Result<ConnectId, ConnectTargetError> {
        Ok(self.connect_from(target.try_into().map_err(Into::into)?, true))
    }

    fn connect_from(&mut self, target: ConnectTarget, allow_relay: bool) -> ConnectId {
        let peer = target.peer_id().clone();
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        let candidates = resolve_book_candidates(
            self.discovery.as_ref().map(|discovery| &discovery.book),
            &peer,
            target.candidates().to_vec(),
        );
        #[cfg(not(any(feature = "discovery", feature = "mdns")))]
        let candidates = target.candidates().to_vec();
        let now = self.swarm.now();
        let id = admit_connect(
            &mut self.connect,
            self.swarm.runtime_mut(),
            #[cfg(feature = "nat")]
            self.nat.as_ref(),
            #[cfg(all(feature = "_nat-driver", not(feature = "nat")))]
            None,
            ConnectAdmission {
                peer: peer.clone(),
                candidates,
                allow_relay,
            },
            &mut dial::expand_dial_targets,
            now.monotonic_ms,
        );
        #[cfg(feature = "nat")]
        if let Some(nat) = self.nat.as_mut() {
            let now = self.swarm.now();
            nat.attach_leg(
                &self.connect,
                id,
                peer,
                allow_relay,
                self.swarm.runtime_mut(),
                now,
            );
        }
        self.feed_nat_to_connect();
        self.flush_step_events();
        id
    }

    /// Idempotent. Settled or unknown ids are a no-op. Never disconnects.
    pub fn cancel_connect(&mut self, id: ConnectId) {
        #[cfg(feature = "nat")]
        {
            let now = self.swarm.now();
            let needs_pump = cancel_attempt(
                &mut self.connect,
                self.nat.as_mut(),
                id,
                self.swarm.runtime_mut(),
                now,
            );
            if needs_pump && let Some(nat) = self.nat.as_mut() {
                nat.pump(self.swarm.runtime_mut(), now);
            }
        }
        #[cfg(not(feature = "nat"))]
        self.connect.cancel(id, self.swarm.runtime_mut());
        self.feed_nat_to_connect();
        self.flush_step_events();
    }

    /// Sends a ping to `peer_id`.
    ///
    /// The RTT is emitted later as [`EndpointEvent::PingRttMeasured`].
    pub fn ping(&mut self, peer_id: &PeerId) -> Result<(), Error> {
        self.swarm.ping(peer_id)
    }

    /// Closes the active connection to `peer_id`.
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), Error> {
        self.swarm.disconnect(peer_id)
    }

    /// Returns the current usable NAT-orchestrated path to `peer_id`.
    ///
    /// The map is updated before the corresponding NAT event is queued, is
    /// independent of event consumption, and is cleared after the peer's last
    /// usable connection closes. Raw swarm dials are not tracked.
    #[cfg(feature = "nat")]
    pub fn path(&self, peer_id: &PeerId) -> Option<Path> {
        self.nat.as_ref().and_then(|nat| nat.path(peer_id))
    }

    /// Returns peers with an established connection.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers()
    }

    /// Returns whether Identify has completed for `peer_id`.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.swarm.is_peer_ready(peer_id)
    }

    /// Returns the latest Identify information received for `peer_id`.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.swarm.peer_info(peer_id)
    }

    /// Returns the active transport connection selected for `peer_id`.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connection_id(&self, peer_id: &PeerId) -> Option<ConnectionId> {
        self.swarm.connection_id(peer_id)
    }

    /// Returns the remote transport address recorded for an exact connection.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connection_remote_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr> {
        self.swarm.connection_remote_addr(conn_id)
    }

    /// Returns addresses currently bound on the local transport.
    ///
    /// These are what the sockets were given, not a signal that
    /// [`Self::listen`] / [`Self::listen_all`] has started accepting. The set
    /// can be non-empty before listening begins.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn bound_addresses(&self) -> Vec<Multiaddr> {
        self.swarm.transport().local_addresses()
    }

    /// Registers an application protocol for inbound and outbound negotiation.
    ///
    /// Built-in ids ([`RESERVED_PROTOCOL_IDS`]) are rejected with
    /// [`SwarmError::ReservedProtocol`]; the endpoint's own identify and
    /// ping handlers already own them.
    pub fn add_protocol(&mut self, protocol_id: impl Into<String>) -> Result<(), Error> {
        self.swarm.add_protocol(protocol_id)
    }

    /// Opens an application stream after negotiating `protocol_id`.
    ///
    /// Allowed once the peer is connected. Identify (`PeerReady`) is not
    /// required first; after Identify completes, an unsupported protocol can
    /// fail early with [`SwarmError::RemoteDoesNotSupport`].
    pub fn open_stream(&mut self, peer_id: &PeerId, protocol_id: &str) -> Result<StreamId, Error> {
        self.swarm.open_stream(peer_id, protocol_id)
    }

    /// Opens an application stream and returns its connection and stream ids.
    pub fn open_stream_with_connection(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
    ) -> Result<(ConnectionId, StreamId), Error> {
        self.swarm.open_stream_with_connection(peer_id, protocol_id)
    }

    /// Sends bytes on a negotiated application stream.
    pub fn send_stream(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
        data: impl Into<Vec<u8>>,
    ) -> Result<(), Error> {
        self.swarm.send_stream(peer_id, stream_id, data.into())
    }

    /// Half-closes the local write side of an application stream.
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> Result<(), Error> {
        self.swarm.close_stream_write(peer_id, stream_id)
    }

    /// Resets an application stream.
    pub fn reset_stream(&mut self, peer_id: &PeerId, stream_id: StreamId) -> Result<(), Error> {
        self.swarm.reset_stream(peer_id, stream_id)
    }

    /// Resets and forgets an application stream that will no longer be consumed.
    ///
    /// Unlike [`Endpoint::reset_stream`], this also discards matching events
    /// already buffered by the endpoint and suppresses later data, EOF, and
    /// close events for the stream. Repeated calls are idempotent.
    pub fn abandon_stream(&mut self, peer_id: &PeerId, stream_id: StreamId) -> Result<(), Error> {
        self.swarm.abandon_stream(peer_id, stream_id)?;
        self.pending_events
            .retain(|event| !event.matches_stream(peer_id, stream_id));
        Ok(())
    }

    /// Polls the endpoint once and returns all currently available events.
    ///
    /// Returned values are [`EndpointEvent`]s from the Endpoint event stream,
    /// including enabled capability output. Each swarm event is finished
    /// before the next, matching [`Self::wait`]: that event, then capability
    /// events, then Connection-attempt terminals. Streams owned by an agent
    /// (NAT, relay service, Gossipsub) are consumed here and never surface as
    /// application stream events.
    pub fn poll(&mut self) -> Result<Vec<EndpointEvent>, Error> {
        self.tick_connect();
        let mut events: Vec<EndpointEvent> = self.pending_events.drain(..).collect();
        let polled = self.swarm.poll()?;
        if polled.is_empty() {
            // A quiet poll still ticks drivers and drains anything they queued.
            self.finish_step(&mut events)?;
        } else {
            for event in polled {
                events.extend(self.step_events(event)?);
            }
        }
        Ok(events)
    }

    /// Drives the endpoint until an Endpoint event, the caller's deadline, or
    /// an interruption.
    ///
    /// This is the single Endpoint blocking wait. Deadline and interruption
    /// stay visible so a loop can service its own timers and commands (a
    /// [`WaitHandle`] from another thread interrupts it). If an absolute
    /// [`std::time::Instant`] deadline has already passed, this returns
    /// [`EndpointWaitOutcome::Deadline`] before delivering another queued
    /// event. Relative [`std::time::Duration`] deadlines (including
    /// [`std::time::Duration::ZERO`] non-blocking drains) still inspect
    /// buffered events and poll once. Enabled capabilities deliver their
    /// output here as [`EndpointEvent`] variants, so one `wait` loop sees
    /// every event exactly once. Each call drives only this endpoint.
    ///
    /// # Examples
    ///
    /// The canonical event loop: wait for one correlated outcome while still
    /// dispatching every unrelated event.
    ///
    /// ```no_run
    /// use std::time::{Duration, Instant};
    ///
    /// use minip2p::{ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr};
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let mut node = Endpoint::builder().listen_default()?.bind()?;
    ///     // A complete peer address, copied from the remote's `listen()` output.
    ///     let target: PeerAddr = "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
    ///         .parse()?;
    ///     let connect_id = node.connect(target)?;
    ///     let deadline = Instant::now() + Duration::from_secs(10);
    ///     loop {
    ///         match node.wait(deadline)? {
    ///             EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
    ///                 connect_id: settled,
    ///                 outcome,
    ///                 ..
    ///             }) if settled == connect_id => match outcome {
    ///                 ConnectOutcome::Connected { conn_id } => {
    ///                     println!("connected on {conn_id:?}");
    ///                     return Ok(());
    ///                 }
    ///                 other => return Err(format!("connect failed: {other:?}").into()),
    ///             },
    ///             // Unrelated events keep flowing: dispatch them as usual.
    ///             EndpointWaitOutcome::Event(event) => println!("{event:?}"),
    ///             // Another thread woke us; service its commands, then wait again.
    ///             EndpointWaitOutcome::Interrupted => {}
    ///             // Giving up locally does not cancel the attempt; do that explicitly.
    ///             EndpointWaitOutcome::Deadline => {
    ///                 node.cancel_connect(connect_id);
    ///                 return Err("connect did not settle before the deadline".into());
    ///             }
    ///         }
    ///     }
    /// }
    /// ```
    pub fn wait(&mut self, deadline: impl Into<Deadline>) -> Result<EndpointWaitOutcome, Error> {
        let deadline = deadline.into();
        // Absolute Instant already past: Deadline wins over queued events.
        // Relative Duration::ZERO still drains / polls once.
        if deadline.prefers_deadline_over_queued() {
            return Ok(EndpointWaitOutcome::Deadline);
        }
        // `Swarm::poll_next_interruptible` performs one synchronous poll even
        // for an expired deadline. Allow that once, so a continuous event
        // stream cannot keep this wait running past its deadline.
        let mut expired_poll_used = false;
        loop {
            // A shortened step deadline is an internal timer, not the
            // caller's. Tick first so an attempt Timeout lands as
            // ConnectSettled.
            self.tick_connect();
            if let Some(event) = self.pending_events.pop_front() {
                return Ok(EndpointWaitOutcome::Event(event));
            }
            if deadline.has_passed() {
                if expired_poll_used {
                    return Ok(EndpointWaitOutcome::Deadline);
                }
                expired_poll_used = true;
            }
            let step = self.step_deadline(deadline);
            let polled = self.swarm.poll_next_interruptible(step)?;
            if deadline.has_passed() {
                expired_poll_used = true;
            }
            match polled {
                PollNext::Event(event) => {
                    let produced = self.step_events(event)?;
                    self.pending_events.extend(produced);
                }
                PollNext::Deadline => {
                    // An agent timer may have ended this step; let it act.
                    let mut produced = Vec::new();
                    self.finish_step(&mut produced)?;
                    if produced.is_empty() && deadline.has_passed() {
                        return Ok(EndpointWaitOutcome::Deadline);
                    }
                    self.pending_events.extend(produced);
                }
                PollNext::Interrupted => return Ok(EndpointWaitOutcome::Interrupted),
            }
        }
    }

    fn tick_connect(&mut self) {
        let now_ms = self.swarm.now().monotonic_ms;
        self.connect.tick(self.swarm.runtime_mut(), now_ms);
        self.flush_step_events();
    }

    /// Queues output produced outside a swarm step (API calls, timers):
    /// capability events first, then Connection-attempt events, so a
    /// terminal never overtakes the NAT events of the same call.
    fn flush_step_events(&mut self) {
        let mut out = Vec::new();
        self.drain_step_events(&mut out);
        self.pending_events.extend(out);
    }

    /// Runs one Endpoint step for a swarm event and returns everything it
    /// produced, in Endpoint emission order.
    fn step_events(&mut self, event: SwarmEvent) -> Result<Vec<EndpointEvent>, Error> {
        let mut produced: Vec<EndpointEvent> = self.ingest(event).into_iter().collect();
        self.finish_step(&mut produced)?;
        Ok(produced)
    }

    /// Ends one Endpoint step: ticks the agents, then appends capability
    /// events and Connection-attempt events in the documented order.
    fn finish_step(&mut self, out: &mut Vec<EndpointEvent>) -> Result<(), Error> {
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        self.tick_drivers()?;
        self.drain_step_events(out);
        Ok(())
    }

    /// Appends already-queued capability events, then Connection-attempt
    /// events, without driving anything.
    fn drain_step_events(&mut self, out: &mut Vec<EndpointEvent>) {
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        self.collect_capability_events(out);
        out.extend(self.take_connect_events());
    }

    /// Moves every queued capability event into `out` exactly once, in
    /// relay-server, NAT, Gossipsub, Discovery order.
    ///
    /// The discovery sweep removes beacon-topic Gossipsub traffic and
    /// discovery-owned NAT events before this drain. [`Self::finish_step`]
    /// runs that sweep and then calls this. [`Self::flush_step_events`] also
    /// calls this from `connect`, `cancel_connect`, and `tick_connect`
    /// without sweeping again; that stays correct only while
    /// every path that fills a driver queue ends in `finish_step` first.
    /// NAT output reaches the Connection-attempt engine before the drain;
    /// the attempt terminals it turns into `ConnectSettled` are not repeated
    /// as NAT events.
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn collect_capability_events(&mut self, out: &mut Vec<EndpointEvent>) {
        #[cfg(all(debug_assertions, any(feature = "discovery", feature = "mdns")))]
        if let (Some(discovery), Some(nat)) = (self.discovery.as_ref(), self.nat.as_ref()) {
            debug_assert!(
                nat.queued_events()
                    .all(|event| !discovery.owns_nat_event(event)),
                "discovery-owned NAT events must be swept before the capability drain"
            );
        }
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_mut() {
            out.extend(
                relay_server
                    .events
                    .drain(..)
                    .map(EndpointEvent::RelayServer),
            );
        }
        #[cfg(feature = "nat")]
        {
            self.feed_nat_to_connect();
            if let Some(nat) = self.nat.as_mut() {
                out.extend(nat.drain_application_events().map(EndpointEvent::Nat));
            }
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.gossipsub.as_mut() {
            out.extend(pubsub.events.drain(..).map(EndpointEvent::Gossipsub));
        }
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        if let Some(discovery) = self.discovery.as_mut() {
            discovery.drain_events(out);
        }
    }

    fn take_connect_events(&mut self) -> Vec<EndpointEvent> {
        let mut out = Vec::new();
        while let Some(event) = self.connect.pop_event() {
            #[cfg(feature = "nat")]
            self.cancel_nat_leg_on_terminal(&event);
            #[cfg(any(feature = "discovery", feature = "mdns"))]
            if self.discovery_claim_settled(&event) {
                continue;
            }
            out.push(event);
        }
        out
    }

    #[cfg(feature = "nat")]
    fn cancel_nat_leg_on_terminal(&mut self, event: &EndpointEvent) {
        if let Some(nat) = self.nat.as_mut() {
            let now = self.swarm.now();
            nat.cancel_leg_on_terminal(event, self.swarm.runtime_mut(), now);
        }
    }

    #[cfg(any(feature = "discovery", feature = "mdns"))]
    fn discovery_claim_settled(&mut self, event: &EndpointEvent) -> bool {
        let Some(discovery) = self.discovery.as_mut() else {
            return false;
        };
        let now_ms = self.swarm.now().monotonic_ms;
        discovery.claim_settled(event, now_ms)
    }

    /// Lets the Connection-attempt engine observe NAT output it has not seen
    /// yet, by reference; the events stay queued for the application.
    fn feed_nat_to_connect(&mut self) {
        #[cfg(feature = "nat")]
        if let Some(nat) = self.nat.as_mut() {
            let now = self.swarm.now();
            nat.feed_unobserved_to_connect(&mut self.connect, self.swarm.runtime_mut(), now);
        }
    }

    /// Feeds one swarm event to the Connection engine and the agents.
    ///
    /// Returns the event when no one claimed it. Capability and
    /// Connection-attempt output follows via [`Self::finish_step`].
    fn ingest(&mut self, event: SwarmEvent) -> Option<EndpointEvent> {
        let now_ms = self.swarm.now().monotonic_ms;
        let engine_consumed = self
            .connect
            .observe(&event, self.swarm.runtime_mut(), now_ms);
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        let driver_consumed = !engine_consumed && self.ingest_into_drivers(&event);
        #[cfg(not(any(feature = "nat", feature = "pubsub", feature = "relay-server")))]
        let driver_consumed = false;
        self.feed_nat_to_connect();
        (!engine_consumed && !driver_consumed).then(|| EndpointEvent::from(event))
    }

    /// One wait step's deadline: the caller's, shortened by whichever
    /// Connection-attempt or agent timer is due first.
    fn step_deadline(&mut self, deadline: Deadline) -> Deadline {
        let now = self.swarm.now();
        let mut step = deadline;
        let mut shorten = |ms: u64| {
            step = step.earliest(Deadline::from(std::time::Duration::from_millis(ms.max(1))));
        };
        if let Some(next) = self.connect.next_deadline() {
            shorten(next.millis_until(now));
        }
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_ref()
            && let Some(ms) = relay_server.agent.next_timeout(relay_server.now())
        {
            shorten(ms);
        }
        #[cfg(feature = "nat")]
        if let Some(ms) = self.nat.as_ref().and_then(|nat| nat.next_timeout(now)) {
            shorten(ms);
        }
        #[cfg(feature = "pubsub")]
        if let Some(ms) = self
            .gossipsub
            .as_ref()
            .and_then(|pubsub| pubsub.next_timeout(now.monotonic_ms))
        {
            shorten(ms);
        }
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        if let Some(ms) = self
            .discovery
            .as_ref()
            .and_then(|discovery| discovery.next_timeout(now.monotonic_ms))
        {
            shorten(ms);
        }
        #[cfg(feature = "mdns")]
        if let Some(ms) = self
            .mdns
            .as_ref()
            .and_then(|mdns| mdns.next_timeout(mdns.now_ms()))
        {
            shorten(ms);
        }
        step
    }

    /// Feeds one swarm event through relay-server, NAT, then pubsub.
    ///
    /// Relay service owns inbound HOP before NAT considers its client-side
    /// streams. Neither service claims connection lifecycle or `PeerReady`,
    /// so both still observe the shared connection state.
    ///
    /// Returns `true` when a driver claimed the event.
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn ingest_into_drivers(&mut self, event: &SwarmEvent) -> bool {
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        if let Some(discovery) = self.discovery.as_mut() {
            let now_ms = self.swarm.now().monotonic_ms;
            discovery.observe(event, self.swarm.core(), now_ms);
        }
        let mut claimed = false;
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_mut() {
            claimed = relay_server.ingest(event, &mut self.swarm);
        }
        #[cfg(feature = "nat")]
        if !claimed && let Some(nat) = self.nat.as_mut() {
            let now = self.swarm.now();
            claimed = nat.ingest(event, self.swarm.runtime_mut(), now);
        }
        #[cfg(feature = "pubsub")]
        if !claimed && let Some(pubsub) = self.gossipsub.as_mut() {
            let now_ms = self.swarm.now().monotonic_ms;
            claimed = pubsub.ingest(event, self.swarm.runtime_mut(), now_ms);
        }
        #[cfg(any(feature = "nat", feature = "relay-server"))]
        self.refresh_external_address_contributions();
        claimed
    }

    /// Ticks every active driver.
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn tick_drivers(&mut self) -> Result<(), Error> {
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_mut() {
            relay_server.tick(&mut self.swarm);
        }
        #[cfg(feature = "nat")]
        if let Some(nat) = self.nat.as_mut() {
            let now = self.swarm.now();
            nat.tick(self.swarm.runtime_mut(), now);
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.gossipsub.as_mut() {
            let now_ms = self.swarm.now().monotonic_ms;
            pubsub.tick(self.swarm.runtime_mut(), now_ms);
        }
        #[cfg(feature = "mdns")]
        if let Some(mdns) = self.mdns.as_mut() {
            mdns.tick(self.swarm.core().local_addresses())
                .map_err(mdns_driver_error)?;
        }
        self.feed_nat_to_connect();
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        if let Some(discovery) = self.discovery.as_mut() {
            #[cfg(feature = "mdns")]
            if let Some(mdns) = self.mdns.as_mut() {
                let now_ms = self.swarm.now().monotonic_ms;
                while let Some(event) = mdns.poll_event() {
                    discovery.handle_mdns_event(event, now_ms);
                }
            }
            let now = self.swarm.now();
            let work = discovery.sweep(
                #[cfg(feature = "pubsub")]
                self.gossipsub.as_mut(),
                self.nat.as_mut(),
                &mut self.connect,
                self.swarm.runtime_mut(),
                &mut dial::expand_dial_targets,
                now,
            );
            // Both discovery features imply `nat`.
            if let Some(nat) = self.nat.as_mut() {
                nat.apply_sweep_work(work, &self.connect, self.swarm.runtime_mut(), now);
                // Attaching a leg can queue a synchronous terminal the
                // sweep's claim pass already ran past; the engine must
                // observe it before the capability drain filters it out.
                discovery.claim_nat_events(
                    nat,
                    &mut self.connect,
                    self.swarm.runtime_mut(),
                    now.monotonic_ms,
                );
            }
        }
        #[cfg(any(feature = "nat", feature = "relay-server"))]
        self.refresh_external_address_contributions();
        self.feed_nat_to_connect();
        Ok(())
    }

    /// Pauses or resumes admission of new relay reservations and circuits.
    ///
    /// Existing reservations and circuits remain active, and HOP remains
    /// advertised while admission is paused.
    #[cfg(feature = "relay-server")]
    #[expect(
        clippy::result_large_err,
        reason = "The error retains the rejected address for actionable host diagnostics."
    )]
    pub fn set_relay_server_accepting(
        &mut self,
        accepting: bool,
    ) -> Result<(), RelayServerControlError> {
        let relay_server = self
            .relay_server
            .as_mut()
            .ok_or(RelayServerControlError::NotConfigured)?;
        relay_server.agent.set_accepting(accepting);
        Ok(())
    }

    /// Atomically replaces the relay server's explicit announce-address override.
    ///
    /// Each address must be a concrete direct TCP or QUIC address for this
    /// endpoint's peer id. [`RelayServerControlError::InvalidAddress`] retains
    /// the rejected input's index and reason; on error, the previous override
    /// remains active. An empty replacement clears the override, restoring the
    /// confirmed-NAT-then-concrete-listener fallback order.
    #[cfg(feature = "relay-server")]
    #[expect(
        clippy::result_large_err,
        reason = "The error retains the rejected address for actionable host diagnostics."
    )]
    pub fn set_relay_server_announce_addrs(
        &mut self,
        addrs: Vec<Multiaddr>,
    ) -> Result<(), RelayServerControlError> {
        let relay_server = self
            .relay_server
            .as_mut()
            .ok_or(RelayServerControlError::NotConfigured)?;
        relay_server
            .agent
            .replace_announce_addrs(addrs)
            .map_err(RelayServerControlError::InvalidAddress)?;
        self.refresh_external_address_contributions();
        Ok(())
    }

    #[cfg(any(feature = "nat", feature = "relay-server"))]
    fn refresh_external_address_contributions(&mut self) {
        if self.swarm.external_addresses_revision() != self.external_addresses_revision {
            self.caller_external_addresses = self.swarm.external_addresses().to_vec();
        }
        #[cfg(feature = "relay-server")]
        {
            let listeners = concrete_relay_listener_addrs(self.swarm.transport().local_addresses());
            #[cfg(feature = "nat")]
            let confirmed = self
                .nat
                .as_ref()
                .map(NatDriver::confirmed_public_addrs)
                .unwrap_or_default();
            if let Some(relay_server) = self.relay_server.as_mut() {
                // The address source comes from local bound listeners; on
                // rejection the agent deliberately keeps its previous source.
                drop(relay_server.agent.set_listener_addrs(listeners));
                #[cfg(feature = "nat")]
                // Confirmed addresses were already accepted by the NAT agent;
                // retain the previous relay source if conversion rejects one.
                drop(relay_server.agent.set_confirmed_addrs(confirmed));
            }
        }
        let mut addresses = self.caller_external_addresses.clone();
        #[cfg(feature = "nat")]
        if let Some(nat) = self.nat.as_ref() {
            for address in nat.advertised_addrs() {
                if !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_ref() {
            for address in relay_server.agent.selected_addrs() {
                if !addresses.contains(address) {
                    addresses.push(address.clone());
                }
            }
        }
        self.swarm.set_external_addresses(addresses);
        self.external_addresses_revision = self.swarm.external_addresses_revision();
    }

    /// Our current reachability verdict from AutoNAT probing
    /// ([`ReachabilityState::Unknown`] until probes gather confidence, or
    /// when NAT is not configured).
    #[cfg(feature = "nat")]
    pub fn reachability(&self) -> ReachabilityState {
        self.nat
            .as_ref()
            .map(|nat| nat.reachability())
            .unwrap_or_default()
    }

    /// The relay reservation currently held, if any.
    #[cfg(feature = "nat")]
    pub fn active_reservation(&self) -> Option<ReservationInfo> {
        self.nat
            .as_ref()
            .and_then(|nat| nat.active_reservation().cloned())
    }

    /// Subscribes to a pubsub topic. Returns `Ok(false)` when already
    /// subscribed. The subscription is announced over gossipsub.
    ///
    /// Errors with [`GossipsubError::NotEnabled`] unless the endpoint was
    /// built with [`EndpointBuilder::gossipsub`].
    #[cfg(feature = "pubsub")]
    pub fn subscribe(&mut self, topic: &str) -> Result<bool, GossipsubError> {
        let Some(pubsub) = self.gossipsub.as_mut() else {
            return Err(GossipsubError::NotEnabled);
        };
        let now_ms = self.swarm.now().monotonic_ms;
        Ok(pubsub.subscribe(topic, self.swarm.runtime_mut(), now_ms)?)
    }

    /// Withdraws a pubsub subscription. Returns `Ok(false)` when not
    /// subscribed. The configured discovery topic is reserved while
    /// discovery is enabled and returns
    /// [`GossipsubError::DiscoveryTopicReserved`].
    #[cfg(feature = "pubsub")]
    pub fn unsubscribe(&mut self, topic: &str) -> Result<bool, GossipsubError> {
        #[cfg(feature = "discovery")]
        let reserved = self.discovery.as_ref().and_then(|d| d.topic());
        #[cfg(not(feature = "discovery"))]
        let reserved = None;
        let Some(pubsub) = self.gossipsub.as_mut() else {
            return Err(GossipsubError::NotEnabled);
        };
        let now_ms = self.swarm.now().monotonic_ms;
        pubsub.unsubscribe(topic, reserved, self.swarm.runtime_mut(), now_ms)
    }

    /// Publishes `data` on `topic`, signed with this endpoint's identity and
    /// forwarded over gossipsub.
    ///
    /// A successful return means the message was accepted and its outbound
    /// streams were initiated — the frames themselves go out as the
    /// endpoint is driven (`wait` / `poll`), so keep driving after
    /// publishing. Delivery failures are never synchronous errors; they
    /// surface later as [`GossipsubEvent::OutboundFailure`] (or
    /// [`EndpointEvent::Error`] runtime events). There is no self-delivery. The
    /// configured discovery topic is reserved while discovery is enabled
    /// and returns [`GossipsubError::DiscoveryTopicReserved`].
    #[cfg(feature = "pubsub")]
    pub fn publish(&mut self, topic: &str, data: impl Into<Vec<u8>>) -> Result<(), GossipsubError> {
        #[cfg(feature = "discovery")]
        let reserved = self.discovery.as_ref().and_then(|d| d.topic());
        #[cfg(not(feature = "discovery"))]
        let reserved = None;
        let Some(pubsub) = self.gossipsub.as_mut() else {
            return Err(GossipsubError::NotEnabled);
        };
        let now_ms = self.swarm.now().monotonic_ms;
        pubsub.publish(
            topic,
            data.into(),
            reserved,
            self.swarm.runtime_mut(),
            now_ms,
        )?;
        Ok(())
    }

    /// Returns the current discovery address-book snapshot.
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    pub fn known_peers(&self) -> Vec<KnownPeer> {
        self.discovery
            .as_ref()
            .map(|driver| driver.book.known_peers())
            .unwrap_or_default()
    }

    /// Returns the discovery driver's current monotonic timestamp.
    ///
    /// This uses the same private clock origin as
    /// `KnownPeer::beacon_last_seen_ms` and `KnownPeer::mdns_last_seen_ms`.
    /// Callers computing source ages must use this value rather than an
    /// independently created clock. Returns `None` when no discovery source
    /// is active.
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    pub fn discovery_now_ms(&mut self) -> Option<u64> {
        self.discovery.as_ref()?;
        Some(self.swarm.now().monotonic_ms)
    }

    /// Borrows the underlying swarm.
    pub fn swarm(&self) -> &EndpointSwarm {
        &self.swarm
    }

    /// Mutably borrows the underlying swarm.
    pub fn swarm_mut(&mut self) -> &mut EndpointSwarm {
        &mut self.swarm
    }

    /// Sends mDNS goodbyes once and cancels discovery-owned dial attempts.
    ///
    /// mDNS becomes permanently inactive, while QUIC and the rest of the
    /// endpoint remain usable. Every interface send and every cancellation is
    /// attempted; the first mDNS socket error is returned afterwards.
    ///
    /// This does not close QUIC/TCP peers; use [`close`](Self::close) or drop.
    #[cfg(feature = "mdns")]
    pub fn shutdown(&mut self) -> Result<(), Error> {
        let result = self
            .mdns
            .as_mut()
            .map(mdns::MdnsDriver::shutdown)
            .transpose()
            .map(|_| ())
            .map_err(mdns_driver_error);
        if let Some(discovery) = self.discovery.as_mut() {
            let now = self.swarm.now();
            let work = discovery.shutdown(
                &mut self.connect,
                self.nat.as_mut(),
                self.swarm.runtime_mut(),
                now,
            );
            // `mdns` implies `nat`. Shutdown already cleared `inflight`, so
            // its queued events are not discovery-owned anymore; the next
            // poll feeds them to the engine and the app like any NAT event.
            if let Some(nat) = self.nat.as_mut() {
                nat.apply_sweep_work(work, &self.connect, self.swarm.runtime_mut(), now);
            }
        }
        result
    }

    /// Disconnects established peers, waits briefly until none remain,
    /// and consumes the endpoint.
    ///
    /// Named `close` because `shutdown` is already used for mDNS goodbyes.
    /// Dropping without `close` still disconnects (errors ignored). Neither
    /// notifies a peer after `kill -9` or a hard partition. A replacement
    /// that lands while draining is disconnected too, including a handshake
    /// still pending when the superseded connection closes.
    pub fn close(mut self) -> Result<Vec<EndpointEvent>, Error> {
        let mut first_error = None;
        #[cfg(feature = "mdns")]
        if let Err(error) = self.shutdown() {
            first_error = Some(error);
        }
        let drain_by = std::time::Instant::now() + std::time::Duration::from_millis(500);
        let mut events = Vec::new();
        loop {
            if let Some(error) = self.disconnect_established()
                && first_error.is_none()
            {
                first_error = Some(error);
            }
            if std::time::Instant::now() >= drain_by {
                break;
            }
            let polled = if self.close_drain_busy() {
                self.swarm.poll_next(drain_by)
            } else {
                self.swarm.poll_next(std::time::Duration::ZERO)
            };
            match polled {
                Ok(Some(event)) => {
                    // No agent tick or discovery sweep runs while closing, so
                    // only connection and attempt events are returned.
                    events.extend(self.ingest(event));
                    events.extend(self.take_connect_events());
                }
                Ok(None) => {
                    if !self.close_drain_busy() || std::time::Instant::now() >= drain_by {
                        break;
                    }
                }
                Err(error) => {
                    return match first_error {
                        Some(first) => Err(first),
                        None => Err(error),
                    };
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(events),
        }
    }

    fn close_drain_busy(&self) -> bool {
        !self.swarm.connected_peers().is_empty() || self.swarm.core().has_tracked_connections()
    }

    fn disconnect_established(&mut self) -> Option<Error> {
        let mut first_error = None;
        for peer in self.swarm.connected_peers() {
            if let Err(error) = self.swarm.disconnect(&peer)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        // Drop cannot surface disconnect failures; transports own final cleanup.
        drop(self.disconnect_established());
    }
}

#[cfg(feature = "mdns")]
fn mdns_driver_error(error: minip2p_mdns::MdnsError) -> Error {
    TransportError::PollError {
        reason: error.to_string(),
    }
    .into()
}

#[cfg(feature = "mdns")]
fn mdns_seed(keypair: &Ed25519Keypair) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let peer_id = keypair.peer_id();
    let digest = peer_id.digest_bytes();
    for (slot, byte) in seed.iter_mut().zip(digest.iter().cycle()) {
        *slot ^= *byte;
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
        .to_le_bytes();
    for (slot, byte) in seed.iter_mut().zip(timestamp.iter().cycle()) {
        *slot ^= *byte;
    }
    seed
}

/// Default dual-stack QUIC listen addresses used by
/// [`EndpointBuilder::listen_default`].
#[cfg(feature = "quic")]
fn default_listen_quic_addrs() -> [Multiaddr; 2] {
    [
        Multiaddr::from_protocols(vec![
            Protocol::Ip4([0, 0, 0, 0]),
            Protocol::Udp(0),
            Protocol::QuicV1,
        ]),
        Multiaddr::from_protocols(vec![
            Protocol::Ip6([0; 16]),
            Protocol::Udp(0),
            Protocol::QuicV1,
        ]),
    ]
}

/// Builder for [`Endpoint`].
pub struct EndpointBuilder {
    keypair: Option<Ed25519Keypair>,
    agent_version: String,
    #[cfg(feature = "quic")]
    quic_limits: QuicLimits,
    #[cfg(feature = "tcp")]
    tcp_config: TcpConfig,
    /// Ordered listen addresses; transport is inferred from address shape.
    #[cfg(any(feature = "quic", feature = "tcp"))]
    listen_addrs: Vec<Multiaddr>,
    protocols: Vec<String>,
    #[cfg(feature = "relay-server")]
    relay_server_config: Option<RelayServerConfig>,
    #[cfg(feature = "relay-server")]
    relay_server_announce_addrs: Vec<Multiaddr>,
    #[cfg(feature = "nat")]
    nat_config: Option<NatConfig>,
    #[cfg(feature = "nat")]
    relays: Vec<PeerAddr>,
    #[cfg(feature = "nat")]
    autonat_servers: Vec<PeerAddr>,
    #[cfg(feature = "pubsub")]
    gossipsub_config: Option<GossipsubConfig>,
    #[cfg(feature = "discovery")]
    discovery_config: Option<BeaconConfig>,
    #[cfg(feature = "mdns")]
    mdns_config: Option<MdnsConfig>,
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    peer_discovery_config: PeerDiscoveryConfig,
    connect_deadline: std::time::Duration,
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self {
            keypair: None,
            agent_version: DEFAULT_AGENT_VERSION.to_string(),
            connect_deadline: std::time::Duration::from_millis(DEFAULT_CONNECT_DEADLINE_MS),
            #[cfg(feature = "quic")]
            quic_limits: QuicLimits::default(),
            #[cfg(feature = "tcp")]
            tcp_config: TcpConfig::default(),
            #[cfg(any(feature = "quic", feature = "tcp"))]
            listen_addrs: Vec::new(),
            protocols: Vec::new(),
            #[cfg(feature = "relay-server")]
            relay_server_config: None,
            #[cfg(feature = "relay-server")]
            relay_server_announce_addrs: Vec::new(),
            #[cfg(feature = "nat")]
            nat_config: None,
            #[cfg(feature = "nat")]
            relays: Vec::new(),
            #[cfg(feature = "nat")]
            autonat_servers: Vec::new(),
            #[cfg(feature = "pubsub")]
            gossipsub_config: None,
            #[cfg(feature = "discovery")]
            discovery_config: None,
            #[cfg(feature = "mdns")]
            mdns_config: None,
            #[cfg(any(feature = "discovery", feature = "mdns"))]
            peer_discovery_config: PeerDiscoveryConfig::default(),
        }
    }
}

impl EndpointBuilder {
    /// Uses an explicit host keypair.
    pub fn identity(mut self, keypair: Ed25519Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Overrides the Identify `agentVersion` string.
    pub fn agent_version(mut self, value: impl Into<String>) -> Self {
        self.agent_version = value.into();
        self
    }

    /// Sets the Connection-attempt deadline. Default is 30 seconds.
    pub fn connect_deadline(mut self, deadline: std::time::Duration) -> Self {
        self.connect_deadline = deadline;
        self
    }

    /// Overrides QUIC connection, stream, queue, and timeout limits.
    #[cfg(feature = "quic")]
    pub fn quic_limits(mut self, limits: QuicLimits) -> Self {
        self.quic_limits = limits;
        self
    }

    /// Overrides TCP connection, buffer, and timeout limits, and the
    /// connection-id namespace the TCP transport allocates in.
    #[cfg(feature = "tcp")]
    pub fn tcp_config(mut self, config: TcpConfig) -> Self {
        self.tcp_config = config;
        self
    }

    /// Adds a listener from a complete transport multiaddress.
    ///
    /// QUIC (`/ip4|ip6/udp/<port>/quic-v1`) and TCP (`/ip4|ip6/tcp/<port>`)
    /// shapes are accepted. Compatible addresses are grouped at
    /// [`EndpointBuilder::bind`]; unsupported or contradictory shapes fail
    /// here with an actionable error.
    ///
    /// Named `listen_on` to avoid colliding with [`Endpoint::listen`], which
    /// returns the first bound address after bind.
    #[cfg(any(feature = "quic", feature = "tcp"))]
    pub fn listen_on(mut self, address: impl AsRef<str>) -> Result<Self, Error> {
        let raw = address.as_ref();
        let parsed = Multiaddr::from_str(raw).map_err(|error| TransportError::InvalidAddress {
            context: "listen address",
            reason: format!("`{raw}` is not a multiaddr: {error}"),
        })?;
        self.push_listen_addr(parsed)?;
        Ok(self)
    }

    /// Adds a listener from an already-parsed transport multiaddress.
    #[cfg(any(feature = "quic", feature = "tcp"))]
    pub fn listen_on_multiaddr(mut self, address: &Multiaddr) -> Result<Self, Error> {
        self.push_listen_addr(address.clone())?;
        Ok(self)
    }

    /// Configures the common dual-stack QUIC defaults
    /// (`/ip4/0.0.0.0/udp/0/quic-v1` and `/ip6/::/udp/0/quic-v1`).
    ///
    /// Returns [`Error`] if the builder already has a QUIC listen for either
    /// family (same duplicate-family rule as [`Self::listen_on`]).
    #[cfg(feature = "quic")]
    pub fn listen_default(mut self) -> Result<Self, Error> {
        for address in default_listen_quic_addrs() {
            self.push_listen_addr(address)?;
        }
        Ok(self)
    }

    #[cfg(any(feature = "quic", feature = "tcp"))]
    fn push_listen_addr(&mut self, address: Multiaddr) -> Result<(), Error> {
        validate_listen_multiaddr(&address)?;
        #[cfg(feature = "quic")]
        if address.is_quic_transport() {
            reject_duplicate_quic_family(&self.listen_addrs, &address)?;
        }
        self.listen_addrs.push(address);
        Ok(())
    }

    /// Registers an application protocol before the endpoint starts.
    ///
    /// Built-in ids ([`RESERVED_PROTOCOL_IDS`]) are reserved; registering
    /// one makes the bind step fail with
    /// [`SwarmError::ReservedProtocol`].
    pub fn protocol(mut self, protocol_id: impl Into<String>) -> Self {
        let id = protocol_id.into();
        if !self.protocols.iter().any(|protocol| protocol == &id) {
            self.protocols.push(id);
        }
        self
    }

    /// Enables Circuit Relay v2 service with production-oriented defaults.
    ///
    /// After binding, use [`Endpoint::set_relay_server_accepting`] to pause or
    /// resume admission. Reservation, circuit, accounting, and asynchronous
    /// failure events arrive from [`Endpoint::wait`] as
    /// [`EndpointEvent::RelayServer`].
    #[cfg(feature = "relay-server")]
    pub fn relay_server(mut self) -> Self {
        self.relay_server_config
            .get_or_insert_with(RelayServerConfig::default);
        self
    }

    /// Enables Circuit Relay v2 service with validated custom limits.
    ///
    /// Returns [`RelayServerConfigError`] with the invalid field path and reason
    /// when a required value is zero or a duration exceeds the wire encoding.
    /// A failed call leaves the builder unchanged.
    #[cfg(feature = "relay-server")]
    pub fn relay_server_config(
        mut self,
        config: RelayServerConfig,
    ) -> Result<Self, RelayServerConfigError> {
        config.validate()?;
        self.relay_server_config = Some(config);
        Ok(self)
    }

    /// Configures advertised direct addresses without enabling relay service.
    ///
    /// This method validates direct TCP/QUIC shape, rejects wildcard and circuit
    /// addresses, and checks a trailing peer id against an already-fixed builder
    /// identity. [`RelayServerAnnounceError`] preserves either the rejected input
    /// or a validator configuration failure. When identity is not fixed yet, the peer-id match is
    /// checked again at bind. Announce addresses alone do not enable the service;
    /// also call [`EndpointBuilder::relay_server`] or
    /// [`EndpointBuilder::relay_server_config`].
    #[cfg(feature = "relay-server")]
    #[expect(
        clippy::result_large_err,
        reason = "The error owns the rejected announce address for actionable host diagnostics."
    )]
    pub fn relay_server_announce_addrs(
        mut self,
        addrs: Vec<Multiaddr>,
    ) -> Result<Self, RelayServerAnnounceError> {
        let validation_peer = self
            .keypair
            .as_ref()
            .map(Ed25519Keypair::peer_id)
            .or_else(|| {
                addrs
                    .iter()
                    .find_map(|address| match address.iter().last() {
                        Some(Protocol::P2p(peer_id)) => Some(peer_id.clone()),
                        _ => None,
                    })
            })
            .unwrap_or_else(|| Ed25519Keypair::generate().peer_id());
        let mut validator = minip2p_relay_server::RelayServerAgent::new(
            validation_peer,
            RelayServerConfig::default(),
        )?;
        validator.replace_announce_addrs(addrs.clone())?;
        self.relay_server_announce_addrs = addrs;
        Ok(self)
    }

    /// Adds a relay for NAT traversal (circuit legs and reservations), in
    /// preference order. Configuring at least one relay (or calling
    /// [`EndpointBuilder::nat_config`]) enables the traversal agent.
    #[cfg(feature = "nat")]
    pub fn relay(mut self, relay: PeerAddr) -> Self {
        self.relays.push(relay);
        self
    }

    /// Adds an AutoNAT server used for reachability probing.
    #[cfg(feature = "nat")]
    pub fn autonat_server(mut self, server: PeerAddr) -> Self {
        self.autonat_servers.push(server);
        self
    }

    /// Sets the base NAT configuration (timeouts, punch retries,
    /// reservation policy, …). Relays and AutoNAT servers added through
    /// [`EndpointBuilder::relay`] / [`EndpointBuilder::autonat_server`] are
    /// appended to the config's own lists.
    #[cfg(feature = "nat")]
    pub fn nat_config(mut self, config: NatConfig) -> Self {
        self.nat_config = Some(config);
        self
    }

    /// Enables pubsub with the default gossipsub configuration.
    ///
    /// Builder-time opt-in (rather than a lazy `subscribe`-time enable)
    /// because the gossipsub protocol ids must be in Identify's advertised
    /// set from the first handshake.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub(mut self) -> Self {
        self.gossipsub_config
            .get_or_insert_with(GossipsubConfig::default);
        self
    }

    /// Enables pubsub with an explicit gossipsub configuration.
    ///
    /// Invalid mesh relationships or zero bounds fail the later `bind()`
    /// before a socket is allocated.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub_config(mut self, config: GossipsubConfig) -> Self {
        self.gossipsub_config = Some(config);
        self
    }

    /// Enables signed pubsub peer discovery with interoperable defaults.
    ///
    /// The discovery topic is driver-owned: subscribing to it again through
    /// [`Endpoint::subscribe`] is redundant, and its pubsub messages and
    /// subscription events are consumed before reaching the application.
    #[cfg(feature = "discovery")]
    pub fn discovery(mut self) -> Self {
        self.gossipsub_config
            .get_or_insert_with(GossipsubConfig::default);
        self.discovery_config = Some(BeaconConfig::default());
        self
    }

    /// Enables discovery with an explicitly validated configuration.
    ///
    /// Validation occurs before any transport bind can allocate a socket.
    /// The configured topic is driver-owned: subscribing to it again through
    /// [`Endpoint::subscribe`] is redundant, and its pubsub messages and
    /// subscription events are consumed before reaching the application.
    #[cfg(feature = "discovery")]
    pub fn discovery_config(mut self, config: BeaconConfig) -> Result<Self, DiscoveryConfigError> {
        config.validate()?;
        self.gossipsub_config
            .get_or_insert_with(GossipsubConfig::default);
        self.discovery_config = Some(config);
        Ok(self)
    }

    /// Enables local-link mDNS discovery with interoperable defaults.
    #[cfg(feature = "mdns")]
    pub fn mdns(mut self) -> Self {
        self.mdns_config = Some(MdnsConfig::default());
        self
    }

    /// Enables local-link mDNS discovery with an explicitly validated configuration.
    ///
    /// Validation occurs before the QUIC or mDNS sockets are allocated.
    #[cfg(feature = "mdns")]
    pub fn mdns_config(mut self, config: MdnsConfig) -> Result<Self, MdnsConfigError> {
        config.validate()?;
        self.mdns_config = Some(config);
        Ok(self)
    }

    /// Overrides the shared address-book and automatic-dial policy.
    ///
    /// This policy is shared by every enabled discovery source.
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    pub fn peer_discovery_config(
        mut self,
        config: PeerDiscoveryConfig,
    ) -> Result<Self, DiscoveryConfigError> {
        config.validate()?;
        self.peer_discovery_config = config;
        Ok(self)
    }

    /// Builds the endpoint, bringing up every transport it was given.
    ///
    /// A `/udp/…/quic-v1` address is then dialed over QUIC and a `/tcp` one
    /// over TCP, decided from the address rather than by the caller. An
    /// endpoint with nothing to bind is refused: it could neither dial nor be
    /// reached, and failing here says so more clearly than every later call
    /// would.
    pub fn bind(mut self) -> Result<Endpoint, Error> {
        self.validate()?;
        let keypair = self.keypair.take().unwrap_or_else(Ed25519Keypair::generate);
        let transport = bind_transports(&self, &keypair)?;
        build_endpoint(self, keypair, transport)
    }

    /// Validates the static configuration.
    ///
    /// Reserved protocol ids are rejected here -- before any socket is
    /// bound -- so a configuration error can neither allocate resources
    /// nor be masked by a bind failure.
    fn validate(&self) -> Result<(), Error> {
        if let Some(protocol) = self
            .protocols
            .iter()
            .find(|protocol| RESERVED_PROTOCOL_IDS.contains(&protocol.as_str()))
        {
            return Err(SwarmError::ReservedProtocol {
                protocol_id: protocol.clone(),
            }
            .into());
        }
        #[cfg(feature = "pubsub")]
        if let Some(config) = &self.gossipsub_config {
            config
                .validate()
                .map_err(|error| TransportError::InvalidConfig {
                    reason: error.to_string(),
                })?;
        }
        #[cfg(feature = "relay-server")]
        if self.relay_server_config.is_none() && !self.relay_server_announce_addrs.is_empty() {
            return Err(TransportError::InvalidConfig {
                reason: "relay-server announce addresses were configured, but the relay server is not enabled; call EndpointBuilder::relay_server or relay_server_config".into(),
            }
            .into());
        }
        Ok(())
    }

    /// The NAT configuration to run, if any builder option enabled NAT:
    /// explicit config, relays, AutoNAT servers, or a discovery source.
    #[cfg(feature = "nat")]
    fn take_nat_config(&mut self) -> Option<NatConfig> {
        #[cfg(feature = "discovery")]
        let discovery = self.discovery_config.is_some();
        #[cfg(not(feature = "discovery"))]
        let discovery = false;
        #[cfg(feature = "mdns")]
        let mdns = self.mdns_config.is_some();
        #[cfg(not(feature = "mdns"))]
        let mdns = false;
        let enabled = self.nat_config.is_some()
            || !self.relays.is_empty()
            || !self.autonat_servers.is_empty()
            || discovery
            || mdns;
        enabled.then(|| {
            let mut config = self.nat_config.take().unwrap_or_default();
            config.relays.append(&mut self.relays);
            config.autonat_servers.append(&mut self.autonat_servers);
            config
        })
    }
}

#[cfg(any(feature = "quic", feature = "tcp"))]
fn validate_listen_multiaddr(address: &Multiaddr) -> Result<(), Error> {
    if address
        .protocols()
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2p(_) | Protocol::P2pCircuit))
    {
        return Err(TransportError::InvalidAddress {
            context: "listen address",
            reason: format!(
                "`{address}` is not a listen address; omit /p2p and /p2p-circuit (those belong on dial targets)"
            ),
        }
        .into());
    }

    let ip_host = matches!(
        address.protocols().first(),
        Some(Protocol::Ip4(_)) | Some(Protocol::Ip6(_))
    );
    if !ip_host {
        return Err(TransportError::InvalidAddress {
            context: "listen address",
            reason: format!("`{address}` must use /ip4 or /ip6; DNS names are dial-only"),
        }
        .into());
    }

    #[cfg(feature = "quic")]
    if address.is_quic_transport() {
        return Ok(());
    }
    #[cfg(feature = "tcp")]
    if address.is_tcp_transport() {
        return Ok(());
    }

    #[cfg(all(feature = "quic", feature = "tcp"))]
    let hint = "expected `/ip4|ip6/udp/<port>/quic-v1` or `/ip4|ip6/tcp/<port>`";
    #[cfg(all(feature = "quic", not(feature = "tcp")))]
    let hint = "expected `/ip4|ip6/udp/<port>/quic-v1`";
    #[cfg(all(feature = "tcp", not(feature = "quic")))]
    let hint = "expected `/ip4|ip6/tcp/<port>`";
    Err(TransportError::InvalidAddress {
        context: "listen address",
        reason: format!("`{address}` is not a supported listen shape ({hint})"),
    }
    .into())
}

#[cfg(feature = "quic")]
fn listen_ip_family(address: &Multiaddr) -> Option<&'static str> {
    match address.protocols().first() {
        Some(Protocol::Ip4(_)) => Some("IPv4"),
        Some(Protocol::Ip6(_)) => Some("IPv6"),
        _ => None,
    }
}

#[cfg(feature = "quic")]
fn reject_duplicate_quic_family(existing: &[Multiaddr], next: &Multiaddr) -> Result<(), Error> {
    let Some(family) = listen_ip_family(next) else {
        return Ok(());
    };
    if existing
        .iter()
        .filter(|address| address.is_quic_transport())
        .any(|address| listen_ip_family(address) == Some(family))
    {
        return Err(TransportError::InvalidConfig {
            reason: format!(
                "QUIC listen addresses may contain at most one address per IP family; `{next}` repeats {family}"
            ),
        }
        .into());
    }
    Ok(())
}

/// Brings up every requested transport behind one set.
///
/// Listen multiaddresses are grouped by transport shape: compatible QUIC IPv4
/// and IPv6 addresses become one QUIC member, and every `/tcp` address lands on
/// one TCP member. Members are inserted in the order their shape first appears,
/// so `listen_all` reports addresses in configuration order.
fn bind_transports(
    _options: &EndpointBuilder,
    _keypair: &Ed25519Keypair,
) -> Result<TransportSet, Error> {
    #[cfg(any(feature = "quic", feature = "tcp"))]
    let mut set = TransportSet::new();
    #[cfg(not(any(feature = "quic", feature = "tcp")))]
    let set = TransportSet::new();

    #[cfg(any(feature = "quic", feature = "tcp"))]
    {
        let addrs = &_options.listen_addrs;
        #[cfg(feature = "quic")]
        let quic_addrs: Vec<&Multiaddr> = addrs
            .iter()
            .filter(|address| address.is_quic_transport())
            .collect();
        #[cfg(feature = "tcp")]
        let tcp_addrs: Vec<&Multiaddr> = addrs
            .iter()
            .filter(|address| address.is_tcp_transport())
            .collect();
        let quic_first = addrs
            .first()
            .is_none_or(|address| address.is_quic_transport());
        let order = if quic_first {
            [true, false]
        } else {
            [false, true]
        };
        for want_quic in order {
            #[cfg(feature = "quic")]
            if want_quic && !quic_addrs.is_empty() {
                let config =
                    QuicNodeConfig::new(_keypair.clone()).with_limits(_options.quic_limits.clone());
                let transport = match quic_addrs.as_slice() {
                    [address] => QuicEndpoint::bind_multiaddr(config, address)?,
                    [first, second] => QuicEndpoint::bind_dual_multiaddr(config, first, second)?,
                    // `listen_on` allows at most one QUIC address per family.
                    _ => {
                        return Err(Error::Invariant {
                            reason: "more than one QUIC listen address per IP family",
                        });
                    }
                };
                let namespaces = transport.namespaces();
                insert_member(&mut set, TransportKind::Quic, namespaces, transport)?;
            }
            #[cfg(feature = "tcp")]
            if !want_quic && !tcp_addrs.is_empty() {
                let transport = bind_tcp_member(_options, _keypair, &tcp_addrs)?;
                let namespace = transport.namespace();
                insert_member(&mut set, TransportKind::Tcp, [namespace], transport)?;
            }
        }
    }

    if set.is_empty() {
        return Err(TransportError::InvalidConfig {
            reason: "an endpoint needs at least one transport to bind; add a listen address with EndpointBuilder::listen_on or listen_default".into(),
        }
        .into());
    }
    Ok(set)
}

/// Builds the one TCP transport, listening on every `/tcp` address asked for.
#[cfg(feature = "tcp")]
fn bind_tcp_member(
    options: &EndpointBuilder,
    keypair: &Ed25519Keypair,
    tcp_addrs: &[&Multiaddr],
) -> Result<TcpTransport<StdTcpProvider, StdEntropy>, Error> {
    // Checked before a socket exists: the namespace is what routes a connection
    // id back to the transport that minted it, so a TCP transport tagged as
    // something else hands out ids that name the wrong carrier -- and would
    // take a claim a QUIC member needs.
    let namespace = options.tcp_config.namespace;
    if namespace != ConnectionNamespace::TCP_IPV4 && namespace != ConnectionNamespace::TCP_IPV6 {
        return Err(TransportError::InvalidConfig {
            reason: format!(
                "a tcp transport must allocate in a tcp namespace, not {namespace}; \
                 see TcpConfig::namespace"
            ),
        }
        .into());
    }

    let provider = StdTcpProvider::new().map_err(|error| TransportError::ListenFailed {
        reason: error.to_string(),
    })?;
    let mut transport = TcpTransport::with_config(
        provider,
        keypair.clone(),
        StdEntropy::new(),
        options.tcp_config.clone(),
    );
    for addr in tcp_addrs {
        // Bound here, like a QUIC socket is: `Endpoint::listen` then listens
        // on what is already bound, and a caller that asked for port 0 learns
        // which port it got before the first event.
        transport.listen(addr)?;
    }
    Ok(transport)
}

#[cfg(any(feature = "quic", feature = "tcp"))]
fn insert_member<T: minip2p_transport::BlockingTransport + Send + 'static>(
    set: &mut TransportSet,
    kind: TransportKind,
    namespaces: impl IntoIterator<Item = ConnectionNamespace>,
    transport: T,
) -> Result<(), Error> {
    set.insert(kind, namespaces, Box::new(transport))
        .map_err(|rejected| {
            TransportError::InvalidConfig {
                reason: rejected.error().to_string(),
            }
            .into()
        })
}

fn build_endpoint(
    options: EndpointBuilder,
    keypair: Ed25519Keypair,
    transport: TransportSet,
) -> Result<Endpoint, Error> {
    #[cfg(feature = "nat")]
    let mut options = options;
    #[cfg(feature = "nat")]
    let nat_config = options.take_nat_config();
    let mut builder = SwarmBuilder::new(&keypair).agent_version(options.agent_version);
    #[cfg(any(feature = "nat", feature = "pubsub"))]
    let mut protocols = options.protocols;
    #[cfg(not(any(feature = "nat", feature = "pubsub")))]
    let protocols = options.protocols;
    #[cfg(feature = "nat")]
    if nat_config.is_some() {
        for id in [
            minip2p_nat::DCUTR_PROTOCOL_ID,
            minip2p_nat::AUTONAT_PROTOCOL_ID,
        ] {
            if !protocols.iter().any(|existing| existing == id) {
                protocols.push(id.to_string());
            }
        }
    }
    #[cfg(feature = "pubsub")]
    if options.gossipsub_config.is_some() {
        // Pubsub streams route as ordinary user protocols, and the gossipsub
        // ids must be advertised by Identify from the first handshake.
        for id in minip2p_pubsub::GOSSIPSUB_PROTOCOL_IDS {
            if !protocols.iter().any(|existing| existing == id) {
                protocols.push((*id).to_string());
            }
        }
    }
    for protocol in protocols {
        builder = builder.protocol(protocol);
    }
    #[cfg(feature = "nat")]
    let transport = minip2p_circuit::CircuitTransport::new_os(transport, keypair.clone());
    #[cfg(any(feature = "nat", feature = "relay-server"))]
    let mut swarm = builder.build(transport)?;
    #[cfg(not(any(feature = "nat", feature = "relay-server")))]
    let swarm = builder.build(transport)?;
    #[cfg(feature = "relay-server")]
    if options.relay_server_config.is_some() {
        swarm.add_inbound_protocol(RELAY_HOP_PROTOCOL_ID)?;
        swarm.add_advertised_protocol(RELAY_HOP_PROTOCOL_ID)?;
        swarm.add_outbound_protocol(RELAY_STOP_PROTOCOL_ID)?;
    }
    #[cfg(feature = "nat")]
    if nat_config.is_some() {
        swarm.add_outbound_protocol(minip2p_nat::HOP_PROTOCOL_ID)?;
        swarm.add_inbound_protocol(minip2p_nat::STOP_PROTOCOL_ID)?;
        swarm.add_advertised_protocol(minip2p_nat::STOP_PROTOCOL_ID)?;
    }
    #[cfg(feature = "nat")]
    let nat = nat_config.map(|config| {
        let relay_addrs = config
            .relays
            .iter()
            .map(|relay| (relay.peer_id().clone(), relay.transport().clone()))
            .collect();
        let agent = minip2p_nat::NatAgent::new(swarm.local_peer_id().clone(), config);
        NatDriver::new(agent, relay_addrs, minip2p_platform::StdEntropy)
    });
    #[cfg(feature = "relay-server")]
    let relay_server = options
        .relay_server_config
        .map(|config| -> Result<relay_server::RelayServerDriver, Error> {
            let mut agent =
                minip2p_relay_server::RelayServerAgent::new(swarm.local_peer_id().clone(), config)
                    .map_err(|error| TransportError::InvalidConfig {
                        reason: error.to_string(),
                    })?;
            agent
                .replace_announce_addrs(options.relay_server_announce_addrs)
                .map_err(|error| TransportError::InvalidConfig {
                    reason: error.to_string(),
                })?;
            agent
                .set_listener_addrs(concrete_relay_listener_addrs(
                    swarm.transport().local_addresses(),
                ))
                .map_err(|error| TransportError::InvalidConfig {
                    reason: error.to_string(),
                })?;
            Ok(relay_server::RelayServerDriver::new(agent))
        })
        .transpose()?;
    #[cfg(feature = "discovery")]
    let discovery_config = options.discovery_config;
    #[cfg(feature = "mdns")]
    let mdns_config = options.mdns_config;
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    let peer_discovery_config = options.peer_discovery_config;
    #[cfg(feature = "pubsub")]
    let gossipsub = options
        .gossipsub_config
        .map(|config| -> Result<GossipsubDriver, Error> {
            // Message ids are (from, seqno); a wall-clock seed keeps restarts
            // from reusing ids the network may still remember. Mix the local
            // identity into the peer-selection seed so endpoints created in the
            // same clock tick do not walk the same deterministic sequence.
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let initial_seqno = timestamp as u64;
            let entropy_seed = keypair
                .peer_id()
                .digest_bytes()
                .iter()
                .fold(initial_seqno ^ (timestamp >> 64) as u64, |seed, byte| {
                    seed.rotate_left(5) ^ u64::from(*byte)
                });
            let agent = minip2p_pubsub::GossipsubAgent::new(
                keypair.clone(),
                config,
                initial_seqno,
                entropy_seed,
            )
            .map_err(|error| TransportError::InvalidConfig {
                reason: error.to_string(),
            })?;
            Ok(GossipsubDriver::new(agent))
        })
        .transpose()?;
    #[cfg(feature = "discovery")]
    let mut gossipsub = gossipsub;
    #[cfg(feature = "discovery")]
    if let (Some(pubsub), Some(config)) = (gossipsub.as_mut(), discovery_config.as_ref()) {
        #[expect(
            clippy::map_err_ignore,
            reason = "Both agents validate the shared topic before construction, so this exposes a stable invariant."
        )]
        pubsub
            .agent
            .subscribe(&config.topic, 0)
            .map_err(|_| Error::Invariant {
                reason: "validated discovery topic was rejected by pubsub",
            })?;
    }
    #[cfg(feature = "discovery")]
    #[expect(
        clippy::map_err_ignore,
        reason = "The builder validated this beacon configuration before creating the agent."
    )]
    let beacon = match discovery_config {
        Some(config) => Some(
            minip2p_discovery::BeaconAgent::new(keypair.public_key(), config).map_err(|_| {
                Error::Invariant {
                    reason: "validated beacon configuration was rejected",
                }
            })?,
        ),
        None => None,
    };
    // `mdns` enables the shared driver without `discovery`, so no beacon can
    // be configured; the driver's pubsub slot stays empty in that build.
    #[cfg(all(feature = "pubsub", feature = "mdns", not(feature = "discovery")))]
    let beacon = None;
    #[cfg(feature = "mdns")]
    let mdns = match mdns_config {
        Some(config) => {
            let agent = minip2p_mdns::MdnsAgent::new(
                keypair.peer_id(),
                config.clone(),
                mdns_seed(&keypair),
            )
            .map_err(|error| TransportError::InvalidConfig {
                reason: error.to_string(),
            })?;
            let sockets = minip2p_mdns::MdnsSockets::new(&config).map_err(|error| {
                TransportError::ListenFailed {
                    reason: error.to_string(),
                }
            })?;
            Some(mdns::MdnsDriver::new(agent, sockets, &config))
        }
        None => None,
    };
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    let discovery_enabled = {
        #[cfg(feature = "discovery")]
        {
            beacon.is_some()
        }
        #[cfg(not(feature = "discovery"))]
        {
            false
        }
    } || {
        #[cfg(feature = "mdns")]
        {
            mdns.is_some()
        }
        #[cfg(not(feature = "mdns"))]
        {
            false
        }
    };
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    #[expect(
        clippy::map_err_ignore,
        reason = "The shared discovery policy was validated before the endpoint reached this point."
    )]
    let discovery = if discovery_enabled {
        let book =
            minip2p_discovery::PeerDiscoveryAgent::new(keypair.peer_id(), peer_discovery_config)
                .map_err(|_| Error::Invariant {
                    reason: "validated discovery configuration was rejected",
                })?;
        Some(DiscoveryDriver::new(
            book,
            #[cfg(feature = "pubsub")]
            beacon,
        ))
    } else {
        None
    };
    Ok(Endpoint {
        swarm,
        connect: ConnectEngine::new(
            u64::try_from(options.connect_deadline.as_millis()).unwrap_or(u64::MAX),
        ),
        #[cfg(feature = "relay-server")]
        relay_server,
        #[cfg(feature = "nat")]
        nat,
        #[cfg(feature = "pubsub")]
        gossipsub,
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        discovery,
        #[cfg(feature = "mdns")]
        mdns,
        pending_events: std::collections::VecDeque::new(),
        #[cfg(any(feature = "nat", feature = "relay-server"))]
        caller_external_addresses: Vec::new(),
        #[cfg(any(feature = "nat", feature = "relay-server"))]
        external_addresses_revision: 0,
    })
}

#[cfg(feature = "relay-server")]
fn concrete_relay_listener_addrs(addrs: Vec<Multiaddr>) -> Vec<Multiaddr> {
    addrs
        .into_iter()
        .filter(|address| {
            !matches!(address.iter().next(), Some(Protocol::Ip4(ip)) if *ip == [0; 4])
                && !matches!(address.iter().next(), Some(Protocol::Ip6(ip)) if *ip == [0; 16])
        })
        .collect()
}

/// Test-only convenience over [`Endpoint::wait`]: the next event, or `None`
/// once the deadline passes. Interruptions are retried.
#[cfg(all(test, feature = "quic"))]
pub(crate) trait NextEvent {
    fn next_event(&mut self, deadline: impl Into<Deadline>)
    -> Result<Option<EndpointEvent>, Error>;
}

#[cfg(all(test, feature = "quic"))]
impl NextEvent for Endpoint {
    fn next_event(
        &mut self,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<EndpointEvent>, Error> {
        let deadline = deadline.into();
        loop {
            match self.wait(deadline)? {
                EndpointWaitOutcome::Event(event) => return Ok(Some(event)),
                EndpointWaitOutcome::Deadline => return Ok(None),
                EndpointWaitOutcome::Interrupted => {}
            }
        }
    }
}

#[cfg(test)]
#[test]
fn default_agent_version_matches_package_version() {
    assert_eq!(
        EndpointBuilder::default().agent_version,
        format!("minip2p/{}", env!("CARGO_PKG_VERSION"))
    );
}

#[cfg(all(test, feature = "quic"))]
mod tests {
    use super::*;
    use crate::{ConnectFailure, ConnectOutcome};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    /// Drives `endpoint` on a thread until the returned guard is dropped.
    ///
    /// A peer that is not being driven answers nothing, so anything asserting
    /// on a connection needs the other end alive for as long as the assertion
    /// takes.
    struct Driven {
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Driven {
        fn new(mut endpoint: Endpoint) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    endpoint
                        .next_event(Duration::from_millis(20))
                        .expect("drive peer");
                }
            });
            Self {
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for Driven {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                // A test panic in the driver must not panic again while unwinding.
                drop(thread.join());
            }
        }
    }

    /// Drives `endpoint` until an event `wanted` accepts, or gives up.
    ///
    /// A connection produces more than the event a test is waiting for --
    /// identify, ping, readiness -- and an earlier connection keeps producing
    /// them, so taking whatever arrives next is a race rather than an
    /// assertion.
    #[expect(
        clippy::panic,
        reason = "A timed-out test must include the unexpected event trace."
    )]
    fn wait_for(
        endpoint: &mut Endpoint,
        what: &str,
        mut wanted: impl FnMut(&EndpointEvent) -> bool,
    ) -> EndpointEvent {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut seen = Vec::new();
        while std::time::Instant::now() < deadline {
            let Some(event) = endpoint
                .next_event(Duration::from_millis(50))
                .expect("drive endpoint")
            else {
                continue;
            };
            if wanted(&event) {
                return event;
            }
            seen.push(event);
        }
        panic!("no {what} arrived; saw {seen:?}");
    }

    #[expect(
        clippy::panic,
        reason = "A timed-out test must include the unexpected event."
    )]
    fn connect_outcome(endpoint: &mut Endpoint, id: ConnectId) -> ConnectOutcome {
        match wait_for(
            endpoint,
            "connect settled",
            |event| matches!(event, EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == id),
        ) {
            EndpointEvent::ConnectSettled { outcome, .. } => outcome,
            other => panic!("expected ConnectSettled, got {other:?}"),
        }
    }

    fn tcp_peer_addr(peer: PeerId, port: u16) -> PeerAddr {
        PeerAddr::new(
            Multiaddr::from_protocols(vec![Protocol::Ip4([127, 0, 0, 1]), Protocol::Tcp(port)]),
            peer,
        )
        .expect("peer addr")
    }

    #[test]
    fn connect_races_quic_and_tcp_candidates_on_a_quic_only_endpoint() {
        let mut listener = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind listener");
        let quic_addr = listener.listen().expect("listen");
        let tcp_addr = tcp_peer_addr(quic_addr.peer_id().clone(), 9);
        let _driver = Driven::new(listener);
        let mut dialer = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind dialer");
        let id = dialer
            .connect(vec![quic_addr.clone(), tcp_addr.clone()])
            .expect("connect");
        let ConnectOutcome::Connected { conn_id } = connect_outcome(&mut dialer, id) else {
            panic!("expected connected");
        };
        let remote = dialer
            .connection_remote_addr(conn_id)
            .expect("remote addr")
            .clone();
        assert!(
            remote == *quic_addr.transport() || remote == *tcp_addr.transport(),
            "remote {remote} must be one of the candidates"
        );
    }

    #[test]
    fn connect_without_a_transport_for_the_address_is_no_usable_route() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind");
        let target = tcp_peer_addr(Ed25519Keypair::generate().peer_id(), 9);
        let id = endpoint.connect(target.clone()).expect("admitted");
        match connect_outcome(&mut endpoint, id) {
            ConnectOutcome::Failed(ConnectFailure::NoUsableRoute { candidates, .. }) => {
                assert_eq!(candidates.len(), 1);
                assert_eq!(candidates[0].addr, target);
                assert!(
                    candidates[0].reason.contains("Tcp transport"),
                    "{}",
                    candidates[0].reason
                );
            }
            other => panic!("expected NoUsableRoute, got {other:?}"),
        }
    }

    #[test]
    fn cancel_connect_before_handshake_settles_cancelled() {
        let mut listener = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind listener");
        let addr = listener.listen().expect("listen");
        let _driver = Driven::new(listener);
        let mut dialer = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind dialer");
        let id = dialer.connect(addr).expect("connect");
        dialer.cancel_connect(id);
        assert!(matches!(
            connect_outcome(&mut dialer, id),
            ConnectOutcome::Cancelled
        ));
        assert!(dialer.connected_peers().is_empty());
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn connect_reaches_quic_when_the_tcp_candidate_is_closed() {
        let mut listener = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind listener");
        let quic_addr = listener.listen().expect("listen");
        let tcp_addr = tcp_peer_addr(quic_addr.peer_id().clone(), 9);
        let _driver = Driven::new(listener);
        let mut dialer = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic")
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp")
            .bind()
            .expect("bind both");
        let id = dialer
            .connect(vec![quic_addr.clone(), tcp_addr])
            .expect("connect");
        let ConnectOutcome::Connected { conn_id } = connect_outcome(&mut dialer, id) else {
            panic!("expected connected");
        };
        let remote = dialer.connection_remote_addr(conn_id).expect("remote");
        assert_eq!(remote, quic_addr.transport());
    }

    #[test]
    fn wait_delivers_connect_timeout_before_the_caller_deadline() {
        let mut listener = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind listener");
        let addr = listener.listen().expect("listen");
        // Leave the listener undriven so the handshake hangs past the
        // attempt deadline instead of failing immediately.
        let mut dialer = Endpoint::builder()
            .connect_deadline(Duration::from_millis(80))
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind dialer");
        let id = dialer.connect(addr).expect("connect");
        let caller = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match dialer.wait(caller).expect("wait") {
                EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                    connect_id,
                    outcome: ConnectOutcome::Failed(ConnectFailure::Timeout { .. }),
                    ..
                }) if connect_id == id => return,
                EndpointWaitOutcome::Event(_) => {}
                EndpointWaitOutcome::Deadline => {
                    panic!("caller deadline beat the connect timeout")
                }
                EndpointWaitOutcome::Interrupted => {}
            }
        }
    }

    #[cfg(feature = "tcp")]
    #[expect(
        clippy::panic,
        reason = "A malformed fixture address is a test setup failure."
    )]
    fn tcp_port(addr: &PeerAddr) -> u16 {
        match addr.transport().protocols() {
            [_, Protocol::Tcp(port)] => *port,
            other => panic!("not a /tcp address: {other:?}"),
        }
    }

    #[cfg(feature = "discovery")]
    #[test]
    fn discovery_config_is_rejected_before_binding() {
        let config = BeaconConfig {
            beacon_interval_ms: 0,
            ..BeaconConfig::default()
        };
        assert!(matches!(
            Endpoint::builder().discovery_config(config),
            Err(DiscoveryConfigError::ZeroBeaconInterval)
        ));
    }

    #[test]
    fn an_endpoint_with_nothing_to_bind_is_refused() {
        // It could neither dial nor be reached; failing here says that once,
        // where the mistake is, instead of at every later call.
        let Err(error) = Endpoint::builder().bind() else {
            panic!("an endpoint with no transport must not build");
        };
        assert!(
            format!("{error}").contains("at least one transport"),
            "got {error}"
        );
    }

    #[test]
    fn listen_configures_a_quic_multiaddr() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("listen accepts QUIC")
            .bind()
            .expect("bind");
        let addrs = endpoint.listen_all().expect("listen_all");
        assert_eq!(addrs.len(), 1);
        assert!(
            addrs[0]
                .transport()
                .to_string()
                .starts_with("/ip4/127.0.0.1/udp/"),
            "{addrs:?}"
        );
        assert!(
            addrs[0].transport().to_string().ends_with("/quic-v1"),
            "{addrs:?}"
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn listen_configures_a_tcp_multiaddr() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("listen accepts TCP")
            .bind()
            .expect("bind");
        let addrs = endpoint.listen_all().expect("listen_all");
        assert_eq!(addrs.len(), 1);
        assert!(
            addrs[0]
                .transport()
                .to_string()
                .starts_with("/ip4/127.0.0.1/tcp/"),
            "{addrs:?}"
        );
    }

    #[test]
    fn listen_groups_ipv4_and_ipv6_quic_without_duplicating_transports() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("ipv4")
            .listen_on("/ip6/::1/udp/0/quic-v1")
            .expect("ipv6")
            .bind()
            .expect("bind dual");
        let addrs = endpoint.listen_all().expect("listen_all");
        assert_eq!(addrs.len(), 2, "{addrs:?}");
        assert!(
            addrs
                .iter()
                .any(|a| a.transport().to_string().contains("/ip4/"))
        );
        assert!(
            addrs
                .iter()
                .any(|a| a.transport().to_string().contains("/ip6/"))
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn listen_composes_quic_and_tcp() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic")
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp")
            .bind()
            .expect("bind both");
        let reported: Vec<String> = endpoint
            .listen_all()
            .expect("listen_all")
            .iter()
            .map(|addr| addr.transport().to_string())
            .collect();
        assert_eq!(reported.len(), 2, "{reported:?}");
        assert!(reported.iter().any(|addr| addr.contains("/quic-v1")));
        assert!(reported.iter().any(|addr| addr.contains("/tcp/")));
    }

    #[test]
    fn listen_rejects_unsupported_and_contradictory_shapes() {
        let Err(dns) = Endpoint::builder().listen_on("/dns/example.com/udp/0/quic-v1") else {
            panic!("DNS listen must fail");
        };
        assert!(
            matches!(
                &dns,
                Error::Transport(TransportError::InvalidAddress { reason, .. })
                    if reason.contains("DNS")
            ),
            "{dns}"
        );

        let Err(circuit) =
            Endpoint::builder().listen_on("/ip4/127.0.0.1/udp/0/quic-v1/p2p-circuit")
        else {
            panic!("circuit listen must fail");
        };
        assert!(
            matches!(
                &circuit,
                Error::Transport(TransportError::InvalidAddress { reason, .. })
                    if reason.contains("p2p-circuit") || reason.contains("listen address")
            ),
            "{circuit}"
        );

        let Err(duplicate) = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("first")
            .listen_on("/ip4/0.0.0.0/udp/0/quic-v1")
        else {
            panic!("duplicate IPv4 QUIC must fail");
        };
        assert!(
            matches!(
                &duplicate,
                Error::Transport(TransportError::InvalidConfig { reason })
                    if reason.contains("IPv4")
            ),
            "{duplicate}"
        );
    }

    #[test]
    fn listen_default_binds_dual_stack_quic() {
        let mut endpoint = Endpoint::builder()
            .listen_default()
            .expect("default listen")
            .bind()
            .expect("default dual-stack");
        let addrs = endpoint.listen_all().expect("listen_all");
        assert_eq!(
            addrs.len(),
            2,
            "dual-stack default binds both families: {addrs:?}"
        );
        assert!(
            addrs
                .iter()
                .all(|addr| addr.transport().to_string().contains("/quic-v1")),
            "{addrs:?}"
        );
        let has_v4 = addrs
            .iter()
            .any(|addr| addr.transport().to_string().contains("/ip4/"));
        let has_v6 = addrs
            .iter()
            .any(|addr| addr.transport().to_string().contains("/ip6/"));
        assert!(
            has_v4 && has_v6,
            "default listen binds IPv4 and IPv6: {addrs:?}"
        );
    }

    #[test]
    fn listen_default_rejects_duplicate_quic_family() {
        let ipv4 = "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("ipv4");
        let Err(error) = Endpoint::builder()
            .listen_on_multiaddr(&ipv4)
            .expect("listen ipv4")
            .listen_default()
        else {
            panic!("listen_default after IPv4 QUIC must return InvalidConfig");
        };
        assert!(
            matches!(
                &error,
                Error::Transport(TransportError::InvalidConfig { reason })
                    if reason.contains("IPv4")
            ),
            "{error}"
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn a_tcp_endpoint_reports_the_port_it_was_given() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("bind tcp endpoint");

        // Bound at build time like a QUIC socket, so a caller that asked for
        // port 0 can learn which port it got without driving anything first.
        let addrs = endpoint.listen_all().expect("listen");
        assert_eq!(addrs.len(), 1, "one transport, one address: {addrs:?}");
        let port = tcp_port(&addrs[0]);
        assert_ne!(
            port, 0,
            "an ephemeral bind reports the port it actually got"
        );
        assert_eq!(
            addrs[0].transport().to_string(),
            format!("/ip4/127.0.0.1/tcp/{port}"),
            "the host asked for is the host reported, and nothing is added to it"
        );
        assert_eq!(addrs[0].peer_id(), endpoint.peer_id());
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn every_bound_transport_reports_where_it_listens() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("bind both");

        // A host announces where it can be reached. Leaving a transport out
        // would make half of those ways invisible to peers, and the host would
        // have no way to tell.
        let reported: Vec<String> = endpoint
            .listen_all()
            .expect("listen")
            .iter()
            .map(|addr| addr.transport().to_string())
            .collect();
        assert_eq!(reported.len(), 2, "one per transport: {reported:?}");
        assert!(
            reported.iter().any(|addr| addr.contains("/quic-v1")),
            "{reported:?}"
        );
        assert!(
            reported.iter().any(|addr| addr.contains("/tcp/")),
            "{reported:?}"
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn a_second_tcp_address_joins_the_transport_that_already_serves_tcp() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("both tcp addresses bind");
        let addrs = endpoint.listen_all().expect("listen");
        assert_eq!(addrs.len(), 2, "both addresses are listening: {addrs:?}");
        assert_ne!(
            tcp_port(&addrs[0]),
            tcp_port(&addrs[1]),
            "two binds, two sockets"
        );

        // A transport claims an address shape, not an address family, so
        // asking for two /tcp addresses asks for two sockets on one transport
        // -- not a second one, which the set would refuse.
        let second = addrs[1].clone();
        let _driver = Driven::new(endpoint);
        let mut dialer = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("bind dialer");
        dialer
            .connect(second.clone())
            .expect("connect to the second address");
        wait_for(
            &mut dialer,
            "connection",
            |event| matches!(event, EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == second.peer_id()),
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn listening_arms_every_bound_transport_not_just_the_first() {
        // TCP first, so the transport that still needs arming is the one
        // `listen` does not return. An endpoint that reported success while
        // QUIC accepted nothing would look bound and be unreachable.
        let mut listener = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind both");
        // Read straight off the bound sockets, so nothing here arms anything:
        // `listen` below is the only call that does.
        let bound = listener
            .swarm()
            .transport()
            .local_addresses()
            .into_iter()
            .find(|addr| addr.to_string().contains("quic"))
            .expect("a bound quic socket");
        let quic_addr = PeerAddr::new(bound, listener.peer_id().clone()).expect("target");
        let first = listener.listen().expect("listen returns the first address");
        assert!(
            first.transport().to_string().contains("/tcp/"),
            "the returned address is the first bound one: {first:?}"
        );
        let _driver = Driven::new(listener);

        let mut dialer = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind dialer");
        dialer.connect(&quic_addr).expect("connect");
        wait_for(
            &mut dialer,
            "connection",
            |event| matches!(event, EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == quic_addr.peer_id()),
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn a_peer_is_reached_over_the_transport_its_address_names() {
        // One peer per transport: the swarm keeps a single connection per
        // peer, so two paths to one host would be the second superseding the
        // first rather than a test of which path each address took.
        let mut over_tcp = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("bind tcp peer");
        let mut over_quic = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind quic peer");
        let tcp_addr = over_tcp.listen().expect("tcp peer listens");
        let quic_addr = over_quic.listen().expect("quic peer listens");

        let mut dialer = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("bind dialer");
        let _drivers = (Driven::new(over_tcp), Driven::new(over_quic));

        // The address decides the transport, and nothing above the endpoint
        // had to choose: the namespace on the connection id says which one
        // actually carried it. Each connection is waited for by name, since
        // the one before it keeps producing events of its own.
        for (addr, expected) in [
            (&tcp_addr, ConnectionNamespace::TCP_IPV4),
            (&quic_addr, ConnectionNamespace::QUIC_IPV4),
        ] {
            dialer.connect(addr).expect("connect");
            let event = wait_for(
                &mut dialer,
                "connection",
                |event| matches!(event, EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == addr.peer_id()),
            );
            let EndpointEvent::ConnectionEstablished { conn_id, .. } = event else {
                panic!("the connection predicate returned an unrelated event")
            };
            assert_eq!(
                conn_id.namespace(),
                expected,
                "{} should have been carried by {expected}",
                addr.transport()
            );
        }
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn tcp_limits_and_namespace_reach_the_transport() {
        let mut endpoint = Endpoint::builder()
            .tcp_config(TcpConfig {
                namespace: ConnectionNamespace::TCP_IPV6,
                ..TcpConfig::default()
            })
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("bind tcp endpoint");
        let target = PeerAddr::new(
            "/ip4/127.0.0.1/tcp/1".parse().expect("address"),
            Ed25519Keypair::generate().peer_id(),
        )
        .expect("target");

        // The id a raw swarm dial hands back is minted by the transport, so
        // its namespace is what the configuration actually reached -- whether
        // anything answers is beside the point.
        let id = endpoint.swarm_mut().dial(&target).expect("the dial starts");
        assert_eq!(id.namespace(), ConnectionNamespace::TCP_IPV6);
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn a_tcp_transport_tagged_for_another_carrier_is_refused() {
        // The namespace routes a connection id back to the transport that
        // minted it. Tagged as QUIC's, TCP's ids would name the wrong carrier
        // and take a claim the QUIC member needs.
        let Err(error) = Endpoint::builder()
            .tcp_config(TcpConfig {
                namespace: ConnectionNamespace::QUIC_IPV4,
                ..TcpConfig::default()
            })
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
        else {
            panic!("a tcp transport must not claim another transport's ids");
        };
        assert!(
            format!("{error}").contains("must allocate in a tcp namespace"),
            "got {error}"
        );
    }

    #[test]
    fn wait_reports_deadline_without_swallowing_control_outcomes() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");

        assert!(matches!(
            endpoint.wait(Duration::ZERO).expect("wait endpoint"),
            EndpointWaitOutcome::Deadline
        ));
    }

    #[test]
    fn wait_prefers_deadline_over_queued_events_when_instant_has_passed() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        {
            endpoint
                .pending_events
                .push_back(EndpointEvent::ConnectionClosed {
                    peer_id: Ed25519Keypair::generate().peer_id(),
                    conn_id: ConnectionId::new(1),
                    cause: minip2p_swarm::ConnectionCloseCause::Transport,
                });
        }
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(std::time::Instant::now);
        assert!(matches!(
            endpoint.wait(past).expect("wait past deadline"),
            EndpointWaitOutcome::Deadline
        ));
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        assert_eq!(
            endpoint.pending_events.len(),
            1,
            "queued events stay queued when the Instant has already passed"
        );
    }

    #[cfg(feature = "nat")]
    #[test]
    fn wait_with_duration_zero_still_drains_queued_events() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");
        let peer = Ed25519Keypair::generate().peer_id();
        endpoint
            .pending_events
            .push_back(EndpointEvent::ConnectionClosed {
                peer_id: peer.clone(),
                conn_id: ConnectionId::new(1),
                cause: minip2p_swarm::ConnectionCloseCause::Transport,
            });
        assert!(matches!(
            endpoint.wait(Duration::ZERO).expect("zero-duration drain"),
            EndpointWaitOutcome::Event(EndpointEvent::ConnectionClosed { peer_id, .. })
                if peer_id == peer
        ));
        assert!(
            endpoint.pending_events.is_empty(),
            "Duration::ZERO must drain queued events"
        );
    }

    #[test]
    fn wait_reports_interrupt_without_swallowing_it() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");
        endpoint.wait_handle().interrupt();

        assert!(matches!(
            endpoint.wait(Deadline::NEVER).expect("wait endpoint"),
            EndpointWaitOutcome::Interrupted
        ));
    }

    #[test]
    fn wait_delivers_connection_events_once_through_the_endpoint_stream() {
        let mut listener = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind listener");
        let listen_addr = listener.listen().expect("listen");
        let mut dialer = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind dialer");
        let _listener = Driven::new(listener);

        dialer.connect(&listen_addr).expect("connect");
        let peer = listen_addr.peer_id().clone();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut established_count = 0u32;
        let mut conn_id = None;
        let mut saw_peer_ready = false;
        while std::time::Instant::now() < deadline {
            match dialer.wait(deadline).expect("wait") {
                EndpointWaitOutcome::Event(EndpointEvent::ConnectionEstablished {
                    peer_id,
                    conn_id: id,
                }) if peer_id == peer => {
                    established_count += 1;
                    conn_id = Some(id);
                }
                EndpointWaitOutcome::Event(EndpointEvent::PeerReady { peer_id, .. })
                    if peer_id == peer =>
                {
                    saw_peer_ready = true;
                    break;
                }
                EndpointWaitOutcome::Event(_) | EndpointWaitOutcome::Interrupted => {}
                EndpointWaitOutcome::Deadline => break,
            }
        }
        assert_eq!(
            established_count, 1,
            "ConnectionEstablished must appear exactly once before PeerReady"
        );
        let conn_id = conn_id.expect("dialer saw ConnectionEstablished");
        assert!(saw_peer_ready, "PeerReady follows the single establishment");
        assert_eq!(dialer.connection_id(&peer), Some(conn_id));
        assert!(dialer.connected_peers().contains(&peer));
    }

    #[test]
    fn wait_delivers_peer_ready_through_the_endpoint_stream() {
        let mut listener = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind listener");
        let listen_addr = listener.listen().expect("listen");
        let mut dialer = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind dialer");
        let _listener = Driven::new(listener);

        dialer.connect(&listen_addr).expect("connect");
        let peer = listen_addr.peer_id().clone();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut ready = false;
        while std::time::Instant::now() < deadline {
            match dialer.wait(deadline).expect("wait") {
                EndpointWaitOutcome::Event(EndpointEvent::PeerReady { peer_id, .. })
                    if peer_id == peer =>
                {
                    ready = true;
                    break;
                }
                EndpointWaitOutcome::Event(_) | EndpointWaitOutcome::Interrupted => {}
                EndpointWaitOutcome::Deadline => break,
            }
        }
        assert!(ready, "PeerReady arrives once through Endpoint::wait");
        assert!(dialer.is_peer_ready(&peer));
        assert!(dialer.peer_info(&peer).is_some());
    }

    #[test]
    fn state_getters_expose_bound_addresses_and_connection_without_driving() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");
        let before = endpoint.bound_addresses();
        assert!(
            !before.is_empty(),
            "bound transport addresses are visible before listen/drive"
        );
        let listened = endpoint.listen_all().expect("listen");
        assert_eq!(endpoint.bound_addresses(), before);
        assert_eq!(endpoint.connected_peers(), Vec::<PeerId>::new());
        assert!(endpoint.connection_id(listened[0].peer_id()).is_none());
        assert!(endpoint.peer_info(listened[0].peer_id()).is_none());
        assert!(!endpoint.is_peer_ready(listened[0].peer_id()));
    }

    #[cfg(feature = "nat")]
    #[test]
    fn wait_delivers_queued_nat_events_once() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind NAT endpoint");
        endpoint
            .nat
            .as_mut()
            .expect("NAT configured")
            .push_event(NatEvent::ReachabilityChanged {
                old: ReachabilityState::Unknown,
                new: ReachabilityState::Private,
                confirmed_addrs: Vec::new(),
            });

        assert!(matches!(
            endpoint.wait(Duration::ZERO).expect("wait"),
            EndpointWaitOutcome::Event(EndpointEvent::Nat(NatEvent::ReachabilityChanged { .. }))
        ));
        assert!(matches!(
            endpoint.wait(Duration::ZERO).expect("wait"),
            EndpointWaitOutcome::Deadline
        ));
    }

    #[cfg(feature = "pubsub")]
    #[test]
    fn wait_delivers_queued_gossipsub_events_as_endpoint_events() {
        let mut endpoint = Endpoint::builder()
            .gossipsub()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind pubsub endpoint");
        let peer = Ed25519Keypair::generate().peer_id();
        endpoint
            .gossipsub
            .as_mut()
            .expect("pubsub configured")
            .events
            .push_back(GossipsubEvent::PeerSubscribed {
                peer: peer.clone(),
                topic: "test".into(),
            });

        assert!(matches!(
            endpoint.wait(Duration::ZERO).expect("wait"),
            EndpointWaitOutcome::Event(EndpointEvent::Gossipsub(GossipsubEvent::PeerSubscribed {
                peer: returned,
                topic,
            })) if returned == peer && topic == "test"
        ));
    }

    #[cfg(all(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    #[test]
    fn capability_events_leave_once_in_endpoint_order() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .gossipsub()
            .relay_server()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind capability endpoint");
        let peer = Ed25519Keypair::generate().peer_id();
        endpoint
            .gossipsub
            .as_mut()
            .unwrap()
            .events
            .push_back(GossipsubEvent::PeerSubscribed {
                peer: peer.clone(),
                topic: "test".into(),
            });
        let nat = endpoint.nat.as_mut().unwrap();
        nat.push_event(NatEvent::FellBackToRelay {
            connect_id: ConnectId::from_u64(99),
            peer: peer.clone(),
        });
        nat.push_event(NatEvent::ReachabilityChanged {
            old: ReachabilityState::Unknown,
            new: ReachabilityState::Private,
            confirmed_addrs: Vec::new(),
        });
        endpoint
            .relay_server
            .as_mut()
            .unwrap()
            .events
            .push_back(RelayServerEvent::Error(RelayServerRuntimeError {
                kind: RelayServerRuntimeErrorKind::InternalInvariant,
                peer_id: None,
                detail: "test diagnostic".into(),
            }));

        // A Peer-ID target with no route settles inside `connect`; its
        // terminal must still follow the capability events already queued.
        let settled_id = endpoint
            .connect(Ed25519Keypair::generate().peer_id())
            .expect("admit route-less connect");

        let events = endpoint.poll().expect("poll");
        let order: Vec<&str> = events
            .iter()
            .filter_map(|event| match event {
                EndpointEvent::RelayServer(_) => Some("relay-server"),
                EndpointEvent::Nat(_) => Some("nat"),
                EndpointEvent::Gossipsub(_) => Some("gossipsub"),
                EndpointEvent::ConnectSettled { connect_id, .. } if *connect_id == settled_id => {
                    Some("settled")
                }
                _ => None,
            })
            .collect();
        // FellBackToRelay is an attempt terminal the engine reports as
        // ConnectSettled; it is not repeated as a NAT event.
        assert_eq!(order, ["relay-server", "nat", "gossipsub", "settled"]);
    }

    /// One transport poll can return several swarm events. `poll` must finish
    /// each one before the next, the same way `wait` does. Batching the whole
    /// poll and calling `finish_step` once puts `ConnectSettled` after the
    /// later swarm event.
    #[test]
    fn poll_finishes_each_swarm_event_before_the_next() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind endpoint");
        let peer = Ed25519Keypair::generate().peer_id();
        let unreachable = PeerAddr::quic_v1(IpAddr::V4(Ipv4Addr::LOCALHOST), 9, peer.clone());
        let connect_id = endpoint.connect(&unreachable).expect("start connect");
        endpoint.swarm_mut().preload_poll_events([
            SwarmEvent::ConnectionEstablished {
                peer_id: peer.clone(),
                conn_id: ConnectionId::new(1),
            },
            SwarmEvent::PingTimeout {
                peer_id: peer.clone(),
            },
        ]);

        let events = endpoint.poll().expect("poll");
        let established = events.iter().position(|event| {
            matches!(
                event,
                EndpointEvent::ConnectionEstablished { peer_id, .. } if peer_id == &peer
            )
        });
        let settled = events.iter().position(|event| {
            matches!(
                event,
                EndpointEvent::ConnectSettled { connect_id: id, .. } if *id == connect_id
            )
        });
        let ping = events.iter().position(
            |event| matches!(event, EndpointEvent::PingTimeout { peer_id } if peer_id == &peer),
        );
        match (established, settled, ping) {
            (Some(established_at), Some(settled_at), Some(ping_at)) => {
                assert!(
                    established_at < settled_at && settled_at < ping_at,
                    "ConnectSettled must follow its ConnectionEstablished and precede the next swarm event: {events:?}"
                );
            }
            _ => panic!(
                "expected ConnectionEstablished, ConnectSettled, then PingTimeout; got {events:?}"
            ),
        }
    }

    #[cfg(feature = "nat")]
    #[test]
    fn wait_honors_expired_deadline_with_active_driver() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind NAT endpoint");

        assert!(matches!(
            endpoint.wait(Duration::ZERO).expect("expired wait"),
            EndpointWaitOutcome::Deadline
        ));
    }

    #[cfg(feature = "nat")]
    #[test]
    fn wait_returns_application_event_produced_during_driver_poll() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind driven endpoint");
        let mut remote = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind remote endpoint");
        endpoint.listen().expect("driven endpoint listens");
        let remote_addr = remote.listen().expect("remote listens");

        let stop = Arc::new(AtomicBool::new(false));
        let remote_stop = Arc::clone(&stop);
        let remote_thread = std::thread::spawn(move || {
            while !remote_stop.load(Ordering::Relaxed) {
                remote
                    .next_event(Duration::from_millis(20))
                    .expect("drive remote");
            }
        });

        endpoint.connect(&remote_addr).expect("connect to remote");
        let wake = endpoint
            .wait(Duration::from_secs(5))
            .expect("wait for application event");
        stop.store(true, Ordering::Relaxed);
        remote_thread.join().expect("remote driver exits");

        assert!(matches!(
            wake,
            EndpointWaitOutcome::Event(EndpointEvent::ConnectionEstablished { peer_id, .. })
                if peer_id == *remote_addr.peer_id()
        ));
    }

    /// A step's first event is often `ConnectionEstablished`, with the NAT
    /// path and `ConnectSettled` behind it. `wait` must hand them out in that
    /// order: the terminal never overtakes the connection it reports.
    #[cfg(feature = "nat")]
    #[test]
    fn nat_path_and_connect_settled_follow_connection_established() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind NAT endpoint");
        let mut remote = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind remote endpoint");
        endpoint.listen().expect("NAT endpoint listens");
        let remote_addr = remote.listen().expect("remote listens");
        let _remote = Driven::new(remote);

        let connect_id = endpoint.connect(&remote_addr).expect("connect");
        let mut events = Vec::new();
        wait_for(&mut endpoint, "connect settled", |event| {
            events.push(format!("{event:?}"));
            matches!(event, EndpointEvent::ConnectSettled { connect_id: id, .. } if *id == connect_id)
        });
        let position = |needle: &str| events.iter().position(|event| event.contains(needle));
        match (
            position("ConnectionEstablished"),
            position("PathEstablished"),
            position("ConnectSettled"),
        ) {
            (Some(established), Some(path), Some(settled)) => assert!(
                established < path && path < settled,
                "expected ConnectionEstablished, PathEstablished, ConnectSettled: {events:?}"
            ),
            _ => panic!("missing connection, path, or terminal event: {events:?}"),
        }
    }

    #[cfg(feature = "nat")]
    #[test]
    fn wait_delivers_connect_timeout_with_an_active_driver() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut endpoint = Endpoint::builder()
            .connect_deadline(Duration::from_millis(20))
            .nat_config(NatConfig::default())
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind NAT endpoint");
        let unreachable = PeerAddr::quic_v1(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9,
            Ed25519Keypair::generate().peer_id(),
        );
        let id = endpoint.connect(&unreachable).expect("start timed connect");

        let wake = endpoint
            .wait(Duration::from_secs(1))
            .expect("wait for connect deadline");
        match wake {
            EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                connect_id,
                outcome: ConnectOutcome::Failed(ConnectFailure::Timeout { .. }),
                ..
            }) => assert_eq!(connect_id, id),
            other => panic!("expected ConnectSettled Timeout, got {other:?}"),
        }
    }

    #[cfg(any(feature = "discovery", feature = "mdns"))]
    #[test]
    fn discovery_clock_is_present_only_for_an_active_source() {
        let mut inactive = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind plain endpoint");
        assert_eq!(inactive.discovery_now_ms(), None);

        let builder = Endpoint::builder();
        #[cfg(feature = "discovery")]
        let builder = builder.discovery();
        #[cfg(all(feature = "mdns", not(feature = "discovery")))]
        let builder = builder.mdns();
        let mut active = builder
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind discovery endpoint");
        let first = active.discovery_now_ms().expect("discovery clock");
        let second = active.discovery_now_ms().expect("discovery clock");
        assert!(second >= first);
    }

    #[cfg(feature = "mdns")]
    #[test]
    fn mdns_config_is_rejected_before_binding() {
        let config = MdnsConfig {
            max_packet_bytes: 4_097,
            ..MdnsConfig::default()
        };
        assert!(matches!(
            Endpoint::builder().mdns_config(config),
            Err(MdnsConfigError::InvalidMaxPacketBytes)
        ));
    }

    #[cfg(feature = "mdns")]
    #[test]
    fn mdns_shutdown_is_idempotent_and_leaves_quic_usable() {
        let mut endpoint = Endpoint::builder()
            .mdns()
            .peer_discovery_config(PeerDiscoveryConfig {
                auto_dial: false,
                ..PeerDiscoveryConfig::default()
            })
            .expect("valid peer discovery policy")
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind mDNS endpoint");
        endpoint.listen().expect("QUIC listens");
        endpoint.shutdown().expect("first mDNS shutdown");
        endpoint.shutdown().expect("second mDNS shutdown");
        assert!(
            endpoint.poll().is_ok(),
            "QUIC remains usable after shutdown"
        );
    }

    #[cfg(feature = "discovery")]
    #[test]
    fn discovery_topic_cannot_be_unsubscribed_independently() {
        let topic = "/minip2p/test/discovery";
        let config = BeaconConfig {
            topic: topic.into(),
            ..BeaconConfig::default()
        };
        let mut endpoint = Endpoint::builder()
            .discovery_config(config)
            .expect("valid discovery configuration")
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind discovery endpoint");

        assert!(matches!(
            endpoint.unsubscribe(topic),
            Err(GossipsubError::DiscoveryTopicReserved)
        ));
        assert!(matches!(
            endpoint.publish(topic, b"not a beacon".to_vec()),
            Err(GossipsubError::DiscoveryTopicReserved)
        ));
    }

    const PROTOCOL: &str = "/myapp/1.0.0";

    #[test]
    fn builder_protocol_registers_for_stream_routing() {
        let mut endpoint = Endpoint::builder()
            .protocol(PROTOCOL)
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");

        // A registered protocol fails with NotConnected for an unknown
        // peer, not ProtocolNotRegistered -- proving the builder wired the
        // protocol into user-stream routing.
        let peer_id = Ed25519Keypair::generate().peer_id();
        assert!(matches!(
            endpoint.open_stream(&peer_id, PROTOCOL),
            Err(Error::Swarm(SwarmError::NotConnected { .. }))
        ));
        assert!(matches!(
            endpoint.open_stream(&peer_id, "/other/1.0.0"),
            Err(Error::Swarm(SwarmError::ProtocolNotRegistered { .. }))
        ));
    }

    #[test]
    fn builder_rejects_reserved_protocol_ids() {
        for reserved in RESERVED_PROTOCOL_IDS {
            let error = Endpoint::builder()
                .protocol(reserved)
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
                .expect("quic listen address")
                .bind()
                .err()
                .expect("reserved ids must fail the build");
            assert!(matches!(
                error,
                Error::Swarm(SwarmError::ReservedProtocol { .. })
            ));
        }
    }

    #[test]
    fn builder_rejects_reserved_protocol_ids_before_binding() {
        // An unbindable address must not mask the configuration error:
        // validation happens before any socket is allocated.
        let error = Endpoint::builder()
            .protocol(RESERVED_PROTOCOL_IDS[0])
            // TEST-NET-1 is never a local address, so this bind would fail.
            .listen_on("/ip4/192.0.2.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .err()
            .expect("reserved ids must fail the build");
        assert!(matches!(
            error,
            Error::Swarm(SwarmError::ReservedProtocol { .. })
        ));
    }

    #[test]
    fn add_protocol_rejects_reserved_protocol_ids() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");
        let error = endpoint
            .add_protocol(RESERVED_PROTOCOL_IDS[0])
            .expect_err("reserved ids must be rejected");
        assert!(matches!(
            error,
            Error::Swarm(SwarmError::ReservedProtocol { .. })
        ));
        endpoint
            .add_protocol(PROTOCOL)
            .expect("application ids must be accepted");
    }

    #[cfg(all(feature = "relay-server", feature = "tcp"))]
    #[test]
    fn relay_server_builder_is_order_independent_and_announce_does_not_enable() {
        let announce = vec!["/ip4/127.0.0.1/tcp/4001".parse().unwrap()];
        let endpoint = Endpoint::builder()
            .relay_server_announce_addrs(announce.clone())
            .expect("valid announce address")
            .relay_server()
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("enabled relay server binds");
        assert!(endpoint.relay_server.is_some());

        let result = Endpoint::builder()
            .relay_server_announce_addrs(announce)
            .expect("valid announce address")
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind();
        let error = match result {
            Ok(_) => panic!("announce addresses alone must not enable the service"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("relay server is not enabled"));
    }

    #[cfg(feature = "relay-server")]
    #[test]
    fn relay_server_builder_rejects_structurally_invalid_addresses_immediately() {
        let wildcard = "/ip4/0.0.0.0/tcp/4001".parse().unwrap();
        let error = match Endpoint::builder().relay_server_announce_addrs(vec![wildcard]) {
            Ok(_) => panic!("wildcards are not announceable"),
            Err(RelayServerAnnounceError::Address(error)) => error,
            Err(RelayServerAnnounceError::Config(error)) => {
                panic!("default validator configuration is valid: {error}")
            }
        };
        assert_eq!(error.index, 0);
        assert_eq!(error.reason, RelayServerAddressErrorKind::Wildcard);
    }

    #[cfg(feature = "relay-server")]
    #[test]
    fn relay_server_builder_checks_announce_peer_against_fixed_identity_immediately() {
        let identity = Ed25519Keypair::from_secret_key_bytes([91; 32]);
        let other = Ed25519Keypair::from_secret_key_bytes([92; 32]).peer_id();
        let address = format!("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/{other}")
            .parse()
            .unwrap();
        let error = match Endpoint::builder()
            .identity(identity.clone())
            .relay_server_announce_addrs(vec![address])
        {
            Ok(_) => panic!("conflicting peer id must fail immediately"),
            Err(RelayServerAnnounceError::Address(error)) => error,
            Err(RelayServerAnnounceError::Config(error)) => {
                panic!("default validator configuration is valid: {error}")
            }
        };
        assert!(matches!(
            error.reason,
            RelayServerAddressErrorKind::ConflictingPeerId { expected, found }
                if expected == identity.peer_id() && found == other
        ));
    }

    #[cfg(feature = "relay-server")]
    #[test]
    fn relay_server_runtime_controls_are_typed_and_address_replacement_is_atomic() {
        let mut absent = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind endpoint");
        assert!(matches!(
            absent.set_relay_server_accepting(false),
            Err(RelayServerControlError::NotConfigured)
        ));

        let original: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap();
        let mut endpoint = Endpoint::builder()
            .relay_server()
            .relay_server_announce_addrs(vec![original.clone()])
            .expect("valid initial address")
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind relay server");
        let invalid = "/ip4/0.0.0.0/udp/4002/quic-v1".parse().unwrap();
        let error = endpoint
            .set_relay_server_announce_addrs(vec![invalid])
            .expect_err("invalid replacement");
        assert!(matches!(
            error,
            RelayServerControlError::InvalidAddress(RelayServerAddressError {
                index: 0,
                reason: RelayServerAddressErrorKind::Wildcard,
                ..
            })
        ));
        assert_eq!(
            endpoint
                .relay_server
                .as_ref()
                .unwrap()
                .agent
                .selected_addrs(),
            core::slice::from_ref(&original)
        );
        endpoint
            .set_relay_server_announce_addrs(Vec::new())
            .expect("empty replacement clears override");
        let selected = endpoint
            .relay_server
            .as_ref()
            .unwrap()
            .agent
            .selected_addrs();
        assert!(!selected.is_empty());
        assert_ne!(selected, [original]);
    }

    #[cfg(feature = "relay-server")]
    #[test]
    fn wildcard_listener_binds_without_becoming_a_relay_announce_address() {
        let endpoint = Endpoint::builder()
            .relay_server()
            .listen_on("/ip4/0.0.0.0/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("wildcard listener may host once a usable address source appears");
        assert!(
            endpoint
                .relay_server
                .as_ref()
                .unwrap()
                .agent
                .selected_addrs()
                .is_empty()
        );
    }

    #[cfg(feature = "relay-server")]
    #[test]
    fn wait_delivers_relay_server_events() {
        let mut endpoint = Endpoint::builder()
            .relay_server()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind relay server");
        endpoint
            .relay_server
            .as_mut()
            .unwrap()
            .events
            .push_back(RelayServerEvent::Error(RelayServerRuntimeError {
                kind: RelayServerRuntimeErrorKind::InternalInvariant,
                peer_id: None,
                detail: "test diagnostic".into(),
            }));
        assert!(matches!(
            endpoint.wait(Duration::ZERO).expect("queue wait"),
            EndpointWaitOutcome::Event(EndpointEvent::RelayServer(RelayServerEvent::Error(_)))
        ));
        assert!(matches!(
            endpoint.wait(Duration::ZERO).expect("drained wait"),
            EndpointWaitOutcome::Deadline
        ));
    }

    #[cfg(all(feature = "nat", feature = "relay-server"))]
    #[test]
    fn nat_and_relay_address_contributions_form_a_stable_first_wins_union() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .relay_server()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind combined endpoint");
        let nat_only: Multiaddr = "/ip4/203.0.113.1/udp/4001/quic-v1".parse().unwrap();
        let duplicate: Multiaddr = "/ip4/203.0.113.2/udp/4002/quic-v1".parse().unwrap();
        let relay_only: Multiaddr = "/ip4/203.0.113.3/udp/4003/quic-v1".parse().unwrap();
        endpoint
            .nat
            .as_mut()
            .unwrap()
            .set_test_public_addrs(vec![nat_only.clone(), duplicate.clone()]);
        endpoint
            .relay_server
            .as_mut()
            .unwrap()
            .agent
            .replace_announce_addrs(vec![duplicate.clone(), relay_only.clone()])
            .unwrap();
        endpoint.refresh_external_address_contributions();
        endpoint.swarm.poll().expect("refresh identify snapshot");
        let advertised = endpoint.swarm.core().local_addresses();
        let nat_index = advertised
            .iter()
            .position(|addr| addr == &nat_only)
            .unwrap();
        let duplicate_indices: Vec<_> = advertised
            .iter()
            .enumerate()
            .filter_map(|(index, addr)| (addr == &duplicate).then_some(index))
            .collect();
        let relay_index = advertised
            .iter()
            .position(|addr| addr == &relay_only)
            .unwrap();
        assert_eq!(duplicate_indices.len(), 1);
        assert!(nat_index < duplicate_indices[0] && duplicate_indices[0] < relay_index);
    }

    #[cfg(feature = "relay-server")]
    #[test]
    fn relay_refresh_preserves_caller_owned_swarm_external_addresses() {
        let mut endpoint = Endpoint::builder()
            .relay_server()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind relay endpoint");
        let caller_owned: Multiaddr = "/ip4/203.0.113.8/udp/4008/quic-v1".parse().unwrap();
        let relay_owned: Multiaddr = "/ip4/203.0.113.9/udp/4009/quic-v1".parse().unwrap();
        endpoint
            .swarm_mut()
            .set_external_addresses(vec![caller_owned.clone()]);
        endpoint
            .set_relay_server_announce_addrs(vec![relay_owned.clone()])
            .expect("replace relay addresses");
        endpoint.swarm.poll().expect("refresh identify snapshot");

        let advertised = endpoint.swarm.core().local_addresses();
        assert!(advertised.contains(&caller_owned));
        assert!(advertised.contains(&relay_owned));
    }

    #[cfg(feature = "relay-server")]
    #[test]
    fn caller_keeps_an_address_after_the_matching_driver_contribution_clears() {
        let mut endpoint = Endpoint::builder()
            .relay_server()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind relay endpoint");
        let shared: Multiaddr = "/ip4/203.0.113.10/udp/4010/quic-v1".parse().unwrap();
        endpoint
            .set_relay_server_announce_addrs(vec![shared.clone()])
            .expect("set relay contribution");
        endpoint
            .swarm_mut()
            .set_external_addresses(vec![shared.clone()]);

        endpoint
            .set_relay_server_announce_addrs(Vec::new())
            .expect("clear relay contribution");
        endpoint.swarm.poll().expect("refresh identify snapshot");

        assert!(endpoint.swarm.core().local_addresses().contains(&shared));
    }
}
