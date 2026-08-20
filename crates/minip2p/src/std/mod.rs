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
//! An endpoint brings up whatever it was asked to bind --
//! `EndpointBuilder::quic`, `EndpointBuilder::quic_dual_stack`,
//! `EndpointBuilder::tcp`, in any combination -- and routes by address from
//! then on: a `/udp/…/quic-v1` peer is reached over QUIC and a `/tcp` one over
//! TCP without the caller choosing, and without anything above the endpoint
//! knowing there is more than one. `bind_quic`, `bind_quic_multiaddr`,
//! `bind_quic_dual_stack`, and `bind_tcp` are the one-transport shorthands.
//!
//! With the `pubsub` feature, `EndpointBuilder::pubsub` selects gossipsub by
//! default. `EndpointBuilder::pubsub_config` accepts either a
//! `GossipsubConfig` or `FloodsubConfig`; the selected engine controls which
//! pubsub protocol ids are advertised.
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
//! `Endpoint::builder().relay_server().bind_*()` hosting path. Relay-only
//! endpoints advertise inbound HOP and open outbound STOP; NAT-only endpoints
//! install the trusted client roles, and combined endpoints compose both.

mod dial;
#[cfg(any(feature = "discovery", feature = "mdns"))]
mod discovery;
#[cfg(feature = "mdns")]
mod mdns;
#[cfg(feature = "nat")]
mod nat;
#[cfg(feature = "pubsub")]
mod pubsub;
#[cfg(feature = "relay-server")]
mod relay_server;

#[cfg(any(feature = "discovery", feature = "mdns"))]
pub use discovery::DiscoveryError;
#[allow(unused_imports)] // Only transport-less `std` builds leave this unused.
use minip2p_core::Multiaddr;
#[cfg(any(feature = "tcp", feature = "relay-server"))]
use minip2p_core::Protocol;
#[cfg(any(feature = "quic", feature = "tcp"))]
use minip2p_core::TransportKind;
use minip2p_core::{PeerAddr, PeerId};
#[cfg(feature = "discovery")]
pub use minip2p_discovery::{BeaconConfig, DISCOVERY_TOPIC};
#[cfg(any(feature = "discovery", feature = "mdns"))]
pub use minip2p_discovery::{
    DiscoveryConfigError, DiscoveryEvent, DiscoverySource, KnownPeer, PeerDiscoveryConfig,
};
pub use minip2p_identify::IdentifyMessage;
pub use minip2p_identity::Ed25519Keypair;
#[cfg(feature = "mdns")]
pub use minip2p_mdns::{MdnsConfig, MdnsConfigError};
#[cfg(feature = "nat")]
pub use minip2p_nat::{
    ConnectId, NatConfig, NatError, NatEvent, Path, ReachabilityState, ReservationInfo,
    ReservationPolicy,
};
#[cfg(feature = "tcp")]
use minip2p_platform::StdEntropy;
#[cfg(feature = "pubsub")]
pub use minip2p_pubsub::{
    FLOODSUB_PROTOCOL_ID, FloodsubConfig, GossipsubConfig, MESHSUB_PROTOCOL_ID_V10,
    MESHSUB_PROTOCOL_ID_V11, PublishError, PubsubConfig, PubsubConfigError, PubsubEvent,
    TopicError,
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
#[cfg(feature = "relay-server")]
pub use minip2p_swarm::ConnectionCloseCause;
use minip2p_swarm::SwarmBuilder;
pub use minip2p_swarm::{
    Deadline, DriverError as Error, PollNext, RESERVED_PROTOCOL_IDS, RUN_UNTIL_SKIP_LIMIT, Swarm,
    SwarmError, SwarmEvent as Event,
};
#[cfg(feature = "tcp")]
use minip2p_tcp::{StdTcpProvider, TcpConfig, TcpTransport};
#[cfg(any(feature = "quic", feature = "tcp"))]
use minip2p_transport::ConnectionNamespace;
#[cfg(any(feature = "tcp", feature = "relay-server"))]
use minip2p_transport::Transport;
pub use minip2p_transport::{ConnectionId, StreamId, TransportError, TransportSet, WaitHandle};
#[cfg(feature = "pubsub")]
pub use pubsub::PubsubError;

const DEFAULT_AGENT_VERSION: &str = "minip2p/0.1.0";
#[cfg(feature = "relay-server")]
const RELAY_HOP_PROTOCOL_ID: &str = "/libp2p/circuit/relay/0.2.0/hop";
#[cfg(feature = "relay-server")]
const RELAY_STOP_PROTOCOL_ID: &str = "/libp2p/circuit/relay/0.2.0/stop";

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
/// `Endpoint` owns identity, transports, and the std swarm driver. Advanced
/// users can still borrow the underlying [`Swarm`] with [`Endpoint::swarm`]
/// and [`Endpoint::swarm_mut`].
///
/// QUIC, TCP, or both -- see `EndpointBuilder::quic`,
/// `EndpointBuilder::tcp`, and [`EndpointBuilder::bind`]. They live behind
/// one [`TransportSet`], which routes each address to the transport that
/// serves its shape, so nothing here or above changes with the second one:
/// [`dial`](Self::dial) takes the same [`PeerAddr`], [`listen`](Self::listen)
/// arms every bound address, and the events are the same events.
///
/// With the `nat` cargo feature and a NAT configuration
/// (`EndpointBuilder::relay` / `EndpointBuilder::nat_config`), the endpoint
/// additionally runs the `minip2p_nat::NatAgent` traversal orchestrator:
/// see `Endpoint::connect`, `Endpoint::wait_path`, and
/// `Endpoint::take_nat_events`.
///
/// [`close`](Self::close) or drop disconnects established peers so a listener
/// is not left on the QUIC idle timeout. Neither path helps after `kill -9`
/// or a hard partition.
pub struct Endpoint {
    swarm: EndpointSwarm,
    #[cfg(feature = "relay-server")]
    relay_server: Option<relay_server::RelayServerDriver>,
    #[cfg(feature = "nat")]
    nat: Option<nat::NatDriver>,
    #[cfg(feature = "pubsub")]
    pubsub: Option<pubsub::PubsubDriver>,
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    discovery: Option<discovery::DiscoveryDriver>,
    #[cfg(feature = "mdns")]
    mdns: Option<mdns::MdnsDriver>,
    /// Application events set aside while a driver-focused wait was driving
    /// the endpoint; drained first by [`Endpoint::next_event`].
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    pending_events: std::collections::VecDeque<Event>,
    /// Addresses installed by the composed NAT and relay-server drivers on the
    /// previous refresh, kept separate from caller-owned Swarm contributions.
    #[cfg(any(feature = "nat", feature = "relay-server"))]
    managed_external_addresses: Vec<Multiaddr>,
}

/// Why one [`Endpoint::next_wake`] call returned.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // Preserve Event ownership without a heap allocation.
#[must_use = "handle the wake reason and drain every non-empty agent queue after DriverProgress"]
pub enum EndpointWake {
    /// An application event not owned by an active agent.
    ///
    /// The event has been removed from the endpoint and belongs to the
    /// caller.
    Event(Event),
    /// At least one agent queue contains an event.
    ///
    /// Drain the enabled queues with `Endpoint::take_nat_events`,
    /// `Endpoint::take_pubsub_events`, or `Endpoint::take_discovery_events`,
    /// as applicable. Before calling [`Endpoint::next_wake`] again, callers
    /// must drain every non-empty agent queue counted by this notification;
    /// otherwise the next call returns `DriverProgress` immediately again.
    DriverProgress,
    /// The transport wait was interrupted by an external wait handle.
    Interrupted,
    /// The caller's deadline elapsed without an application event or agent
    /// progress.
    Deadline,
}

/// Why one driver-aware swarm-driving step returned.
#[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
enum DriverPollKind {
    /// An event not owned by any agent is ready for the application.
    Application,
    /// An agent produced application-visible output; focused waits should
    /// re-check their queue immediately.
    Progress,
    /// The transport wait was interrupted externally.
    Interrupted,
    /// The caller's deadline elapsed.
    Deadline,
}

#[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
struct DriverPoll {
    kind: DriverPollKind,
    event: Option<Event>,
}

#[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
impl DriverPoll {
    fn application(event: Event) -> Self {
        Self {
            kind: DriverPollKind::Application,
            event: Some(event),
        }
    }

    fn progress() -> Self {
        Self {
            kind: DriverPollKind::Progress,
            event: None,
        }
    }

    fn deadline() -> Self {
        Self {
            kind: DriverPollKind::Deadline,
            event: None,
        }
    }

    fn interrupted() -> Self {
        Self {
            kind: DriverPollKind::Interrupted,
            event: None,
        }
    }
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
        #[cfg(feature = "nat")]
        self.sync_nat_listen_addrs(&addrs);
        Ok(addrs)
    }

    /// Seeds the NAT agent's advertised addresses from the bound set
    /// (wildcards and anything no transport can dial filtered out). No-op when
    /// NAT is not configured.
    #[cfg(feature = "nat")]
    fn sync_nat_listen_addrs(&mut self, addrs: &[PeerAddr]) {
        if let Some(nat) = self.nat.as_mut() {
            let transports: Vec<Multiaddr> =
                addrs.iter().map(|addr| addr.transport().clone()).collect();
            let validated = minip2p_core::select_direct_addrs(&transports, None, None);
            nat.agent.set_listen_addrs(&validated);
        }
    }

    /// Dials a remote peer on every applicable local address family.
    ///
    /// `/dns` targets are resolved first, and a name that answers with both
    /// families is dialed over both. The address shape decides which transport
    /// carries each dial, so a `/tcp` target goes to TCP and a
    /// `/udp/quic-v1` one to QUIC without the caller choosing. Use
    /// [`Endpoint::dial_ip4`] or [`Endpoint::dial_ip6`] to force one family.
    ///
    /// Fails only if every address failed; the returned ids are the dials that
    /// started.
    pub fn dial(&mut self, addr: &PeerAddr) -> Result<Vec<ConnectionId>, Error> {
        let targets = dial::targets(addr)?;
        let mut ids = Vec::with_capacity(targets.len());
        let mut failure = None;
        for (_, target) in targets {
            match self.swarm.dial(&target) {
                Ok(id) => ids.push(id),
                // One family being unreachable is not the dial failing: the
                // other may still connect, and reporting the first error would
                // hide a path that worked.
                Err(error) => failure = failure.or(Some(error)),
            }
        }
        match failure {
            Some(error) if ids.is_empty() => Err(error),
            _ => Ok(ids),
        }
    }

    /// Dials a remote peer using IPv4.
    pub fn dial_ip4(&mut self, addr: &PeerAddr) -> Result<ConnectionId, Error> {
        self.dial_family(addr, dial::Family::V4)
    }

    /// Dials a remote peer using IPv6.
    pub fn dial_ip6(&mut self, addr: &PeerAddr) -> Result<ConnectionId, Error> {
        self.dial_family(addr, dial::Family::V6)
    }

    fn dial_family(
        &mut self,
        addr: &PeerAddr,
        family: dial::Family,
    ) -> Result<ConnectionId, Error> {
        let target = dial::targets(addr)?
            .into_iter()
            .find(|(candidate, _)| *candidate == family)
            .map(|(_, target)| target)
            .ok_or_else(|| TransportError::InvalidAddress {
                context: "dial target",
                reason: format!("{} names no {family:?} address", addr.transport()),
            })?;
        self.swarm.dial(&target)
    }

    /// Sends a ping to `peer_id`.
    ///
    /// The RTT is emitted later as [`Event::PingRttMeasured`].
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
    /// usable connection closes. Raw `dial*` connections are not tracked.
    #[cfg(feature = "nat")]
    pub fn path(&self, peer_id: &PeerId) -> Option<Path> {
        self.nat.as_ref().and_then(|nat| nat.path(peer_id))
    }

    /// Returns peers with an established connection.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers()
    }

    /// Returns whether Identify has completed for `peer_id`.
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.swarm.is_peer_ready(peer_id)
    }

    /// Returns the latest Identify information received for `peer_id`.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.swarm.peer_info(peer_id)
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
        let result = self.swarm.abandon_stream(peer_id, stream_id);
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        self.pending_events
            .retain(|event| !event.matches_stream(peer_id, stream_id));
        result
    }

    /// Polls the endpoint once and returns all currently available events.
    ///
    /// With NAT configured, events belonging to the traversal agent are
    /// consumed here (never surfaced to the application); the agent's own
    /// events accumulate for `Endpoint::take_nat_events`.
    pub fn poll(&mut self) -> Result<Vec<Event>, Error> {
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        {
            let polled = self.swarm.poll()?;
            let mut events: Vec<Event> = self.pending_events.drain(..).collect();
            for event in polled {
                if !self.ingest_into_drivers(&event) {
                    events.push(event);
                }
            }
            self.tick_drivers()?;
            Ok(events)
        }
        #[cfg(not(any(feature = "nat", feature = "pubsub", feature = "relay-server")))]
        {
            self.swarm.poll()
        }
    }

    /// Returns the next event, waiting internally until `deadline`.
    ///
    /// `deadline` accepts an [`std::time::Instant`], a relative
    /// [`std::time::Duration`], or [`Deadline::NEVER`] to wait indefinitely.
    pub fn next_event(&mut self, deadline: impl Into<Deadline>) -> Result<Option<Event>, Error> {
        let deadline = deadline.into();
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        if self.has_drivers() {
            return self.next_event_driven(deadline);
        }
        loop {
            match self.swarm.poll_next_interruptible(deadline)? {
                PollNext::Event(event) => return Ok(Some(event)),
                PollNext::Deadline => return Ok(None),
                PollNext::Interrupted => {}
            }
        }
    }

    /// Drives the endpoint until an application event, agent progress, or the
    /// caller's deadline.
    ///
    /// Unlike [`Endpoint::next_event`], this returns as soon as an active NAT,
    /// pubsub, or discovery agent has queued application-visible output. It
    /// also reports already-queued agent output immediately. An
    /// [`EndpointWake::Event`] has been removed from the endpoint; agent
    /// events remain in their focused queues for the corresponding `take_*`
    /// method.
    ///
    /// `DriverProgress` is level-triggered across all active agents. Before
    /// calling `next_wake` again, drain every non-empty enabled agent queue,
    /// not just the queue currently relevant to the application. Leaving any
    /// such queue non-empty makes subsequent calls return immediately and can
    /// busy-spin a caller that expected the supplied deadline to block.
    pub fn next_wake(&mut self, deadline: impl Into<Deadline>) -> Result<EndpointWake, Error> {
        let deadline = deadline.into();
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        if self.has_drivers() {
            if let Some(event) = self.pending_events.pop_front() {
                return Ok(EndpointWake::Event(event));
            }
            if self.driver_events_len() > 0 {
                return Ok(EndpointWake::DriverProgress);
            }
            let mut expired_poll_used = false;
            let poll = self.poll_new_event_driven(deadline, &mut expired_poll_used)?;
            return Ok(match poll.kind {
                DriverPollKind::Application => {
                    EndpointWake::Event(poll.event.expect("application poll carries event"))
                }
                DriverPollKind::Progress => EndpointWake::DriverProgress,
                DriverPollKind::Interrupted => EndpointWake::Interrupted,
                DriverPollKind::Deadline => EndpointWake::Deadline,
            });
        }
        self.swarm
            .poll_next_interruptible(deadline)
            .map(|event| match event {
                PollNext::Event(event) => EndpointWake::Event(event),
                PollNext::Deadline => EndpointWake::Deadline,
                PollNext::Interrupted => EndpointWake::Interrupted,
            })
    }

    /// Whether any agent driver is active on this endpoint.
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn has_drivers(&self) -> bool {
        #[cfg(feature = "relay-server")]
        if self.relay_server.is_some() {
            return true;
        }
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        if self.discovery.is_some() {
            return true;
        }
        #[cfg(feature = "mdns")]
        if self.mdns.is_some() {
            return true;
        }
        #[cfg(feature = "nat")]
        if self.nat.is_some() {
            return true;
        }
        #[cfg(feature = "pubsub")]
        if self.pubsub.is_some() {
            return true;
        }
        false
    }

    /// Feeds one swarm event through relay-server, NAT, then pubsub.
    ///
    /// Relay service owns inbound HOP before NAT considers its client-side
    /// streams. Neither service claims connection lifecycle or `PeerReady`,
    /// so both still observe the shared connection state.
    ///
    /// Returns `true` when a driver claimed the event.
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn ingest_into_drivers(&mut self, event: &Event) -> bool {
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        if let Some(discovery) = self.discovery.as_mut() {
            discovery.observe(event, &self.swarm);
        }
        let mut claimed = false;
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_mut() {
            claimed = relay_server.ingest(event, &mut self.swarm);
        }
        #[cfg(feature = "nat")]
        if !claimed && let Some(nat) = self.nat.as_mut() {
            claimed = nat.ingest(event, &mut self.swarm);
        }
        #[cfg(feature = "pubsub")]
        if !claimed && let Some(pubsub) = self.pubsub.as_mut() {
            claimed = pubsub.ingest(event, &mut self.swarm);
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
            nat.tick(&mut self.swarm);
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.pubsub.as_mut() {
            pubsub.tick(&mut self.swarm);
        }
        #[cfg(feature = "mdns")]
        if let Some(mdns) = self.mdns.as_mut() {
            mdns.tick(self.swarm.core().local_addresses())
                .map_err(mdns_driver_error)?;
        }
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        if let (Some(discovery), Some(nat)) = (self.discovery.as_mut(), self.nat.as_mut()) {
            discovery.sweep(
                #[cfg(feature = "discovery")]
                self.pubsub.as_mut(),
                #[cfg(feature = "mdns")]
                self.mdns.as_mut(),
                nat,
                &mut self.swarm,
            );
        }
        #[cfg(any(feature = "nat", feature = "relay-server"))]
        self.refresh_external_address_contributions();
        Ok(())
    }

    /// Application-visible events queued across every active driver; growth
    /// is the focused waits' progress signal.
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn driver_events_len(&self) -> usize {
        let mut len = 0;
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_ref() {
            len += relay_server.events.len();
        }
        #[cfg(feature = "nat")]
        if let Some(nat) = self.nat.as_ref() {
            len += nat.events.len();
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.pubsub.as_ref() {
            len += pubsub.events.len();
        }
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        if let Some(discovery) = self.discovery.as_ref() {
            len += discovery.book.pending_event_count();
        }
        len
    }

    /// One wait step's deadline: the caller's, shortened by whichever agent
    /// timer is due first.
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn driver_step_deadline(&self, deadline: Deadline) -> Deadline {
        let mut step = deadline;
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_ref()
            && let Some(ms) = relay_server.agent.next_timeout(relay_server.now())
        {
            step = step.earliest(Deadline::from(std::time::Duration::from_millis(ms.max(1))));
        }
        #[cfg(feature = "nat")]
        if let Some(nat) = self.nat.as_ref()
            && let Some(ms) = nat.agent.next_timeout(nat.now().mono_ms)
        {
            step = step.earliest(Deadline::from(std::time::Duration::from_millis(ms.max(1))));
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.pubsub.as_ref()
            && let Some(ms) = pubsub.agent.next_timeout(pubsub.now_ms())
        {
            step = step.earliest(Deadline::from(std::time::Duration::from_millis(ms.max(1))));
        }
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        if let Some(discovery) = self.discovery.as_ref()
            && let Some(ms) = discovery.next_timeout(discovery.now_ms())
        {
            step = step.earliest(Deadline::from(std::time::Duration::from_millis(ms.max(1))));
        }
        #[cfg(feature = "mdns")]
        if let Some(mdns) = self.mdns.as_ref()
            && let Some(ms) = mdns.next_timeout(mdns.now_ms())
        {
            step = step.earliest(Deadline::from(std::time::Duration::from_millis(ms.max(1))));
        }
        step
    }

    /// `next_event` with the active agents folded into the wait: the sleep
    /// budget never overshoots an agent's next timer, agent-owned stream
    /// events are consumed instead of surfaced, and ticks run between
    /// waits.
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn next_event_driven(&mut self, deadline: Deadline) -> Result<Option<Event>, Error> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(Some(event));
        }
        let mut expired_poll_used = false;
        loop {
            let poll = self.poll_new_event_driven(deadline, &mut expired_poll_used)?;
            match poll.kind {
                DriverPollKind::Application => return Ok(poll.event),
                DriverPollKind::Progress => {}
                DriverPollKind::Interrupted => {}
                DriverPollKind::Deadline => return Ok(None),
            }
        }
    }

    /// Drives the swarm and the active agents until a newly-arrived
    /// application event is available. Unlike [`Self::next_event_driven`],
    /// this never drains `pending_events`: focused waits must leave
    /// application events aside instead of repeatedly picking up the same
    /// one.
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn poll_new_event_driven(
        &mut self,
        deadline: Deadline,
        expired_poll_used: &mut bool,
    ) -> Result<DriverPoll, Error> {
        loop {
            // `Swarm::poll_next` deliberately performs one synchronous poll
            // even for an expired deadline. That is useful for one-shot
            // callers, but repeating it here under a continuous event stream
            // would let a focused wait run forever past its deadline.
            if deadline.has_passed() {
                if *expired_poll_used {
                    return Ok(DriverPoll::deadline());
                }
                *expired_poll_used = true;
            }
            let step = self.driver_step_deadline(deadline);
            let polled = self.swarm.poll_next_interruptible(step)?;
            if deadline.has_passed() {
                *expired_poll_used = true;
            }
            let events_before = self.driver_events_len();
            match polled {
                PollNext::Event(event) => {
                    let consumed = self.ingest_into_drivers(&event);
                    self.tick_drivers()?;
                    if !consumed {
                        return Ok(DriverPoll::application(event));
                    }
                    if self.driver_events_len() > events_before {
                        return Ok(DriverPoll::progress());
                    }
                }
                PollNext::Deadline => {
                    self.tick_drivers()?;
                    if self.driver_events_len() > events_before {
                        return Ok(DriverPoll::progress());
                    }
                    // Distinguish the caller's deadline from a mere agent
                    // timer that shortened this wait step.
                    if deadline.has_passed() {
                        return Ok(DriverPoll::deadline());
                    }
                }
                PollNext::Interrupted => return Ok(DriverPoll::interrupted()),
            }
        }
    }

    /// Waits until a peer is ready or `deadline` expires.
    pub fn wait_peer_ready(
        &mut self,
        peer_id: &PeerId,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<Event>, Error> {
        let deadline = deadline.into();
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        if self.has_drivers() {
            return self.wait_for_event_driven(deadline, |event| {
                matches!(event, Event::PeerReady { peer_id: ready, .. } if ready == peer_id)
            });
        }
        self.swarm.run_until(
            deadline,
            |event| matches!(event, Event::PeerReady { peer_id: ready, .. } if ready == peer_id),
        )
    }

    /// Waits until a ping RTT for `peer_id` is measured or `deadline` expires.
    pub fn wait_ping_rtt(
        &mut self,
        peer_id: &PeerId,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<u64>, Error> {
        let deadline = deadline.into();
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        let event = if self.has_drivers() {
            self.wait_for_event_driven(deadline, |event| {
                matches!(event, Event::PingRttMeasured { peer_id: ready, .. } if ready == peer_id)
            })?
        } else {
            self.swarm.run_until(deadline, |event| {
                matches!(event, Event::PingRttMeasured { peer_id: ready, .. } if ready == peer_id)
            })?
        };
        #[cfg(not(any(feature = "nat", feature = "pubsub", feature = "relay-server")))]
        let event = self.swarm.run_until(deadline, |event| {
            matches!(event, Event::PingRttMeasured { peer_id: ready, .. } if ready == peer_id)
        })?;
        Ok(match event {
            Some(Event::PingRttMeasured { rtt_ms, .. }) => Some(rtt_ms),
            _ => None,
        })
    }

    /// Starts a NAT-traversing connect toward `peer` with no known direct
    /// addresses: the relay leg carries the attempt and DCUtR upgrades it.
    ///
    /// Progress arrives as [`NatEvent`]s ([`Endpoint::take_nat_events`]);
    /// [`Endpoint::wait_path`] blocks for the outcome.
    #[cfg(feature = "nat")]
    pub fn connect(&mut self, peer: &PeerId) -> Result<ConnectId, Error> {
        self.connect_with_addrs(peer.clone(), Vec::new())
    }

    /// Starts a NAT-traversing connect racing dials of `direct_addrs`
    /// against the relay leg.
    #[cfg(feature = "nat")]
    pub fn connect_with_addrs(
        &mut self,
        peer: PeerId,
        direct_addrs: Vec<Multiaddr>,
    ) -> Result<ConnectId, Error> {
        let Some(nat) = self.nat.as_mut() else {
            return Err(Error::Invariant {
                reason: "NAT traversal is not configured; use EndpointBuilder::relay / nat_config",
            });
        };
        let now = nat.now();
        let id = nat.agent.connect(peer, direct_addrs, now);
        nat.pump(&mut self.swarm);
        Ok(id)
    }

    /// Starts a NAT-traversing connect toward a known peer address.
    #[cfg(feature = "nat")]
    pub fn connect_addr(&mut self, addr: &PeerAddr) -> Result<ConnectId, Error> {
        self.connect_with_addrs(addr.peer_id().clone(), vec![addr.transport().clone()])
    }

    /// Abandons a connect attempt. Streams it holds are reset; no further
    /// events are emitted for `id`.
    #[cfg(feature = "nat")]
    pub fn cancel_connect(&mut self, id: ConnectId) {
        if let Some(nat) = self.nat.as_mut() {
            let now = nat.now();
            nat.agent.cancel(id, now);
            nat.pump(&mut self.swarm);
        }
    }

    /// Waits for the first usable path of connect attempt `id`.
    ///
    /// Returns `Ok(Some(path))` on [`NatEvent::PathEstablished`] (the event
    /// is consumed), and `Ok(None)` when the attempt failed or `deadline`
    /// passed — on failure the [`NatEvent::ConnectFailed`] stays queued so
    /// its error remains inspectable via [`Endpoint::take_nat_events`].
    /// Application events arriving meanwhile are buffered for later
    /// [`Endpoint::next_event`] calls, never dropped.
    #[cfg(feature = "nat")]
    pub fn wait_path(
        &mut self,
        id: ConnectId,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<Path>, Error> {
        let deadline = deadline.into();
        let mut expired_poll_used = false;
        loop {
            {
                let Some(nat) = self.nat.as_mut() else {
                    return Err(Error::Invariant {
                        reason: "NAT traversal is not configured",
                    });
                };
                if let Some(index) = nat.events.iter().position(|event| {
                    matches!(
                        event,
                        NatEvent::PathEstablished { connect_id, .. } if *connect_id == id
                    )
                }) {
                    let Some(NatEvent::PathEstablished { path, .. }) = nat.events.remove(index)
                    else {
                        unreachable!("position matched PathEstablished");
                    };
                    return Ok(Some(path));
                }
                if nat.events.iter().any(|event| {
                    matches!(
                        event,
                        NatEvent::ConnectFailed { connect_id, .. } if *connect_id == id
                    )
                }) {
                    return Ok(None);
                }
            }
            self.ensure_pending_event_capacity()?;
            let poll = self.poll_new_event_driven(deadline, &mut expired_poll_used)?;
            match poll.kind {
                DriverPollKind::Application => self
                    .pending_events
                    .push_back(poll.event.expect("application poll carries event")),
                DriverPollKind::Progress => {}
                DriverPollKind::Interrupted => {}
                DriverPollKind::Deadline => return Ok(None),
            }
        }
    }

    /// Pauses or resumes admission of new relay reservations and circuits.
    ///
    /// Existing reservations and circuits remain active, and HOP remains
    /// advertised while admission is paused.
    #[cfg(feature = "relay-server")]
    #[allow(clippy::result_large_err)]
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
    #[allow(clippy::result_large_err)]
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

    /// Drains only application-visible relay-server events.
    ///
    /// Returns an empty vector when relay service is not configured and leaves
    /// ordinary endpoint events untouched.
    #[cfg(feature = "relay-server")]
    pub fn take_relay_server_events(&mut self) -> Vec<RelayServerEvent> {
        self.relay_server
            .as_mut()
            .map(|driver| driver.events.drain(..).collect())
            .unwrap_or_default()
    }

    /// Drives the whole endpoint until a relay-server event or caller deadline.
    ///
    /// Ordinary endpoint events encountered while waiting are preserved for
    /// [`Endpoint::next_event`]. Returns `Ok(None)` when relay service is absent
    /// or the deadline expires. It can return [`Error::EventBacklogExceeded`]
    /// when preserving those events exhausts the bounded backlog. Transport/action
    /// failures discovered asynchronously are returned as
    /// [`RelayServerEvent::Error`] rather than as this method's `Err` value.
    #[cfg(feature = "relay-server")]
    pub fn next_relay_server_event(
        &mut self,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<RelayServerEvent>, Error> {
        let deadline = deadline.into();
        let mut expired_poll_used = false;
        loop {
            match self.relay_server.as_mut() {
                Some(driver) => {
                    if let Some(event) = driver.events.pop_front() {
                        return Ok(Some(event));
                    }
                }
                None => return Ok(None),
            }
            self.ensure_pending_event_capacity()?;
            let poll = self.poll_new_event_driven(deadline, &mut expired_poll_used)?;
            match poll.kind {
                DriverPollKind::Application => self
                    .pending_events
                    .push_back(poll.event.expect("application poll carries event")),
                DriverPollKind::Progress | DriverPollKind::Interrupted => {}
                DriverPollKind::Deadline => return Ok(None),
            }
        }
    }

    #[cfg(any(feature = "nat", feature = "relay-server"))]
    fn refresh_external_address_contributions(&mut self) {
        #[cfg(feature = "relay-server")]
        {
            let listeners = concrete_relay_listener_addrs(self.swarm.transport().local_addresses());
            #[cfg(feature = "nat")]
            let confirmed = self
                .nat
                .as_ref()
                .map(nat::NatDriver::confirmed_public_addrs)
                .unwrap_or_default();
            if let Some(relay_server) = self.relay_server.as_mut() {
                let _ = relay_server.agent.set_listener_addrs(listeners);
                #[cfg(feature = "nat")]
                let _ = relay_server.agent.set_confirmed_addrs(confirmed);
            }
        }
        let mut addresses: Vec<_> = self
            .swarm
            .external_addresses()
            .iter()
            .filter(|address| !self.managed_external_addresses.contains(address))
            .cloned()
            .collect();
        let caller_address_count = addresses.len();
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
        self.managed_external_addresses = addresses[caller_address_count..].to_vec();
        self.swarm.set_external_addresses(addresses);
    }

    /// Drains all queued NAT events.
    #[cfg(feature = "nat")]
    pub fn take_nat_events(&mut self) -> Vec<NatEvent> {
        match self.nat.as_mut() {
            Some(nat) => nat.events.drain(..).collect(),
            None => Vec::new(),
        }
    }

    /// Returns the next NAT event, waiting internally until `deadline`.
    /// Application events arriving meanwhile are buffered for
    /// [`Endpoint::next_event`].
    #[cfg(feature = "nat")]
    pub fn next_nat_event(
        &mut self,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<NatEvent>, Error> {
        let deadline = deadline.into();
        let mut expired_poll_used = false;
        loop {
            match self.nat.as_mut() {
                Some(nat) => {
                    if let Some(event) = nat.events.pop_front() {
                        return Ok(Some(event));
                    }
                }
                None => return Ok(None),
            }
            self.ensure_pending_event_capacity()?;
            let poll = self.poll_new_event_driven(deadline, &mut expired_poll_used)?;
            match poll.kind {
                DriverPollKind::Application => self
                    .pending_events
                    .push_back(poll.event.expect("application poll carries event")),
                DriverPollKind::Progress => {}
                DriverPollKind::Interrupted => {}
                DriverPollKind::Deadline => return Ok(None),
            }
        }
    }

    /// Driver-aware equivalent of `Swarm::run_until`. Every swarm event
    /// goes through the active drivers, and non-matching application events
    /// are retained for [`Endpoint::next_event`].
    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn wait_for_event_driven<F>(
        &mut self,
        deadline: Deadline,
        mut predicate: F,
    ) -> Result<Option<Event>, Error>
    where
        F: FnMut(&Event) -> bool,
    {
        if let Some(index) = self.pending_events.iter().position(&mut predicate) {
            return Ok(self.pending_events.remove(index));
        }
        let mut expired_poll_used = false;
        loop {
            self.ensure_pending_event_capacity()?;
            let poll = self.poll_new_event_driven(deadline, &mut expired_poll_used)?;
            match poll.kind {
                DriverPollKind::Application => {
                    let event = poll.event.expect("application poll carries event");
                    if predicate(&event) {
                        return Ok(Some(event));
                    }
                    self.pending_events.push_back(event);
                }
                DriverPollKind::Progress => {}
                DriverPollKind::Interrupted => {}
                DriverPollKind::Deadline => return Ok(None),
            }
        }
    }

    #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
    fn ensure_pending_event_capacity(&self) -> Result<(), Error> {
        if self.pending_events.len() >= RUN_UNTIL_SKIP_LIMIT {
            return Err(Error::EventBacklogExceeded {
                limit: RUN_UNTIL_SKIP_LIMIT,
            });
        }
        Ok(())
    }

    /// Our current reachability verdict from AutoNAT probing
    /// ([`ReachabilityState::Unknown`] until probes gather confidence, or
    /// when NAT is not configured).
    #[cfg(feature = "nat")]
    pub fn reachability(&self) -> ReachabilityState {
        self.nat
            .as_ref()
            .map(|nat| nat.agent.reachability())
            .unwrap_or_default()
    }

    /// The relay reservation currently held, if any.
    #[cfg(feature = "nat")]
    pub fn active_reservation(&self) -> Option<ReservationInfo> {
        self.nat
            .as_ref()
            .and_then(|nat| nat.agent.active_reservation().cloned())
    }

    /// Subscribes to a pubsub topic. Returns `Ok(false)` when already
    /// subscribed. The subscription is announced through the configured
    /// pubsub routing engine.
    ///
    /// Errors with [`PubsubError::NotEnabled`] unless the endpoint was
    /// built with [`EndpointBuilder::pubsub`].
    #[cfg(feature = "pubsub")]
    pub fn subscribe(&mut self, topic: &str) -> Result<bool, PubsubError> {
        let Some(pubsub) = self.pubsub.as_mut() else {
            return Err(PubsubError::NotEnabled);
        };
        let now_ms = pubsub.now_ms();
        let newly = pubsub.agent.subscribe(topic, now_ms)?;
        pubsub.pump(&mut self.swarm);
        Ok(newly)
    }

    /// Withdraws a pubsub subscription. Returns `Ok(false)` when not
    /// subscribed. The configured discovery topic is reserved while
    /// discovery is enabled and returns
    /// [`PubsubError::DiscoveryTopicReserved`].
    #[cfg(feature = "pubsub")]
    pub fn unsubscribe(&mut self, topic: &str) -> Result<bool, PubsubError> {
        #[cfg(feature = "discovery")]
        if self
            .discovery
            .as_ref()
            .is_some_and(|discovery| discovery.topic() == Some(topic))
        {
            return Err(PubsubError::DiscoveryTopicReserved);
        }
        let Some(pubsub) = self.pubsub.as_mut() else {
            return Err(PubsubError::NotEnabled);
        };
        let now_ms = pubsub.now_ms();
        let removed = pubsub.agent.unsubscribe(topic, now_ms);
        pubsub.pump(&mut self.swarm);
        Ok(removed)
    }

    /// Publishes `data` on `topic`, signed with this endpoint's identity and
    /// routed through the configured pubsub engine.
    ///
    /// A successful return means the message was accepted and its outbound
    /// streams were initiated — the frames themselves go out as the
    /// endpoint is driven (`next_event` / `poll`), so keep driving after
    /// publishing. Delivery failures are never synchronous errors; they
    /// surface later as [`PubsubEvent::OutboundFailure`] (or
    /// [`Event::Error`] runtime events). There is no self-delivery.
    #[cfg(feature = "pubsub")]
    pub fn publish(&mut self, topic: &str, data: impl Into<Vec<u8>>) -> Result<(), PubsubError> {
        let Some(pubsub) = self.pubsub.as_mut() else {
            return Err(PubsubError::NotEnabled);
        };
        let now_ms = pubsub.now_ms();
        pubsub.agent.publish(topic, data.into(), now_ms)?;
        pubsub.pump(&mut self.swarm);
        Ok(())
    }

    /// Drains all queued pubsub events.
    #[cfg(feature = "pubsub")]
    pub fn take_pubsub_events(&mut self) -> Vec<PubsubEvent> {
        match self.pubsub.as_mut() {
            Some(pubsub) => pubsub.events.drain(..).collect(),
            None => Vec::new(),
        }
    }

    /// Returns the next pubsub event, waiting internally until `deadline`.
    /// Application events arriving meanwhile are buffered for
    /// [`Endpoint::next_event`].
    #[cfg(feature = "pubsub")]
    pub fn next_pubsub_event(
        &mut self,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<PubsubEvent>, PubsubError> {
        let deadline = deadline.into();
        let mut expired_poll_used = false;
        loop {
            match self.pubsub.as_mut() {
                Some(pubsub) => {
                    if let Some(event) = pubsub.events.pop_front() {
                        return Ok(Some(event));
                    }
                }
                None => return Err(PubsubError::NotEnabled),
            }
            self.ensure_pending_event_capacity()?;
            let poll = self.poll_new_event_driven(deadline, &mut expired_poll_used)?;
            match poll.kind {
                DriverPollKind::Application => self
                    .pending_events
                    .push_back(poll.event.expect("application poll carries event")),
                DriverPollKind::Progress => {}
                DriverPollKind::Interrupted => {}
                DriverPollKind::Deadline => return Ok(None),
            }
        }
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
    pub fn discovery_now_ms(&self) -> Option<u64> {
        self.discovery
            .as_ref()
            .map(discovery::DiscoveryDriver::now_ms)
    }

    /// Drains all queued discovery events.
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    pub fn take_discovery_events(&mut self) -> Vec<DiscoveryEvent> {
        self.discovery
            .as_mut()
            .map(|driver| {
                let mut events = Vec::new();
                while let Some(event) = driver.book.poll_event() {
                    events.push(event);
                }
                events
            })
            .unwrap_or_default()
    }

    /// Returns the next discovery event while preserving unrelated swarm events.
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    pub fn next_discovery_event(
        &mut self,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<DiscoveryEvent>, DiscoveryError> {
        let deadline = deadline.into();
        let mut expired_poll_used = false;
        loop {
            match self.discovery.as_mut() {
                Some(discovery) => {
                    if let Some(event) = discovery.book.poll_event() {
                        return Ok(Some(event));
                    }
                }
                None => return Err(DiscoveryError::NotEnabled),
            }
            self.ensure_pending_event_capacity()?;
            let poll = self.poll_new_event_driven(deadline, &mut expired_poll_used)?;
            match poll.kind {
                DriverPollKind::Application => self
                    .pending_events
                    .push_back(poll.event.expect("application poll carries event")),
                DriverPollKind::Progress => {}
                DriverPollKind::Interrupted => {}
                DriverPollKind::Deadline => return Ok(None),
            }
        }
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
        if let (Some(discovery), Some(nat)) = (self.discovery.as_mut(), self.nat.as_mut()) {
            discovery.shutdown(nat, &mut self.swarm);
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
    pub fn close(mut self) -> Result<Vec<Event>, Error> {
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
                Ok(Some(event)) => events.push(event),
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
        let _ = self.disconnect_established();
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
    for (index, byte) in digest.iter().enumerate() {
        seed[index % seed.len()] ^= *byte;
    }
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
        .to_le_bytes();
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte ^= timestamp[index % timestamp.len()];
    }
    seed
}

/// One socket an endpoint is asked to bring up.
///
/// Held as a request rather than a socket so nothing is allocated until the
/// configuration has been validated: a builder that failed after binding would
/// leave a port taken by an endpoint that never existed.
enum Bind {
    #[cfg(feature = "quic")]
    Quic(QuicBind),
    #[cfg(feature = "tcp")]
    Tcp(TcpBind),
}

#[cfg(feature = "quic")]
enum QuicBind {
    Addr(String),
    Multiaddr(Multiaddr),
    DualMultiaddr(Multiaddr, Multiaddr),
    DualStack,
}

#[cfg(feature = "tcp")]
enum TcpBind {
    Addr(String),
    Multiaddr(Multiaddr),
}

/// Builder for [`Endpoint`].
pub struct EndpointBuilder {
    keypair: Option<Ed25519Keypair>,
    agent_version: String,
    #[cfg(feature = "quic")]
    quic_limits: QuicLimits,
    #[cfg(feature = "tcp")]
    tcp_config: TcpConfig,
    binds: Vec<Bind>,
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
    pubsub_config: Option<PubsubConfig>,
    #[cfg(feature = "discovery")]
    discovery_config: Option<BeaconConfig>,
    #[cfg(feature = "mdns")]
    mdns_config: Option<MdnsConfig>,
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    peer_discovery_config: PeerDiscoveryConfig,
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self {
            keypair: None,
            agent_version: DEFAULT_AGENT_VERSION.to_string(),
            #[cfg(feature = "quic")]
            quic_limits: QuicLimits::default(),
            #[cfg(feature = "tcp")]
            tcp_config: TcpConfig::default(),
            binds: Vec::new(),
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
            pubsub_config: None,
            #[cfg(feature = "discovery")]
            discovery_config: None,
            #[cfg(feature = "mdns")]
            mdns_config: None,
            #[cfg(any(feature = "discovery", feature = "mdns"))]
            peer_discovery_config: PeerDiscoveryConfig::default(),
        }
    }
}

/// Validated builder output consumed by the bind step.
struct BuilderParts {
    keypair: Ed25519Keypair,
    agent_version: String,
    #[cfg(feature = "quic")]
    quic_limits: QuicLimits,
    #[cfg(feature = "tcp")]
    tcp_config: TcpConfig,
    binds: Vec<Bind>,
    protocols: Vec<String>,
    #[cfg(feature = "relay-server")]
    relay_server_config: Option<RelayServerConfig>,
    #[cfg(feature = "relay-server")]
    relay_server_announce_addrs: Vec<Multiaddr>,
    #[cfg(feature = "nat")]
    nat_config: Option<NatConfig>,
    #[cfg(feature = "pubsub")]
    pubsub_config: Option<PubsubConfig>,
    #[cfg(feature = "discovery")]
    discovery_config: Option<BeaconConfig>,
    #[cfg(feature = "mdns")]
    mdns_config: Option<MdnsConfig>,
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    peer_discovery_config: PeerDiscoveryConfig,
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

    /// Adds a QUIC socket bound to `bind_addr`, e.g. `"0.0.0.0:4001"`.
    #[cfg(feature = "quic")]
    pub fn quic(mut self, bind_addr: impl Into<String>) -> Self {
        self.binds
            .push(Bind::Quic(QuicBind::Addr(bind_addr.into())));
        self
    }

    /// Adds a QUIC socket bound to a `/ip4|ip6/udp/<port>/quic-v1` multiaddr.
    #[cfg(feature = "quic")]
    pub fn quic_multiaddr(mut self, addr: &Multiaddr) -> Self {
        self.binds
            .push(Bind::Quic(QuicBind::Multiaddr(addr.clone())));
        self
    }

    /// Adds one dual QUIC member bound to exact IPv4 and IPv6 multiaddresses.
    #[cfg(feature = "quic")]
    pub fn quic_dual_multiaddr(mut self, first: &Multiaddr, second: &Multiaddr) -> Self {
        self.binds.push(Bind::Quic(QuicBind::DualMultiaddr(
            first.clone(),
            second.clone(),
        )));
        self
    }

    /// Adds separate IPv4 and IPv6 wildcard QUIC sockets.
    #[cfg(feature = "quic")]
    pub fn quic_dual_stack(mut self) -> Self {
        self.binds.push(Bind::Quic(QuicBind::DualStack));
        self
    }

    /// Adds a TCP listener bound to `bind_addr`, e.g. `"0.0.0.0:4001"`.
    ///
    /// One TCP transport serves `/ip4` and `/ip6` alike, so a host that wants
    /// both listens twice on the one member rather than running two.
    #[cfg(feature = "tcp")]
    pub fn tcp(mut self, bind_addr: impl Into<String>) -> Self {
        self.binds.push(Bind::Tcp(TcpBind::Addr(bind_addr.into())));
        self
    }

    /// Adds a TCP listener bound to a `/ip4|ip6/tcp/<port>` multiaddr.
    #[cfg(feature = "tcp")]
    pub fn tcp_multiaddr(mut self, addr: &Multiaddr) -> Self {
        self.binds.push(Bind::Tcp(TcpBind::Multiaddr(addr.clone())));
        self
    }

    /// Registers an application protocol before the endpoint starts.
    ///
    /// Built-in ids ([`RESERVED_PROTOCOL_IDS`]) are reserved; registering
    /// one makes the `bind_quic*` build step fail with
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
    /// resume admission and [`Endpoint::next_relay_server_event`] to consume
    /// reservation, circuit, accounting, and asynchronous failure events.
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
    /// identity. The indexed [`RelayServerAddressError`] identifies the rejected
    /// input and reason. When identity is not fixed yet, the peer-id match is
    /// checked again at bind. Announce addresses alone do not enable the service;
    /// also call [`EndpointBuilder::relay_server`] or
    /// [`EndpointBuilder::relay_server_config`].
    #[cfg(feature = "relay-server")]
    #[allow(clippy::result_large_err)]
    pub fn relay_server_announce_addrs(
        mut self,
        addrs: Vec<Multiaddr>,
    ) -> Result<Self, RelayServerAddressError> {
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
        )
        .expect("default relay-server configuration is valid");
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
    /// because the selected engine's protocol ids must be in Identify's
    /// advertised set from the first handshake.
    #[cfg(feature = "pubsub")]
    pub fn pubsub(mut self) -> Self {
        self.pubsub_config.get_or_insert_with(PubsubConfig::default);
        self
    }

    /// Enables pubsub with an explicit gossipsub or floodsub configuration.
    ///
    /// [`GossipsubConfig`] and [`FloodsubConfig`] both convert into
    /// [`PubsubConfig`]. The selected engine determines which protocol ids
    /// the endpoint advertises. Invalid gossipsub relationships or zero
    /// bounds fail the later `bind_quic*` call before a socket is allocated.
    #[cfg(feature = "pubsub")]
    pub fn pubsub_config(mut self, config: impl Into<PubsubConfig>) -> Self {
        self.pubsub_config = Some(config.into());
        self
    }

    /// Enables signed pubsub peer discovery with interoperable defaults.
    ///
    /// The discovery topic is driver-owned: subscribing to it again through
    /// [`Endpoint::subscribe`] is redundant, and its pubsub messages and
    /// subscription events are consumed before reaching the application.
    #[cfg(feature = "discovery")]
    pub fn discovery(mut self) -> Self {
        self.pubsub_config.get_or_insert_with(PubsubConfig::default);
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
        self.pubsub_config.get_or_insert_with(PubsubConfig::default);
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
    pub fn bind(self) -> Result<Endpoint, Error> {
        let parts = self.into_parts()?;
        let transport = bind_transports(&parts)?;
        build_endpoint(parts, transport)
    }

    /// Builds an endpoint with a QUIC transport bound to `bind_addr`.
    #[cfg(feature = "quic")]
    pub fn bind_quic(self, bind_addr: impl Into<String>) -> Result<Endpoint, Error> {
        self.quic(bind_addr).bind()
    }

    /// Builds an endpoint with a QUIC transport bound to a QUIC multiaddr.
    #[cfg(feature = "quic")]
    pub fn bind_quic_multiaddr(self, addr: &Multiaddr) -> Result<Endpoint, Error> {
        self.quic_multiaddr(addr).bind()
    }

    /// Builds an endpoint with separate IPv4 and IPv6 wildcard QUIC sockets.
    #[cfg(feature = "quic")]
    pub fn bind_quic_dual_stack(self) -> Result<Endpoint, Error> {
        self.quic_dual_stack().bind()
    }

    /// Builds an endpoint with a TCP transport listening on `bind_addr`.
    #[cfg(feature = "tcp")]
    pub fn bind_tcp(self, bind_addr: impl Into<String>) -> Result<Endpoint, Error> {
        self.tcp(bind_addr).bind()
    }

    /// Validates the static configuration and decomposes the builder.
    ///
    /// Reserved protocol ids are rejected here -- before any socket is
    /// bound -- so a configuration error can neither allocate resources
    /// nor be masked by a bind failure.
    fn into_parts(self) -> Result<BuilderParts, Error> {
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
        if let Some(config) = &self.pubsub_config {
            config
                .validate()
                .map_err(|error| TransportError::InvalidConfig {
                    reason: error.to_string(),
                })?;
        }
        #[cfg(feature = "nat")]
        let nat_config = {
            let enabled = self.nat_config.is_some()
                || !self.relays.is_empty()
                || !self.autonat_servers.is_empty()
                || {
                    #[cfg(feature = "discovery")]
                    {
                        self.discovery_config.is_some()
                    }
                    #[cfg(not(feature = "discovery"))]
                    {
                        false
                    }
                }
                || {
                    #[cfg(feature = "mdns")]
                    {
                        self.mdns_config.is_some()
                    }
                    #[cfg(not(feature = "mdns"))]
                    {
                        false
                    }
                };
            enabled.then(|| {
                let mut config = self.nat_config.unwrap_or_default();
                config.relays.extend(self.relays);
                config.autonat_servers.extend(self.autonat_servers);
                config
            })
        };
        #[cfg(feature = "relay-server")]
        if self.relay_server_config.is_none() && !self.relay_server_announce_addrs.is_empty() {
            return Err(TransportError::InvalidConfig {
                reason: "relay-server announce addresses were configured, but the relay server is not enabled; call EndpointBuilder::relay_server or relay_server_config".into(),
            }
            .into());
        }
        Ok(BuilderParts {
            keypair: self.keypair.unwrap_or_else(Ed25519Keypair::generate),
            agent_version: self.agent_version,
            #[cfg(feature = "quic")]
            quic_limits: self.quic_limits,
            #[cfg(feature = "tcp")]
            tcp_config: self.tcp_config,
            binds: self.binds,
            protocols: self.protocols,
            #[cfg(feature = "relay-server")]
            relay_server_config: self.relay_server_config,
            #[cfg(feature = "relay-server")]
            relay_server_announce_addrs: self.relay_server_announce_addrs,
            #[cfg(feature = "nat")]
            nat_config,
            #[cfg(feature = "pubsub")]
            pubsub_config: self.pubsub_config,
            #[cfg(feature = "discovery")]
            discovery_config: self.discovery_config,
            #[cfg(feature = "mdns")]
            mdns_config: self.mdns_config,
            #[cfg(any(feature = "discovery", feature = "mdns"))]
            peer_discovery_config: self.peer_discovery_config,
        })
    }
}

/// Reads a `host:port` bind spec as the `/tcp` addresses it names.
///
/// The same shape `bind_quic` accepts, so a host does not have to know that one
/// transport speaks socket addresses and the other multiaddrs.
///
/// A name that answers with more than one address gives more than one: a host
/// that asked to be reachable as `localhost` means both families, and listening
/// on whichever the resolver happened to put first would leave half of that
/// silently unserved. One TCP transport holds them all.
#[cfg(feature = "tcp")]
fn tcp_bind_addrs(spec: &str) -> Result<Vec<Multiaddr>, Error> {
    use std::net::ToSocketAddrs;

    let resolved = spec
        .to_socket_addrs()
        .map_err(|error| TransportError::InvalidAddress {
            context: "tcp bind address",
            reason: format!("{spec} is not a bindable address: {error}"),
        })?;
    let addrs = tcp_addrs_of(resolved);
    if addrs.is_empty() {
        return Err(TransportError::InvalidAddress {
            context: "tcp bind address",
            reason: format!("{spec} resolved to no address"),
        }
        .into());
    }
    Ok(addrs)
}

/// The `/tcp` multiaddrs for resolved socket addresses, in order, without
/// repeats.
///
/// Split from resolution so what is kept can be tested without a resolver: no
/// test can make a name answer with two families on demand, and "keeps every
/// answer" is exactly the part that was wrong when it kept only the first.
#[cfg(feature = "tcp")]
fn tcp_addrs_of(resolved: impl IntoIterator<Item = std::net::SocketAddr>) -> Vec<Multiaddr> {
    let mut addrs: Vec<Multiaddr> = Vec::new();
    for addr in resolved {
        let host = match addr.ip() {
            std::net::IpAddr::V4(v4) => Protocol::Ip4(v4.octets()),
            std::net::IpAddr::V6(v6) => Protocol::Ip6(v6.octets()),
        };
        let addr = Multiaddr::from_protocols(vec![host, Protocol::Tcp(addr.port())]);
        // A resolver may answer with the same address twice; binding it twice
        // would fail the second time with the address in use.
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    addrs
}

/// Brings up every requested transport behind one set.
///
/// Each member claims the address shape it serves and the namespaces its
/// allocator stamps -- taken from the transport itself, so a claim cannot
/// drift from what it actually mints. Asking for two of one shape is refused
/// here rather than producing a set that routes by coin toss.
///
/// Every `/tcp` address asked for lands on **one** TCP member, listening on
/// each: a transport claims an address shape rather than an address family, so
/// two of them would be two claims on one shape -- and a host asking for IPv4
/// and IPv6 is asking for two sockets, not two transports.
fn bind_transports(parts: &BuilderParts) -> Result<TransportSet, Error> {
    #[allow(unused_mut)] // No member can be inserted in a std-only feature build.
    let mut set = TransportSet::new();
    #[cfg(feature = "tcp")]
    let mut tcp_bound = false;
    for bind in &parts.binds {
        match bind {
            #[cfg(feature = "quic")]
            Bind::Quic(spec) => {
                let config = QuicNodeConfig::new(parts.keypair.clone())
                    .with_limits(parts.quic_limits.clone());
                let transport = match spec {
                    QuicBind::Addr(addr) => QuicEndpoint::bind(config, addr)?,
                    QuicBind::Multiaddr(addr) => QuicEndpoint::bind_multiaddr(config, addr)?,
                    QuicBind::DualMultiaddr(first, second) => {
                        QuicEndpoint::bind_dual_multiaddr(config, first, second)?
                    }
                    QuicBind::DualStack => QuicEndpoint::dual_stack(config)?,
                };
                let namespaces = transport.namespaces();
                insert_member(&mut set, TransportKind::Quic, namespaces, transport)?;
            }
            // Handled together at the first one, in the position the host put
            // it, so the order addresses are reported in follows the order they
            // were asked for.
            #[cfg(feature = "tcp")]
            Bind::Tcp(_) if tcp_bound => {}
            #[cfg(feature = "tcp")]
            Bind::Tcp(_) => {
                tcp_bound = true;
                let transport = bind_tcp_member(parts)?;
                let namespace = transport.namespace();
                insert_member(&mut set, TransportKind::Tcp, [namespace], transport)?;
            }
            #[cfg(not(any(feature = "quic", feature = "tcp")))]
            _ => unreachable!("Bind has no constructible variants without a transport feature"),
        }
    }
    if set.is_empty() {
        return Err(TransportError::InvalidConfig {
            reason: "an endpoint needs at least one transport to bind".into(),
        }
        .into());
    }
    Ok(set)
}

/// Builds the one TCP transport, listening on every `/tcp` address asked for.
#[cfg(feature = "tcp")]
fn bind_tcp_member(
    parts: &BuilderParts,
) -> Result<TcpTransport<StdTcpProvider, StdEntropy>, Error> {
    // Checked before a socket exists: the namespace is what routes a connection
    // id back to the transport that minted it, so a TCP transport tagged as
    // something else hands out ids that name the wrong carrier -- and would
    // take a claim a QUIC member needs.
    let namespace = parts.tcp_config.namespace;
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
        parts.keypair.clone(),
        StdEntropy::new(),
        parts.tcp_config.clone(),
    );
    for bind in &parts.binds {
        #[cfg(feature = "quic")]
        let spec = match bind {
            Bind::Tcp(spec) => spec,
            Bind::Quic(_) => continue,
        };
        #[cfg(not(feature = "quic"))]
        let Bind::Tcp(spec) = bind;
        match spec {
            TcpBind::Addr(spec) => {
                for addr in tcp_bind_addrs(spec)? {
                    // Bound here, like a QUIC socket is: `Endpoint::listen`
                    // then listens on what is already bound, and a caller that
                    // asked for port 0 learns which port it got before the
                    // first event.
                    transport.listen(&addr)?;
                }
            }
            TcpBind::Multiaddr(addr) => {
                transport.listen(addr)?;
            }
        }
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

fn build_endpoint(parts: BuilderParts, transport: TransportSet) -> Result<Endpoint, Error> {
    let mut builder = SwarmBuilder::new(&parts.keypair).agent_version(parts.agent_version);
    #[cfg(any(feature = "nat", feature = "pubsub"))]
    let mut protocols = parts.protocols;
    #[cfg(not(any(feature = "nat", feature = "pubsub")))]
    let protocols = parts.protocols;
    #[cfg(feature = "nat")]
    if parts.nat_config.is_some() {
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
    if let Some(config) = &parts.pubsub_config {
        // Pubsub streams route as ordinary user protocols, and the selected
        // engine's ids must be advertised by Identify from the first
        // handshake.
        for id in config.protocol_ids() {
            if !protocols.iter().any(|existing| existing == id) {
                protocols.push((*id).to_string());
            }
        }
    }
    for protocol in protocols {
        builder = builder.protocol(protocol);
    }
    #[cfg(feature = "nat")]
    let transport = minip2p_circuit::CircuitTransport::new_os(transport, parts.keypair.clone());
    #[allow(unused_mut)] // Mutated only by feature-gated composed services.
    let mut swarm = builder.build(transport)?;
    #[cfg(feature = "relay-server")]
    if parts.relay_server_config.is_some() {
        swarm.add_inbound_protocol(RELAY_HOP_PROTOCOL_ID)?;
        swarm.add_advertised_protocol(RELAY_HOP_PROTOCOL_ID)?;
        swarm.add_outbound_protocol(RELAY_STOP_PROTOCOL_ID)?;
    }
    #[cfg(feature = "nat")]
    if parts.nat_config.is_some() {
        swarm.add_outbound_protocol(minip2p_nat::HOP_PROTOCOL_ID)?;
        swarm.add_inbound_protocol(minip2p_nat::STOP_PROTOCOL_ID)?;
        swarm.add_advertised_protocol(minip2p_nat::STOP_PROTOCOL_ID)?;
    }
    #[cfg(feature = "nat")]
    let nat = parts.nat_config.map(|config| {
        let relay_addrs = config
            .relays
            .iter()
            .map(|relay| (relay.peer_id().clone(), relay.transport().clone()))
            .collect();
        let agent = minip2p_nat::NatAgent::new(swarm.local_peer_id().clone(), config);
        nat::NatDriver::new(agent, relay_addrs)
    });
    #[cfg(feature = "relay-server")]
    let relay_server = parts
        .relay_server_config
        .map(|config| -> Result<relay_server::RelayServerDriver, Error> {
            let mut agent =
                minip2p_relay_server::RelayServerAgent::new(swarm.local_peer_id().clone(), config)
                    .map_err(|error| TransportError::InvalidConfig {
                        reason: error.to_string(),
                    })?;
            agent
                .replace_announce_addrs(parts.relay_server_announce_addrs)
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
    let discovery_config = parts.discovery_config;
    #[cfg(feature = "mdns")]
    let mdns_config = parts.mdns_config;
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    let peer_discovery_config = parts.peer_discovery_config;
    #[cfg(feature = "pubsub")]
    let pubsub = parts
        .pubsub_config
        .map(|config| -> Result<pubsub::PubsubDriver, Error> {
            // Message ids are (from, seqno); a wall-clock seed keeps restarts
            // from reusing ids the network may still remember. Mix the local
            // identity into the peer-selection seed so endpoints created in the
            // same clock tick do not walk the same deterministic sequence.
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let initial_seqno = timestamp as u64;
            let entropy_seed = parts
                .keypair
                .peer_id()
                .digest_bytes()
                .iter()
                .fold(initial_seqno ^ (timestamp >> 64) as u64, |seed, byte| {
                    seed.rotate_left(5) ^ u64::from(*byte)
                });
            let agent = minip2p_pubsub::PubsubAgent::new(
                parts.keypair.clone(),
                config,
                initial_seqno,
                entropy_seed,
            )
            .map_err(|error| TransportError::InvalidConfig {
                reason: error.to_string(),
            })?;
            Ok(pubsub::PubsubDriver::new(agent))
        })
        .transpose()?;
    #[cfg(feature = "discovery")]
    let mut pubsub = pubsub;
    #[cfg(feature = "discovery")]
    if let (Some(pubsub), Some(config)) = (pubsub.as_mut(), discovery_config.as_ref()) {
        pubsub
            .agent
            .subscribe(&config.topic, 0)
            .map_err(|_| Error::Invariant {
                reason: "validated discovery topic was rejected by pubsub",
            })?;
    }
    #[cfg(feature = "discovery")]
    let beacon = match discovery_config {
        Some(config) => Some(
            minip2p_discovery::BeaconAgent::new(parts.keypair.public_key(), config).map_err(
                |_| Error::Invariant {
                    reason: "validated beacon configuration was rejected",
                },
            )?,
        ),
        None => None,
    };
    #[cfg(feature = "mdns")]
    let mdns = match mdns_config {
        Some(config) => {
            let agent = minip2p_mdns::MdnsAgent::new(
                parts.keypair.peer_id(),
                config.clone(),
                mdns_seed(&parts.keypair),
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
    let discovery = if discovery_enabled {
        let book = minip2p_discovery::PeerDiscoveryAgent::new(
            parts.keypair.peer_id(),
            peer_discovery_config,
        )
        .map_err(|_| Error::Invariant {
            reason: "validated discovery configuration was rejected",
        })?;
        Some(discovery::DiscoveryDriver::new(
            book,
            #[cfg(feature = "discovery")]
            beacon,
        ))
    } else {
        None
    };
    Ok(Endpoint {
        swarm,
        #[cfg(feature = "relay-server")]
        relay_server,
        #[cfg(feature = "nat")]
        nat,
        #[cfg(feature = "pubsub")]
        pubsub,
        #[cfg(any(feature = "discovery", feature = "mdns"))]
        discovery,
        #[cfg(feature = "mdns")]
        mdns,
        #[cfg(any(feature = "nat", feature = "pubsub", feature = "relay-server"))]
        pending_events: std::collections::VecDeque::new(),
        #[cfg(any(feature = "nat", feature = "relay-server"))]
        managed_external_addresses: Vec::new(),
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

#[cfg(all(test, feature = "quic"))]
mod tests {
    use super::*;
    #[cfg(feature = "tcp")]
    use std::sync::Arc;
    #[cfg(feature = "tcp")]
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Drives `endpoint` on a thread until the returned guard is dropped.
    ///
    /// A peer that is not being driven answers nothing, so anything asserting
    /// on a connection needs the other end alive for as long as the assertion
    /// takes.
    #[cfg(feature = "tcp")]
    struct Driven {
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    #[cfg(feature = "tcp")]
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

    #[cfg(feature = "tcp")]
    impl Drop for Driven {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// Drives `endpoint` until an event `wanted` accepts, or gives up.
    ///
    /// A connection produces more than the event a test is waiting for --
    /// identify, ping, readiness -- and an earlier connection keeps producing
    /// them, so taking whatever arrives next is a race rather than an
    /// assertion.
    #[cfg(feature = "tcp")]
    fn wait_for(
        endpoint: &mut Endpoint,
        what: &str,
        mut wanted: impl FnMut(&Event) -> bool,
    ) -> Event {
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

    #[cfg(feature = "tcp")]
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
    fn one_address_shape_cannot_be_bound_twice() {
        // Two members serving one shape would make routing a guess, and a
        // guess delivers a connection's events to the wrong transport.
        let Err(error) = Endpoint::builder()
            .quic("127.0.0.1:0")
            .quic("127.0.0.1:0")
            .bind()
        else {
            panic!("one shape must not have two members");
        };
        assert_eq!(
            format!("{error}"),
            "invalid transport configuration: this set already has a transport \
             for Quic addresses",
            "the refusal should name the shape that was already claimed"
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn a_tcp_endpoint_reports_the_port_it_was_given() {
        let mut endpoint = Endpoint::builder()
            .bind_tcp("127.0.0.1:0")
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
            .quic("127.0.0.1:0")
            .tcp("127.0.0.1:0")
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
            .tcp("127.0.0.1:0")
            .tcp("127.0.0.1:0")
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
            .bind_tcp("127.0.0.1:0")
            .expect("bind dialer");
        dialer.dial(&second).expect("dial the second address");
        wait_for(
            &mut dialer,
            "connection",
            |event| matches!(event, Event::ConnectionEstablished { peer_id, .. } if peer_id == second.peer_id()),
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn listening_arms_every_bound_transport_not_just_the_first() {
        // TCP first, so the transport that still needs arming is the one
        // `listen` does not return. An endpoint that reported success while
        // QUIC accepted nothing would look bound and be unreachable.
        let mut listener = Endpoint::builder()
            .tcp("127.0.0.1:0")
            .quic("127.0.0.1:0")
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
            .bind_quic("127.0.0.1:0")
            .expect("bind dialer");
        dialer.dial(&quic_addr).expect("dial");
        wait_for(
            &mut dialer,
            "connection",
            |event| matches!(event, Event::ConnectionEstablished { peer_id, .. } if peer_id == quic_addr.peer_id()),
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn a_peer_is_reached_over_the_transport_its_address_names() {
        // One peer per transport: the swarm keeps a single connection per
        // peer, so two paths to one host would be the second superseding the
        // first rather than a test of which path each address took.
        let mut over_tcp = Endpoint::builder()
            .bind_tcp("127.0.0.1:0")
            .expect("bind tcp peer");
        let mut over_quic = Endpoint::builder()
            .bind_quic("127.0.0.1:0")
            .expect("bind quic peer");
        let tcp_addr = over_tcp.listen().expect("tcp peer listens");
        let quic_addr = over_quic.listen().expect("quic peer listens");

        let mut dialer = Endpoint::builder()
            .quic("127.0.0.1:0")
            .tcp("127.0.0.1:0")
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
            dialer.dial(addr).expect("dial");
            let event = wait_for(
                &mut dialer,
                "connection",
                |event| matches!(event, Event::ConnectionEstablished { peer_id, .. } if peer_id == addr.peer_id()),
            );
            let Event::ConnectionEstablished { conn_id, .. } = event else {
                unreachable!("the predicate matched a connection")
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
            .bind_tcp("127.0.0.1:0")
            .expect("bind tcp endpoint");
        let target = PeerAddr::new(
            "/ip4/127.0.0.1/tcp/1".parse().expect("address"),
            Ed25519Keypair::generate().peer_id(),
        )
        .expect("target");

        // The id a dial hands back is minted by the transport, so its
        // namespace is what the configuration actually reached -- whether
        // anything answers is beside the point.
        let ids = endpoint.dial(&target).expect("the dial starts");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].namespace(), ConnectionNamespace::TCP_IPV6);
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
            .bind_tcp("127.0.0.1:0")
        else {
            panic!("a tcp transport must not claim another transport's ids");
        };
        assert!(
            format!("{error}").contains("must allocate in a tcp namespace"),
            "got {error}"
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn a_bind_spec_keeps_every_address_it_named() {
        let resolved: Vec<std::net::SocketAddr> = vec![
            "127.0.0.1:4001".parse().expect("v4"),
            "[::1]:4001".parse().expect("v6"),
            "127.0.0.1:4001".parse().expect("v4 again"),
        ];

        // A host that asked to be reachable as a name meant every address that
        // name answers with; listening on whichever the resolver happened to
        // put first would leave the rest silently unserved. Repeats are not
        // extra sockets, though -- binding one twice fails the second time.
        assert_eq!(
            tcp_addrs_of(resolved)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["/ip4/127.0.0.1/tcp/4001", "/ip6/::1/tcp/4001"]
        );
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn a_tcp_multiaddr_binds_and_a_wrong_shape_is_refused() {
        let mut endpoint = Endpoint::builder()
            .tcp_multiaddr(&"/ip4/127.0.0.1/tcp/0".parse().expect("address"))
            .bind()
            .expect("bind by multiaddr");
        let addrs = endpoint.listen_all().expect("listen");
        assert_eq!(
            addrs[0].transport().to_string(),
            format!("/ip4/127.0.0.1/tcp/{}", tcp_port(&addrs[0]))
        );

        // A QUIC address handed to the TCP transport is a mistake worth
        // reporting, not a socket worth guessing at.
        let Err(error) = Endpoint::builder()
            .tcp_multiaddr(&"/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("address"))
            .bind()
        else {
            panic!("a /udp address is not a tcp bind address");
        };
        assert!(
            matches!(&error, Error::Transport(TransportError::InvalidAddress { reason, .. })
                if reason.contains("not a /tcp transport address")),
            "got {error:?}"
        );
    }

    #[test]
    fn an_address_no_bound_transport_serves_is_refused_by_name() {
        let mut endpoint = Endpoint::builder()
            .bind_quic("127.0.0.1:0")
            .expect("bind loopback endpoint");
        let target = PeerAddr::new(
            "/ip4/127.0.0.1/tcp/4001".parse().expect("address"),
            Ed25519Keypair::generate().peer_id(),
        )
        .expect("target");

        // A QUIC-only endpoint has no business guessing a transport for a
        // /tcp address, and the error has to say which is missing rather than
        // read as "that host refused you".
        let error = endpoint
            .dial(&target)
            .expect_err("nothing serves /tcp here");
        assert!(
            format!("{error}").contains("Tcp"),
            "the error should name the missing transport, got {error}"
        );
    }

    #[test]
    fn a_dial_reaches_a_peer_on_the_transport_its_address_names() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut listener = Endpoint::builder()
            .bind_quic("127.0.0.1:0")
            .expect("bind listener");
        let listen_addr = listener.listen().expect("listen");
        let mut dialer = Endpoint::builder()
            .bind_quic("127.0.0.1:0")
            .expect("bind dialer");

        let stop = Arc::new(AtomicBool::new(false));
        let listener_stop = Arc::clone(&stop);
        let listener_thread = std::thread::spawn(move || {
            while !listener_stop.load(Ordering::Relaxed) {
                listener
                    .next_event(Duration::from_millis(20))
                    .expect("drive listener");
            }
        });

        // Routing the dial through a set, and resolving families above it,
        // must leave an ordinary dial doing exactly what it did.
        let ids = dialer.dial(&listen_addr).expect("dial");
        assert_eq!(ids.len(), 1, "one address, one dial: {ids:?}");
        let connected = dialer
            .next_event(Duration::from_secs(5))
            .expect("drive dialer");
        stop.store(true, Ordering::Relaxed);
        listener_thread.join().expect("listener driver exits");

        assert!(
            matches!(&connected, Some(Event::ConnectionEstablished { peer_id, .. })
                if peer_id == listen_addr.peer_id()),
            "got {connected:?}"
        );
    }

    #[test]
    fn next_wake_reports_deadline_without_active_drivers() {
        let mut endpoint = Endpoint::builder()
            .bind_quic("127.0.0.1:0")
            .expect("bind loopback endpoint");

        assert!(matches!(
            endpoint.next_wake(Duration::ZERO).expect("poll endpoint"),
            EndpointWake::Deadline
        ));
    }

    #[test]
    fn next_wake_reports_interrupt_without_active_drivers() {
        let mut endpoint = Endpoint::builder()
            .bind_quic("127.0.0.1:0")
            .expect("bind loopback endpoint");
        endpoint.wait_handle().interrupt();

        assert!(matches!(
            endpoint.next_wake(Deadline::NEVER).expect("poll endpoint"),
            EndpointWake::Interrupted
        ));
    }

    #[cfg(feature = "nat")]
    #[test]
    fn next_wake_transfers_buffered_application_event_ownership() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .bind_quic("127.0.0.1:0")
            .expect("bind NAT endpoint");
        let peer_id = Ed25519Keypair::generate().peer_id();
        endpoint.pending_events.push_back(Event::ConnectionClosed {
            peer_id: peer_id.clone(),
            conn_id: ConnectionId::new(7),
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        });

        assert!(matches!(
            endpoint.next_wake(Deadline::NEVER).expect("wake"),
            EndpointWake::Event(Event::ConnectionClosed {
                peer_id: returned,
                ..
            }) if returned == peer_id
        ));
        assert!(endpoint.pending_events.is_empty());
    }

    #[cfg(feature = "nat")]
    #[test]
    fn next_wake_reports_already_queued_driver_progress_without_consuming_it() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .bind_quic("127.0.0.1:0")
            .expect("bind NAT endpoint");
        endpoint
            .connect(&Ed25519Keypair::generate().peer_id())
            .expect("start endpoint-local connect");

        assert!(matches!(
            endpoint.next_wake(Deadline::NEVER).expect("wake"),
            EndpointWake::DriverProgress
        ));
        assert_eq!(endpoint.take_nat_events().len(), 1);
    }

    #[cfg(feature = "pubsub")]
    #[test]
    fn next_wake_reports_queued_pubsub_progress_without_consuming_it() {
        let mut endpoint = Endpoint::builder()
            .pubsub()
            .bind_quic("127.0.0.1:0")
            .expect("bind pubsub endpoint");
        let peer = Ed25519Keypair::generate().peer_id();
        endpoint
            .pubsub
            .as_mut()
            .expect("pubsub configured")
            .events
            .push_back(PubsubEvent::PeerSubscribed {
                peer: peer.clone(),
                topic: "test".into(),
            });

        assert!(matches!(
            endpoint.next_wake(Deadline::NEVER).expect("wake"),
            EndpointWake::DriverProgress
        ));
        assert!(matches!(
            endpoint.take_pubsub_events().as_slice(),
            [PubsubEvent::PeerSubscribed {
                peer: returned,
                topic
            }] if returned == &peer && topic == "test"
        ));
    }

    #[cfg(feature = "nat")]
    #[test]
    fn next_wake_honors_expired_deadline_with_active_driver() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .bind_quic("127.0.0.1:0")
            .expect("bind NAT endpoint");

        assert!(matches!(
            endpoint.next_wake(Duration::ZERO).expect("expired wake"),
            EndpointWake::Deadline
        ));
    }

    #[cfg(feature = "nat")]
    #[test]
    fn next_wake_returns_application_event_produced_during_driver_poll() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .bind_quic("127.0.0.1:0")
            .expect("bind driven endpoint");
        let mut remote = Endpoint::builder()
            .bind_quic("127.0.0.1:0")
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

        endpoint.dial(&remote_addr).expect("dial remote");
        let wake = endpoint
            .next_wake(Duration::from_secs(5))
            .expect("wait for application event");
        stop.store(true, Ordering::Relaxed);
        remote_thread.join().expect("remote driver exits");

        assert!(matches!(
            wake,
            EndpointWake::Event(Event::ConnectionEstablished { peer_id, .. })
                if peer_id == *remote_addr.peer_id()
        ));
    }

    #[cfg(feature = "nat")]
    #[test]
    fn next_wake_returns_driver_progress_produced_by_timer_during_poll() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig {
                connect_deadline_ms: 20,
                ..NatConfig::default()
            })
            .bind_quic("127.0.0.1:0")
            .expect("bind NAT endpoint");
        let unreachable = PeerAddr::quic_v1(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            9,
            Ed25519Keypair::generate().peer_id(),
        );
        endpoint
            .connect_addr(&unreachable)
            .expect("start timed connect");
        assert!(endpoint.take_nat_events().is_empty());

        assert!(matches!(
            endpoint
                .next_wake(Duration::from_secs(1))
                .expect("wait for connect deadline"),
            EndpointWake::DriverProgress
        ));
        assert!(matches!(
            endpoint.take_nat_events().as_slice(),
            [NatEvent::ConnectFailed { .. }]
        ));
    }

    #[cfg(any(feature = "discovery", feature = "mdns"))]
    #[test]
    fn discovery_clock_is_present_only_for_an_active_source() {
        let inactive = Endpoint::builder()
            .bind_quic("127.0.0.1:0")
            .expect("bind plain endpoint");
        assert_eq!(inactive.discovery_now_ms(), None);

        let builder = Endpoint::builder();
        #[cfg(feature = "discovery")]
        let builder = builder.discovery();
        #[cfg(all(feature = "mdns", not(feature = "discovery")))]
        let builder = builder.mdns();
        let active = builder
            .bind_quic("127.0.0.1:0")
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
            .bind_quic("127.0.0.1:0")
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
            .bind_quic("127.0.0.1:0")
            .expect("bind discovery endpoint");

        assert!(matches!(
            endpoint.unsubscribe(topic),
            Err(PubsubError::DiscoveryTopicReserved)
        ));
    }

    #[cfg(feature = "discovery")]
    #[test]
    fn discovery_focused_waits_preserve_events_and_enforce_the_spin_guard() {
        let mut endpoint = Endpoint::builder()
            .discovery()
            .bind_quic("127.0.0.1:0")
            .expect("bind discovery endpoint");
        let unrelated = Ed25519Keypair::generate().peer_id();

        endpoint.pending_events.push_back(Event::ConnectionClosed {
            peer_id: unrelated.clone(),
            conn_id: ConnectionId::new(1),
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        });
        assert!(
            endpoint
                .next_discovery_event(Duration::from_millis(5))
                .expect("discovery wait")
                .is_none(),
            "a buffered application event must not make next_discovery_event spin"
        );
        assert!(matches!(
            endpoint
                .next_event(Duration::from_millis(1))
                .expect("drain buffered event"),
            Some(Event::ConnectionClosed { peer_id, .. }) if peer_id == unrelated
        ));

        for _ in 0..RUN_UNTIL_SKIP_LIMIT {
            endpoint.pending_events.push_back(Event::ConnectionClosed {
                peer_id: unrelated.clone(),
                conn_id: ConnectionId::new(1),
                cause: minip2p_swarm::ConnectionCloseCause::Transport,
            });
        }
        assert!(matches!(
            endpoint.next_discovery_event(Deadline::NEVER),
            Err(DiscoveryError::Driver(Error::EventBacklogExceeded { limit }))
                if limit == RUN_UNTIL_SKIP_LIMIT
        ));
    }
    use std::time::Duration;

    const PROTOCOL: &str = "/myapp/1.0.0";

    #[test]
    fn builder_protocol_registers_for_stream_routing() {
        let mut endpoint = Endpoint::builder()
            .protocol(PROTOCOL)
            .bind_quic("127.0.0.1:0")
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
                .bind_quic("127.0.0.1:0")
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
            .bind_quic("not-a-bindable-address")
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
            .bind_quic("127.0.0.1:0")
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

    #[cfg(feature = "nat")]
    #[test]
    fn nat_focused_waits_do_not_repoll_buffered_application_events() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .bind_quic("127.0.0.1:0")
            .expect("bind endpoint");
        let unrelated = Ed25519Keypair::generate().peer_id();

        endpoint.pending_events.push_back(Event::ConnectionClosed {
            peer_id: unrelated.clone(),
            conn_id: ConnectionId::new(1),
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        });
        assert!(
            endpoint
                .next_nat_event(Duration::from_millis(5))
                .expect("NAT wait")
                .is_none(),
            "a buffered application event must not make next_nat_event spin"
        );
        assert!(matches!(
            endpoint
                .next_event(Duration::from_millis(1))
                .expect("drain buffered event"),
            Some(Event::ConnectionClosed { peer_id, .. }) if peer_id == unrelated
        ));

        let id = endpoint
            .connect(&Ed25519Keypair::generate().peer_id())
            .expect("connect");
        // This no-candidate attempt fails synchronously. Remove the failure
        // to exercise the timeout path with a live ConnectId.
        endpoint
            .nat
            .as_mut()
            .expect("NAT configured")
            .events
            .clear();
        endpoint.pending_events.push_back(Event::ConnectionClosed {
            peer_id: unrelated.clone(),
            conn_id: ConnectionId::new(1),
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        });
        assert!(
            endpoint
                .wait_path(id, Duration::from_millis(5))
                .expect("path wait")
                .is_none(),
            "a buffered application event must not make wait_path spin"
        );
        assert!(matches!(
            endpoint
                .next_event(Duration::from_millis(1))
                .expect("drain buffered event"),
            Some(Event::ConnectionClosed { peer_id, .. }) if peer_id == unrelated
        ));

        for _ in 0..RUN_UNTIL_SKIP_LIMIT {
            endpoint.pending_events.push_back(Event::ConnectionClosed {
                peer_id: unrelated.clone(),
                conn_id: ConnectionId::new(1),
                cause: minip2p_swarm::ConnectionCloseCause::Transport,
            });
        }
        assert!(matches!(
            endpoint.next_nat_event(Deadline::NEVER),
            Err(Error::EventBacklogExceeded { limit }) if limit == RUN_UNTIL_SKIP_LIMIT
        ));
    }

    #[cfg(feature = "pubsub")]
    #[test]
    fn pubsub_focused_waits_do_not_repoll_buffered_application_events() {
        let mut endpoint = Endpoint::builder()
            .pubsub()
            .bind_quic("127.0.0.1:0")
            .expect("bind endpoint");
        let unrelated = Ed25519Keypair::generate().peer_id();

        endpoint.pending_events.push_back(Event::ConnectionClosed {
            peer_id: unrelated.clone(),
            conn_id: ConnectionId::new(1),
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        });
        assert!(
            endpoint
                .next_pubsub_event(Duration::ZERO)
                .expect("pubsub wait")
                .is_none(),
            "a buffered application event must not make next_pubsub_event spin"
        );
        assert!(matches!(
            endpoint
                .next_event(Duration::ZERO)
                .expect("drain buffered event"),
            Some(Event::ConnectionClosed { peer_id, .. }) if peer_id == unrelated
        ));

        for _ in 0..RUN_UNTIL_SKIP_LIMIT {
            endpoint.pending_events.push_back(Event::ConnectionClosed {
                peer_id: unrelated.clone(),
                conn_id: ConnectionId::new(1),
                cause: minip2p_swarm::ConnectionCloseCause::Transport,
            });
        }
        assert!(matches!(
            endpoint.next_pubsub_event(Deadline::NEVER),
            Err(PubsubError::Driver(Error::EventBacklogExceeded { limit }))
                if limit == RUN_UNTIL_SKIP_LIMIT
        ));
    }

    #[cfg(all(feature = "relay-server", feature = "tcp"))]
    #[test]
    fn relay_server_builder_is_order_independent_and_announce_does_not_enable() {
        let announce = vec!["/ip4/127.0.0.1/tcp/4001".parse().unwrap()];
        let endpoint = Endpoint::builder()
            .relay_server_announce_addrs(announce.clone())
            .expect("valid announce address")
            .relay_server()
            .bind_tcp("127.0.0.1:0")
            .expect("enabled relay server binds");
        assert!(endpoint.relay_server.is_some());

        let result = Endpoint::builder()
            .relay_server_announce_addrs(announce)
            .expect("valid announce address")
            .bind_tcp("127.0.0.1:0");
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
            Err(error) => error,
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
            Err(error) => error,
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
            .bind_quic("127.0.0.1:0")
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
            .bind_quic("127.0.0.1:0")
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
            .bind_quic("0.0.0.0:0")
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
    fn relay_focused_wait_preserves_unrelated_events_and_reports_queue_progress() {
        let mut endpoint = Endpoint::builder()
            .relay_server()
            .bind_quic("127.0.0.1:0")
            .expect("bind relay server");
        let unrelated = Ed25519Keypair::generate().peer_id();
        endpoint.pending_events.push_back(Event::ConnectionClosed {
            peer_id: unrelated.clone(),
            conn_id: ConnectionId::new(1),
            cause: minip2p_swarm::ConnectionCloseCause::Transport,
        });
        assert!(
            endpoint
                .next_relay_server_event(Duration::ZERO)
                .expect("focused wait")
                .is_none()
        );
        assert!(matches!(
            endpoint.next_event(Duration::ZERO).expect("buffered event"),
            Some(Event::ConnectionClosed { peer_id, .. }) if peer_id == unrelated
        ));

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
            endpoint.next_wake(Duration::ZERO).expect("queue wake"),
            EndpointWake::DriverProgress
        ));
        assert_eq!(endpoint.take_relay_server_events().len(), 1);
    }

    #[cfg(all(feature = "nat", feature = "relay-server"))]
    #[test]
    fn nat_and_relay_address_contributions_form_a_stable_first_wins_union() {
        let mut endpoint = Endpoint::builder()
            .nat_config(NatConfig::default())
            .relay_server()
            .bind_quic("127.0.0.1:0")
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
            .bind_quic("127.0.0.1:0")
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
}
