//! Application-facing `Endpoint` API for minip2p.
//!
//! This is the ergonomic std entrypoint. It composes the lower-level crates
//! without hiding them: protocol crates and `SwarmCore` remain the Sans-I/O /
//! `no_std + alloc` surface, while [`Endpoint`] gives applications a small
//! batteries-included API for identity, transports, listen/dial, ping, and
//! event polling. It runs the same private engine as the portable endpoint
//! and adds what only an operating system has: a clock, socket binding, Name
//! resolution, and a blocking [`Endpoint::wait`].
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
//! The `autonat` feature exposes AutoNAT probing, and `relay` (which
//! includes `autonat`) adds relay paths, reservations, and, with QUIC,
//! DCUtR coordination. The `discovery` feature includes `pubsub`, adding
//! signed presence beacons plus a bounded peer book. The `mdns` feature adds
//! caller-driven local-link multicast discovery over the same book. Enable
//! both discovery sources to feed one shared peer book and automatic-dial
//! state; with `autonat` or `relay` built too, discovered peers are dialed
//! through the NAT connect race. Cargo features expose these APIs; the
//! corresponding builder methods activate their drivers.
//!
//! The `relay-server` feature enables the three-line
//! `Endpoint::builder().relay_server().listen_on(…)?.bind()` hosting path.
//!
//! Capabilities are validated, registered and installed by the same
//! Endpoint setup as the portable endpoint's; this module adds only OS
//! resources around it: the clock, the readiness poll, the mDNS sockets,
//! Name resolution, and WebTransport certificates. A capability's protocols
//! are advertised through Identify only when its configuration uses them:
//! relay-only endpoints advertise inbound HOP, a relay client advertises
//! STOP (and DCUtR with QUIC), and an AutoNAT client the AutoNAT protocol.

mod bind_error;
mod dial;
#[cfg(all(test, feature = "relay", feature = "quic"))]
mod nat_tests;
#[cfg(all(test, feature = "relay", feature = "quic"))]
mod punch_batch_tests;

pub use bind_error::{BindError, EndpointOptionsError, IpFamily};

use std::time::Duration;

#[cfg(feature = "discovery")]
use crate::BeaconConfig;
#[cfg(feature = "relay")]
use crate::CircuitLimits;
#[cfg(feature = "pubsub")]
use crate::GossipsubConfig;
#[cfg(feature = "pubsub")]
use crate::GossipsubError;
#[cfg(feature = "relay")]
use crate::ReservationInfo;
#[cfg(feature = "autonat")]
use crate::connect::Expansion;
use crate::engine::Engine;
#[cfg(feature = "relay")]
use crate::nat::CircuitOps;
use crate::setup::{self, Capabilities, Platform};
use crate::{ConnectionInfo, Path};
#[cfg(any(feature = "discovery", feature = "mdns"))]
use crate::{KnownPeer, PeerDiscoveryConfig};
#[cfg(feature = "mdns")]
use crate::{MdnsConfig, MdnsError};
#[cfg(feature = "autonat")]
use crate::{NatConfig, ReachabilityState};
#[cfg(feature = "relay-server")]
use crate::{
    RelayServerAddressError, RelayServerAddressErrorKind, RelayServerConfig,
    RelayServerConfigError, RelayServerControlError,
};
use minip2p_core::Multiaddr;
#[cfg(any(feature = "quic", feature = "tcp", feature = "relay-server"))]
use minip2p_core::Protocol;
#[cfg(any(feature = "quic", feature = "tcp"))]
use minip2p_core::TransportKind;
use minip2p_core::platform::{Clock, Now, StdClock, StdEntropy};
use minip2p_core::{PeerAddr, PeerId};
pub use minip2p_identify::IdentifyMessage;
pub use minip2p_identity::Ed25519Keypair;
#[cfg(feature = "quic")]
pub use minip2p_quic::{QuicBindError, QuicLimits};
#[cfg(feature = "quic")]
use minip2p_quic::{QuicNodeConfig, QuicTransport, WebTransportCertificates};
use minip2p_swarm::SwarmBuilder;
pub use minip2p_swarm::{
    DriverError as Error, PollNext, RESERVED_PROTOCOL_IDS, Swarm, SwarmError, WaitDeadline,
};
#[cfg(feature = "tcp")]
use minip2p_tcp::{StdTcpProvider, TcpConfig, TcpTransport};
#[cfg(any(feature = "quic", feature = "tcp"))]
use minip2p_transport::ConnectionNamespace;
pub use minip2p_transport::{ConnectionId, StreamId, TransportError, TransportSet, WaitHandle};
use minip2p_transport::{SharedPoll, Transport};
#[cfg(any(feature = "quic", feature = "tcp"))]
use std::str::FromStr;

use crate::portable::{DEFAULT_CONNECT_DEADLINE_MS, StreamAcks};
use crate::{Bytes, ConnectId, ConnectTarget, ConnectTargetError, EndpointEvent};

/// Cap on one readiness wait when the caller has no deadline; re-arming it
/// occasionally keeps unbounded durations out of OS interfaces.
const MAX_IDLE_WAIT: Duration = Duration::from_secs(60);

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
// Non-exhaustive, so a later outcome is not a breaking change: match
// `Event` and `Deadline`, and treat the rest (today, `Interrupted`) with `_`.
#[non_exhaustive]
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

/// Why [`Endpoint::set_webtransport_certificate_pem`] kept the current
/// certificate.
#[cfg(feature = "quic")]
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum SetWebTransportCertificateError {
    /// The endpoint serves no CA-signed WebTransport certificate to replace.
    #[error(
        "this endpoint serves no CA-signed WebTransport certificate; bind it with \
         EndpointBuilder::webtransport_certificate_pem and a /quic-v1/webtransport listen address"
    )]
    NotConfigured,
    /// The PEM is unusable: no certificate, no private key, more than one
    /// key, or a malformed section.
    #[error("WebTransport certificate PEM: {problem}")]
    Pem {
        /// What is wrong with it.
        problem: String,
    },
    /// The certificate can't be served: the key does not match the leaf, or
    /// the leaf has expired by the host clock.
    #[error("WebTransport certificate: {reason}")]
    Invalid {
        /// Why, as bind would report it.
        reason: String,
    },
}

/// Transport used by [`Endpoint`]. With relays built, relay bridges are
/// promoted into ordinary Noise/Yamux connections by `CircuitTransport`.
///
/// The endpoint always holds a [`TransportSet`], even with one member in it:
/// what an address is dialed over is then a routing decision the set makes
/// from the address itself, and adding a second transport changes nothing
/// above this line.
#[cfg(feature = "relay")]
pub(crate) type EndpointTransport =
    minip2p_circuit::CircuitTransport<TransportSet, minip2p_core::platform::StdEntropy>;

/// Transport used by [`Endpoint`] when relays are not compiled in.
#[cfg(not(feature = "relay"))]
pub(crate) type EndpointTransport = TransportSet;

/// The std endpoint's mDNS carrier: OS multicast sockets, which are `Send`
/// (the ffi-core detached driver needs that).
#[cfg(feature = "mdns")]
type StdCarrier = minip2p_mdns::MdnsSockets;
#[cfg(not(feature = "mdns"))]
type StdCarrier = ();

/// The engine the std [`Endpoint`] drives.
type StdEngine = Engine<EndpointTransport, StdEntropy, StdCarrier>;

/// What the std endpoint offers its capabilities: DCUtR with QUIC, circuit
/// operations whenever relays are built (the transport set is wrapped in a
/// `CircuitTransport`), and OS mDNS sockets apart from the transport.
const STD_PLATFORM: Platform = Platform {
    runs_dcutr: cfg!(feature = "quic"),
    has_circuits: cfg!(feature = "relay"),
    mdns_shares_transport: false,
};

/// What [`Endpoint::close_within`] collected: how the drain ended, what it
/// left unfinished, every event, in order, and every error close's own calls
/// hit, in order.
///
/// A failure the swarm reports as it happens (a transport refusing to close
/// a connection, say) arrives as [`EndpointEvent::Error`] in `events`, as it
/// would from [`Endpoint::wait`]; a clean close has no such event either.
#[derive(Debug)]
#[must_use = "a close report carries the close's events and errors"]
#[non_exhaustive]
pub struct CloseReport {
    /// How the drain ended.
    pub outcome: CloseOutcome,
    /// Connections still tracked when the drain ended, pending dials
    /// included, with their peer when known (an inbound handshake may not
    /// have identified one yet). Empty
    /// means no tracked teardown remains, not that peers acknowledged it.
    pub unfinished: Vec<(ConnectionId, Option<PeerId>)>,
    /// Events queued before the close and those its drain produced.
    pub events: Vec<EndpointEvent>,
    /// Every transport or swarm failure: each disconnect, and a failed
    /// drain. An mDNS goodbye that could not be sent is an
    /// [`EndpointEvent::MdnsFailed`] in `events` instead.
    pub errors: Vec<Error>,
}

/// How long [`Endpoint::close`] waits for connections to finish their
/// teardown. Bindings default their stop and close drains to it too.
pub const DEFAULT_CLOSE_TIMEOUT: Duration = Duration::from_millis(500);

/// How [`Endpoint::close_within`]'s drain ended. None of these is an
/// [`Error`]: the endpoint is gone either way.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseOutcome {
    /// Every tracked connection finished its teardown in time.
    Drained,
    /// The deadline passed with connections still tracked; they are listed
    /// in [`CloseReport::unfinished`] and are torn down without waiting.
    DeadlineExpired,
    /// Driving the transports failed, which ended the drain early; the
    /// failure is the last of [`CloseReport::errors`]. A failed disconnect
    /// alone does not end the drain.
    Failed,
}

/// App-facing minip2p endpoint over the transports it was asked to bind.
///
/// `Endpoint` owns identity, transports, a clock, and the same engine as
/// [`crate::PortableEndpoint`]. It has one Connection-attempt entry point,
/// [`connect`](Self::connect), and one ordered Endpoint event stream, read
/// with [`wait`](Self::wait) (blocking) or [`poll`](Self::poll)
/// (non-blocking). Every enabled capability (NAT, Gossipsub, Discovery,
/// relay-server) delivers its output once, as an [`EndpointEvent`] variant
/// on that stream, in the per-batch order documented there.
///
/// Applications correlate events by the IDs they carry (a [`ConnectId`], a
/// [`ConnectionId`], a [`StreamId`]) and dispatch unrelated events while they
/// wait for a particular one; see [`wait`](Self::wait) for the canonical loop.
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
///
/// QUIC, TCP, or both, chosen by the addresses passed to
/// [`EndpointBuilder::listen_on`]. They live behind one [`TransportSet`],
/// which routes each address to the transport that serves its shape, so
/// nothing here or above changes with the second one: [`connect`](Self::connect)
/// takes the same complete peer addresses, [`listen`](Self::listen) arms every
/// bound address, and the events are the same events.
///
/// With the `relay` cargo feature and a relay configuration
/// (`EndpointBuilder::relay` / `EndpointBuilder::nat_config`), `connect`
/// races direct candidates against a relay leg. Path transitions arrive as
/// `EndpointEvent::Nat`; the attempt's outcome is its
/// [`EndpointEvent::ConnectSettled`].
///
/// [`close`](Self::close) or drop disconnects established peers so a listener
/// is not left on the QUIC idle timeout. Neither path helps after `kill -9`
/// or a hard partition.
pub struct Endpoint {
    pub(crate) engine: StdEngine,
    clock: StdClock,
    /// Name resolution for `/dns*` candidates, off the driver thread.
    resolver: dial::Resolver,
    /// NAT relay and AutoNAT dials waiting on Name resolution.
    #[cfg(feature = "autonat")]
    nat_dials: Vec<(minip2p_nat::NatToken, PeerAddr)>,
    /// Whether WebTransport presents a CA-signed certificate, which decides
    /// whether a WebTransport announce address must carry a `/certhash`.
    #[cfg(feature = "relay-server")]
    ca_webtransport_certificate: bool,
    /// Replaces the CA-signed WebTransport certificate; `None` unless one
    /// was configured and a WebTransport listener serves it.
    #[cfg(feature = "quic")]
    webtransport_certificate: Option<minip2p_quic::WebTransportCertificateHandle>,
    /// The one readiness poll the transport and mDNS sockets are registered
    /// with (ADR 0013). Its `Waker` carries caller interrupts and the
    /// endpoint's own wakeups (a finished name lookup) apart.
    poll: SharedPoll,
    /// Swarm events a test's raw poll read but has not handed out yet.
    #[cfg(all(test, feature = "quic"))]
    raw_events: std::collections::VecDeque<crate::SwarmEvent>,
}

// The ffi-core detached driver moves the endpoint onto its own thread.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<Endpoint>();
};

impl Endpoint {
    /// Starts portable endpoint configuration with explicit identity and entropy.
    ///
    /// This constructs the same caller-driven, transport-generic endpoint as
    /// a `no_std` build; the std [`Endpoint::builder`] remains unchanged.
    pub fn portable<E: minip2p_core::platform::EntropySource>(
        identity: &Ed25519Keypair,
        entropy: E,
    ) -> crate::PortableEndpointBuilder<E> {
        crate::PortableEndpointBuilder::new(identity, entropy)
    }

    /// Returns a cloneable handle that can interrupt a blocking endpoint wait
    /// from another thread.
    ///
    /// The interrupt handle of the one readiness poll every transport and
    /// mDNS socket is registered with. Its interrupts surface as
    /// [`EndpointWaitOutcome::Interrupted`]; interrupts sent before one is
    /// reported coalesce into one. The endpoint's own wakeups (a finished
    /// name lookup, mDNS input) use the poll's wake-only handle and never do.
    pub fn wait_handle(&self) -> WaitHandle {
        self.poll.wait_handle()
    }

    /// Starts building an endpoint.
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::default()
    }

    /// Samples the endpoint's clock; every engine call takes one sample.
    pub(crate) fn now(&mut self) -> Now {
        self.clock.now()
    }

    /// Returns this node's peer id.
    pub fn peer_id(&self) -> &PeerId {
        self.engine.core.local_peer_id()
    }

    /// Returns the first listen address.
    ///
    /// [`EndpointBuilder::bind`] already listens on every bound address, so
    /// this only reports; calling it again is harmless. Use
    /// [`listen_all`](Self::listen_all) to see them all.
    pub fn listen(&mut self) -> Result<PeerAddr, Error> {
        let mut addrs = self.listen_all()?;
        // `listen_all` fails rather than return nothing, so there is one here.
        addrs.drain(..).next().ok_or(Error::Invariant {
            reason: "a successful listen reported no address",
        })
    }

    /// Returns every listen address, as complete peer addresses.
    ///
    /// [`EndpointBuilder::bind`] already started listening on them; this
    /// re-confirms each with its transport, which is a no-op for an address
    /// already listening.
    pub fn listen_all(&mut self) -> Result<Vec<PeerAddr>, Error> {
        self.engine.core.listen_on_bound_addrs()
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
    /// Every `/ip4` and `/ip6` candidate is dialed immediately, and the relay
    /// leg (when there is one) starts at once. Candidate completion order is
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
    /// Candidates may name the IP family explicitly (`/ip4`, `/ip6`) or a
    /// host (`/dns`, `/dns4`, `/dns6`). This call never blocks on DNS: a
    /// name is looked up on a background thread and joins the race when it
    /// answers, dialed once per family it answers with (`/dns4` and `/dns6`
    /// keep to their family). A failed lookup is a failed candidate whose
    /// reason names the host; the attempt fails only when every candidate,
    /// including names still resolving, has failed and no relay leg remains.
    /// There is no separate DNS timeout: the attempt deadline covers the
    /// lookup. Under `force_relay` names are not looked up at all.
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
    ) -> Result<ConnectId, ConnectTargetError> {
        let target = target.try_into().map_err(Into::into)?;
        let now = self.now();
        let resolver = &mut self.resolver;
        Ok(self
            .engine
            .connect(target, &mut |addr| resolver.expand(addr), now))
    }

    /// Idempotent. Settled or unknown ids are a no-op. Never disconnects.
    pub fn cancel_connect(&mut self, id: ConnectId) {
        let now = self.now();
        self.engine.cancel_connect(id, now);
    }

    /// Sends a ping to `peer_id`.
    ///
    /// The RTT is emitted later as [`EndpointEvent::PingRttMeasured`].
    pub fn ping(&mut self, peer_id: &PeerId) -> Result<(), Error> {
        let now = self.now();
        self.engine.core.ping(peer_id, now.monotonic_ms)
    }

    /// Closes the active connection to `peer_id`, aborting any dials still
    /// kept open for its simultaneous dial so none of them reconnects it.
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), Error> {
        let now = self.now();
        self.engine.disconnect(peer_id, now)
    }

    /// Returns the [`Path`] of `peer_id`'s established connection; `None`
    /// only while the peer is not connected.
    ///
    /// See [`Self::connection_info`] and
    /// [State snapshots](Self#state-snapshots).
    pub fn path(&self, peer_id: &PeerId) -> Option<Path> {
        self.engine.path(peer_id)
    }

    /// Returns a snapshot of the established connection `conn_id`: its peer,
    /// remote address, [`Path`], and Identify protocols once ready.
    ///
    /// `None` for a pending, replaced, or closed connection. A connection's
    /// path is [`Path::Relayed`] for a circuit, [`Path::Direct`] for a direct
    /// connection we dialed or accepted, or [`Path::Punched`] once NAT
    /// reports its hole punch produced it (before the event announcing the
    /// punch is queued). On [`EndpointEvent::ConnectionReplaced`] the new
    /// connection has its own path; nothing carries over.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connection_info(&self, conn_id: ConnectionId) -> Option<ConnectionInfo> {
        self.engine.connection_info(conn_id)
    }

    /// Returns peers with an established connection.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.engine.core.connected_peers()
    }

    /// Returns whether Identify has completed for `peer_id`.
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.engine.core.is_peer_ready(peer_id)
    }

    /// Returns the peer's current connection and its Identify info once that
    /// connection is ready, as one coherent snapshot.
    ///
    /// Readiness belongs to a connection: after
    /// [`EndpointEvent::ConnectionReplaced`] this is `None` until the new
    /// connection's [`EndpointEvent::PeerReady`]. A ready wait checks this
    /// first, then accepts only a `PeerReady` for the current connection.
    pub fn peer_readiness(&self, peer_id: &PeerId) -> Option<(ConnectionId, &IdentifyMessage)> {
        self.engine.core.peer_readiness(peer_id)
    }

    /// Returns the latest Identify information received for `peer_id`.
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
    /// These are what the sockets were given. A bound endpoint is already
    /// accepting on each (see [`EndpointBuilder::bind`]).
    ///
    /// See [State snapshots](Self#state-snapshots).
    pub fn bound_addresses(&self) -> Vec<Multiaddr> {
        self.engine.core.transport().local_addresses()
    }

    /// Registers an application protocol for inbound and outbound negotiation.
    ///
    /// Built-in ids ([`RESERVED_PROTOCOL_IDS`]) are rejected with
    /// [`SwarmError::ReservedProtocol`]; the endpoint's own identify and
    /// ping handlers already own them.
    pub fn add_protocol(&mut self, protocol_id: impl Into<String>) -> Result<(), Error> {
        Ok(self.engine.core.add_protocol(protocol_id)?)
    }

    /// Registers an application protocol whose received data the
    /// application acknowledges itself, with [`Self::stream_consumed`].
    ///
    /// Otherwise like [`Self::add_protocol`]. Use it when bytes outlive the
    /// event that carried them (a reader that queues them for later), so the
    /// sender is held back until they are really consumed (ADR 0012). Streams
    /// that became ready before this call keep the acknowledgement they had.
    pub fn add_manual_ack_protocol(&mut self, protocol_id: impl Into<String>) -> Result<(), Error> {
        self.engine.add_manual_ack_protocol(protocol_id.into())
    }

    /// Acknowledges `bytes` of a manual-acknowledgement stream's received
    /// data as consumed, replenishing its receive budget so the sender can
    /// continue (ADR 0012).
    ///
    /// A stream delivers at most one receive window of unacknowledged data,
    /// so a reader that never acknowledges stalls its sender. Fails with
    /// [`TransportError::AckExceedsDelivered`] when `bytes` exceeds the
    /// stream's unacknowledged bytes. Acknowledging a closed stream releases
    /// its bytes (and its stream slot, once none are left), also after its
    /// connection closed: an ended connection keeps its connection slot until
    /// all its streams settle, so a reader that holds bytes across peer
    /// churn eventually has the transport refuse new connections (ADR 0012).
    /// A settled or unknown stream or connection is a no-op. Streams of protocols
    /// registered with [`Self::add_protocol`] are acknowledged as their data
    /// is pulled, and must not be acknowledged here too.
    pub fn stream_consumed(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<(), Error> {
        self.engine.core.ack_stream(conn_id, stream_id, bytes)
    }

    /// Opens an application stream after negotiating `protocol_id`.
    ///
    /// Allowed once the peer is connected. Identify (`PeerReady`) is not
    /// required first; after Identify completes, an unsupported protocol can
    /// fail early with [`SwarmError::RemoteDoesNotSupport`].
    ///
    /// Returns the connection and stream ids. Stream ids are only unique per
    /// connection, so every later stream operation takes both. The open ends
    /// in exactly one terminal: [`EndpointEvent::StreamReady`], or an error
    /// event naming the stream (see [`crate::SwarmErrorKind`]) when negotiation
    /// fails, the peer closes the stream first, or
    /// [`crate::OUTBOUND_NEGOTIATION_TIMEOUT_MS`]
    /// passes; a closed or replaced connection ends it with its own event.
    pub fn open_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
    ) -> Result<(ConnectionId, StreamId), Error> {
        let now = self.now();
        self.engine
            .core
            .open_stream(peer_id, protocol_id, now.monotonic_ms)
    }

    /// Sends bytes on a negotiated application stream, named by the
    /// connection and stream ids [`Self::open_stream`] or
    /// [`EndpointEvent::StreamReady`] gave; the peer is the connection's.
    ///
    /// Accepts as much of `data` as the stream can queue (ADR 0012), and
    /// `Ok(())` means every byte was accepted locally, not delivered. When
    /// not every byte fit it returns [`Error::Full`]: **a prefix may already
    /// have been accepted, and only `unsent` is yours.** Hold it, wait for
    /// [`EndpointEvent::StreamWritable`] for the stream, and send it again.
    /// Full is retryable ([`Error::is_retryable`]), never a fault, so `?` on
    /// this call silently drops the tail:
    ///
    /// ```rust,ignore
    /// endpoint.send_stream(conn_id, stream_id, payload)?; // loses `unsent` on Full
    /// ```
    ///
    /// [`StreamWriter`](crate::StreamWriter) holds the tail, resends it on
    /// Writable, and defers a write-side close behind it, which is what most
    /// applications want.
    ///
    /// Fails with [`SwarmError::StreamNotFound`] if `conn_id` is no longer
    /// the connection holding the stream (for example after
    /// `ConnectionReplaced`), so a write never reaches a same-numbered stream
    /// on a newer connection, and with
    /// [`TransportError::ConnectionNotFound`] once nothing names the
    /// connection any more. [`Error::is_stream_gone`] covers both. The other
    /// stream operations behave the same.
    pub fn send_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: impl Into<Bytes>,
    ) -> Result<(), Error> {
        let now = self.now();
        self.engine
            .send_stream(conn_id, stream_id, data.into(), now)
    }

    /// Half-closes the local write side of an application stream.
    ///
    /// The FIN follows every byte the stream accepted; a tail you hold after
    /// a Full is not among them. [`StreamWriter::close_write`](crate::StreamWriter::close_write)
    /// waits for its own pending tail first.
    pub fn close_stream_write(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), Error> {
        let now = self.now();
        self.engine.close_stream_write(conn_id, stream_id, now)
    }

    /// Resets an application stream.
    pub fn reset_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), Error> {
        let now = self.now();
        self.engine.reset_stream(conn_id, stream_id, now)
    }

    /// Resets and forgets an application stream that will no longer be consumed.
    ///
    /// Unlike [`Endpoint::reset_stream`], this also discards matching events
    /// already queued by the endpoint and suppresses later data, EOF, and
    /// close events for the stream. Abandoning a live stream again is a
    /// no-op. A stream the peer has already closed has nothing left to reset:
    /// it is abandoned (and its undelivered data acknowledged) only while its
    /// [`EndpointEvent::StreamClosed`] is undelivered, and fails with
    /// [`SwarmError::StreamNotFound`] after that, including on a second call.
    ///
    /// Once the stream's connection has ended, abandoning always succeeds and
    /// needs no queued event: the endpoint and swarm drop what they hold for
    /// it and the transport settles it, giving up the bytes it delivered so
    /// they no longer hold the connection's slot (ADR 0012).
    pub fn abandon_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), Error> {
        let now = self.now();
        self.engine.abandon_stream(conn_id, stream_id, now)
    }

    /// Runs one drive batch without blocking and returns every queued event.
    ///
    /// Returned values are [`EndpointEvent`]s from the Endpoint event stream,
    /// including enabled capability output, in the per-batch order documented
    /// on [`EndpointEvent`]. Streams owned by an agent (NAT, relay service,
    /// Gossipsub) are consumed here and never surface as application stream
    /// events.
    ///
    /// An error discards nothing: events already queued come out of the next
    /// `poll` or `wait`.
    pub fn poll(&mut self) -> Result<Vec<EndpointEvent>, Error> {
        self.harvest(Duration::ZERO)?;
        let now = self.now();
        self.resolve_names(now);
        self.drive(now)?;
        // Start lookups for NAT dials the batch parked, so they run between
        // polls rather than from the next one.
        self.resolve_names(now);
        Ok(self.engine.take_events())
    }

    /// Drives the endpoint until an Endpoint event, the caller's deadline, or
    /// an interruption.
    ///
    /// This is the single Endpoint blocking wait. It runs one drive batch
    /// whenever its queue is empty and hands the batch's events out one per
    /// call, in the order documented on [`EndpointEvent`]. Deadline and
    /// interruption stay visible so a loop can service its own timers and
    /// commands (a [`WaitHandle`] from another thread interrupts it). A
    /// deadline that has already passed -- a stale [`std::time::Instant`] or
    /// [`std::time::Duration::ZERO`] alike -- never sleeps, but still returns
    /// a queued event or drives the endpoint once, so a stale timer cannot
    /// stall it. The deadline bounds blocking, not delivery: a caller with a
    /// strict operation timeout checks its own clock before each `wait`, as
    /// below. Enabled capabilities deliver their output here as
    /// [`EndpointEvent`] variants, so one `wait` loop sees every event
    /// exactly once. Each call drives only this endpoint.
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
    ///         // `wait` still serves events once the deadline has passed, so
    ///         // enforce the timeout here. Giving up locally does not cancel
    ///         // the attempt; do that explicitly.
    ///         if Instant::now() >= deadline {
    ///             node.cancel_connect(connect_id);
    ///             return Err("connect did not settle before the deadline".into());
    ///         }
    ///         match node.wait(deadline)? {
    ///             EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
    ///                 connect_id: settled,
    ///                 outcome,
    ///                 ..
    ///             }) if settled == connect_id => match outcome {
    ///                 ConnectOutcome::Connected { conn_id, .. } => {
    ///                     println!("connected on {conn_id:?}");
    ///                     return Ok(());
    ///                 }
    ///                 other => return Err(format!("connect failed: {other:?}").into()),
    ///             },
    ///             // Unrelated events keep flowing: dispatch them as usual.
    ///             EndpointWaitOutcome::Event(event) => println!("{event:?}"),
    ///             // The clock check above gives up.
    ///             EndpointWaitOutcome::Deadline => {}
    ///             // `Interrupted`: another thread woke us; service its
    ///             // commands, then wait again.
    ///             _ => {}
    ///         }
    ///     }
    /// }
    /// ```
    pub fn wait(
        &mut self,
        deadline: impl Into<WaitDeadline>,
    ) -> Result<EndpointWaitOutcome, Error> {
        let deadline = deadline.into();
        // A passed deadline still drives the endpoint once, which is what
        // lets a stale timer make progress. Only once, so a continuous event
        // stream cannot keep this wait running past its deadline.
        let mut drove_past_deadline = false;
        // A blocking harvest already collected this batch's readiness; a
        // zero-timeout one right behind it would only cost a syscall.
        let mut harvested = false;
        // A taken host wake owes one more batch, which is what reads the
        // edge-triggered mDNS sockets; a passed deadline must not skip it.
        let mut woken = false;
        // Past the deadline only one such batch runs: a steady stream of
        // wakes (packets mDNS reads and drops) must not hold the caller.
        // Newer wakes stay pending for the next call.
        let mut woke_past_deadline = false;
        loop {
            if let Some(event) = self.engine.pop_event() {
                return Ok(EndpointWaitOutcome::Event(event));
            }
            if drove_past_deadline && deadline.has_passed() && !woken {
                return Ok(EndpointWaitOutcome::Deadline);
            }
            if !harvested {
                self.harvest(Duration::ZERO)?;
            }
            // Lookups start before any sleep; finished ones (a lookup thread
            // is what woke the last sleep, unless the caller did) are applied
            // to the batch.
            let now = self.now();
            self.resolve_names(now);
            drove_past_deadline |= deadline.has_passed();
            woke_past_deadline |= woken && deadline.has_passed();
            woken = false;
            self.drive(now)?;
            if !self.engine.events.is_empty() {
                harvested = false;
                continue;
            }
            // A pending interrupt outranks an expired deadline, so a host's
            // non-blocking pump still notices it. Checked before sleeping
            // even when its `Waker` event was already harvested.
            if self.poll.take_interrupt() {
                return Ok(EndpointWaitOutcome::Interrupted);
            }
            if !(woke_past_deadline && deadline.has_passed()) && self.poll.take_wake() {
                (harvested, woken) = (false, true);
                continue;
            }
            if deadline.has_passed() {
                return Ok(EndpointWaitOutcome::Deadline);
            }
            // The batch may have parked NAT dials to named hosts; their
            // lookups must be under way before this sleeps, or nothing
            // would wake it for them.
            let now = self.now();
            self.resolve_names(now);
            harvested = self.block(deadline)?;
        }
    }

    /// Runs one engine batch, with Name resolution as candidate expansion.
    fn drive(&mut self, now: Now) -> Result<(), Error> {
        let resolver = &mut self.resolver;
        self.engine.drive(now, &mut |addr| resolver.expand(addr))
    }

    /// Sleeps until input on any registered source, a `Waker` wake, the
    /// caller's deadline, or the engine's next timer, and dispatches the
    /// transport's share of the readiness. Returns whether it harvested.
    ///
    /// The engine's own timers (attempt deadlines, capability drivers) are
    /// floored at 1 ms, so a driver reporting "due now" without new input
    /// cannot spin the thread; the swarm's own due work is not.
    fn block(&mut self, deadline: WaitDeadline) -> Result<bool, Error> {
        let now = self.now();
        let mut budget = deadline.remaining().unwrap_or(MAX_IDLE_WAIT);
        if let Some(next) = self.engine.core.next_deadline(now) {
            budget = budget.min(Duration::from_millis(next.millis_until(now)));
        }
        if let Some(next) = self.engine.driver_deadline(now) {
            budget = budget.min(Duration::from_millis(next.millis_until(now).max(1)));
        }
        if budget.is_zero() {
            return Ok(false);
        }
        self.harvest(budget)?;
        Ok(true)
    }

    /// Collects one bounded batch of readiness, blocking up to `timeout`,
    /// and dispatches the transport's share. Every drive path harvests
    /// first: an edge-triggered transport reads only what was dispatched.
    fn harvest(&mut self, timeout: Duration) -> Result<(), Error> {
        self.poll
            .harvest(self.engine.core.transport_mut(), timeout)
            .map(drop)
            .map_err(|error| TransportError::io("waiting for readiness", &error).into())
    }

    /// Starts lookups for NAT dials to named hosts, expires due attempts,
    /// and applies finished lookups to the Connection attempts and NAT dials
    /// still waiting on them.
    ///
    /// Runs before every batch, so a lookup is under way before the driver
    /// sleeps, and its answer is applied on the wake it causes.
    fn resolve_names(&mut self, now: Now) {
        #[cfg(feature = "autonat")]
        let mut nat_answered = Vec::new();
        #[cfg(feature = "autonat")]
        if let Some(nat) = self.engine.nat.as_mut() {
            // A lookup can outlive the flight that wanted it; retire those so
            // retries during a stall do not pile up.
            self.nat_dials
                .retain(|(token, _)| nat.named_dial_wanted(*token, now));
            for (token, addr) in nat.take_named_dials() {
                match self.resolver.expand(&addr) {
                    Expansion::Resolving => self.nat_dials.push((token, addr)),
                    Expansion::Ready(targets) => nat_answered.push((token, Ok(targets))),
                    Expansion::Refused(reason) => nat_answered.push((token, Err(reason))),
                }
            }
        }
        // Expire first: an answer that arrives after an attempt's deadline
        // must not turn its Timeout into another outcome.
        self.engine.expire_attempts(now);
        let answers = self.resolver.take_answers();
        if !answers.is_empty() {
            self.engine.connect.resolved(
                &mut |addr| dial::answer_for(addr, &answers),
                &mut self.engine.core,
            );
            #[cfg(feature = "autonat")]
            self.nat_dials
                .retain(|(token, addr)| match dial::answer_for(addr, &answers) {
                    Some(result) => {
                        nat_answered.push((*token, result));
                        false
                    }
                    None => true,
                });
        }
        #[cfg(feature = "autonat")]
        if let Some(nat) = self.engine.nat.as_mut() {
            for (token, result) in nat_answered {
                nat.named_dial_resolved(token, result, &mut self.engine.core, now);
            }
        }
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
            .engine
            .relay_server
            .as_mut()
            .ok_or(RelayServerControlError::NotConfigured)?;
        relay_server.agent.set_accepting(accepting);
        Ok(())
    }

    /// Replaces the CA-signed WebTransport certificate, for example after a
    /// renewal, without a restart or dropping a connection.
    ///
    /// Takes the same PEM as
    /// [`EndpointBuilder::webtransport_certificate_pem`] and makes bind's
    /// checks. New WebTransport handshakes present the new certificate; live
    /// connections keep theirs. The listen addresses carry no `/certhash`, so
    /// they and the announced addresses stay as they are.
    ///
    /// On any error the current certificate stays in service; see
    /// [`SetWebTransportCertificateError`] for each case.
    #[cfg(feature = "quic")]
    pub fn set_webtransport_certificate_pem(
        &mut self,
        chain_pem: impl AsRef<[u8]>,
        key_pem: impl AsRef<[u8]>,
    ) -> Result<(), SetWebTransportCertificateError> {
        let handle = self
            .webtransport_certificate
            .as_ref()
            .ok_or(SetWebTransportCertificateError::NotConfigured)?;
        let (chain, key) = parse_certificate_pem(chain_pem.as_ref(), key_pem.as_ref())
            .map_err(|problem| SetWebTransportCertificateError::Pem { problem })?;
        handle.replace(chain, key).map_err(|error| match error {
            minip2p_quic::WebTransportCertificateError::Invalid(reason) => {
                SetWebTransportCertificateError::Invalid { reason }
            }
            other => SetWebTransportCertificateError::Invalid {
                reason: other.to_string(),
            },
        })
    }

    /// Atomically replaces the relay server's explicit announce-address override.
    ///
    /// Each address must be a concrete direct TCP, QUIC or WebTransport
    /// address for this endpoint's peer id. A WebTransport address carries a
    /// `/certhash` with the derived self-signed certificates and none with a
    /// CA-signed one (`EndpointBuilder::webtransport_certificate_pem`).
    /// [`RelayServerControlError::InvalidAddress`] retains the rejected
    /// input's index and reason; on error, the previous override remains
    /// active. An empty replacement clears the override, restoring the
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
            .engine
            .relay_server
            .as_mut()
            .ok_or(RelayServerControlError::NotConfigured)?;
        check_webtransport_announce(&addrs, self.ca_webtransport_certificate)
            .map_err(RelayServerControlError::InvalidAddress)?;
        relay_server
            .agent
            .replace_announce_addrs(addrs)
            .map_err(RelayServerControlError::InvalidAddress)?;
        self.engine.addresses_changed();
        Ok(())
    }

    /// Sets externally validated addresses to advertise through Identify.
    ///
    /// Replaces the previous caller-set addresses; pass an empty vector to
    /// stop advertising them. Addresses the endpoint contributes itself (NAT
    /// relay circuits and confirmed public addresses, relay-server announce
    /// addresses) are kept and merged after these.
    pub fn set_external_addresses(&mut self, addresses: Vec<Multiaddr>) {
        self.engine.set_external_addresses(addresses);
    }

    /// Our current reachability verdict from AutoNAT probing
    /// ([`ReachabilityState::Unknown`] until probes gather confidence, or
    /// when NAT is not configured).
    #[cfg(feature = "autonat")]
    pub fn reachability(&self) -> ReachabilityState {
        self.engine.reachability()
    }

    /// The relay reservation currently held, if any.
    #[cfg(feature = "relay")]
    pub fn active_reservation(&self) -> Option<ReservationInfo> {
        self.engine.active_reservation()
    }

    /// Subscribes to a pubsub topic. Returns `Ok(false)` when already
    /// subscribed. The subscription is announced over gossipsub.
    ///
    /// Errors with [`GossipsubError::NotEnabled`] unless the endpoint was
    /// built with [`EndpointBuilder::gossipsub`].
    #[cfg(feature = "pubsub")]
    pub fn subscribe(&mut self, topic: &str) -> Result<bool, GossipsubError> {
        let now = self.now();
        self.engine.subscribe(topic, now)
    }

    /// Withdraws a pubsub subscription. Returns `Ok(false)` when not
    /// subscribed. The configured discovery topic is reserved while
    /// discovery is enabled and returns
    /// [`GossipsubError::DiscoveryTopicReserved`].
    #[cfg(feature = "pubsub")]
    pub fn unsubscribe(&mut self, topic: &str) -> Result<bool, GossipsubError> {
        let now = self.now();
        self.engine.unsubscribe(topic, now)
    }

    /// Publishes `data` on `topic`, signed with this endpoint's identity and
    /// forwarded over gossipsub.
    ///
    /// A successful return means the message was accepted and its outbound
    /// streams were initiated — the frames themselves go out as the
    /// endpoint is driven (`wait` / `poll`), so keep driving after
    /// publishing. Delivery failures are never synchronous errors; they
    /// surface later as [`crate::GossipsubEvent::OutboundFailure`] (or
    /// [`EndpointEvent::Error`] runtime events). There is no self-delivery. The
    /// configured discovery topic is reserved while discovery is enabled
    /// and returns [`GossipsubError::DiscoveryTopicReserved`].
    #[cfg(feature = "pubsub")]
    pub fn publish(&mut self, topic: &str, data: impl Into<Vec<u8>>) -> Result<(), GossipsubError> {
        let now = self.now();
        self.engine.publish(topic, data.into(), now)
    }

    /// Returns the current discovery address-book snapshot.
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    pub fn known_peers(&self) -> Vec<KnownPeer> {
        self.engine.known_peers()
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
        self.engine.discovery.as_ref()?;
        Some(self.now().monotonic_ms)
    }

    /// Sends mDNS goodbyes once and cancels discovery-owned dial attempts.
    ///
    /// mDNS becomes permanently inactive, while QUIC and the rest of the
    /// endpoint remain usable. Every interface send and every cancellation is
    /// attempted; the first goodbye that could not be sent is returned
    /// afterwards, and is also queued as a final
    /// [`EndpointEvent::MdnsFailed`]. Idempotent: a second call does nothing.
    ///
    /// This does not close QUIC/TCP peers; use [`close`](Self::close) or drop.
    #[cfg(feature = "mdns")]
    pub fn shutdown(&mut self) -> Result<(), MdnsError> {
        let now = self.now();
        self.engine.shutdown_mdns(now)
    }

    /// Disconnects established peers, waits up to
    /// [`DEFAULT_CLOSE_TIMEOUT`] (500 ms) until none remain, and consumes
    /// the endpoint: [`close_within`](Self::close_within) with that
    /// deadline.
    ///
    /// Named `close` because `shutdown` is already used for mDNS goodbyes.
    pub fn close(self) -> CloseReport {
        self.close_within(DEFAULT_CLOSE_TIMEOUT)
    }

    /// Disconnects established peers, waits up to `timeout` until no
    /// connection is tracked, and consumes the endpoint. A dial still
    /// pending is tracked: the drain waits for it to fail, or to establish
    /// and then be disconnected.
    ///
    /// The deadline bounds teardown time only, not delivery of accepted
    /// writes: QUIC discards queued writes and TCP may abort. With
    /// [`Duration::ZERO`] this is an immediate best-effort teardown: one
    /// pass disconnects and hands over what is already queued. Running out
    /// the deadline is [`CloseOutcome::DeadlineExpired`], not an error, and
    /// [`CloseReport::unfinished`] lists what was still tracked.
    ///
    /// Dropping without closing still disconnects (errors ignored). Neither
    /// notifies a peer after `kill -9` or a hard partition. A replacement
    /// that lands while draining is disconnected too, including a handshake
    /// still pending when the replaced connection closes.
    ///
    /// Close never stops at the first failure: the [`CloseReport`] carries
    /// every event collected, starting with those already queued, and every
    /// transport or swarm error hit. A failed drain ends the drain early
    /// ([`CloseOutcome::Failed`]). mDNS goodbyes are best effort: one that
    /// could not be sent is an [`EndpointEvent::MdnsFailed`] in the report's
    /// events, not an error.
    pub fn close_within(mut self, timeout: Duration) -> CloseReport {
        let mut report = CloseReport {
            outcome: CloseOutcome::Drained,
            unfinished: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
        };
        report.events.extend(self.engine.events.drain(..));
        // The failure is queued as an event too, and drained below.
        #[cfg(feature = "mdns")]
        drop(self.shutdown());
        let drain_by = std::time::Instant::now() + timeout;
        loop {
            report.errors.extend(self.disconnect_established());
            // Out of time or failed: hand over what the swarm already queued
            // (a disconnect's close failure, say) without polling again.
            let (polled, last, now) = if std::time::Instant::now() >= drain_by {
                (self.engine.core.take_buffered_events(), true, self.now())
            } else {
                let harvested = if self.close_drain_busy() {
                    // Interrupts only end this sleep early.
                    self.block(WaitDeadline::from(drain_by))
                } else {
                    Ok(false)
                };
                let harvested = match harvested {
                    Ok(true) => Ok(()),
                    Ok(false) => self.harvest(Duration::ZERO),
                    Err(error) => Err(error),
                };
                let now = self.now();
                match harvested.and_then(|()| self.engine.core.poll(now)) {
                    Ok(polled) => (polled, false, now),
                    Err(error) => {
                        report.errors.push(error);
                        report.outcome = CloseOutcome::Failed;
                        (self.engine.core.take_buffered_events(), true, now)
                    }
                }
            };
            let quiet = polled.is_empty();
            // No agent tick or discovery sweep runs while closing, so only
            // connection, attempt and capability events (a relay
            // reservation closing, say) are returned.
            for event in polled {
                self.engine.ingest(event, now);
            }
            self.engine.settle(now);
            report.events.extend(self.engine.events.drain(..));
            if last
                || (quiet && (!self.close_drain_busy() || std::time::Instant::now() >= drain_by))
            {
                break;
            }
        }
        // The last pass's own work (a driver's reset the transport refused,
        // say) can queue more swarm events: hand them over without polling.
        let now = self.now();
        for event in self.engine.core.take_buffered_events() {
            self.engine.ingest(event, now);
        }
        self.engine.settle(now);
        report.events.extend(self.engine.events.drain(..));
        report.unfinished = self
            .engine
            .core
            .tracked_connections()
            .map(|(conn_id, peer)| (conn_id, peer.cloned()))
            .collect();
        if report.outcome == CloseOutcome::Drained && !report.unfinished.is_empty() {
            report.outcome = CloseOutcome::DeadlineExpired;
        }
        report
    }

    fn close_drain_busy(&self) -> bool {
        !self.engine.core.connected_peers().is_empty() || self.engine.core.has_tracked_connections()
    }

    /// Disconnects every established peer, returning each failure.
    fn disconnect_established(&mut self) -> Vec<Error> {
        let now = self.now();
        self.engine
            .core
            .connected_peers()
            .iter()
            .filter_map(|peer| self.engine.core.disconnect(peer, now.monotonic_ms).err())
            .collect()
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        // Drop cannot surface disconnect failures; transports own final cleanup.
        drop(self.disconnect_established());
    }
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
    /// What WebTransport listeners present to browsers.
    #[cfg(feature = "quic")]
    webtransport_certificates: WebTransportCertificates,
    #[cfg(feature = "tcp")]
    tcp_config: TcpConfig,
    /// Ordered listen addresses; transport is inferred from address shape.
    #[cfg(any(feature = "quic", feature = "tcp"))]
    listen_addrs: Vec<Multiaddr>,
    protocols: Vec<String>,
    /// Registered protocols whose data the application acknowledges itself.
    manual_ack_protocols: Vec<String>,
    #[cfg(feature = "relay-server")]
    relay_server_config: Option<RelayServerConfig>,
    #[cfg(feature = "relay-server")]
    relay_server_announce_addrs: Vec<Multiaddr>,
    #[cfg(feature = "relay")]
    circuit_limits: CircuitLimits,
    /// Capability intent for Endpoint setup, which applies the defaults; the
    /// relay server joins it at bind.
    capabilities: Capabilities,
    connect_deadline: std::time::Duration,
    simultaneous_dial_window: std::time::Duration,
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self {
            keypair: None,
            agent_version: DEFAULT_AGENT_VERSION.to_string(),
            connect_deadline: std::time::Duration::from_millis(DEFAULT_CONNECT_DEADLINE_MS),
            simultaneous_dial_window: std::time::Duration::from_millis(
                minip2p_swarm::SIMULTANEOUS_DIAL_WINDOW_MS,
            ),
            #[cfg(feature = "quic")]
            quic_limits: QuicLimits::default(),
            #[cfg(feature = "quic")]
            webtransport_certificates: WebTransportCertificates::Derived,
            #[cfg(feature = "tcp")]
            tcp_config: TcpConfig::default(),
            #[cfg(any(feature = "quic", feature = "tcp"))]
            listen_addrs: Vec::new(),
            protocols: Vec::new(),
            manual_ack_protocols: Vec::new(),
            #[cfg(feature = "relay-server")]
            relay_server_config: None,
            #[cfg(feature = "relay-server")]
            relay_server_announce_addrs: Vec::new(),
            #[cfg(feature = "relay")]
            circuit_limits: CircuitLimits::default(),
            capabilities: Capabilities::default(),
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
    pub fn connect_deadline(mut self, deadline: Duration) -> Self {
        self.connect_deadline = deadline;
        self
    }

    /// Sets how long a peer's new connection can lose a race to its current
    /// one. Default is 5 seconds
    /// ([`SIMULTANEOUS_DIAL_WINDOW_MS`](minip2p_swarm::SIMULTANEOUS_DIAL_WINDOW_MS)).
    ///
    /// Both peers settle a race on their own, so they should use the same
    /// window. A shorter one lets a peer that reconnects after its old
    /// connection died silently get back in sooner, at the cost of settling
    /// slow candidate races less reliably.
    pub fn simultaneous_dial_window(mut self, window: Duration) -> Self {
        self.simultaneous_dial_window = window;
        self
    }

    /// Overrides QUIC connection, stream, queue, window and timeout limits.
    /// The windows default to quinn's own (ADR 0022).
    #[cfg(feature = "quic")]
    pub fn quic_limits(mut self, limits: QuicLimits) -> Self {
        self.quic_limits = limits;
        self
    }

    /// Serves WebTransport with a CA-signed certificate instead of the
    /// rotating self-signed ones derived from the identity key.
    ///
    /// `chain_pem` holds the leaf certificate first, then its intermediates
    /// (certbot's `fullchain.pem`); `key_pem` holds the leaf's one private
    /// key (`privkey.pem`, PKCS#8, SEC1 or PKCS#1). Both are parsed here, so a
    /// missing certificate or key, or a second key, is an
    /// [`EndpointOptionsError::WebTransportCertificatePem`].
    /// [`bind`](Self::bind) then checks that the key matches the leaf and the
    /// leaf has not expired ([`BindError::Quic`]), and that a
    /// `/quic-v1/webtransport` listen address exists to serve it
    /// ([`EndpointOptionsError::WebTransportCertificateWithoutListener`]).
    ///
    /// Browsers check the certificate the way they check any HTTPS page, so
    /// they must dial the domain it names, with no `/certhash`:
    /// `/dns/relay.example.com/udp/<port>/quic-v1/webtransport/p2p/…`. The
    /// certificate never rotates, so the listen addresses carry no
    /// `/certhash` and never change. Replace it after a renewal, without a
    /// restart, with [`Endpoint::set_webtransport_certificate_pem`].
    #[cfg(feature = "quic")]
    pub fn webtransport_certificate_pem(
        mut self,
        chain_pem: impl AsRef<[u8]>,
        key_pem: impl AsRef<[u8]>,
    ) -> Result<Self, EndpointOptionsError> {
        let (chain, key) = parse_certificate_pem(chain_pem.as_ref(), key_pem.as_ref())
            .map_err(|problem| EndpointOptionsError::WebTransportCertificatePem { problem })?;
        self.webtransport_certificates = WebTransportCertificates::Provided { chain, key };
        Ok(self)
    }

    /// Overrides TCP connection, buffer, timeout and Yamux limits, and the
    /// connection-id namespace the TCP transport allocates in. Checked at bind
    /// ([`EndpointOptionsError::InvalidLimit`]).
    #[cfg(feature = "tcp")]
    pub fn tcp_config(mut self, config: TcpConfig) -> Self {
        self.tcp_config = config;
        self
    }

    /// Overrides the relay circuits' Yamux limits. Checked at bind
    /// ([`EndpointOptionsError::InvalidLimit`]).
    #[cfg(feature = "relay")]
    pub fn circuit_limits(mut self, limits: CircuitLimits) -> Self {
        self.circuit_limits = limits;
        self
    }

    /// Adds a listener from a complete transport multiaddress.
    ///
    /// QUIC (`/ip4|ip6/udp/<port>/quic-v1`), WebTransport
    /// (`/ip4|ip6/udp/<port>/quic-v1/webtransport`, without a `/certhash`:
    /// the node's certificate supplies it) and TCP (`/ip4|ip6/tcp/<port>`)
    /// shapes are accepted. A `quic-v1` and a WebTransport address on the
    /// same host and port share one UDP socket, which serves both.
    /// Compatible addresses are grouped at [`EndpointBuilder::bind`];
    /// unsupported or contradictory shapes fail here with an actionable
    /// error.
    ///
    /// Named `listen_on` to avoid colliding with [`Endpoint::listen`], which
    /// returns the first bound address after bind.
    #[cfg(any(feature = "quic", feature = "tcp"))]
    pub fn listen_on(mut self, address: impl AsRef<str>) -> Result<Self, EndpointOptionsError> {
        let raw = address.as_ref();
        let parsed = Multiaddr::from_str(raw).map_err(|error| {
            EndpointOptionsError::InvalidListenAddress {
                addr: raw.to_string(),
                error,
            }
        })?;
        self.push_listen_addr(parsed)?;
        Ok(self)
    }

    /// Adds a listener from an already-parsed transport multiaddress.
    #[cfg(any(feature = "quic", feature = "tcp"))]
    pub fn listen_on_multiaddr(
        mut self,
        address: &Multiaddr,
    ) -> Result<Self, EndpointOptionsError> {
        self.push_listen_addr(address.clone())?;
        Ok(self)
    }

    /// Configures the common dual-stack QUIC defaults
    /// (`/ip4/0.0.0.0/udp/0/quic-v1` and `/ip6/::/udp/0/quic-v1`).
    ///
    /// Returns [`EndpointOptionsError::DuplicateQuicFamily`] if the builder
    /// already has a QUIC listen for either family (same rule as
    /// [`Self::listen_on`]).
    #[cfg(feature = "quic")]
    pub fn listen_default(mut self) -> Result<Self, EndpointOptionsError> {
        for address in default_listen_quic_addrs() {
            self.push_listen_addr(address)?;
        }
        Ok(self)
    }

    #[cfg(any(feature = "quic", feature = "tcp"))]
    fn push_listen_addr(&mut self, address: Multiaddr) -> Result<(), EndpointOptionsError> {
        validate_listen_multiaddr(&address)?;
        #[cfg(feature = "quic")]
        if is_quic_listen(&address) {
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

    /// Registers an application protocol whose received data the
    /// application acknowledges itself, with [`Endpoint::stream_consumed`]
    /// (see [`Endpoint::add_manual_ack_protocol`]).
    pub fn manual_ack_protocol(mut self, protocol_id: impl Into<String>) -> Self {
        let id = protocol_id.into();
        if !self.manual_ack_protocols.contains(&id) {
            self.manual_ack_protocols.push(id.clone());
        }
        self.protocol(id)
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

    /// Enables Circuit Relay v2 service with custom limits.
    ///
    /// Checked at bind ([`BindError::RelayServer`], naming the invalid field
    /// and why): a required value that is zero, or a duration the wire
    /// encoding cannot carry.
    #[cfg(feature = "relay-server")]
    pub fn relay_server_config(mut self, config: RelayServerConfig) -> Self {
        self.relay_server_config = Some(config);
        self
    }

    /// Configures advertised direct addresses without enabling relay service.
    ///
    /// This method validates direct TCP/QUIC/WebTransport shape, rejects wildcard
    /// and circuit addresses, and checks a trailing peer id against an
    /// already-fixed builder identity. Whether a WebTransport address must carry
    /// a `/certhash` depends on
    /// `EndpointBuilder::webtransport_certificate_pem`, so that is checked at
    /// bind: with the derived self-signed certificates it must, with a CA-signed
    /// one it must not. [`RelayServerAnnounceError`] preserves either the rejected input
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

    /// Adds a relay, in preference order; each call adds one.
    ///
    /// A relay is a path, not a mode: connects still race direct candidates
    /// against a leg through the relay, upgrade a relayed connection with
    /// DCUtR where the endpoint runs it (QUIC), and reserve a slot on the
    /// relay for inbound connections while the endpoint is not known to be
    /// public. Without [`EndpointBuilder::nat_config`], that is the default
    /// policy ([`ReservationPolicy::WhenPrivate`](crate::ReservationPolicy::WhenPrivate)),
    /// with DCUtR only when the endpoint is built with QUIC. For relay-only
    /// connects set [`NatConfig::force_relay`].
    #[cfg(feature = "relay")]
    pub fn relay(mut self, relay: PeerAddr) -> Self {
        self.capabilities.relays.push(relay);
        self
    }

    /// Adds an AutoNAT server used for reachability probing; each call adds
    /// one.
    ///
    /// Call once per server: a reachability verdict needs a quorum of
    /// distinct servers ([`NatConfig::confidence_threshold`], 3 by default),
    /// so with fewer reachable servers reachability stays Unknown. Without
    /// [`EndpointBuilder::nat_config`] or a relay, the endpoint holds no
    /// reservation ([`ReservationPolicy::Never`](crate::ReservationPolicy::Never)).
    #[cfg(feature = "autonat")]
    pub fn autonat_server(mut self, server: PeerAddr) -> Self {
        self.capabilities.autonat_servers.push(server);
        self
    }

    /// Sets the base NAT configuration (timeouts, punch retries,
    /// reservation policy, …), kept as given. A second call replaces the
    /// first. Relays and AutoNAT servers added through
    /// `EndpointBuilder::relay` / [`EndpointBuilder::autonat_server`] are
    /// appended to the config's own lists, in either call order, without
    /// exact repeats.
    ///
    /// Checked at bind, after the merge ([`BindError::NatConfig`]): it needs
    /// a relay or an AutoNAT server, and a reservation policy other than
    /// `Never` or `force_relay` needs a relay. Without any NAT
    /// configuration, discovery and mDNS turn NAT on for the peers they find.
    #[cfg(feature = "autonat")]
    pub fn nat_config(mut self, config: NatConfig) -> Self {
        self.capabilities.nat = Some(config);
        self
    }

    /// Enables pubsub with the default gossipsub configuration.
    ///
    /// Builder-time opt-in (rather than a lazy `subscribe`-time enable)
    /// because the gossipsub protocol ids must be in Identify's advertised
    /// set from the first handshake.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub(mut self) -> Self {
        self.capabilities
            .gossipsub
            .get_or_insert_with(GossipsubConfig::default);
        self
    }

    /// Enables pubsub with an explicit gossipsub configuration.
    ///
    /// Invalid mesh relationships or zero bounds fail the later `bind()`
    /// before a socket is allocated.
    #[cfg(feature = "pubsub")]
    pub fn gossipsub_config(mut self, config: GossipsubConfig) -> Self {
        self.capabilities.gossipsub = Some(config);
        self
    }

    /// Enables signed pubsub peer discovery with interoperable defaults.
    ///
    /// The discovery topic is driver-owned: subscribing to it again through
    /// [`Endpoint::subscribe`] is redundant, and its pubsub messages and
    /// subscription events are consumed before reaching the application.
    #[cfg(feature = "discovery")]
    pub fn discovery(mut self) -> Self {
        self.capabilities
            .gossipsub
            .get_or_insert_with(GossipsubConfig::default);
        self.capabilities.beacon = Some(BeaconConfig::default());
        self
    }

    /// Enables discovery with an explicit beacon configuration, checked at
    /// bind before any socket opens ([`BindError::Discovery`]).
    ///
    /// The configured topic is driver-owned: subscribing to it again through
    /// [`Endpoint::subscribe`] is redundant, and its pubsub messages and
    /// subscription events are consumed before reaching the application.
    #[cfg(feature = "discovery")]
    pub fn discovery_config(mut self, config: BeaconConfig) -> Self {
        self.capabilities
            .gossipsub
            .get_or_insert_with(GossipsubConfig::default);
        self.capabilities.beacon = Some(config);
        self
    }

    /// Enables local-link mDNS discovery with interoperable defaults.
    #[cfg(feature = "mdns")]
    pub fn mdns(mut self) -> Self {
        self.capabilities.mdns = Some(MdnsConfig::default());
        self
    }

    /// Enables local-link mDNS discovery with an explicit configuration,
    /// checked at bind before the QUIC or mDNS sockets open
    /// ([`BindError::Mdns`]).
    #[cfg(feature = "mdns")]
    pub fn mdns_config(mut self, config: MdnsConfig) -> Self {
        self.capabilities.mdns = Some(config);
        self
    }

    /// Overrides the shared address-book and automatic-dial policy, checked
    /// at bind ([`BindError::Discovery`]).
    ///
    /// This policy is shared by every enabled discovery source.
    #[cfg(any(feature = "discovery", feature = "mdns"))]
    pub fn peer_discovery_config(mut self, config: PeerDiscoveryConfig) -> Self {
        self.capabilities.peer_discovery = config;
        self
    }

    /// Builds the endpoint, bringing up every transport it was given.
    ///
    /// A `/udp/…/quic-v1` address is then dialed over QUIC and a `/tcp` one
    /// over TCP, decided from the address rather than by the caller. An
    /// endpoint with nothing to bind is refused: it could neither dial nor be
    /// reached, and failing here says so more clearly than every later call
    /// would.
    ///
    /// Every transport starts accepting at once, QUIC and TCP alike, so the
    /// returned endpoint is reachable on each listen address without a
    /// further call. [`Endpoint::listen_all`] reports those addresses.
    ///
    /// Every failure is a [`BindError`] naming what failed, before any event
    /// is polled; see its variants.
    pub fn bind(mut self) -> Result<Endpoint, BindError> {
        let (keypair, capabilities) = self.prepare()?;
        let (transport, _certificate) = bind_transports(&self, &keypair)?;
        let mut endpoint = build_endpoint(self, keypair, transport, capabilities)?;
        #[cfg(feature = "quic")]
        {
            endpoint.webtransport_certificate = _certificate;
        }
        endpoint
            .engine
            .core
            .listen_on_bound_addrs()
            .map_err(|error| match error {
                Error::Transport(error) => BindError::Listen(error),
                _ => BindError::Invariant {
                    reason: "listening on bound addresses failed outside the transport",
                },
            })?;
        Ok(endpoint)
    }

    /// Validates the static configuration.
    ///
    /// Reserved protocol ids are rejected here -- before any socket is
    /// bound -- so a configuration error can neither allocate resources
    /// nor be masked by a bind failure. Capabilities are validated by
    /// Endpoint setup, also before binding.
    fn validate(&self) -> Result<(), BindError> {
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
        #[cfg(feature = "relay-server")]
        if self.relay_server_config.is_none() && !self.relay_server_announce_addrs.is_empty() {
            return Err(EndpointOptionsError::RelayAnnounceWithoutServer.into());
        }
        #[cfg(feature = "quic")]
        if self.ca_webtransport_certificate()
            && !self.listen_addrs.iter().any(Multiaddr::is_webtransport)
        {
            return Err(EndpointOptionsError::WebTransportCertificateWithoutListener.into());
        }
        // Checked here rather than in `relay_server_announce_addrs`, which
        // may run before the certificate option.
        #[cfg(feature = "relay-server")]
        check_webtransport_announce(
            &self.relay_server_announce_addrs,
            self.ca_webtransport_certificate(),
        )
        .map_err(|error| BindError::RelayServerAnnounce(Box::new(error)))?;
        Ok(())
    }

    /// Whether WebTransport presents a CA-signed certificate rather than the
    /// derived self-signed ones.
    #[cfg(any(feature = "quic", feature = "relay-server"))]
    fn ca_webtransport_certificate(&self) -> bool {
        #[cfg(feature = "quic")]
        return matches!(
            self.webtransport_certificates,
            WebTransportCertificates::Provided { .. }
        );
        #[cfg(not(feature = "quic"))]
        false
    }

    /// Moves the capability intent out for Endpoint setup, which applies
    /// every default; the relay server joins it with its announce addresses.
    fn take_capabilities(&mut self) -> Capabilities {
        #[cfg_attr(
            not(feature = "relay-server"),
            expect(unused_mut, reason = "only the relay server joins here")
        )]
        let mut capabilities = std::mem::take(&mut self.capabilities);
        #[cfg(feature = "relay-server")]
        if let Some(config) = self.relay_server_config.take() {
            capabilities.relay_server = Some(setup::RelayServerSetup {
                config,
                announce_addrs: std::mem::take(&mut self.relay_server_announce_addrs),
            });
        }
        capabilities
    }

    /// Everything bind checks before a socket opens: the options, then the
    /// capabilities through Endpoint setup. Returns the identity and the
    /// validated capabilities.
    fn prepare(&mut self) -> Result<(Ed25519Keypair, setup::Validated), BindError> {
        self.validate()?;
        let keypair = self.keypair.take().unwrap_or_else(Ed25519Keypair::generate);
        let capabilities =
            setup::validate(self.take_capabilities(), STD_PLATFORM, &keypair.peer_id())?;
        Ok((keypair, capabilities))
    }

    /// Binds over an already-bound transport set, for the crate's tests.
    #[cfg(test)]
    pub(crate) fn bind_over(mut self, transport: TransportSet) -> Result<Endpoint, BindError> {
        let (keypair, capabilities) = self.prepare()?;
        build_endpoint(self, keypair, transport, capabilities)
    }
}

#[cfg(any(feature = "quic", feature = "tcp"))]
fn validate_listen_multiaddr(address: &Multiaddr) -> Result<(), EndpointOptionsError> {
    let unsupported = |expected| EndpointOptionsError::UnsupportedListenShape {
        addr: address.clone(),
        expected,
    };
    if address
        .protocols()
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2p(_) | Protocol::P2pCircuit))
    {
        return Err(unsupported(
            "a transport address without /p2p or /p2p-circuit (those belong on dial targets)",
        ));
    }

    let ip_host = matches!(
        address.protocols().first(),
        Some(Protocol::Ip4(_)) | Some(Protocol::Ip6(_))
    );
    if !ip_host {
        return Err(unsupported(
            "an /ip4 or /ip6 host (DNS names are dial-only)",
        ));
    }

    #[cfg(feature = "quic")]
    if address.is_quic_transport() {
        return Ok(());
    }
    #[cfg(feature = "quic")]
    if address.is_webtransport() {
        if address.certhashes().next().is_some() {
            return Err(unsupported(
                "`/ip4|ip6/udp/<port>/quic-v1/webtransport` without /certhash \
                 (the node's own certificate supplies it)",
            ));
        }
        return Ok(());
    }
    #[cfg(feature = "tcp")]
    if address.is_tcp_transport() {
        return Ok(());
    }

    #[cfg(all(feature = "quic", feature = "tcp"))]
    let expected =
        "`/ip4|ip6/udp/<port>/quic-v1`, `…/quic-v1/webtransport` or `/ip4|ip6/tcp/<port>`";
    #[cfg(all(feature = "quic", not(feature = "tcp")))]
    let expected = "`/ip4|ip6/udp/<port>/quic-v1` or `…/quic-v1/webtransport`";
    #[cfg(all(feature = "tcp", not(feature = "quic")))]
    let expected = "`/ip4|ip6/tcp/<port>`";
    Err(unsupported(expected))
}

#[cfg(feature = "quic")]
fn listen_ip_family(address: &Multiaddr) -> Option<IpFamily> {
    match address.protocols().first() {
        Some(Protocol::Ip4(_)) => Some(IpFamily::Ipv4),
        Some(Protocol::Ip6(_)) => Some(IpFamily::Ipv6),
        _ => None,
    }
}

/// Whether a listen address is one the QUIC transport binds: `quic-v1` or
/// WebTransport.
#[cfg(feature = "quic")]
fn is_quic_listen(address: &Multiaddr) -> bool {
    address.is_quic_transport() || address.is_webtransport()
}

/// QUIC binds one socket per family, which may serve one `quic-v1` and one
/// WebTransport address: a second address of a family must name the same
/// host and port as the first, in the other shape.
#[cfg(feature = "quic")]
fn reject_duplicate_quic_family(
    existing: &[Multiaddr],
    next: &Multiaddr,
) -> Result<(), EndpointOptionsError> {
    let Some(family) = listen_ip_family(next) else {
        return Ok(());
    };
    let socket = |address: &Multiaddr| address.protocols().get(..2).map(<[Protocol]>::to_vec);
    if existing
        .iter()
        .filter(|address| is_quic_listen(address))
        .filter(|address| listen_ip_family(address) == Some(family))
        .any(|address| {
            address.is_webtransport() == next.is_webtransport() || socket(address) != socket(next)
        })
    {
        return Err(EndpointOptionsError::DuplicateQuicFamily {
            addr: next.clone(),
            family,
        });
    }
    Ok(())
}

/// Browsers pin a self-signed WebTransport certificate by the address's
/// `/certhash` and check a CA-signed one by its chain, so a WebTransport
/// announce address carries a hash exactly when the certificate is derived.
#[cfg(feature = "relay-server")]
#[expect(
    clippy::result_large_err,
    reason = "The error owns the rejected announce address for actionable host diagnostics."
)]
fn check_webtransport_announce(
    addrs: &[Multiaddr],
    ca_certificate: bool,
) -> Result<(), RelayServerAddressError> {
    for (index, address) in addrs.iter().enumerate() {
        if !address
            .iter()
            .any(|protocol| matches!(protocol, Protocol::WebTransport))
        {
            continue;
        }
        let reason = match (ca_certificate, address.certhashes().next().is_some()) {
            (false, false) => RelayServerAddressErrorKind::MissingCerthash,
            (true, true) => RelayServerAddressErrorKind::UnexpectedCerthash,
            _ => continue,
        };
        return Err(RelayServerAddressError {
            index,
            address: address.clone(),
            reason,
        });
    }
    Ok(())
}

/// Brings up every requested transport behind one set.
///
/// Listen multiaddresses are grouped by transport shape: compatible QUIC IPv4
/// and IPv6 addresses become one QUIC member, and every `/tcp` address lands on
/// one TCP member. Members are inserted in the order their shape first appears,
/// so `listen_all` reports addresses in configuration order.
#[cfg_attr(
    not(any(feature = "quic", feature = "tcp")),
    expect(
        unused_mut,
        unused_variables,
        reason = "without a transport feature there is nothing to bind"
    )
)]
fn bind_transports(
    options: &EndpointBuilder,
    keypair: &Ed25519Keypair,
) -> Result<(TransportSet, CertificateHandle), BindError> {
    let mut set = TransportSet::new();
    #[cfg_attr(
        not(feature = "quic"),
        expect(unused_mut, reason = "only a QUIC transport sets it")
    )]
    let mut certificate: CertificateHandle = None;

    #[cfg(any(feature = "quic", feature = "tcp"))]
    {
        let addrs = &options.listen_addrs;
        #[cfg(feature = "quic")]
        let quic_addrs: Vec<&Multiaddr> = addrs
            .iter()
            .filter(|address| is_quic_listen(address))
            .collect();
        #[cfg(feature = "tcp")]
        let tcp_addrs: Vec<&Multiaddr> = addrs
            .iter()
            .filter(|address| address.is_tcp_transport())
            .collect();
        let quic_first = addrs
            .first()
            .is_none_or(|address| address.transport_kind() == Some(TransportKind::Quic));
        let order = if quic_first {
            [true, false]
        } else {
            [false, true]
        };
        for want_quic in order {
            #[cfg(feature = "quic")]
            if want_quic && !quic_addrs.is_empty() {
                let config = QuicNodeConfig::new(keypair.clone())
                    .with_limits(options.quic_limits.clone())
                    .with_webtransport_certificates(options.webtransport_certificates.clone());
                // `listen_on` allows one socket per family, which is what the
                // transport binds; its `quic-v1` and WebTransport shapes are
                // grouped onto that socket there.
                let addresses: Vec<Multiaddr> =
                    quic_addrs.iter().map(|&address| address.clone()).collect();
                let transport = QuicTransport::bind(config, &addresses).map_err(BindError::Quic)?;
                certificate = transport.webtransport_certificate_handle();
                let namespaces = transport.namespaces();
                insert_member(&mut set, TransportKind::Quic, namespaces, transport)?;
            }
            #[cfg(feature = "tcp")]
            if !want_quic && !tcp_addrs.is_empty() {
                let transport = bind_tcp_member(options, keypair, &tcp_addrs)?;
                let namespace = transport.namespace();
                insert_member(&mut set, TransportKind::Tcp, [namespace], transport)?;
            }
        }
    }

    if set.is_empty() {
        return Err(EndpointOptionsError::NoTransport.into());
    }
    Ok((set, certificate))
}

/// What [`Endpoint::set_webtransport_certificate_pem`] replaces a CA-signed
/// certificate through: the QUIC transport's handle, since the transport
/// itself is boxed in the [`TransportSet`].
#[cfg(feature = "quic")]
type CertificateHandle = Option<minip2p_quic::WebTransportCertificateHandle>;
#[cfg(not(feature = "quic"))]
type CertificateHandle = Option<core::convert::Infallible>;

/// A certificate chain (leaf first) and its one private key from PEM, or
/// what is wrong with them.
#[cfg(feature = "quic")]
fn parse_certificate_pem(
    chain_pem: &[u8],
    key_pem: &[u8],
) -> Result<
    (
        Vec<minip2p_quic::pki_types::CertificateDer<'static>>,
        minip2p_quic::pki_types::PrivateKeyDer<'static>,
    ),
    String,
> {
    use minip2p_quic::pki_types::pem::PemObject;
    use minip2p_quic::pki_types::{CertificateDer, PrivateKeyDer};

    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("certificate chain: {error}"))?;
    if chain.is_empty() {
        return Err("the certificate chain has no `BEGIN CERTIFICATE` section".into());
    }
    let mut keys = PrivateKeyDer::pem_slice_iter(key_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("private key: {error}"))?;
    match keys.len() {
        1 => Ok((chain, keys.remove(0))),
        0 => Err(
            "the key PEM has no `BEGIN PRIVATE KEY`, `BEGIN EC PRIVATE KEY` or \
                  `BEGIN RSA PRIVATE KEY` section"
                .into(),
        ),
        count => Err(format!(
            "the key PEM has {count} private keys; pass only the leaf's"
        )),
    }
}

/// Builds the one TCP transport, listening on every `/tcp` address asked for.
#[cfg(feature = "tcp")]
fn bind_tcp_member(
    options: &EndpointBuilder,
    keypair: &Ed25519Keypair,
    tcp_addrs: &[&Multiaddr],
) -> Result<TcpTransport<StdTcpProvider, StdEntropy>, BindError> {
    // Checked before a socket exists: the namespace is what routes a connection
    // id back to the transport that minted it, so a TCP transport tagged as
    // something else hands out ids that name the wrong carrier -- and would
    // take a claim a QUIC member needs.
    let namespace = options.tcp_config.namespace;
    if namespace != ConnectionNamespace::TCP_IPV4 && namespace != ConnectionNamespace::TCP_IPV6 {
        return Err(EndpointOptionsError::TcpNamespace { namespace }.into());
    }

    let mut transport = TcpTransport::with_config(
        StdTcpProvider::new(),
        keypair.clone(),
        StdEntropy::new(),
        options.tcp_config.clone(),
    )
    .map_err(EndpointOptionsError::InvalidLimit)?;
    for addr in tcp_addrs {
        // Bound here, like a QUIC socket is: `Endpoint::listen` then listens
        // on what is already bound, and a caller that asked for port 0 learns
        // which port it got before the first event.
        transport.listen(addr).map_err(BindError::Listen)?;
    }
    Ok(transport)
}

#[cfg(any(feature = "quic", feature = "tcp"))]
fn insert_member<T: minip2p_transport::BlockingTransport + Send + 'static>(
    set: &mut TransportSet,
    kind: TransportKind,
    namespaces: impl IntoIterator<Item = ConnectionNamespace>,
    transport: T,
) -> Result<(), BindError> {
    set.insert(kind, namespaces, Box::new(transport))
        .map_err(|rejected| {
            let (error, _transport) = rejected.into_parts();
            EndpointOptionsError::TransportConflict(error).into()
        })
}

/// Wraps the bound transports in the OS resources the endpoint drives them
/// with (circuits, the readiness poll, mDNS sockets, Name resolution), and
/// installs the validated capabilities through Endpoint setup.
fn build_endpoint(
    options: EndpointBuilder,
    keypair: Ed25519Keypair,
    transport: TransportSet,
    capabilities: setup::Validated,
) -> Result<Endpoint, BindError> {
    #[cfg(feature = "relay-server")]
    let ca_webtransport_certificate = options.ca_webtransport_certificate();
    let mut builder = SwarmBuilder::new(&keypair)
        .agent_version(options.agent_version)
        .simultaneous_dial_window_ms(
            u64::try_from(options.simultaneous_dial_window.as_millis()).unwrap_or(u64::MAX),
        );
    for protocol in options.protocols {
        builder = builder.protocol(protocol);
    }
    let mut acks = StreamAcks::default();
    for protocol in options.manual_ack_protocols {
        acks.set_manual(protocol, []);
    }
    #[cfg(feature = "relay")]
    let mut transport = minip2p_circuit::CircuitTransport::with_limits(
        transport,
        keypair.clone(),
        StdEntropy::new(),
        options.circuit_limits.clone(),
    )
    .map_err(EndpointOptionsError::InvalidLimit)?;
    #[cfg(not(feature = "relay"))]
    let mut transport = transport;
    let mut poll = SharedPoll::new()
        .map_err(|error| BindError::readiness_poll("opening the readiness poll", &error))?;
    poll.attach(&mut transport)
        .map_err(|error| BindError::readiness_poll("attaching the transport", &error))?;
    let resolver = dial::Resolver::new(poll.wake_handle());
    #[cfg(feature = "mdns")]
    let mdns_sockets = match capabilities.mdns() {
        Some(config) => {
            let mut sockets =
                minip2p_mdns::MdnsSockets::new(config).map_err(BindError::MdnsSocket)?;
            // The sockets only wake the endpoint's wait; the next batch's
            // mDNS tick reads them, and a refresh re-registers what it
            // rebuilds.
            poll.attach_host_source(&mut sockets)
                .map_err(|error| BindError::readiness_poll("attaching the mDNS sockets", &error))?;
            Some(sockets)
        }
        None => None,
    };
    let core = builder.build_core(transport, StdEntropy::new())?;
    let mut engine = Engine::new(
        core,
        u64::try_from(options.connect_deadline.as_millis()).unwrap_or(u64::MAX),
        acks,
    );
    setup::install(
        &mut engine,
        capabilities,
        &keypair,
        #[cfg(feature = "relay")]
        Some(CircuitOps::circuit_transport()),
        #[cfg(feature = "mdns")]
        mdns_sockets,
    )?;
    // Relay and AutoNAT server addresses may name a host; the endpoint
    // resolves those off the driver, like Connection-attempt candidates.
    #[cfg(feature = "autonat")]
    if let Some(nat) = engine.nat.as_mut() {
        nat.park_named_dials();
    }
    Ok(Endpoint {
        engine,
        clock: StdClock::new(),
        resolver,
        #[cfg(feature = "autonat")]
        nat_dials: Vec::new(),
        #[cfg(feature = "relay-server")]
        ca_webtransport_certificate,
        #[cfg(feature = "quic")]
        webtransport_certificate: None,
        poll,
        #[cfg(all(test, feature = "quic"))]
        raw_events: std::collections::VecDeque::new(),
    })
}

/// Raw swarm access for the crate's own tests, bypassing the engine.
#[cfg(all(test, feature = "quic"))]
impl Endpoint {
    pub(crate) fn core(&self) -> &minip2p_swarm::SwarmCore<EndpointTransport, StdEntropy> {
        &self.engine.core
    }

    #[cfg(any(feature = "relay", feature = "tcp"))]
    pub(crate) fn core_mut(
        &mut self,
    ) -> &mut minip2p_swarm::SwarmCore<EndpointTransport, StdEntropy> {
        &mut self.engine.core
    }

    /// One swarm poll whose events skip the engine.
    pub(crate) fn raw_poll(&mut self) -> Result<Vec<crate::SwarmEvent>, Error> {
        self.harvest(Duration::ZERO)?;
        let now = self.now();
        self.engine.core.poll(now)
    }

    /// The next swarm event within `timeout`, skipping the engine. A poll's
    /// other events are kept for the next call.
    pub(crate) fn raw_poll_next(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<crate::SwarmEvent>, Error> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(event) = self.raw_events.pop_front() {
                return Ok(Some(event));
            }
            let polled = self.raw_poll()?;
            self.raw_events.extend(polled);
            if self.raw_events.is_empty() {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Ok(None);
                }
                let budget = (deadline - now).min(Duration::from_millis(10));
                self.harvest(budget)?;
            }
        }
    }
}

/// Test-only convenience over [`Endpoint::wait`]: the next event, or `None`
/// once the deadline passes. Interruptions are retried.
#[cfg(all(test, feature = "quic"))]
pub(crate) trait NextEvent {
    fn next_event(
        &mut self,
        deadline: impl Into<WaitDeadline>,
    ) -> Result<Option<EndpointEvent>, Error>;
}

#[cfg(all(test, feature = "quic"))]
impl NextEvent for Endpoint {
    fn next_event(
        &mut self,
        deadline: impl Into<WaitDeadline>,
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
    use crate::ConnectionCloseReason;
    #[cfg(feature = "pubsub")]
    use crate::GossipsubEvent;
    #[cfg(feature = "relay")]
    use crate::NatEvent;
    use crate::SwarmEvent;
    use crate::{ConnectFailure, ConnectOutcome};
    #[cfg(feature = "relay-server")]
    use crate::{RelayServerEvent, RelayServerRuntimeError, RelayServerRuntimeErrorKind};
    #[cfg(any(feature = "tcp", feature = "relay"))]
    use minip2p_transport::InvalidLimit;
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
        let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
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

    /// A lookup that reports each name it is asked for on `started` and
    /// then blocks until the test sends it an answer (or drops the sender).
    fn stalling_lookup() -> (
        dial::Lookup,
        std::sync::mpsc::Receiver<String>,
        std::sync::mpsc::Sender<dial::Answer>,
    ) {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (answer_tx, answer_rx) = std::sync::mpsc::channel::<dial::Answer>();
        let answer_rx = std::sync::Mutex::new(answer_rx);
        let lookup: dial::Lookup = Arc::new(move |host: &str| {
            drop(started_tx.send(host.to_string()));
            let answer = answer_rx.lock().expect("lookup lock").recv();
            answer.unwrap_or_else(|_| Err("test ended".to_string()))
        });
        (lookup, started_rx, answer_tx)
    }

    fn quic_endpoint() -> Endpoint {
        Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind")
    }

    fn with_lookup(endpoint: &mut Endpoint, lookup: dial::Lookup) {
        let wake = endpoint.poll.wake_handle();
        endpoint.resolver = dial::Resolver::with_lookup(move || wake.wake(), lookup);
    }

    /// `addr` with its host swapped for the name `host`.
    fn named(addr: &PeerAddr, host: &str) -> PeerAddr {
        let mut protocols = addr.transport().protocols().to_vec();
        *protocols.first_mut().expect("a host") = Protocol::Dns(host.to_string());
        PeerAddr::new(Multiaddr::from_protocols(protocols), addr.peer_id().clone())
            .expect("named peer addr")
    }

    #[test]
    fn a_stalled_lookup_does_not_hold_up_other_attempts() {
        let mut listener = quic_endpoint();
        let addr = listener.listen().expect("listen");
        let _driver = Driven::new(listener);
        let mut dialer = quic_endpoint();
        let (lookup, started, _answer) = stalling_lookup();
        with_lookup(&mut dialer, lookup);

        let stalled_peer = Ed25519Keypair::generate().peer_id();
        let stalled = dialer
            .connect(named(
                &PeerAddr::new(addr.transport().clone(), stalled_peer).expect("addr"),
                "stalled.invalid",
            ))
            .expect("connect returns without waiting for the lookup");
        assert_eq!(started.recv().expect("lookup started"), "stalled.invalid");

        let id = dialer.connect(addr).expect("connect");
        assert!(matches!(
            connect_outcome(&mut dialer, id),
            ConnectOutcome::Connected { .. }
        ));
        assert!(
            dialer.engine.connect.is_pending(stalled),
            "the stalled attempt is still waiting on its lookup"
        );
    }

    #[test]
    fn an_ip_candidate_dials_while_a_name_in_the_same_attempt_resolves() {
        let mut listener = quic_endpoint();
        let addr = listener.listen().expect("listen");
        let _driver = Driven::new(listener);
        let mut dialer = quic_endpoint();
        let (lookup, _started, _answer) = stalling_lookup();
        with_lookup(&mut dialer, lookup);

        let id = dialer
            .connect(vec![named(&addr, "stalled.invalid"), addr.clone()])
            .expect("connect");
        let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
            panic!("the /ip4 candidate must not wait for the name");
        };
        assert_eq!(
            dialer.connection_remote_addr(conn_id),
            Some(addr.transport())
        );
    }

    #[test]
    fn attempts_naming_one_host_share_a_lookup_and_its_failure() {
        let mut dialer = quic_endpoint();
        let (lookup, started, answer) = stalling_lookup();
        with_lookup(&mut dialer, lookup);
        let peer = Ed25519Keypair::generate().peer_id();
        let target = |text: &str| {
            PeerAddr::new(text.parse().expect("addr"), peer.clone()).expect("peer addr")
        };

        let first = dialer
            .connect(target("/dns/gone.invalid/udp/4001/quic-v1"))
            .expect("connect");
        let second = dialer
            .connect(target("/dns4/gone.invalid/udp/4002/quic-v1"))
            .expect("connect");
        assert_eq!(started.recv().expect("lookup started"), "gone.invalid");
        assert!(
            started.recv_timeout(Duration::from_millis(200)).is_err(),
            "the second attempt joined the first lookup"
        );
        answer
            .send(Err("NXDOMAIN".to_string()))
            .expect("lookup waiting");

        // The lookup thread wakes the driver; that is not the caller's
        // interrupt, so `wait` keeps going instead of surfacing it.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut unsettled = vec![first, second];
        while !unsettled.is_empty() {
            match dialer.wait(deadline).expect("wait") {
                EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                    connect_id,
                    outcome,
                    ..
                }) => {
                    let ConnectOutcome::Failed(ConnectFailure::NoUsableRoute {
                        candidates, ..
                    }) = outcome
                    else {
                        panic!("expected NoUsableRoute, got {outcome:?}");
                    };
                    assert!(
                        candidates[0].reason.contains("gone.invalid")
                            && candidates[0].reason.contains("NXDOMAIN"),
                        "the reason names the host: {}",
                        candidates[0].reason
                    );
                    unsettled.retain(|id| *id != connect_id);
                }
                EndpointWaitOutcome::Event(_) => {}
                other => panic!("expected both attempts to settle, got {other:?}"),
            }
        }
    }

    /// A lookup's wake and an event queued in the same batch both arrive:
    /// the event is returned first, the wake stays pending behind it, and
    /// neither is lost or reported as the caller's interrupt.
    #[test]
    fn a_resolver_wake_and_a_queued_event_in_one_batch_both_arrive() {
        let mut dialer = quic_endpoint();
        let (lookup, started, answer) = stalling_lookup();
        with_lookup(&mut dialer, lookup);
        let peer = Ed25519Keypair::generate().peer_id();
        let named_target = PeerAddr::new(
            "/dns/gone.invalid/udp/4001/quic-v1".parse().expect("addr"),
            peer.clone(),
        )
        .expect("peer addr");
        let connect_id = dialer.connect(named_target).expect("connect");
        assert_eq!(started.recv().expect("lookup started"), "gone.invalid");

        answer
            .send(Err("NXDOMAIN".to_string()))
            .expect("lookup waiting");
        // Let the lookup thread queue its answer and wake the poll.
        std::thread::sleep(Duration::from_millis(100));
        let other = Ed25519Keypair::generate().peer_id();
        dialer.engine.events.push_back(EndpointEvent::PingTimeout {
            peer_id: other.clone(),
            conn_id: ConnectionId::new(1),
        });

        let (mut settled, mut queued) = (false, false);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !(settled && queued) {
            match dialer.wait(deadline).expect("wait") {
                EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                    connect_id: id,
                    ..
                }) if id == connect_id => settled = true,
                EndpointWaitOutcome::Event(EndpointEvent::PingTimeout { peer_id, .. })
                    if peer_id == other =>
                {
                    queued = true;
                }
                EndpointWaitOutcome::Event(_) => {}
                other => panic!("lost something: settled {settled}, queued {queued}: {other:?}"),
            }
        }
    }

    #[test]
    fn cancelling_a_resolving_attempt_is_immediate_and_the_late_answer_is_dropped() {
        let mut listener = quic_endpoint();
        let addr = listener.listen().expect("listen");
        let _driver = Driven::new(listener);
        let mut dialer = quic_endpoint();
        let (lookup, started, answer) = stalling_lookup();
        with_lookup(&mut dialer, lookup);

        let id = dialer
            .connect(named(&addr, "late.invalid"))
            .expect("connect");
        started.recv().expect("lookup started");
        dialer.cancel_connect(id);
        assert!(matches!(
            dialer.poll().expect("poll").as_slice(),
            [EndpointEvent::ConnectSettled {
                connect_id,
                outcome: ConnectOutcome::Cancelled,
                ..
            }] if *connect_id == id
        ));

        // An answer that would reach the live listener, had anything kept it.
        answer
            .send(Ok(vec![std::net::Ipv4Addr::LOCALHOST.into()]))
            .expect("lookup waiting");
        let until = std::time::Instant::now() + Duration::from_millis(500);
        while let Some(event) = dialer.next_event(until).expect("drive") {
            assert!(
                !matches!(
                    event,
                    EndpointEvent::ConnectSettled { .. }
                        | EndpointEvent::ConnectionEstablished { .. }
                ),
                "the late answer must have no effect, got {event:?}"
            );
        }
        assert!(dialer.connected_peers().is_empty());
    }

    #[test]
    fn an_answer_after_the_deadline_leaves_the_attempt_timed_out() {
        let mut dialer = Endpoint::builder()
            .connect_deadline(Duration::from_millis(50))
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind");
        let (lookup, started, answer) = stalling_lookup();
        with_lookup(&mut dialer, lookup);
        let target = PeerAddr::new(
            "/dns/slow.invalid/udp/4001/quic-v1".parse().expect("addr"),
            Ed25519Keypair::generate().peer_id(),
        )
        .expect("peer addr");

        let id = dialer.connect(target).expect("connect");
        started.recv().expect("lookup started");
        // The answer lands past the deadline but before the next poll: the
        // attempt already ran out of time, so the answer must not decide it.
        std::thread::sleep(Duration::from_millis(100));
        answer
            .send(Err("NXDOMAIN".to_string()))
            .expect("lookup waiting");
        // Give the lookup thread time to queue its answer.
        std::thread::sleep(Duration::from_millis(50));
        match connect_outcome(&mut dialer, id) {
            ConnectOutcome::Failed(ConnectFailure::Timeout { candidates, .. }) => {
                assert!(candidates[0].reason.contains("resolving"), "{candidates:?}");
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[test]
    fn a_dns_candidate_connects_through_the_system_resolver() {
        let mut listener = quic_endpoint();
        let addr = listener.listen().expect("listen");
        let _driver = Driven::new(listener);
        let mut dialer = quic_endpoint();

        let mut protocols = addr.transport().protocols().to_vec();
        *protocols.first_mut().expect("a host") = Protocol::Dns4("localhost".to_string());
        let target = PeerAddr::new(Multiaddr::from_protocols(protocols), addr.peer_id().clone())
            .expect("named peer addr");
        let id = dialer.connect(target).expect("connect");
        let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
            panic!("localhost must resolve and connect");
        };
        assert_eq!(
            dialer.connection_remote_addr(conn_id),
            Some(addr.transport())
        );
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
        let ConnectOutcome::Connected { conn_id, .. } = connect_outcome(&mut dialer, id) else {
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
        // TEST-NET-1 is never a local address: a socket bind would fail.
        assert!(matches!(
            Endpoint::builder()
                .discovery_config(config)
                .listen_on("/ip4/192.0.2.1/udp/0/quic-v1")
                .expect("quic listen address")
                .bind()
                .err(),
            Some(BindError::Discovery(
                crate::DiscoveryConfigError::ZeroBeaconInterval
            ))
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
                EndpointOptionsError::UnsupportedListenShape { expected, .. }
                    if expected.contains("DNS")
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
                EndpointOptionsError::UnsupportedListenShape { expected, .. }
                    if expected.contains("p2p-circuit")
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
                EndpointOptionsError::DuplicateQuicFamily {
                    family: IpFamily::Ipv4,
                    ..
                }
            ),
            "{duplicate}"
        );
    }

    #[test]
    fn webtransport_listens_share_the_quic_socket_of_their_family() {
        let builder = || {
            Endpoint::builder()
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
                .expect("quic-v1")
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
                .expect("WebTransport on the same socket")
        };
        for rejected in [
            // Another port: QUIC has one socket per family.
            "/ip4/127.0.0.1/udp/4001/quic-v1/webtransport",
            // The same shape twice.
            "/ip4/127.0.0.1/udp/0/quic-v1/webtransport",
        ] {
            let Err(error) = builder().listen_on(rejected) else {
                panic!("{rejected} must be refused");
            };
            assert!(
                matches!(error, EndpointOptionsError::DuplicateQuicFamily { .. }),
                "{rejected}: {error}"
            );
        }
        let Err(certhash) = Endpoint::builder().listen_on(
            "/ip4/127.0.0.1/udp/0/quic-v1/webtransport/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g",
        ) else {
            panic!("a listen certhash must be refused");
        };
        assert!(
            matches!(
                &certhash,
                EndpointOptionsError::UnsupportedListenShape { expected, .. }
                    if expected.contains("without /certhash")
            ),
            "{certhash}"
        );
    }

    /// The `localhost` leaf and key from the QUIC transport's CA fixtures.
    #[cfg(feature = "quic")]
    const CA_LEAF: &[u8] =
        include_bytes!("../../../../transports/quic/tests/fixtures/ca/localhost.pem");
    #[cfg(feature = "quic")]
    const CA_KEY: &[u8] =
        include_bytes!("../../../../transports/quic/tests/fixtures/ca/localhost.key");

    #[cfg(feature = "quic")]
    #[test]
    fn webtransport_certificate_pem_names_what_is_missing() {
        let two_keys = [CA_KEY, CA_KEY].concat();
        for (chain, key, expected) in [
            (CA_KEY, CA_KEY, "no `BEGIN CERTIFICATE`"),
            (CA_LEAF, CA_LEAF, "no `BEGIN PRIVATE KEY`"),
            (CA_LEAF, two_keys.as_slice(), "2 private keys"),
        ] {
            let Err(error) = Endpoint::builder().webtransport_certificate_pem(chain, key) else {
                panic!("{expected}: the PEM must be refused");
            };
            assert!(
                matches!(
                    &error,
                    EndpointOptionsError::WebTransportCertificatePem { problem }
                        if problem.contains(expected)
                ),
                "{expected}: {error}"
            );
        }
    }

    #[cfg(feature = "quic")]
    #[test]
    fn webtransport_certificate_without_a_webtransport_listener_fails_bind() {
        let result = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic-v1")
            .webtransport_certificate_pem(CA_LEAF, CA_KEY)
            .expect("fixture PEM")
            .bind();
        assert!(matches!(
            result,
            Err(BindError::Options(
                EndpointOptionsError::WebTransportCertificateWithoutListener
            ))
        ));
    }

    #[cfg(feature = "quic")]
    #[test]
    fn ca_webtransport_listener_reports_a_hash_free_address() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
            .expect("WebTransport")
            .webtransport_certificate_pem(CA_LEAF, CA_KEY)
            .expect("fixture PEM")
            .bind()
            .expect("bind with the fixture certificate");
        let addrs = endpoint.listen_all().expect("listen_all");
        assert!(
            matches!(
                addrs.as_slice(),
                [addr] if addr.transport().is_webtransport()
                    && addr.transport().certhashes().next().is_none()
            ),
            "{addrs:?}"
        );
    }

    #[cfg(feature = "quic")]
    #[test]
    fn set_webtransport_certificate_pem_needs_ca_mode_and_a_matching_key() {
        const CHAIN: &[u8] =
            include_bytes!("../../../../transports/quic/tests/fixtures/ca/chain.pem");
        const CHAIN_KEY: &[u8] =
            include_bytes!("../../../../transports/quic/tests/fixtures/ca/chain.key");
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
            .expect("WebTransport")
            .webtransport_certificate_pem(CA_LEAF, CA_KEY)
            .expect("fixture PEM")
            .bind()
            .expect("bind with the fixture certificate");
        endpoint
            .set_webtransport_certificate_pem(CHAIN, CHAIN_KEY)
            .expect("replace");
        assert!(matches!(
            endpoint.set_webtransport_certificate_pem(CA_LEAF, CHAIN_KEY),
            Err(SetWebTransportCertificateError::Invalid { reason })
                if reason.contains("does not match")
        ));

        let mut derived = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
            .expect("WebTransport")
            .bind()
            .expect("bind");
        assert_eq!(
            derived.set_webtransport_certificate_pem(CHAIN, CHAIN_KEY),
            Err(SetWebTransportCertificateError::NotConfigured)
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
            panic!("listen_default after IPv4 QUIC must fail");
        };
        assert!(
            matches!(
                &error,
                EndpointOptionsError::DuplicateQuicFamily {
                    family: IpFamily::Ipv4,
                    ..
                }
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
            .core()
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
        // peer, so two paths to one host would be the second replacing the
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
        let id = endpoint.core_mut().dial(&target).expect("the dial starts");
        assert_eq!(id.namespace(), ConnectionNamespace::TCP_IPV6);
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn a_tcp_config_that_breaks_the_yamux_invariants_is_refused_at_bind() {
        let mut config = TcpConfig::default();
        config.yamux.max_frame_len = 0;
        let Err(error) = Endpoint::builder()
            .tcp_config(config)
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
        else {
            panic!("a zero frame length cannot work");
        };
        assert!(
            matches!(
                error,
                BindError::Options(EndpointOptionsError::InvalidLimit(InvalidLimit {
                    field: "TcpConfig::yamux",
                    ..
                }))
            ),
            "got {error}"
        );
    }

    #[cfg(all(feature = "relay", feature = "quic"))]
    #[test]
    fn circuit_limits_that_break_the_yamux_invariants_are_refused_at_bind() {
        let mut limits = CircuitLimits::default();
        limits.yamux.max_frame_len = 0;
        let Err(error) = Endpoint::builder()
            .circuit_limits(limits)
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
        else {
            panic!("a zero frame length cannot work");
        };
        assert!(
            matches!(
                error,
                BindError::Options(EndpointOptionsError::InvalidLimit(InvalidLimit {
                    field: "CircuitLimits::yamux",
                    ..
                }))
            ),
            "got {error}"
        );
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
            matches!(
                error,
                BindError::Options(EndpointOptionsError::TcpNamespace {
                    namespace: ConnectionNamespace::QUIC_IPV4
                })
            ),
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

    /// An `Instant` that has already passed.
    fn past_instant() -> std::time::Instant {
        let now = std::time::Instant::now();
        now.checked_sub(Duration::from_secs(1)).unwrap_or(now)
    }

    #[test]
    fn wait_with_a_passed_instant_delivers_a_queued_event() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");
        let peer = Ed25519Keypair::generate().peer_id();
        endpoint
            .engine
            .events
            .push_back(EndpointEvent::ConnectionClosed {
                peer_id: peer.clone(),
                conn_id: ConnectionId::new(1),
                reason: ConnectionCloseReason::Local,
            });
        assert!(matches!(
            endpoint.wait(past_instant()).expect("wait past deadline"),
            EndpointWaitOutcome::Event(EndpointEvent::ConnectionClosed { peer_id, .. })
                if peer_id == peer
        ));
    }

    #[test]
    fn wait_with_a_passed_instant_drives_a_connect_to_settlement() {
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

        // A loop whose own timer has gone stale: every call gets a past
        // deadline, yet each call must still drive the endpoint.
        let connect_id = dialer.connect(&listen_addr).expect("connect");
        let stale = past_instant();
        let give_up = std::time::Instant::now() + Duration::from_secs(10);
        let outcome = loop {
            assert!(
                std::time::Instant::now() < give_up,
                "a stale deadline must not stop the connect from settling"
            );
            if let EndpointWaitOutcome::Event(EndpointEvent::ConnectSettled {
                connect_id: settled,
                outcome,
                ..
            }) = dialer.wait(stale).expect("wait past deadline")
                && settled == connect_id
            {
                break outcome;
            }
        };
        assert!(
            matches!(outcome, ConnectOutcome::Connected { .. }),
            "got {outcome:?}"
        );
    }

    #[test]
    fn a_caller_clock_check_ends_a_fixed_deadline_loop_while_events_keep_arriving() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");
        let peer = Ed25519Keypair::generate().peer_id();
        let arrive = |endpoint: &mut Endpoint| {
            endpoint
                .engine
                .events
                .push_back(EndpointEvent::ConnectionClosed {
                    peer_id: peer.clone(),
                    conn_id: ConnectionId::new(1),
                    reason: ConnectionCloseReason::Local,
                });
        };
        let deadline = std::time::Instant::now() + Duration::from_millis(50);
        loop {
            // The documented guard: `wait` serves events past the deadline.
            if std::time::Instant::now() >= deadline {
                break;
            }
            arrive(&mut endpoint);
            assert!(matches!(
                endpoint.wait(deadline).expect("wait"),
                EndpointWaitOutcome::Event(_)
            ));
        }
        assert!(std::time::Instant::now() < deadline + Duration::from_secs(1));
        // Without the guard, a steady stream keeps the loop going.
        arrive(&mut endpoint);
        assert!(matches!(
            endpoint.wait(deadline).expect("wait past deadline"),
            EndpointWaitOutcome::Event(_)
        ));
    }

    #[test]
    fn a_pending_interrupt_is_reported_once_even_past_the_deadline() {
        let mut endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");
        endpoint.wait_handle().interrupt();
        endpoint.wait_handle().interrupt();

        // A pending interrupt outranks an expired deadline, so a host's
        // non-blocking pump still notices it; the two calls are one.
        assert!(matches!(
            endpoint.wait(past_instant()).expect("wait past deadline"),
            EndpointWaitOutcome::Interrupted
        ));
        assert!(matches!(
            endpoint.wait(past_instant()).expect("wait past deadline"),
            EndpointWaitOutcome::Deadline
        ));
    }

    /// A steady stream of host wakes cannot hold a wait past its deadline:
    /// it runs at most one batch for them, and newer wakes stay pending.
    #[test]
    fn a_stream_of_wakes_does_not_hold_a_wait_past_its_deadline() {
        let mut endpoint = quic_endpoint();
        let wake = endpoint.poll.wake_handle();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sent = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = {
            let (stop, sent) = (std::sync::Arc::clone(&stop), std::sync::Arc::clone(&sent));
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    wake.wake();
                    sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    std::thread::yield_now();
                }
            })
        };
        // The stream is flowing before the wait starts.
        while sent.load(std::sync::atomic::Ordering::Relaxed) < 100 {
            std::thread::yield_now();
        }
        let passes = endpoint.engine.stats.capability_passes;
        let outcome = endpoint.wait(past_instant()).expect("wait past deadline");
        let batches = endpoint.engine.stats.capability_passes - passes;
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        waker.join().expect("waker thread");
        assert!(
            matches!(outcome, EndpointWaitOutcome::Deadline),
            "{outcome:?}"
        );
        // The one drive every wait makes, plus at most one for a wake.
        assert!(batches <= 2, "ran {batches} batches past the deadline");
    }

    #[cfg(feature = "relay")]
    #[test]
    fn wait_with_duration_zero_still_drains_queued_events() {
        let mut endpoint = Endpoint::builder()
            .nat_config(super::nat_tests::idle_nat_config())
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind loopback endpoint");
        let peer = Ed25519Keypair::generate().peer_id();
        endpoint
            .engine
            .events
            .push_back(EndpointEvent::ConnectionClosed {
                peer_id: peer.clone(),
                conn_id: ConnectionId::new(1),
                reason: ConnectionCloseReason::Local,
            });
        assert!(matches!(
            endpoint.wait(Duration::ZERO).expect("zero-duration drain"),
            EndpointWaitOutcome::Event(EndpointEvent::ConnectionClosed { peer_id, .. })
                if peer_id == peer
        ));
        assert!(
            endpoint.engine.events.is_empty(),
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
            endpoint.wait(WaitDeadline::NEVER).expect("wait endpoint"),
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

    #[cfg(feature = "relay")]
    #[test]
    fn wait_delivers_queued_nat_events_once() {
        let mut endpoint = Endpoint::builder()
            .nat_config(super::nat_tests::idle_nat_config())
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind NAT endpoint");
        endpoint
            .engine
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
            .engine
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

    #[cfg(all(feature = "relay", feature = "pubsub", feature = "relay-server"))]
    #[test]
    fn capability_events_leave_once_in_endpoint_order() {
        let mut endpoint = Endpoint::builder()
            .nat_config(super::nat_tests::idle_nat_config())
            .gossipsub()
            .relay_server()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind capability endpoint");
        let peer = Ed25519Keypair::generate().peer_id();
        endpoint
            .engine
            .gossipsub
            .as_mut()
            .unwrap()
            .events
            .push_back(GossipsubEvent::PeerSubscribed {
                peer: peer.clone(),
                topic: "test".into(),
            });
        let nat = endpoint.engine.nat.as_mut().unwrap();
        nat.push_event(NatEvent::FellBackToRelay {
            connect_id: ConnectId::from_u64(99),
            peer: peer.clone(),
            reason: minip2p_nat::UpgradeStop::PunchFailed { rounds: 3 },
        });
        nat.push_event(NatEvent::ReachabilityChanged {
            old: ReachabilityState::Unknown,
            new: ReachabilityState::Private,
            confirmed_addrs: Vec::new(),
        });
        endpoint
            .engine
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

    /// A transport with nothing to do whose `poll` fails while `fail` is set.
    struct FlakyPollTransport {
        fail: Arc<AtomicBool>,
    }

    impl Transport for FlakyPollTransport {
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
            _: Bytes,
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
        fn ack_stream(
            &mut self,
            _: ConnectionId,
            _: StreamId,
            _: usize,
        ) -> Result<(), TransportError> {
            Ok(())
        }
        fn close(&mut self, _: ConnectionId) -> Result<(), TransportError> {
            Err(TransportError::Unsupported {
                operation: "close connection",
            })
        }
        fn poll(
            &mut self,
            _: minip2p_core::platform::Now,
        ) -> Result<Vec<minip2p_transport::TransportEvent>, TransportError> {
            if self.fail.load(Ordering::SeqCst) {
                return Err(TransportError::PollError {
                    reason: "injected".into(),
                });
            }
            Ok(Vec::new())
        }
    }

    impl minip2p_transport::PollSource for FlakyPollTransport {
        fn attach(
            &mut self,
            _: minip2p_transport::mio::Registry,
            _: minip2p_transport::TokenSpace,
            _: std::sync::Arc<minip2p_transport::mio::Waker>,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn dispatch(&mut self, _: &minip2p_transport::mio::event::Event) {}
    }

    /// Events already queued survive a `poll` that fails, and come out of the
    /// next one.
    #[test]
    fn a_failed_poll_keeps_queued_events_for_the_next() {
        let fail = Arc::new(AtomicBool::new(false));
        let mut set = TransportSet::new();
        insert_member(
            &mut set,
            TransportKind::Tcp,
            [ConnectionNamespace::TCP_IPV4],
            FlakyPollTransport {
                fail: Arc::clone(&fail),
            },
        )
        .expect("insert transport");
        let mut endpoint = Endpoint::builder().bind_over(set).expect("build");
        let peer = Ed25519Keypair::generate().peer_id();
        endpoint
            .engine
            .events
            .push_back(EndpointEvent::ConnectionClosed {
                peer_id: peer.clone(),
                conn_id: ConnectionId::new(1),
                reason: ConnectionCloseReason::Local,
            });

        fail.store(true, Ordering::SeqCst);
        endpoint.poll().expect_err("injected poll failure");
        fail.store(false, Ordering::SeqCst);

        let events = endpoint.poll().expect("poll");
        assert!(
            events.iter().any(|event| matches!(
                event,
                EndpointEvent::ConnectionClosed { peer_id, .. } if peer_id == &peer
            )),
            "the queued event must survive the failed poll: {events:?}"
        );
    }

    /// A close whose drain fails still returns the events queued before it,
    /// alongside the error.
    #[test]
    fn close_reports_queued_events_with_a_drain_failure() {
        let fail = Arc::new(AtomicBool::new(true));
        let mut set = TransportSet::new();
        insert_member(
            &mut set,
            TransportKind::Tcp,
            [ConnectionNamespace::TCP_IPV4],
            FlakyPollTransport { fail },
        )
        .expect("insert transport");
        let mut endpoint = Endpoint::builder().bind_over(set).expect("build");
        let peer = Ed25519Keypair::generate().peer_id();
        endpoint
            .engine
            .events
            .push_back(EndpointEvent::ConnectionClosed {
                peer_id: peer.clone(),
                conn_id: ConnectionId::new(1),
                reason: ConnectionCloseReason::Local,
            });

        let report = endpoint.close();
        assert!(
            matches!(
                report.events.as_slice(),
                [EndpointEvent::ConnectionClosed { peer_id, .. }] if peer_id == &peer
            ),
            "{:?}",
            report.events
        );
        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
        assert_eq!(report.outcome, CloseOutcome::Failed);
    }

    #[test]
    fn closing_an_idle_endpoint_drains_with_nothing_unfinished() {
        let endpoint = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind");

        let report = endpoint.close();
        assert_eq!(report.outcome, CloseOutcome::Drained);
        assert!(report.unfinished.is_empty(), "{:?}", report.unfinished);
        assert!(report.errors.is_empty(), "{:?}", report.errors);
    }

    /// A zero deadline tears down at once and names the live connection it
    /// did not wait for.
    #[test]
    fn closing_within_zero_reports_the_live_connection_unfinished() {
        let mut listener = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind listener");
        let addr = listener.listen().expect("listen");
        let _listener = Driven::new(listener);
        let mut dialer = Endpoint::builder()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind dialer");
        dialer.connect(addr.clone()).expect("connect");
        let EndpointEvent::ConnectionEstablished { conn_id, .. } =
            wait_for(&mut dialer, "connection", |event| {
                matches!(event, EndpointEvent::ConnectionEstablished { .. })
            })
        else {
            panic!("the connection predicate returned an unrelated event")
        };

        let report = dialer.close_within(Duration::ZERO);
        assert_eq!(report.outcome, CloseOutcome::DeadlineExpired);
        assert_eq!(report.unfinished, [(conn_id, Some(addr.peer_id().clone()))]);
    }

    /// A dial the transport still holds is unfinished teardown, not a drain.
    #[test]
    fn closing_within_zero_reports_a_pending_dial_unfinished() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind silent socket");
        let port = silent.local_addr().expect("silent addr").port();
        let peer = Ed25519Keypair::generate().peer_id();
        let target = PeerAddr::new(
            format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
                .parse()
                .expect("addr"),
            peer.clone(),
        )
        .expect("peer addr");
        let mut dialer = quic_endpoint();
        dialer.connect(target).expect("connect");

        let report = dialer.close_within(Duration::ZERO);
        assert_eq!(report.outcome, CloseOutcome::DeadlineExpired);
        assert!(
            matches!(report.unfinished.as_slice(), [(_, Some(unfinished))] if *unfinished == peer),
            "{:?}",
            report.unfinished
        );
    }

    #[cfg(feature = "relay")]
    #[test]
    fn wait_honors_expired_deadline_with_active_driver() {
        let mut endpoint = Endpoint::builder()
            .nat_config(super::nat_tests::idle_nat_config())
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind NAT endpoint");

        assert!(matches!(
            endpoint.wait(Duration::ZERO).expect("expired wait"),
            EndpointWaitOutcome::Deadline
        ));
    }

    #[cfg(feature = "relay")]
    #[test]
    fn wait_returns_application_event_produced_during_driver_poll() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut endpoint = Endpoint::builder()
            .nat_config(super::nat_tests::idle_nat_config())
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
    #[cfg(feature = "relay")]
    #[test]
    fn nat_path_and_connect_settled_follow_connection_established() {
        let mut endpoint = Endpoint::builder()
            .nat_config(super::nat_tests::idle_nat_config())
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

    #[cfg(feature = "relay")]
    #[test]
    fn wait_delivers_connect_timeout_with_an_active_driver() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut endpoint = Endpoint::builder()
            .connect_deadline(Duration::from_millis(20))
            .nat_config(super::nat_tests::idle_nat_config())
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
        // TEST-NET-1 is never a local address: a socket bind would fail.
        assert!(matches!(
            Endpoint::builder()
                .mdns_config(config)
                .listen_on("/ip4/192.0.2.1/udp/0/quic-v1")
                .expect("quic listen address")
                .bind()
                .err(),
            Some(BindError::Mdns(
                crate::MdnsConfigError::InvalidMaxPacketBytes
            ))
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

    /// Every bind failure names what failed and carries its typed cause.
    #[test]
    fn bind_errors_name_what_failed() {
        let quic = || {
            Endpoint::builder()
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
                .expect("quic listen address")
        };
        let limits = QuicLimits {
            idle_timeout_ms: 0,
            ..QuicLimits::default()
        };
        assert!(matches!(
            quic().quic_limits(limits).bind().err(),
            Some(BindError::Quic(minip2p_quic::QuicBindError::InvalidLimit {
                field: "idle_timeout_ms",
                ..
            }))
        ));
        assert!(matches!(
            Endpoint::builder().bind().err(),
            Some(BindError::Options(EndpointOptionsError::NoTransport))
        ));
        #[cfg(feature = "pubsub")]
        assert!(matches!(
            quic()
                .gossipsub_config(crate::GossipsubConfig {
                    heartbeat_interval_ms: 0,
                    ..crate::GossipsubConfig::default()
                })
                .bind()
                .err(),
            Some(BindError::Gossipsub(crate::GossipsubConfigError {
                field: "heartbeat_interval_ms",
                ..
            }))
        ));
        #[cfg(feature = "relay-server")]
        {
            let announce: Multiaddr = format!(
                "/ip4/198.51.100.7/udp/4001/quic-v1/p2p/{}",
                Ed25519Keypair::generate().peer_id()
            )
            .parse()
            .expect("announce address");
            assert!(matches!(
                quic()
                    .relay_server_announce_addrs(vec![announce.clone()])
                    .expect("valid for the peer it names")
                    .bind()
                    .err(),
                Some(BindError::Options(
                    EndpointOptionsError::RelayAnnounceWithoutServer
                ))
            ));
            // Valid for the peer it names, but this endpoint is another one.
            let Some(BindError::RelayServerAnnounce(error)) = quic()
                .relay_server()
                .relay_server_announce_addrs(vec![announce])
                .expect("valid for the peer it names")
                .bind()
                .err()
            else {
                panic!("a foreign announce address must fail the bind");
            };
            assert!(matches!(
                error.reason,
                minip2p_relay_server::RelayServerAddressErrorKind::ConflictingPeerId { .. }
            ));
        }
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
                BindError::Swarm(SwarmError::ReservedProtocol { .. })
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
            BindError::Swarm(SwarmError::ReservedProtocol { .. })
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
        assert!(endpoint.engine.relay_server.is_some());

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
                .engine
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
            .engine
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
                .engine
                .relay_server
                .as_ref()
                .unwrap()
                .agent
                .selected_addrs()
                .is_empty()
        );
    }

    #[cfg(all(feature = "relay-server", feature = "quic"))]
    #[test]
    fn relay_server_webtransport_announces_follow_the_certificate_mode() {
        let hash_free: Multiaddr = "/dns/relay.example/udp/4001/quic-v1/webtransport"
            .parse()
            .unwrap();
        let hashed: Multiaddr =
            format!("{hash_free}/certhash/uEiDDq4_xNyDorZBH3TlGazyJdOWSwvo4PUo5YHFMrvDE8g")
                .parse()
                .unwrap();
        // Announce addresses are set before the certificate: the mode is
        // checked at bind, once every option is in.
        let relay = |announce: &Multiaddr, ca: bool| {
            let builder = Endpoint::builder()
                .relay_server()
                .relay_server_announce_addrs(vec![announce.clone()])
                .expect("well-shaped announce address")
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1/webtransport")
                .expect("WebTransport");
            if ca {
                builder
                    .webtransport_certificate_pem(CA_LEAF, CA_KEY)
                    .expect("fixture PEM")
            } else {
                builder
            }
            .bind()
        };
        let reason = |result: Result<Endpoint, BindError>| match result {
            Err(BindError::RelayServerAnnounce(error)) => error.reason,
            Err(error) => panic!("unexpected bind error: {error}"),
            Ok(_) => panic!("the announce address must be refused"),
        };
        assert_eq!(
            reason(relay(&hash_free, false)),
            RelayServerAddressErrorKind::MissingCerthash
        );
        assert_eq!(
            reason(relay(&hashed, true)),
            RelayServerAddressErrorKind::UnexpectedCerthash
        );

        // At runtime too, and a refused replacement keeps the override.
        let mut ca = relay(&hash_free, true).expect("CA mode announces hash-free");
        let error = ca
            .set_relay_server_announce_addrs(vec![hashed.clone()])
            .expect_err("CA mode refuses a certhash");
        assert!(matches!(
            error,
            RelayServerControlError::InvalidAddress(RelayServerAddressError {
                index: 0,
                reason: RelayServerAddressErrorKind::UnexpectedCerthash,
                ..
            })
        ));
        let selected = ca
            .engine
            .relay_server
            .as_ref()
            .unwrap()
            .agent
            .selected_addrs();
        assert_eq!(selected, core::slice::from_ref(&hash_free));

        let mut derived = relay(&hashed, false).expect("derived mode announces a certhash");
        let error = derived
            .set_relay_server_announce_addrs(vec![hash_free])
            .expect_err("derived mode needs a certhash");
        assert!(matches!(
            error,
            RelayServerControlError::InvalidAddress(RelayServerAddressError {
                reason: RelayServerAddressErrorKind::MissingCerthash,
                ..
            })
        ));
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
            .engine
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

    #[cfg(all(feature = "relay", feature = "relay-server"))]
    #[test]
    fn nat_and_relay_address_contributions_form_a_stable_first_wins_union() {
        let mut endpoint = Endpoint::builder()
            .nat_config(super::nat_tests::idle_nat_config())
            .relay_server()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind combined endpoint");
        let nat_only: Multiaddr = "/ip4/203.0.113.1/udp/4001/quic-v1".parse().unwrap();
        let duplicate: Multiaddr = "/ip4/203.0.113.2/udp/4002/quic-v1".parse().unwrap();
        let relay_only: Multiaddr = "/ip4/203.0.113.3/udp/4003/quic-v1".parse().unwrap();
        endpoint
            .engine
            .nat
            .as_mut()
            .unwrap()
            .set_test_public_addrs(vec![nat_only.clone(), duplicate.clone()]);
        endpoint
            .engine
            .relay_server
            .as_mut()
            .unwrap()
            .agent
            .replace_announce_addrs(vec![duplicate.clone(), relay_only.clone()])
            .unwrap();
        // One batch merges the contributions; the next advertises them.
        endpoint.poll().expect("merge address contributions");
        endpoint.poll().expect("refresh identify snapshot");
        let advertised = endpoint.core().local_addresses();
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
        endpoint.set_external_addresses(vec![caller_owned.clone()]);
        endpoint
            .set_relay_server_announce_addrs(vec![relay_owned.clone()])
            .expect("replace relay addresses");
        endpoint.raw_poll().expect("refresh identify snapshot");

        let advertised = endpoint.core().local_addresses();
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
        endpoint.set_external_addresses(vec![shared.clone()]);

        endpoint
            .set_relay_server_announce_addrs(Vec::new())
            .expect("clear relay contribution");
        endpoint.raw_poll().expect("refresh identify snapshot");

        assert!(endpoint.core().local_addresses().contains(&shared));
    }

    #[test]
    fn abandoning_a_closed_stream_acks_data_left_in_the_endpoint_queue() {
        const PROTOCOL: &str = "/test/abandon-split/1";
        let bind = || {
            Endpoint::builder()
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
                .expect("quic listen address")
                .protocol(PROTOCOL)
                .bind()
                .expect("bind endpoint")
        };
        let (mut writer, mut reader) = (bind(), bind());
        let (writer_peer, reader_peer) = (writer.peer_id().clone(), reader.peer_id().clone());
        let give_up = std::time::Instant::now() + Duration::from_secs(10);
        let tick = Duration::from_millis(5);
        writer
            .connect(reader.listen().expect("listen"))
            .expect("connect");
        while !writer.is_peer_ready(&reader_peer) || !reader.is_peer_ready(&writer_peer) {
            assert!(std::time::Instant::now() < give_up, "never ready");
            writer.next_event(tick).expect("drive writer");
            reader.next_event(tick).expect("drive reader");
        }
        let (_, out_stream) = writer.open_stream(&reader_peer, PROTOCOL).expect("open");
        let (conn, stream) = loop {
            assert!(std::time::Instant::now() < give_up, "never negotiated");
            writer.next_event(tick).expect("drive writer");
            if let Some(EndpointEvent::StreamReady {
                conn_id, stream_id, ..
            }) = reader.next_event(tick).expect("drive reader")
            {
                break (conn_id, stream_id);
            }
        };
        // The reader closes first, so the writer's FIN closes the stream.
        reader
            .close_stream_write(conn, stream)
            .expect("reader close");
        loop {
            assert!(std::time::Instant::now() < give_up, "reader FIN lost");
            reader.next_event(tick).expect("drive reader");
            if let Some(EndpointEvent::StreamRemoteWriteClosed { stream_id, .. }) =
                writer.next_event(tick).expect("drive writer")
                && stream_id == out_stream
            {
                break;
            }
        }
        let conn_out = writer.core().connection_id(&reader_peer).expect("conn");
        writer
            .send_stream(conn_out, out_stream, vec![1, 2, 3])
            .expect("send");
        writer
            .close_stream_write(conn_out, out_stream)
            .expect("writer close");
        writer.next_event(tick).expect("flush writer");

        // Stage what a `wait` cut short leaves behind: the batch's data and
        // its close still in the Endpoint queue, the close already gone from
        // the swarm. Data and FIN may arrive separately, so pull until the
        // close.
        loop {
            assert!(std::time::Instant::now() < give_up, "stream never closed");
            writer.next_event(tick).expect("drive writer");
            match reader.raw_poll_next(tick).expect("poll reader") {
                Some(event @ SwarmEvent::StreamData { stream_id, .. }) if stream_id == stream => {
                    reader.engine.events.push_back(event.into());
                }
                Some(event @ SwarmEvent::StreamClosed { stream_id, .. }) if stream_id == stream => {
                    reader.engine.events.push_back(event.into());
                    break;
                }
                _ => {}
            }
        }

        reader.abandon_stream(conn, stream).expect("abandon");
        // Its three bytes were acknowledged, so the stream settled and an
        // over-acknowledgement is a no-op rather than `AckExceedsDelivered`.
        reader
            .stream_consumed(conn, stream, 4)
            .expect("stream settled");
    }
}
