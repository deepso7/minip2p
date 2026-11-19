extern crate alloc;

#[cfg(feature = "mdns")]
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

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
    // The default first-Identify deadline (`SwarmTimeouts::identify_ms`).
    IDENTIFY_TIMEOUT_MS,
    IdentifyFailure,
    IdentifyMessage,
    // The default negotiation deadline (`SwarmTimeouts::negotiation_ms`).
    OUTBOUND_NEGOTIATION_TIMEOUT_MS,
    // Part of `EndpointEvent::PingFailed`.
    PingFailure,
    SwarmError,
    SwarmErrorKind,
    SwarmEvent,
    SwarmRuntimeError,
    // The negotiation, first-Identify and ping deadlines the builders take.
    SwarmTimeouts,
};
pub use minip2p_transport::{
    ConnectionCloseReason, ConnectionId, InvalidLimit, StreamId, StreamKey, Transport,
    TransportError,
};

pub(crate) use crate::connect::DEFAULT_CONNECT_DEADLINE_MS;
pub use crate::connect::{
    CandidateFailure, ConnectFailure, ConnectId, ConnectOutcome, ConnectTarget, ConnectTargetError,
    RelayFailure,
};
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
    CircuitByteCounts, CircuitCloseReason, CircuitDirection, CircuitLeg, MeshRejectionReason,
    RateLimit, RelayServerAddrSource, RelayServerAddressError, RelayServerAddressErrorKind,
    RelayServerConfig, RelayServerConfigError, RelayServerConfigErrorKind, RelayServerEvent,
    RelayServerRuntimeError, RelayServerRuntimeErrorKind, ReservationCloseReason,
    ReservationDenialReason, Status,
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

pub use crate::endpoint::{CloseOutcome, CloseReport, ConnectionInfo, Endpoint, EndpointStats};
use crate::engine::Engine;
use crate::names::Concrete;
#[cfg(feature = "relay")]
use crate::nat::CircuitOps;
#[cfg(feature = "mdns")]
use crate::platform::PortableCarrier;
pub use crate::platform::{Platform, Portable};
#[cfg(feature = "autonat")]
use crate::setup::NatConfigError;
use crate::setup::{self, Capabilities, PlatformCaps, SetupError};
use crate::writes::WriteQueue;
pub use minip2p_core::platform::{Clock, ManualClock};

/// A portable endpoint: an [`Endpoint`] on the [`Portable`] platform, over
/// transport `T`, entropy source `E` and caller-supplied [`Clock`] `C`.
///
/// It is `Send` whenever its transport, entropy source and clock are,
/// unless `mdns` (or `smoltcp`, which enables it) is compiled in: the
/// carrier is then held as a `Box<dyn MdnsIo>`, which embedded carriers on a
/// shared stack are not.
///
/// Portable entry point for embedded systems, browsers and deterministic
/// event loops. It performs no blocking and reads time only from its
/// [`Clock`], sampled once per call. Callers drive it with
/// [`poll`](Endpoint::poll) and may inspect
/// [`next_deadline`](Endpoint::next_deadline) to decide how long their
/// platform loop can idle. Call [`close`](Endpoint::close) to notify peers
/// and collect the final events.
///
/// Every shared method is on [`Endpoint`]; the portable-only ones are
/// [`listen_on`](Endpoint::listen_on), [`next_deadline`](Endpoint::next_deadline)
/// and [`close`](Endpoint::close). Capabilities configured on
/// [`PortableEndpointBuilder`] (AutoNAT and relay, the relay server,
/// Gossipsub, signed discovery, mDNS) report through their [`EndpointEvent`]
/// variants.
pub type PortableEndpoint<T, E, C> = Endpoint<Portable<T, E, C>>;

/// The form for hosts that sample time themselves, over a [`ManualClock`].
impl<T: Transport, E: EntropySource> Endpoint<Portable<T, E, ManualClock>> {
    /// Sets the endpoint's clock to `now` and returns the endpoint, so the
    /// next call runs at that sample: `endpoint.at(now).poll()`.
    pub fn at(&mut self, now: Now) -> &mut Self {
        self.platform.clock_mut().set(now);
        self
    }
}

/// What a portable endpoint offers its capabilities: no DCUtR, circuit
/// operations only over a `CircuitTransport`, and an mDNS carrier that may
/// share the transport's stack.
fn portable_platform(has_circuits: bool) -> PlatformCaps {
    PlatformCaps {
        runs_dcutr: false,
        has_circuits,
        mdns_shares_transport: true,
    }
}

impl<T: Transport, E: EntropySource, C: Clock> Endpoint<Portable<T, E, C>> {
    /// The clock the endpoint samples, as passed to the builder.
    pub fn clock_mut(&mut self) -> &mut C {
        self.platform.clock_mut()
    }

    /// Starts listening on a transport address and returns the address the
    /// transport listens on.
    pub fn listen_on(&mut self, address: &Multiaddr) -> Result<Multiaddr, DriverError> {
        self.engine.core.listen(address)
    }

    /// Returns when the endpoint next needs to be polled: immediately while
    /// events wait to be returned, else the earliest transport, swarm,
    /// Connection-attempt, or capability timer. Compare it with the same
    /// clock the endpoint samples.
    pub fn next_deadline(&mut self) -> Option<Deadline> {
        let now = self.now();
        self.engine.next_deadline(now)
    }

    /// Drives queued writes and FINs one batch further onto the wire and
    /// returns whether none is left ([`Endpoint::has_pending_writes`]).
    ///
    /// Never blocks: a host that is about to close, or to stop driving the
    /// endpoint, calls it until it returns `true` or its own deadline
    /// passes, waiting on [`Self::next_deadline`] (and its transport's
    /// readiness) in between. Returns `true` at once, without a drive, when
    /// nothing is pending. Events the drive produced stay queued for the
    /// next [`poll`](Endpoint::poll) or [`close`](Endpoint::close); an error
    /// discards nothing either.
    pub fn flush(&mut self) -> Result<bool, DriverError> {
        if !self.has_pending_writes() {
            return Ok(true);
        }
        let now = self.now();
        let names = crate::platform::sealed::Sealed::names(&mut self.platform);
        self.engine.drive(now, names)?;
        Ok(!self.has_pending_writes())
    }

    /// [`Endpoint::close`] on a portable platform; see its docs.
    pub(crate) fn close_portable(mut self) -> CloseReport {
        // One sample for the whole teardown (and the `Drop` after it), as
        // the caller's `now` was.
        let now = self.now();
        self.closed_at = Some(now);
        // The failure is queued as an event too.
        #[cfg(feature = "mdns")]
        drop(self.engine.shutdown_mdns(now));
        let mut errors = self.disconnect_established(now);
        let mut outcome = CloseOutcome::Drained;
        // Two final drives: the first runs the swarm's deferred closes, the
        // second puts them on the wire (a smoltcp provider sends its FINs
        // only when polled).
        for _ in 0..2 {
            if let Err(error) = self.engine.drive(now, &mut Concrete) {
                errors.push(error);
                outcome = CloseOutcome::Failed;
                break;
            }
        }
        // Hand over what the swarm queued without polling again: a failed
        // drive's leftovers (a disconnect's close failure, say), or what the
        // final drive's own work produced.
        for event in self.engine.core.take_buffered_events() {
            self.engine.ingest(event, now);
        }
        #[cfg(feature = "pubsub")]
        self.engine.collect_agent_events();
        self.engine.settle(now);
        // Queued writes the transport has not ended yet die with the endpoint.
        let aborted = self.engine.writes.abort_all();
        self.engine.events.extend(aborted);
        let unfinished = self.tracked_connections();
        if outcome == CloseOutcome::Drained && !unfinished.is_empty() {
            outcome = CloseOutcome::DeadlineExpired;
        }
        CloseReport {
            outcome,
            unfinished,
            events: self.engine.take_events(),
            errors,
        }
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
pub struct PortableEndpointBuilder<E, C> {
    swarm: SwarmBuilder,
    /// The application protocols `protocol` registered, in order: the
    /// order their handles number them in.
    protocols: Vec<String>,
    identity: Ed25519Keypair,
    entropy: E,
    clock: C,
    connect_deadline_ms: u64,
    write_budget: usize,
    capabilities: Capabilities,
    /// The carrier [`Self::mdns`] hands over with `capabilities.mdns`.
    #[cfg(feature = "mdns")]
    mdns_io: Option<PortableCarrier>,
}

impl<E: EntropySource, C: Clock> PortableEndpointBuilder<E, C> {
    /// Starts a builder with explicit identity, entropy, and the clock every
    /// endpoint call samples.
    pub fn new(identity: &Ed25519Keypair, entropy: E, clock: C) -> Self {
        Self {
            swarm: SwarmBuilder::new(identity),
            protocols: Vec::new(),
            identity: identity.clone(),
            entropy,
            clock,
            connect_deadline_ms: DEFAULT_CONNECT_DEADLINE_MS,
            write_budget: crate::DEFAULT_WRITE_BUDGET,
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
        let protocol_id = protocol_id.into();
        self.protocols.push(protocol_id.clone());
        self.swarm = self.swarm.protocol(protocol_id);
        self
    }

    /// Sets how long a peer's new connection can lose a race to its current
    /// one. Default 5 seconds
    /// ([`SIMULTANEOUS_DIAL_WINDOW_MS`](minip2p_swarm::SIMULTANEOUS_DIAL_WINDOW_MS));
    /// both peers should use the same window.
    pub fn simultaneous_dial_window(mut self, window: Duration) -> Self {
        self.swarm = self.swarm.simultaneous_dial_window_ms(duration_ms(window));
        self
    }

    /// Sets the Connection-attempt deadline. Default 30 seconds.
    pub fn connect_deadline(mut self, deadline: Duration) -> Self {
        self.connect_deadline_ms = duration_ms(deadline);
        self
    }

    /// Sets how many bytes [`Endpoint::send_stream`](crate::Endpoint::send_stream)
    /// may hold, across every stream, until their streams accept them.
    /// Default [`DEFAULT_WRITE_BUDGET`](crate::DEFAULT_WRITE_BUDGET) (8 MiB);
    /// `0` queues nothing, for hosts that use `try_send_stream` and hold
    /// unsent tails themselves.
    pub fn write_budget(mut self, bytes: usize) -> Self {
        self.write_budget = bytes;
        self
    }

    /// Overrides the negotiation, first-Identify and ping deadlines
    /// (default [`SwarmTimeouts::default`]: 30 s, 30 s and 10 s). A zero deadline
    /// fails the build with [`SwarmError::ZeroTimeout`]. See the crate
    /// README's deadline table for how they relate to the connect deadline.
    pub fn timeouts(mut self, timeouts: SwarmTimeouts) -> Self {
        self.swarm = self.swarm.timeouts(timeouts);
        self
    }

    /// Adds a relay, in preference order; each call adds one.
    ///
    /// A relay is a path, not a mode: connects still race direct candidates
    /// against a leg through the relay, and the endpoint reserves a slot on
    /// the relay for inbound connections while it is not known to be public.
    /// Without [`Self::nat_config`], that is the default policy
    /// ([`ReservationPolicy::WhenPrivate`](crate::ReservationPolicy::WhenPrivate))
    /// with `dcutr = false`, since portable endpoints do not run DCUtR. For
    /// relay-only connects set [`NatConfig::force_relay`].
    ///
    /// Needs a transport with circuit operations: build with
    /// `build_with_circuits`.
    #[cfg(feature = "relay")]
    pub fn relay(mut self, relay: PeerAddr) -> Self {
        self.capabilities.relays.push(relay);
        self
    }

    /// Adds a trusted AutoNAT server, enabling probing; each call adds one.
    ///
    /// Call once per server: a reachability verdict needs a quorum of
    /// distinct servers ([`NatConfig::confidence_threshold`], 3 by default),
    /// so with fewer reachable servers reachability stays Unknown. Without
    /// [`Self::nat_config`] or a relay, the endpoint holds no reservation.
    #[cfg(feature = "autonat")]
    pub fn autonat_server(mut self, server: PeerAddr) -> Self {
        self.capabilities.autonat_servers.push(server);
        self
    }

    /// Sets the base NAT configuration, kept as given. A second call
    /// replaces the first. Relays and AutoNAT servers added through
    /// `relay` / [`Self::autonat_server`] are appended to the config's own
    /// lists, in either call order, without exact repeats.
    ///
    /// Checked at build, after the merge (`PortableBuildError::NatConfig`).
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
    /// with [`Endpoint::set_relay_server_accepting`]; its events
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
        self.discovery_config(BeaconConfig::default())
    }

    /// Enables signed-beacon discovery with explicit beacon policy,
    /// validated at build.
    #[cfg(feature = "discovery")]
    pub fn discovery_config(mut self, config: BeaconConfig) -> Self {
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
    ) -> Result<PortableEndpoint<T, E, C>, PortableBuildError> {
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
    ) -> Result<PortableEndpoint<CircuitTransport<T, R>, E, C>, PortableBuildError> {
        self.assemble(transport, Some(CircuitOps::circuit_transport()))
    }

    /// Validates the capabilities, builds the swarm over `transport`, and
    /// installs them through Endpoint setup.
    fn assemble<T: Transport>(
        self,
        transport: T,
        #[cfg(feature = "relay")] circuits: Option<CircuitOps<T>>,
    ) -> Result<PortableEndpoint<T, E, C>, PortableBuildError> {
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
        engine.writes = WriteQueue::new(self.write_budget);
        for protocol in &self.protocols {
            engine.protocols.intern(protocol)?;
        }
        setup::install(
            &mut engine,
            validated,
            &self.identity,
            #[cfg(feature = "relay")]
            circuits,
            #[cfg(feature = "mdns")]
            self.mdns_io,
        )?;
        Ok(Endpoint {
            engine,
            platform: Portable::new(self.clock),
            closed_at: None,
        })
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
    ) -> SmoltcpEndpointBuilder<D, E, C> {
        let entropy = SharedEntropy::new(self.entropy);
        SmoltcpEndpointBuilder {
            portable: PortableEndpointBuilder {
                swarm: self.swarm,
                protocols: self.protocols,
                identity: self.identity,
                entropy: entropy.clone(),
                clock: self.clock,
                connect_deadline_ms: self.connect_deadline_ms,
                write_budget: self.write_budget,
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

/// Whole milliseconds in `duration`, saturating.
fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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

/// The endpoint a [`SmoltcpEndpointBuilder`] builds.
#[cfg(feature = "smoltcp")]
pub type SmoltcpEndpoint<D, E, C> = PortableEndpoint<SmoltcpTransport<D, E>, SharedEntropy<E>, C>;

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
pub struct SmoltcpEndpointBuilder<D: smoltcp::phy::Device, E: EntropySource, C: Clock> {
    portable: PortableEndpointBuilder<SharedEntropy<E>, C>,
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
impl<D: smoltcp::phy::Device, E: EntropySource, C: Clock> SmoltcpEndpointBuilder<D, E, C> {
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

    /// Sets how long a peer's new connection can lose a race to its current
    /// one (see [`PortableEndpointBuilder::simultaneous_dial_window`]).
    pub fn simultaneous_dial_window(mut self, window: Duration) -> Self {
        self.portable = self.portable.simultaneous_dial_window(window);
        self
    }

    /// Sets the Connection-attempt deadline. Default 30 seconds.
    pub fn connect_deadline(mut self, deadline: Duration) -> Self {
        self.portable = self.portable.connect_deadline(deadline);
        self
    }

    /// Sets the write queue's budget (see
    /// [`PortableEndpointBuilder::write_budget`]).
    pub fn write_budget(mut self, bytes: usize) -> Self {
        self.portable = self.portable.write_budget(bytes);
        self
    }

    /// Overrides the protocol deadlines (see
    /// [`PortableEndpointBuilder::timeouts`]).
    pub fn timeouts(mut self, timeouts: SwarmTimeouts) -> Self {
        self.portable = self.portable.timeouts(timeouts);
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

    /// Enables signed-beacon discovery with explicit beacon policy,
    /// validated at build.
    #[cfg(feature = "discovery")]
    pub fn discovery_config(mut self, config: BeaconConfig) -> Self {
        self.portable = self.portable.discovery_config(config);
        self
    }

    /// Overrides the shared bounded peer-book and automatic-dial policy.
    pub fn peer_discovery_config(mut self, config: PeerDiscoveryConfig) -> Self {
        self.portable = self.portable.peer_discovery_config(config);
        self
    }

    /// Adds a relay, in preference order: a path raced against direct
    /// candidates, with a reservation while the endpoint is not known to be
    /// public (see [`PortableEndpointBuilder::relay`]). For relay-only
    /// connects set [`NatConfig::force_relay`].
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

    /// Adds a trusted AutoNAT server, enabling probing; each call adds one.
    ///
    /// Call once per server: a reachability verdict needs a quorum of
    /// distinct servers ([`NatConfig::confidence_threshold`], 3 by default),
    /// so with fewer reachable servers reachability stays Unknown.
    #[cfg(feature = "autonat")]
    pub fn autonat_server(mut self, server: PeerAddr) -> Self {
        self.portable = self.portable.autonat_server(server);
        self
    }

    /// Sets the base NAT configuration; a second call replaces the first,
    /// and the relay and AutoNAT setters add to its lists in either order
    /// (see [`PortableEndpointBuilder::nat_config`]).
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
    pub fn build(self) -> Result<SmoltcpEndpoint<D, E, C>, PortableBuildError>
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
            endpoint.listen_on(&parsed)?;
        }
        Ok(endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::Cell;
    use minip2p_core::platform::EntropyError;
    use minip2p_core::platform::ManualClock;
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
        /// Fails every close and poll, as a transport that has gone away.
        broken: bool,
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
            if self.broken {
                return Err(TransportError::PollError {
                    reason: "transport gone".into(),
                });
            }
            self.closed.set(true);
            self.events.push(TransportEvent::Closed {
                id,
                reason: ConnectionCloseReason::Local,
            });
            Ok(())
        }

        fn poll(&mut self, _: Now) -> Result<Vec<TransportEvent>, TransportError> {
            if self.broken {
                return Err(TransportError::PollError {
                    reason: "transport gone".into(),
                });
            }
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
        let mut endpoint =
            PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
                .mdns(BrokenMdns, MdnsConfig::default())
                .build(NoopTransport)
                .expect("mdns endpoint");
        let peer = Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();
        let stream = StreamKey::new(ConnectionId::new(1), StreamId::new(3));
        let other = EndpointEvent::ConnectionClosed {
            peer_id: peer,
            conn_id: ConnectionId::new(2),
            reason: ConnectionCloseReason::Local,
        };
        endpoint.engine.events.extend([
            EndpointEvent::StreamData {
                peer_id: peer,
                stream,
                data: minip2p_core::Bytes::from_static(b"late"),
            },
            EndpointEvent::StreamClosed {
                peer_id: peer,
                stream,
            },
            other,
        ]);
        endpoint
            .at(Now::from_millis(0))
            .abandon_stream(stream)
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
        let mut endpoint =
            PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
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
            .at(Now::from_millis(0))
            .connect(target)
            .expect("admitted");

        let events = endpoint.at(Now::from_millis(1)).poll().expect("poll");
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
            .at(Now::from_millis(1 + MDNS_FAILURE_RETRY))
            .poll()
            .expect("poll");
        assert_eq!(failures(&retried), 0, "{retried:?}");
    }

    /// Goodbyes are best effort: one that cannot be sent is a final
    /// `MdnsFailed` among the shutdown's events, not a shutdown error.
    #[cfg(feature = "mdns")]
    #[test]
    fn a_failed_goodbye_is_an_event_from_shutdown() {
        let identity = Ed25519Keypair::from_secret_key_bytes([7; 32]);
        let mut endpoint =
            PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
                .mdns(BrokenMdns, MdnsConfig::default())
                .build(NoopTransport)
                .expect("mdns endpoint");
        endpoint.at(Now::from_millis(0));
        let report = endpoint.close();
        assert!(report.errors.is_empty(), "goodbyes are best effort");
        let events = report.events;
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
        let mut endpoint =
            PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
                .protocol("/example/1.0.0")
                .build(NoopTransport)
                .expect("portable endpoint configuration is valid");
        let remote = Ed25519Keypair::from_secret_key_bytes([8; 32]).peer_id();

        assert_eq!(endpoint.peer_id(), &identity.peer_id());
        let now = Now::from_millis(0);
        assert!(matches!(
            endpoint.at(now).open_stream(&remote, "/example/1.0.0"),
            Err(DriverError::Swarm(SwarmError::NotConnected { .. }))
        ));
        assert!(matches!(
            endpoint.at(now).open_stream(&remote, "/missing/1.0.0"),
            Err(DriverError::Swarm(SwarmError::ProtocolNotRegistered { .. }))
        ));

        let error = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
            .protocol(minip2p_swarm::RESERVED_PROTOCOL_IDS[0])
            .build(NoopTransport)
            .err()
            .expect("reserved protocols must be rejected");
        assert!(matches!(
            error,
            PortableBuildError::Swarm(SwarmError::ReservedProtocol { .. })
        ));

        let error = PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
            .timeouts(SwarmTimeouts {
                negotiation_ms: 0,
                ..SwarmTimeouts::default()
            })
            .build(NoopTransport)
            .err()
            .expect("a zero deadline must be rejected");
        assert!(matches!(
            error,
            PortableBuildError::Swarm(SwarmError::ZeroTimeout {
                field: "negotiation_ms"
            })
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
            Multiaddr::from_protocols(vec![Protocol::P2p(relay), Protocol::P2pCircuit]);
        let direct = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("id");
        let direct_addr: Multiaddr = "/ip4/192.0.2.7/tcp/4001".parse().expect("address");
        let transport = RecordingTransport {
            events: vec![
                TransportEvent::Connected {
                    id: circuit,
                    endpoint: ConnectionEndpoint::with_peer_id(circuit_addr.clone(), peer),
                },
                TransportEvent::IncomingConnection {
                    id: direct,
                    endpoint: ConnectionEndpoint::new(direct_addr.clone()),
                },
            ],
            local_address: direct_addr.clone(),
            next_stream_id: 0,
            closed: Rc::new(Cell::new(false)),
            broken: false,
        };
        let mut endpoint =
            PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
                .build(transport)
                .expect("endpoint configuration is valid");
        endpoint.at(Now::from_millis(0)).poll().expect("poll");

        assert_eq!(
            endpoint.connection_info(circuit),
            Some(ConnectionInfo {
                peer_id: peer,
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
                endpoint: ConnectionEndpoint::with_peer_id(direct_addr, peer),
            });
        endpoint.at(Now::from_millis(1)).poll().expect("poll");
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
        endpoint.at(Now::from_millis(2)).poll().expect("poll");
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
            Multiaddr::from_protocols(vec![Protocol::P2p(relay), Protocol::P2pCircuit]);
        let direct = ConnectionId::namespaced(ConnectionNamespace::TCP_IPV4, 1).expect("id");
        let direct_addr: Multiaddr = "/ip4/192.0.2.8/tcp/4001".parse().expect("address");
        let transport = RecordingTransport {
            events: vec![TransportEvent::Connected {
                id: circuit,
                endpoint: ConnectionEndpoint::with_peer_id(circuit_addr, peer),
            }],
            local_address: direct_addr.clone(),
            next_stream_id: 0,
            closed: Rc::new(Cell::new(false)),
            broken: false,
        };
        let mut endpoint =
            PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
                .build(transport)
                .expect("endpoint configuration is valid");
        endpoint.at(Now::from_millis(0)).poll().expect("poll");

        // Settles at once on the circuit; a direct connection replaces it
        // before the terminal is read.
        let target = PeerAddr::new(direct_addr.clone(), peer).expect("peer addr");
        let id = endpoint
            .at(Now::from_millis(1))
            .connect(target)
            .expect("connect admitted");
        endpoint
            .engine
            .core
            .transport_mut()
            .events
            .push(TransportEvent::Connected {
                id: direct,
                endpoint: ConnectionEndpoint::with_peer_id(direct_addr, peer),
            });
        let events = endpoint.at(Now::from_millis(2)).poll().expect("poll");

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
        let mut a = PortableEndpointBuilder::new(&a_identity, ZeroEntropy, ManualClock::default())
            .build(a_transport)
            .expect("a endpoint configuration is valid");
        let mut b = PortableEndpointBuilder::new(&b_identity, ZeroEntropy, ManualClock::default())
            .protocol("/app/1")
            .build(b_transport)
            .expect("b endpoint configuration is valid");

        a.at(Now::from_millis(0)).poll().expect("drive a");
        let info = a.connection_info(conn_id).expect("established");
        assert_eq!(info.path, Path::Direct);
        assert_eq!(info.ready_protocols, None, "not identified yet");

        for now_ms in 1..64 {
            b.at(Now::from_millis(now_ms)).poll().expect("drive b");
            a.at(Now::from_millis(now_ms)).poll().expect("drive a");
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
        let mut a = PortableEndpointBuilder::new(&a_identity, ZeroEntropy, ManualClock::default())
            .build(a_transport)
            .expect("a endpoint configuration is valid");
        let mut b = PortableEndpointBuilder::new(&b_identity, ZeroEntropy, ManualClock::default())
            .build(b_transport)
            .expect("b endpoint configuration is valid");

        for now_ms in 0..64 {
            a.at(Now::from_millis(now_ms)).poll().expect("drive a");
            b.at(Now::from_millis(now_ms)).poll().expect("drive b");
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
        let mut a = PortableEndpointBuilder::new(&a_identity, ZeroEntropy, ManualClock::default())
            .build(a_transport)
            .expect("a endpoint configuration is valid");
        let mut b = PortableEndpointBuilder::new(&b_identity, ZeroEntropy, ManualClock::default())
            .build(b_transport)
            .expect("b endpoint configuration is valid");

        for now_ms in 0..64 {
            a.at(Now::from_millis(now_ms)).poll().expect("drive a");
            b.at(Now::from_millis(now_ms)).poll().expect("drive b");
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
            .at(Now::from_millis(80))
            .connect(target)
            .expect("connect admitted");
        let events = a.at(Now::from_millis(80)).poll().expect("drain settled");
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
                endpoint: ConnectionEndpoint::with_peer_id(address.clone(), remote),
            }],
            local_address: address.clone(),
            next_stream_id: 0,
            closed: closed.clone(),
            broken: false,
        };
        let mut endpoint =
            PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
                .build(transport)
                .expect("portable endpoint configuration is valid");

        endpoint
            .at(Now::from_millis(1))
            .poll()
            .expect("connection event is accepted");
        assert_eq!(
            endpoint.stats(),
            EndpointStats {
                connected_peers: 1,
                ready_peers: 0,
                bound_addresses: vec![address],
            }
        );

        endpoint.at(Now::from_millis(2));

        let report = endpoint.close();
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert!(report.unfinished.is_empty(), "{:?}", report.unfinished);
        assert!(
            closed.get(),
            "the established transport connection was closed"
        );
        assert!(report.events.iter().any(|event| matches!(
            event,
            EndpointEvent::ConnectionClosed { peer_id, conn_id: closed_id, .. }
                if peer_id == &remote && closed_id == &conn_id
        )));
    }

    /// A failed final drive still hands over the events the shutdown
    /// queued (here the close failure the swarm reported), reports the
    /// error, and lists the connection the transport drop abandons.
    #[test]
    fn a_failed_shutdown_still_reports_its_events_errors_and_unfinished() {
        let identity = Ed25519Keypair::from_secret_key_bytes([13; 32]);
        let remote = Ed25519Keypair::from_secret_key_bytes([14; 32]).peer_id();
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().expect("address");
        let conn_id = ConnectionId::new(1);
        let transport = RecordingTransport {
            events: vec![TransportEvent::Connected {
                id: conn_id,
                endpoint: ConnectionEndpoint::with_peer_id(address.clone(), remote),
            }],
            local_address: address,
            next_stream_id: 0,
            closed: Rc::new(Cell::new(false)),
            broken: false,
        };
        let mut endpoint =
            PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
                .build(transport)
                .expect("portable endpoint configuration is valid");
        endpoint.at(Now::from_millis(1)).poll().expect("connected");
        endpoint.engine.core.transport_mut().broken = true;

        endpoint.at(Now::from_millis(2));

        let report = endpoint.close();
        assert!(
            matches!(
                report.errors.as_slice(),
                [DriverError::Transport(TransportError::PollError { .. })]
            ),
            "{:?}",
            report.errors
        );
        assert!(
            report.events.iter().any(|event| matches!(
                event,
                EndpointEvent::Error(error) if error.conn_id == Some(conn_id)
            )),
            "the close failure was dropped: {:?}",
            report.events
        );
        assert_eq!(report.unfinished, vec![(conn_id, Some(remote))]);
        assert_eq!(report.outcome, CloseOutcome::Failed);
    }

    /// A clock that advances on every read, counting the reads.
    struct CountingClock {
        reads: Rc<Cell<u64>>,
    }

    impl Clock for CountingClock {
        fn now(&mut self) -> Now {
            self.reads.set(self.reads.get() + 1);
            Now::from_millis(self.reads.get())
        }
    }

    /// `poll` and the whole of `close` (its `Drop` included, after a failed
    /// final drive left the peer connected) each sample the clock once.
    #[test]
    fn poll_and_close_each_sample_the_clock_once() {
        let identity = Ed25519Keypair::from_secret_key_bytes([15; 32]);
        let remote = Ed25519Keypair::from_secret_key_bytes([16; 32]).peer_id();
        let address: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().expect("address");
        let transport = RecordingTransport {
            events: vec![TransportEvent::Connected {
                id: ConnectionId::new(1),
                endpoint: ConnectionEndpoint::with_peer_id(address.clone(), remote),
            }],
            local_address: address,
            next_stream_id: 0,
            closed: Rc::new(Cell::new(false)),
            broken: false,
        };
        let reads = Rc::new(Cell::new(0));
        let mut endpoint = PortableEndpointBuilder::new(
            &identity,
            ZeroEntropy,
            CountingClock {
                reads: reads.clone(),
            },
        )
        .build(transport)
        .expect("portable endpoint configuration is valid");

        let before = reads.get();
        endpoint.poll().expect("connected");
        assert_eq!(reads.get(), before + 1, "poll samples once");
        endpoint.engine.core.transport_mut().broken = true;

        let before = reads.get();
        let report = endpoint.close();
        assert!(!report.unfinished.is_empty(), "the peer survives the drive");
        assert_eq!(reads.get(), before + 1, "close and its Drop sample once");
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
        let mut endpoint =
            PortableEndpointBuilder::new(&identity, ZeroEntropy, ManualClock::default())
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
                peer_id: peer,
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
                peer_id: peer,
                conn_id,
                stream_id,
                data: Bytes::from(encode_frame(&rpc.encode())),
            },
            0,
        ));

        endpoint.at(Now::from_millis(0));

        let report = endpoint.close();
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        let events = report.events;
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
