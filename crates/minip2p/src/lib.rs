//! App-facing facade for minip2p.
//!
//! This crate is the ergonomic std entrypoint. It composes the lower-level
//! crates without hiding them: protocol crates and `SwarmCore` remain the
//! Sans-I/O / `no_std + alloc` surface, while [`Endpoint`] gives applications a
//! small batteries-included API for identity, QUIC, listen/dial, ping, and
//! event polling.

#[cfg(feature = "nat")]
mod nat;

pub use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
pub use minip2p_identify::IdentifyMessage;
pub use minip2p_identity::Ed25519Keypair;
#[cfg(feature = "nat")]
pub use minip2p_nat::{
    ConnectId, NatConfig, NatError, NatEvent, Path, ReachabilityState, ReservationInfo,
    ReservationPolicy,
};
pub use minip2p_quic::QuicLimits;
use minip2p_quic::{QuicEndpoint, QuicNodeConfig};
pub use minip2p_swarm::{
    Deadline, DriverError as Error, RESERVED_PROTOCOL_IDS, RUN_UNTIL_SKIP_LIMIT, SwarmError,
    SwarmEvent as Event,
};
use minip2p_swarm::{Swarm, SwarmBuilder};
pub use minip2p_transport::{ConnectionId, StreamId, TransportError};

const DEFAULT_AGENT_VERSION: &str = "minip2p/0.1.0";

/// App-facing minip2p endpoint over the default QUIC transport.
///
/// `Endpoint` owns identity, transport, and the std swarm driver. Advanced
/// users can still borrow the underlying [`Swarm`] with [`Endpoint::swarm`]
/// and [`Endpoint::swarm_mut`].
///
/// With the `nat` cargo feature and a NAT configuration
/// (`EndpointBuilder::relay` / `EndpointBuilder::nat_config`), the endpoint
/// additionally runs the `minip2p_nat::NatAgent` traversal orchestrator:
/// see `Endpoint::connect`, `Endpoint::wait_path`, and
/// `Endpoint::take_nat_events`.
pub struct Endpoint {
    swarm: Swarm<QuicEndpoint>,
    #[cfg(feature = "nat")]
    nat: Option<nat::NatDriver>,
    /// Application events set aside while a NAT-aware wait was driving the
    /// endpoint; drained first by [`Endpoint::next_event`].
    #[cfg(feature = "nat")]
    pending_events: std::collections::VecDeque<Event>,
}

/// Why one NAT-aware swarm-driving step returned.
#[cfg(feature = "nat")]
enum NatPollKind {
    /// An event not owned by the NAT agent is ready for the application.
    Application,
    /// The agent produced application-visible NAT output; NAT-focused waits
    /// should re-check its queue immediately.
    Progress,
    /// The caller's deadline elapsed.
    Deadline,
}

#[cfg(feature = "nat")]
struct NatPoll {
    kind: NatPollKind,
    event: Option<Event>,
}

#[cfg(feature = "nat")]
impl NatPoll {
    fn application(event: Event) -> Self {
        Self {
            kind: NatPollKind::Application,
            event: Some(event),
        }
    }

    fn progress() -> Self {
        Self {
            kind: NatPollKind::Progress,
            event: None,
        }
    }

    fn deadline() -> Self {
        Self {
            kind: NatPollKind::Deadline,
            event: None,
        }
    }
}

impl Endpoint {
    /// Starts building an endpoint.
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::default()
    }

    /// Returns this node's peer id.
    pub fn peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Starts listening on the transport's first already-bound address.
    pub fn listen(&mut self) -> Result<PeerAddr, Error> {
        let addr = self.swarm.listen_on_bound_addr()?;
        self.sync_nat_listen_addrs(std::slice::from_ref(&addr));
        Ok(addr)
    }

    /// Starts listening on all transport-bound addresses.
    pub fn listen_all(&mut self) -> Result<Vec<PeerAddr>, Error> {
        let addrs = self.swarm.listen_on_bound_addrs()?;
        self.sync_nat_listen_addrs(&addrs);
        Ok(addrs)
    }

    /// Seeds the NAT agent's advertised addresses from the bound set
    /// (wildcards and non-QUIC shapes filtered out). No-op without the
    /// `nat` feature or when NAT is not configured.
    #[allow(unused_variables)]
    fn sync_nat_listen_addrs(&mut self, addrs: &[PeerAddr]) {
        #[cfg(feature = "nat")]
        if let Some(nat) = self.nat.as_mut() {
            let transports: Vec<Multiaddr> =
                addrs.iter().map(|addr| addr.transport().clone()).collect();
            let validated =
                minip2p_core::select_direct_candidates(&transports, None, None).into_addrs();
            nat.agent.set_listen_addrs(&validated);
        }
    }

    /// Dials a remote peer on every applicable local address family.
    ///
    /// For dual-stack endpoints, `/dns` targets are resolved and both IPv4 and
    /// IPv6 dials are started when both families are available. Use
    /// [`Endpoint::dial_ip4`] or [`Endpoint::dial_ip6`] to force one family.
    pub fn dial(&mut self, addr: &PeerAddr) -> Result<Vec<ConnectionId>, Error> {
        Ok(self.swarm.transport_mut().dial_all(addr)?)
    }

    /// Dials a remote peer using IPv4.
    pub fn dial_ip4(&mut self, addr: &PeerAddr) -> Result<ConnectionId, Error> {
        Ok(self.swarm.transport_mut().dial_ip4(addr)?)
    }

    /// Dials a remote peer using IPv6.
    pub fn dial_ip6(&mut self, addr: &PeerAddr) -> Result<ConnectionId, Error> {
        Ok(self.swarm.transport_mut().dial_ip6(addr)?)
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

    /// Polls the endpoint once and returns all currently available events.
    ///
    /// With NAT configured, events belonging to the traversal agent are
    /// consumed here (never surfaced to the application); the agent's own
    /// events accumulate for `Endpoint::take_nat_events`.
    pub fn poll(&mut self) -> Result<Vec<Event>, Error> {
        #[cfg(feature = "nat")]
        {
            let polled = self.swarm.poll()?;
            let mut events: Vec<Event> = self.pending_events.drain(..).collect();
            match self.nat.as_mut() {
                Some(nat) => {
                    for event in polled {
                        if !nat.ingest(&event, &mut self.swarm) {
                            events.push(event);
                        }
                    }
                    nat.tick(&mut self.swarm);
                }
                None => events.extend(polled),
            }
            Ok(events)
        }
        #[cfg(not(feature = "nat"))]
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
        #[cfg(feature = "nat")]
        if self.nat.is_some() {
            return self.next_event_with_nat(deadline);
        }
        self.swarm.poll_next(deadline)
    }

    /// `next_event` with the NAT agent folded into the wait: the sleep
    /// budget never overshoots the agent's next timer, agent-owned stream
    /// events are consumed instead of surfaced, and ticks run between
    /// waits.
    #[cfg(feature = "nat")]
    fn next_event_with_nat(&mut self, deadline: Deadline) -> Result<Option<Event>, Error> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(Some(event));
        }
        let mut expired_poll_used = false;
        loop {
            let poll = self.poll_new_event_with_nat(deadline, &mut expired_poll_used)?;
            match poll.kind {
                NatPollKind::Application => return Ok(poll.event),
                NatPollKind::Progress => {}
                NatPollKind::Deadline => return Ok(None),
            }
        }
    }

    /// Drives the swarm and NAT agent until a newly-arrived application
    /// event is available. Unlike [`Self::next_event_with_nat`], this never
    /// drains `pending_events`: NAT-focused waits must leave application
    /// events aside instead of repeatedly picking up the same one.
    #[cfg(feature = "nat")]
    fn poll_new_event_with_nat(
        &mut self,
        deadline: Deadline,
        expired_poll_used: &mut bool,
    ) -> Result<NatPoll, Error> {
        loop {
            // `Swarm::poll_next` deliberately performs one synchronous poll
            // even for an expired deadline. That is useful for one-shot
            // callers, but repeating it here under a continuous event stream
            // would let a NAT-focused wait run forever past its deadline.
            if deadline.has_passed() {
                if *expired_poll_used {
                    return Ok(NatPoll::deadline());
                }
                *expired_poll_used = true;
            }
            let step = {
                let nat = self.nat.as_ref().expect("nat checked by caller");
                match nat.agent.next_timeout(nat.now().mono_ms) {
                    Some(ms) => deadline
                        .earliest(Deadline::from(std::time::Duration::from_millis(ms.max(1)))),
                    None => deadline,
                }
            };
            let polled = self.swarm.poll_next(step)?;
            if deadline.has_passed() {
                *expired_poll_used = true;
            }
            let nat = self.nat.as_mut().expect("nat checked by caller");
            let events_before = nat.events.len();
            match polled {
                Some(event) => {
                    let consumed = nat.ingest(&event, &mut self.swarm);
                    nat.tick(&mut self.swarm);
                    if !consumed {
                        return Ok(NatPoll::application(event));
                    }
                    if nat.events.len() > events_before {
                        return Ok(NatPoll::progress());
                    }
                }
                None => {
                    nat.tick(&mut self.swarm);
                    if nat.events.len() > events_before {
                        return Ok(NatPoll::progress());
                    }
                    // Distinguish the caller's deadline from a mere agent
                    // timer that shortened this wait step.
                    if deadline.has_passed() {
                        return Ok(NatPoll::deadline());
                    }
                }
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
        #[cfg(feature = "nat")]
        if self.nat.is_some() {
            return self.wait_for_event_with_nat(deadline, |event| {
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
        #[cfg(feature = "nat")]
        let event = if self.nat.is_some() {
            self.wait_for_event_with_nat(deadline, |event| {
                matches!(event, Event::PingRttMeasured { peer_id: ready, .. } if ready == peer_id)
            })?
        } else {
            self.swarm.run_until(deadline, |event| {
                matches!(event, Event::PingRttMeasured { peer_id: ready, .. } if ready == peer_id)
            })?
        };
        #[cfg(not(feature = "nat"))]
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
            let poll = self.poll_new_event_with_nat(deadline, &mut expired_poll_used)?;
            match poll.kind {
                NatPollKind::Application => self
                    .pending_events
                    .push_back(poll.event.expect("application poll carries event")),
                NatPollKind::Progress => {}
                NatPollKind::Deadline => return Ok(None),
            }
        }
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
            let poll = self.poll_new_event_with_nat(deadline, &mut expired_poll_used)?;
            match poll.kind {
                NatPollKind::Application => self
                    .pending_events
                    .push_back(poll.event.expect("application poll carries event")),
                NatPollKind::Progress => {}
                NatPollKind::Deadline => return Ok(None),
            }
        }
    }

    /// NAT-aware equivalent of `Swarm::run_until`. Every swarm event goes
    /// through `NatDriver::ingest`, and non-matching application events are
    /// retained for [`Endpoint::next_event`].
    #[cfg(feature = "nat")]
    fn wait_for_event_with_nat<F>(
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
            let poll = self.poll_new_event_with_nat(deadline, &mut expired_poll_used)?;
            match poll.kind {
                NatPollKind::Application => {
                    let event = poll.event.expect("application poll carries event");
                    if predicate(&event) {
                        return Ok(Some(event));
                    }
                    self.pending_events.push_back(event);
                }
                NatPollKind::Progress => {}
                NatPollKind::Deadline => return Ok(None),
            }
        }
    }

    #[cfg(feature = "nat")]
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

    /// Borrows the underlying swarm.
    pub fn swarm(&self) -> &Swarm<QuicEndpoint> {
        &self.swarm
    }

    /// Mutably borrows the underlying swarm.
    pub fn swarm_mut(&mut self) -> &mut Swarm<QuicEndpoint> {
        &mut self.swarm
    }

    /// Decomposes this endpoint into the underlying swarm.
    pub fn into_swarm(self) -> Swarm<QuicEndpoint> {
        self.swarm
    }
}

/// Builder for [`Endpoint`].
pub struct EndpointBuilder {
    keypair: Option<Ed25519Keypair>,
    agent_version: String,
    quic_limits: QuicLimits,
    protocols: Vec<String>,
    #[cfg(feature = "nat")]
    nat_config: Option<NatConfig>,
    #[cfg(feature = "nat")]
    relays: Vec<PeerAddr>,
    #[cfg(feature = "nat")]
    autonat_servers: Vec<PeerAddr>,
}

impl Default for EndpointBuilder {
    fn default() -> Self {
        Self {
            keypair: None,
            agent_version: DEFAULT_AGENT_VERSION.to_string(),
            quic_limits: QuicLimits::default(),
            protocols: Vec::new(),
            #[cfg(feature = "nat")]
            nat_config: None,
            #[cfg(feature = "nat")]
            relays: Vec::new(),
            #[cfg(feature = "nat")]
            autonat_servers: Vec::new(),
        }
    }
}

/// Validated builder output consumed by the bind step.
struct BuilderParts {
    keypair: Ed25519Keypair,
    agent_version: String,
    quic_limits: QuicLimits,
    protocols: Vec<String>,
    #[cfg(feature = "nat")]
    nat_config: Option<NatConfig>,
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
    pub fn quic_limits(mut self, limits: QuicLimits) -> Self {
        self.quic_limits = limits;
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

    /// Builds an endpoint with a QUIC transport bound to `bind_addr`.
    pub fn bind_quic(self, bind_addr: impl AsRef<str>) -> Result<Endpoint, Error> {
        let parts = self.into_parts()?;
        let config =
            QuicNodeConfig::new(parts.keypair.clone()).with_limits(parts.quic_limits.clone());
        let transport = QuicEndpoint::bind(config, bind_addr.as_ref())?;
        build_endpoint(parts, transport)
    }

    /// Builds an endpoint with a QUIC transport bound to a QUIC multiaddr.
    pub fn bind_quic_multiaddr(self, addr: &Multiaddr) -> Result<Endpoint, Error> {
        let parts = self.into_parts()?;
        let config =
            QuicNodeConfig::new(parts.keypair.clone()).with_limits(parts.quic_limits.clone());
        let transport = QuicEndpoint::bind_multiaddr(config, addr)?;
        build_endpoint(parts, transport)
    }

    /// Builds an endpoint with separate IPv4 and IPv6 wildcard QUIC sockets.
    pub fn bind_quic_dual_stack(self) -> Result<Endpoint, Error> {
        let parts = self.into_parts()?;
        let config =
            QuicNodeConfig::new(parts.keypair.clone()).with_limits(parts.quic_limits.clone());
        let transport = QuicEndpoint::dual_stack(config)?;
        build_endpoint(parts, transport)
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
        #[cfg(feature = "nat")]
        let nat_config = {
            let enabled = self.nat_config.is_some()
                || !self.relays.is_empty()
                || !self.autonat_servers.is_empty();
            enabled.then(|| {
                let mut config = self.nat_config.unwrap_or_default();
                config.relays.extend(self.relays);
                config.autonat_servers.extend(self.autonat_servers);
                config
            })
        };
        Ok(BuilderParts {
            keypair: self.keypair.unwrap_or_else(Ed25519Keypair::generate),
            agent_version: self.agent_version,
            quic_limits: self.quic_limits,
            protocols: self.protocols,
            #[cfg(feature = "nat")]
            nat_config,
        })
    }
}

fn build_endpoint(parts: BuilderParts, transport: QuicEndpoint) -> Result<Endpoint, Error> {
    let mut builder = SwarmBuilder::new(&parts.keypair).agent_version(parts.agent_version);
    #[cfg(feature = "nat")]
    let mut protocols = parts.protocols;
    #[cfg(not(feature = "nat"))]
    let protocols = parts.protocols;
    #[cfg(feature = "nat")]
    if parts.nat_config.is_some() {
        // The traversal agent's protocols are ordinary user protocols; the
        // swarm just needs to accept and route them.
        for id in [
            minip2p_nat::HOP_PROTOCOL_ID,
            minip2p_nat::STOP_PROTOCOL_ID,
            minip2p_nat::DCUTR_PROTOCOL_ID,
            minip2p_nat::AUTONAT_PROTOCOL_ID,
        ] {
            if !protocols.iter().any(|existing| existing == id) {
                protocols.push(id.to_string());
            }
        }
    }
    for protocol in protocols {
        builder = builder.protocol(protocol);
    }
    let swarm = builder.build(transport)?;
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
    Ok(Endpoint {
        swarm,
        #[cfg(feature = "nat")]
        nat,
        #[cfg(feature = "nat")]
        pending_events: std::collections::VecDeque::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "nat")]
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
            Some(Event::ConnectionClosed { peer_id }) if peer_id == unrelated
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
            Some(Event::ConnectionClosed { peer_id }) if peer_id == unrelated
        ));

        for _ in 0..RUN_UNTIL_SKIP_LIMIT {
            endpoint.pending_events.push_back(Event::ConnectionClosed {
                peer_id: unrelated.clone(),
            });
        }
        assert!(matches!(
            endpoint.next_nat_event(Deadline::NEVER),
            Err(Error::EventBacklogExceeded { limit }) if limit == RUN_UNTIL_SKIP_LIMIT
        ));
    }
}
