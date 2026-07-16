//! App-facing facade for minip2p.
//!
//! This crate is the ergonomic std entrypoint. It composes the lower-level
//! crates without hiding them: protocol crates and `SwarmCore` remain the
//! Sans-I/O / `no_std + alloc` surface, while [`Endpoint`] gives applications a
//! small batteries-included API for identity, QUIC, listen/dial, ping, and
//! event polling.

#[cfg(feature = "nat")]
mod nat;
#[cfg(feature = "pubsub")]
mod pubsub;

pub use minip2p_core::{Multiaddr, PeerAddr, PeerId, Protocol};
pub use minip2p_identify::IdentifyMessage;
pub use minip2p_identity::Ed25519Keypair;
#[cfg(feature = "nat")]
pub use minip2p_nat::{
    ConnectId, NatConfig, NatError, NatEvent, Path, ReachabilityState, ReservationInfo,
    ReservationPolicy,
};
#[cfg(feature = "pubsub")]
pub use minip2p_pubsub::{
    FLOODSUB_PROTOCOL_ID, FloodsubConfig, PublishError, PubsubEvent, TopicError,
};
pub use minip2p_quic::QuicLimits;
use minip2p_quic::{QuicEndpoint, QuicNodeConfig};
pub use minip2p_swarm::{
    Deadline, DriverError as Error, RESERVED_PROTOCOL_IDS, RUN_UNTIL_SKIP_LIMIT, SwarmError,
    SwarmEvent as Event,
};
use minip2p_swarm::{Swarm, SwarmBuilder};
pub use minip2p_transport::{ConnectionId, StreamId, TransportError};
#[cfg(feature = "pubsub")]
pub use pubsub::PubsubError;

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
    #[cfg(feature = "pubsub")]
    pubsub: Option<pubsub::PubsubDriver>,
    /// Application events set aside while a driver-focused wait was driving
    /// the endpoint; drained first by [`Endpoint::next_event`].
    #[cfg(any(feature = "nat", feature = "pubsub"))]
    pending_events: std::collections::VecDeque<Event>,
}

/// Why one driver-aware swarm-driving step returned.
#[cfg(any(feature = "nat", feature = "pubsub"))]
enum DriverPollKind {
    /// An event not owned by any agent is ready for the application.
    Application,
    /// An agent produced application-visible output; focused waits should
    /// re-check their queue immediately.
    Progress,
    /// The caller's deadline elapsed.
    Deadline,
}

#[cfg(any(feature = "nat", feature = "pubsub"))]
struct DriverPoll {
    kind: DriverPollKind,
    event: Option<Event>,
}

#[cfg(any(feature = "nat", feature = "pubsub"))]
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
        #[cfg(any(feature = "nat", feature = "pubsub"))]
        {
            let polled = self.swarm.poll()?;
            let mut events: Vec<Event> = self.pending_events.drain(..).collect();
            for event in polled {
                if !self.ingest_into_drivers(&event) {
                    events.push(event);
                }
            }
            self.tick_drivers();
            Ok(events)
        }
        #[cfg(not(any(feature = "nat", feature = "pubsub")))]
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
        #[cfg(any(feature = "nat", feature = "pubsub"))]
        if self.has_drivers() {
            return self.next_event_driven(deadline);
        }
        self.swarm.poll_next(deadline)
    }

    /// Whether any agent driver is active on this endpoint.
    #[cfg(any(feature = "nat", feature = "pubsub"))]
    fn has_drivers(&self) -> bool {
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

    /// Feeds one swarm event through the active drivers, NAT first (its
    /// control-plane streams are never pubsub-relevant; neither agent
    /// claims connection-lifecycle or PeerReady events, so ordering only
    /// decides who sees its own streams).
    ///
    /// Returns `true` when a driver claimed the event.
    #[cfg(any(feature = "nat", feature = "pubsub"))]
    fn ingest_into_drivers(&mut self, event: &Event) -> bool {
        #[cfg(feature = "nat")]
        if let Some(nat) = self.nat.as_mut()
            && nat.ingest(event, &mut self.swarm)
        {
            return true;
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.pubsub.as_mut()
            && pubsub.ingest(event, &mut self.swarm)
        {
            return true;
        }
        false
    }

    /// Ticks every active driver.
    #[cfg(any(feature = "nat", feature = "pubsub"))]
    fn tick_drivers(&mut self) {
        #[cfg(feature = "nat")]
        if let Some(nat) = self.nat.as_mut() {
            nat.tick(&mut self.swarm);
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.pubsub.as_mut() {
            pubsub.tick(&mut self.swarm);
        }
    }

    /// Application-visible events queued across every active driver; growth
    /// is the focused waits' progress signal.
    #[cfg(any(feature = "nat", feature = "pubsub"))]
    fn driver_events_len(&self) -> usize {
        let mut len = 0;
        #[cfg(feature = "nat")]
        if let Some(nat) = self.nat.as_ref() {
            len += nat.events.len();
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.pubsub.as_ref() {
            len += pubsub.events.len();
        }
        len
    }

    /// One wait step's deadline: the caller's, shortened by whichever agent
    /// timer is due first.
    #[cfg(any(feature = "nat", feature = "pubsub"))]
    fn driver_step_deadline(&self, deadline: Deadline) -> Deadline {
        let mut step = deadline;
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
        step
    }

    /// `next_event` with the active agents folded into the wait: the sleep
    /// budget never overshoots an agent's next timer, agent-owned stream
    /// events are consumed instead of surfaced, and ticks run between
    /// waits.
    #[cfg(any(feature = "nat", feature = "pubsub"))]
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
                DriverPollKind::Deadline => return Ok(None),
            }
        }
    }

    /// Drives the swarm and the active agents until a newly-arrived
    /// application event is available. Unlike [`Self::next_event_driven`],
    /// this never drains `pending_events`: focused waits must leave
    /// application events aside instead of repeatedly picking up the same
    /// one.
    #[cfg(any(feature = "nat", feature = "pubsub"))]
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
            let polled = self.swarm.poll_next(step)?;
            if deadline.has_passed() {
                *expired_poll_used = true;
            }
            let events_before = self.driver_events_len();
            match polled {
                Some(event) => {
                    let consumed = self.ingest_into_drivers(&event);
                    self.tick_drivers();
                    if !consumed {
                        return Ok(DriverPoll::application(event));
                    }
                    if self.driver_events_len() > events_before {
                        return Ok(DriverPoll::progress());
                    }
                }
                None => {
                    self.tick_drivers();
                    if self.driver_events_len() > events_before {
                        return Ok(DriverPoll::progress());
                    }
                    // Distinguish the caller's deadline from a mere agent
                    // timer that shortened this wait step.
                    if deadline.has_passed() {
                        return Ok(DriverPoll::deadline());
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
        #[cfg(any(feature = "nat", feature = "pubsub"))]
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
        #[cfg(any(feature = "nat", feature = "pubsub"))]
        let event = if self.has_drivers() {
            self.wait_for_event_driven(deadline, |event| {
                matches!(event, Event::PingRttMeasured { peer_id: ready, .. } if ready == peer_id)
            })?
        } else {
            self.swarm.run_until(deadline, |event| {
                matches!(event, Event::PingRttMeasured { peer_id: ready, .. } if ready == peer_id)
            })?
        };
        #[cfg(not(any(feature = "nat", feature = "pubsub")))]
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
                DriverPollKind::Deadline => return Ok(None),
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
            let poll = self.poll_new_event_driven(deadline, &mut expired_poll_used)?;
            match poll.kind {
                DriverPollKind::Application => self
                    .pending_events
                    .push_back(poll.event.expect("application poll carries event")),
                DriverPollKind::Progress => {}
                DriverPollKind::Deadline => return Ok(None),
            }
        }
    }

    /// Driver-aware equivalent of `Swarm::run_until`. Every swarm event
    /// goes through the active drivers, and non-matching application events
    /// are retained for [`Endpoint::next_event`].
    #[cfg(any(feature = "nat", feature = "pubsub"))]
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
                DriverPollKind::Deadline => return Ok(None),
            }
        }
    }

    #[cfg(any(feature = "nat", feature = "pubsub"))]
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
    /// subscribed. The subscription is announced to every floodsub peer.
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
    /// subscribed.
    #[cfg(feature = "pubsub")]
    pub fn unsubscribe(&mut self, topic: &str) -> Result<bool, PubsubError> {
        let Some(pubsub) = self.pubsub.as_mut() else {
            return Err(PubsubError::NotEnabled);
        };
        let now_ms = pubsub.now_ms();
        let removed = pubsub.agent.unsubscribe(topic, now_ms);
        pubsub.pump(&mut self.swarm);
        Ok(removed)
    }

    /// Publishes `data` on `topic`, signed with this endpoint's identity
    /// and flooded to every subscribed peer.
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
                DriverPollKind::Deadline => return Ok(None),
            }
        }
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
    #[cfg(feature = "pubsub")]
    pubsub_enabled: bool,
    #[cfg(feature = "pubsub")]
    pubsub_config: Option<FloodsubConfig>,
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
            #[cfg(feature = "pubsub")]
            pubsub_enabled: false,
            #[cfg(feature = "pubsub")]
            pubsub_config: None,
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
    #[cfg(feature = "pubsub")]
    pubsub_config: Option<FloodsubConfig>,
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

    /// Enables floodsub pubsub with the default configuration.
    ///
    /// Builder-time opt-in (rather than a lazy `subscribe`-time enable)
    /// because `/floodsub/1.0.0` must be in Identify's advertised protocol
    /// set from the first handshake — peers only open pubsub streams to
    /// endpoints that advertise it.
    #[cfg(feature = "pubsub")]
    pub fn pubsub(mut self) -> Self {
        self.pubsub_enabled = true;
        self
    }

    /// Enables floodsub pubsub with an explicit configuration.
    #[cfg(feature = "pubsub")]
    pub fn pubsub_config(mut self, config: FloodsubConfig) -> Self {
        self.pubsub_enabled = true;
        self.pubsub_config = Some(config);
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
            #[cfg(feature = "pubsub")]
            pubsub_config: self
                .pubsub_enabled
                .then(|| self.pubsub_config.unwrap_or_default()),
        })
    }
}

fn build_endpoint(parts: BuilderParts, transport: QuicEndpoint) -> Result<Endpoint, Error> {
    let mut builder = SwarmBuilder::new(&parts.keypair).agent_version(parts.agent_version);
    #[cfg(any(feature = "nat", feature = "pubsub"))]
    let mut protocols = parts.protocols;
    #[cfg(not(any(feature = "nat", feature = "pubsub")))]
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
    #[cfg(feature = "pubsub")]
    if parts.pubsub_config.is_some() {
        // Floodsub streams route as an ordinary user protocol, and the id
        // must be advertised by Identify from the first handshake.
        let id = FLOODSUB_PROTOCOL_ID;
        if !protocols.iter().any(|existing| existing == id) {
            protocols.push(id.to_string());
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
    #[cfg(feature = "pubsub")]
    let pubsub = parts.pubsub_config.map(|config| {
        // Message ids are (from, seqno); a wall-clock seed keeps restarts
        // from reusing ids the network may still remember.
        let initial_seqno = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let agent =
            minip2p_pubsub::FloodsubAgent::new(parts.keypair.clone(), config, initial_seqno);
        pubsub::PubsubDriver::new(agent)
    });
    Ok(Endpoint {
        swarm,
        #[cfg(feature = "nat")]
        nat,
        #[cfg(feature = "pubsub")]
        pubsub,
        #[cfg(any(feature = "nat", feature = "pubsub"))]
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
