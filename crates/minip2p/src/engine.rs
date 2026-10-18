//! The one private engine behind both public endpoints.
//!
//! [`crate::PortableEndpoint`] and the std `Endpoint` each own an [`Engine`]
//! and differ only in what they wrap around it: std adds a clock, transport
//! binding, Name resolution, and a blocking wait; portable takes the host's
//! time sample on every call. Everything that decides what the application
//! sees, and in which order, lives here.
//!
//! # One drive batch
//!
//! [`Engine::drive`] runs one batch, the unit of work behind std `poll`,
//! std `wait`, and portable `poll`:
//!
//! 1. Ingest one bounded batch of swarm events: one transport poll, or two
//!    around the mDNS tick when the mDNS carrier shares the transport's
//!    stack (mDNS can put bytes into the shared sockets).
//! 2. One capability pass: relay-server, NAT, Gossipsub, Discovery.
//! 3. Connection-attempt terminals.
//!
//! The batch's output is queued in that order: the swarm events, then
//! capability events (relay-server, NAT, Gossipsub, Discovery, mDNS), then
//! `ConnectSettled`. A capability's failure never fails the batch: it is a
//! capability event (mDNS `MdnsFailed`, relay-server `AddrsRejected`) while
//! the rest of the endpoint keeps running. A batch never drains "until empty", so continuous
//! traffic cannot starve the timers the next batch serves.
//!
//! # NAT event routing
//!
//! Every NAT event reaches the Connection engine exactly once, then
//! discovery's ownership filter, then application staging
//! ([`NatDriver::route`]). Routing runs after every swarm event, after every
//! step that can make the agent speak, and again while Connection-attempt
//! terminals are collected, so even an event produced by a terminal's
//! cleanup is staged before the batch's final drain.
//!
//! # Paths
//!
//! Every established connection has a [`Path`], answered here on every
//! feature set without a record of its own: a circuit (its connection id is
//! in the circuit namespace) is Relayed through the relay its address names;
//! anything else is Direct, unless NAT reports the connection as its hole
//! punch's (`NatAgent::is_punched`). The swarm's connection records and
//! NAT's punch record are the only sources, and both end with the
//! connection, so a replacement never inherits its predecessor's path.
//!
//! A Connected `ConnectSettled` carries its connection's path from the step
//! that settled the attempt, before any later event in the batch can end
//! that connection, so the terminal stays true after it is replaced or
//! closed. An attempt settled on a later connection of the same transport
//! batch takes its path once that connection's own lifecycle event has been
//! ingested, as NAT records a punch on that event.

use alloc::collections::VecDeque;
#[cfg(any(feature = "std", feature = "pubsub"))]
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(not(feature = "_mdns-driver"))]
use core::marker::PhantomData;

use minip2p_core::platform::{Deadline, EntropySource, Now};
use minip2p_core::{Bytes, Multiaddr, Path, PeerAddr, PeerId};
use minip2p_swarm::{DriverError, SwarmCore, SwarmEvent};
use minip2p_transport::{ConnectionId, StreamId, Transport, TransportError};

#[cfg(feature = "_discovery-driver")]
use crate::discovery::{DiscoveryDriver, resolve_book_candidates};
#[cfg(feature = "_nat-driver")]
use crate::nat::NatDriver;
#[cfg(feature = "_nat-driver")]
use crate::portable::connect::cancel_attempt;
use crate::portable::connect::{
    ConnectAdmission, ConnectEngine, ConnectId, ConnectTarget, Expansion, admit_connect,
    circuit_relay,
};
#[cfg(feature = "pubsub")]
use crate::pubsub::{GossipsubDriver, GossipsubError};
#[cfg(feature = "relay-server")]
use crate::std::relay_server::{RelayServerDriver, concrete_relay_listener_addrs};
use crate::{ConnectionInfo, EndpointEvent, StreamAcks};

/// What an engine needs from its mDNS carrier: an `MdnsIo` when mDNS is
/// compiled in, nothing otherwise. Std uses the concrete socket carrier, so
/// a type-erased, non-`Send` carrier never enters it; portable uses
/// `Box<dyn MdnsIo>`.
#[cfg(feature = "_mdns-driver")]
pub(crate) trait Carrier: minip2p_mdns::MdnsIo {}
#[cfg(feature = "_mdns-driver")]
impl<I: minip2p_mdns::MdnsIo> Carrier for I {}
/// What an engine needs from its mDNS carrier: nothing, without mDNS.
#[cfg(not(feature = "_mdns-driver"))]
pub(crate) trait Carrier {}
#[cfg(not(feature = "_mdns-driver"))]
impl<I> Carrier for I {}

/// Private counters for the work-reduction tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct Stats {
    /// Capability passes (the finishing step of a batch).
    pub(crate) capability_passes: usize,
    /// Recomputations of the externally advertised address set.
    pub(crate) address_refreshes: usize,
}

/// The private engine: swarm, Connection attempts, and every capability
/// driver, behind one per-batch step loop.
pub(crate) struct Engine<T: Transport, E: EntropySource, M: Carrier> {
    pub(crate) core: SwarmCore<T, E>,
    pub(crate) connect: ConnectEngine,
    acks: StreamAcks,
    /// The Endpoint event stream: queued output the application has not
    /// pulled yet.
    pub(crate) events: VecDeque<EndpointEvent>,
    /// Addresses set through `set_external_addresses`; driver contributions
    /// are merged after them.
    caller_external_addresses: Vec<Multiaddr>,
    #[cfg(feature = "_nat-driver")]
    pub(crate) nat: Option<NatDriver<T>>,
    #[cfg(feature = "pubsub")]
    pub(crate) gossipsub: Option<GossipsubDriver>,
    #[cfg(feature = "_discovery-driver")]
    pub(crate) discovery: Option<DiscoveryDriver>,
    #[cfg(feature = "_mdns-driver")]
    mdns: Option<minip2p_mdns::MdnsDriver<M>>,
    /// Whether the mDNS carrier shares the transport's stack, so the
    /// transport is polled again after the mDNS tick.
    #[cfg(feature = "_mdns-driver")]
    mdns_shares_transport: bool,
    /// mDNS failure and recovery events of this batch, queued after
    /// Discovery's.
    #[cfg(feature = "_mdns-driver")]
    mdns_events: Vec<EndpointEvent>,
    #[cfg(not(feature = "_mdns-driver"))]
    carrier: PhantomData<fn(M)>,
    #[cfg(feature = "relay-server")]
    pub(crate) relay_server: Option<RelayServerDriver>,
    /// The transport address revision the relay server's listener addresses
    /// were last taken at.
    #[cfg(feature = "relay-server")]
    relay_listeners_revision: Option<u64>,
    #[cfg(test)]
    pub(crate) stats: Stats,
}

impl<T: Transport, E: EntropySource, M: Carrier> Engine<T, E, M> {
    pub(crate) fn new(core: SwarmCore<T, E>, connect_deadline_ms: u64, acks: StreamAcks) -> Self {
        Self {
            core,
            connect: ConnectEngine::new(connect_deadline_ms),
            acks,
            events: VecDeque::new(),
            caller_external_addresses: Vec::new(),
            #[cfg(feature = "_nat-driver")]
            nat: None,
            #[cfg(feature = "pubsub")]
            gossipsub: None,
            #[cfg(feature = "_discovery-driver")]
            discovery: None,
            #[cfg(feature = "_mdns-driver")]
            mdns: None,
            #[cfg(feature = "_mdns-driver")]
            mdns_shares_transport: false,
            #[cfg(feature = "_mdns-driver")]
            mdns_events: Vec::new(),
            #[cfg(not(feature = "_mdns-driver"))]
            carrier: PhantomData,
            #[cfg(feature = "relay-server")]
            relay_server: None,
            #[cfg(feature = "relay-server")]
            relay_listeners_revision: None,
            #[cfg(test)]
            stats: Stats::default(),
        }
    }

    /// Installs mDNS. `shares_transport` asks for the second transport poll
    /// after each mDNS tick.
    #[cfg(feature = "_mdns-driver")]
    pub(crate) fn set_mdns(&mut self, driver: minip2p_mdns::MdnsDriver<M>, shares_transport: bool) {
        self.mdns = Some(driver);
        self.mdns_shares_transport = shares_transport;
    }

    #[cfg(feature = "_mdns-driver")]
    pub(crate) fn has_mdns(&self) -> bool {
        self.mdns.is_some()
    }

    // ---------------------------------------------------------------------
    // Commands
    // ---------------------------------------------------------------------

    /// Admits one Connection attempt. A Peer-ID target resolves through the
    /// discovery book when there is one; the NAT leg attaches when NAT is
    /// configured. Whatever settles at once is queued before this returns.
    pub(crate) fn connect(
        &mut self,
        target: ConnectTarget,
        expand: &mut dyn FnMut(&PeerAddr) -> Expansion,
        now: Now,
    ) -> ConnectId {
        let peer = target.peer_id().clone();
        #[cfg(feature = "_discovery-driver")]
        let candidates = resolve_book_candidates(
            self.discovery.as_ref().map(|discovery| &discovery.book),
            &peer,
            target.candidates().to_vec(),
        );
        #[cfg(not(feature = "_discovery-driver"))]
        let candidates = target.candidates().to_vec();
        let id = admit_connect(
            &mut self.connect,
            &mut self.core,
            #[cfg(feature = "_nat-driver")]
            self.nat.as_ref(),
            ConnectAdmission {
                peer: peer.clone(),
                candidates,
                allow_relay: true,
            },
            expand,
            now.monotonic_ms,
        );
        #[cfg(feature = "_nat-driver")]
        if let Some(nat) = self.nat.as_mut() {
            // Circuit addresses the book knows tell the relay leg where the
            // peer holds a reservation.
            #[cfg(feature = "_discovery-driver")]
            let target_addrs = self
                .discovery
                .as_ref()
                .map(|discovery| discovery.book.known_addrs(&peer))
                .unwrap_or_default();
            #[cfg(not(feature = "_discovery-driver"))]
            let target_addrs = Vec::new();
            nat.attach_leg(
                &self.connect,
                id,
                peer,
                true,
                target_addrs,
                &mut self.core,
                now,
            );
        }
        self.settle(now);
        id
    }

    /// Cancels an attempt and its NAT leg. Settled or unknown ids are a
    /// no-op; the terminal is queued before this returns.
    pub(crate) fn cancel_connect(&mut self, id: ConnectId, now: Now) {
        #[cfg(feature = "_nat-driver")]
        {
            let pump = cancel_attempt(
                &mut self.connect,
                self.nat.as_mut(),
                id,
                &mut self.core,
                now,
            );
            if pump && let Some(nat) = self.nat.as_mut() {
                nat.pump(&mut self.core, now);
            }
        }
        #[cfg(not(feature = "_nat-driver"))]
        self.connect.cancel(id, &mut self.core);
        self.settle(now);
    }

    /// Disconnects a peer, aborting dials still kept open for its
    /// simultaneous dial so none of them reconnects it.
    pub(crate) fn disconnect(&mut self, peer_id: &PeerId, now: Now) -> Result<(), DriverError> {
        self.connect.abort_retained(peer_id, &mut self.core);
        self.core.disconnect(peer_id, now.monotonic_ms)
    }

    /// The peer a stream operation on `stream_id` of `conn_id` addresses:
    /// the connection's peer while it is established, otherwise the peer a
    /// stream event still queued for it names (how `abandon_stream` reaches
    /// a stream whose `StreamClosed` is undelivered). The swarm then checks
    /// the exact connection, so a stale id never reaches a replacement's
    /// stream. A connection with neither is
    /// [`TransportError::ConnectionNotFound`].
    fn stream_peer(
        &self,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<PeerId, DriverError> {
        self.core
            .connection_peer(conn_id)
            .or_else(|| {
                self.events
                    .iter()
                    .find_map(|event| event.stream_peer(conn_id, stream_id))
            })
            .or_else(|| {
                self.core.buffered_events().find_map(|event| {
                    event
                        .peer_id()
                        .filter(|peer| event.matches_stream(peer, conn_id, stream_id))
                })
            })
            .cloned()
            .ok_or(DriverError::Transport(TransportError::ConnectionNotFound {
                id: conn_id,
            }))
    }

    /// Sends on an application stream; see `Endpoint::send_stream`.
    pub(crate) fn send_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        now: Now,
    ) -> Result<(), DriverError> {
        let peer_id = self.stream_peer(conn_id, stream_id)?;
        self.core
            .send_stream(&peer_id, conn_id, stream_id, data, now.monotonic_ms)
    }

    /// Half-closes an application stream's write side.
    pub(crate) fn close_stream_write(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        let peer_id = self.stream_peer(conn_id, stream_id)?;
        self.core
            .close_stream_write(&peer_id, conn_id, stream_id, now.monotonic_ms)
    }

    /// Resets an application stream.
    pub(crate) fn reset_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        let peer_id = self.stream_peer(conn_id, stream_id)?;
        self.core
            .reset_stream(&peer_id, conn_id, stream_id, now.monotonic_ms)
    }

    /// Resets and forgets a stream, dropping its events still queued here.
    ///
    /// A queued `StreamClosed` proves the stream existed even though the
    /// swarm, having already delivered that close, no longer knows it; its
    /// queued events are dropped all the same. Their data was never pulled,
    /// so it is acknowledged here, as the swarm does for data still in its
    /// own queue; after a reset that acknowledgement is moot, so its error
    /// is ignored.
    ///
    /// A stream whose connection ended needs no such proof (ADR 0012): with
    /// nothing left naming it, the transport settles it outright.
    pub(crate) fn abandon_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now: Now,
    ) -> Result<(), DriverError> {
        let Ok(peer_id) = &self.stream_peer(conn_id, stream_id) else {
            self.acks.forget(conn_id, stream_id);
            return self
                .core
                .abandon_ended_stream(conn_id, stream_id, now.monotonic_ms);
        };
        let queued_close = self.events.iter().any(|event| {
            matches!(event, EndpointEvent::StreamClosed { .. })
                && event.matches_stream(peer_id, conn_id, stream_id)
        });
        match self
            .core
            .abandon_stream(peer_id, conn_id, stream_id, now.monotonic_ms)
        {
            Ok(()) => {}
            Err(_) if queued_close => {}
            Err(error) => return Err(error),
        }
        let mut dropped_data = 0usize;
        self.events.retain(|event| {
            if !event.matches_stream(peer_id, conn_id, stream_id) {
                return true;
            }
            if let EndpointEvent::StreamData { data, .. } = event {
                dropped_data += data.len();
            }
            false
        });
        if dropped_data > 0 {
            match self.core.ack_stream(conn_id, stream_id, dropped_data) {
                Ok(()) | Err(_) => {}
            }
        }
        self.acks.forget(conn_id, stream_id);
        Ok(())
    }

    /// Registers a protocol whose data the application acknowledges itself.
    /// Streams already ready, whether their `StreamReady` waits here or in
    /// the swarm, keep the acknowledgement they had.
    #[cfg(feature = "std")]
    pub(crate) fn add_manual_ack_protocol(
        &mut self,
        protocol_id: String,
    ) -> Result<(), DriverError> {
        self.core.add_protocol(protocol_id.clone())?;
        let queued = self.events.iter().filter_map(|event| match event {
            EndpointEvent::StreamReady {
                conn_id,
                stream_id,
                protocol_id: ready,
                ..
            } => (*ready == protocol_id).then_some((*conn_id, *stream_id)),
            _ => None,
        });
        let buffered = self.core.buffered_events().filter_map(|event| match event {
            SwarmEvent::StreamReady {
                conn_id,
                stream_id,
                protocol_id: ready,
                ..
            } => (*ready == protocol_id).then_some((*conn_id, *stream_id)),
            _ => None,
        });
        let already_ready: Vec<_> = queued.chain(buffered).collect();
        self.acks.set_manual(protocol_id, already_ready);
        Ok(())
    }

    /// Takes the next queued event, acknowledging its stream data (ADR
    /// 0012): pulling an event consumes its bytes.
    #[cfg(feature = "std")]
    pub(crate) fn pop_event(&mut self) -> Option<EndpointEvent> {
        let event = self.events.pop_front()?;
        self.ack_pulled(&event);
        Some(event)
    }

    /// Takes every queued event, acknowledging their stream data.
    pub(crate) fn take_events(&mut self) -> Vec<EndpointEvent> {
        let events: Vec<EndpointEvent> = self.events.drain(..).collect();
        for event in &events {
            self.ack_pulled(event);
        }
        events
    }

    /// Acknowledges the data of a user-stream event the application pulls,
    /// unless its protocol takes manual acknowledgement. It only fails for
    /// data the application also acknowledged by hand.
    fn ack_pulled(&mut self, event: &EndpointEvent) {
        if let Some((conn_id, stream_id, bytes)) = self.acks.pulled(event) {
            match self.core.ack_stream(conn_id, stream_id, bytes) {
                Ok(()) | Err(_) => {}
            }
        }
    }

    /// Replaces the caller's external addresses; driver contributions are
    /// kept and merged after them.
    pub(crate) fn set_external_addresses(&mut self, addresses: Vec<Multiaddr>) {
        self.caller_external_addresses = addresses;
        self.refresh_addresses(true);
    }

    /// Re-merges the external address set after a driver's own address
    /// configuration changed outside a batch.
    #[cfg(feature = "relay-server")]
    pub(crate) fn addresses_changed(&mut self) {
        self.refresh_addresses(true);
    }

    #[cfg(feature = "pubsub")]
    pub(crate) fn subscribe(&mut self, topic: &str, now: Now) -> Result<bool, GossipsubError> {
        let pubsub = self.gossipsub.as_mut().ok_or(GossipsubError::NotEnabled)?;
        Ok(pubsub.subscribe(topic, &mut self.core, now.monotonic_ms)?)
    }

    #[cfg(feature = "pubsub")]
    pub(crate) fn unsubscribe(&mut self, topic: &str, now: Now) -> Result<bool, GossipsubError> {
        let reserved = self.reserved_topic();
        let pubsub = self.gossipsub.as_mut().ok_or(GossipsubError::NotEnabled)?;
        pubsub.unsubscribe(topic, reserved.as_deref(), &mut self.core, now.monotonic_ms)
    }

    #[cfg(feature = "pubsub")]
    pub(crate) fn publish(
        &mut self,
        topic: &str,
        data: Vec<u8>,
        now: Now,
    ) -> Result<(), GossipsubError> {
        let reserved = self.reserved_topic();
        let pubsub = self.gossipsub.as_mut().ok_or(GossipsubError::NotEnabled)?;
        pubsub.publish(
            topic,
            data,
            reserved.as_deref(),
            &mut self.core,
            now.monotonic_ms,
        )
    }

    /// The discovery beacon topic, reserved while signed discovery runs.
    #[cfg(feature = "pubsub")]
    fn reserved_topic(&self) -> Option<String> {
        #[cfg(feature = "_discovery-driver")]
        {
            self.discovery
                .as_ref()
                .and_then(DiscoveryDriver::topic)
                .map(String::from)
        }
        #[cfg(not(feature = "_discovery-driver"))]
        None
    }

    #[cfg(feature = "_discovery-driver")]
    pub(crate) fn known_peers(&self) -> Vec<minip2p_discovery::KnownPeer> {
        self.discovery
            .as_ref()
            .map(|discovery| discovery.book.known_peers())
            .unwrap_or_default()
    }

    #[cfg(feature = "_nat-driver")]
    pub(crate) fn reachability(&self) -> minip2p_nat::ReachabilityState {
        self.nat
            .as_ref()
            .map(NatDriver::reachability)
            .unwrap_or_default()
    }

    /// See `Endpoint::path`.
    pub(crate) fn path(&self, peer_id: &PeerId) -> Option<Path> {
        self.connection_path(self.core.connection_id(peer_id)?)
    }

    /// See `Endpoint::connection_info`.
    pub(crate) fn connection_info(&self, conn_id: ConnectionId) -> Option<ConnectionInfo> {
        let peer_id = self.core.connection_peer(conn_id)?.clone();
        let ready_protocols = self
            .core
            .peer_readiness(&peer_id)
            .filter(|(ready, _)| *ready == conn_id)
            .map(|(_, info)| info.protocols.clone());
        Some(ConnectionInfo {
            path: self.connection_path(conn_id)?,
            remote_addr: self.core.connection_remote_addr(conn_id)?.clone(),
            peer_id,
            conn_id,
            ready_protocols,
        })
    }

    /// The path of an established connection (see the module docs); `None`
    /// for a pending, replaced, or closed one.
    fn connection_path(&self, conn_id: ConnectionId) -> Option<Path> {
        self.core.connection_peer(conn_id)?;
        #[cfg(feature = "_nat-driver")]
        let punched = self.nat.as_ref().is_some_and(|nat| nat.is_punched(conn_id));
        #[cfg(not(feature = "_nat-driver"))]
        let punched = false;
        path_of(&self.core, punched, conn_id)
    }

    /// Names the path of every attempt that settled Connected in the step
    /// just run (or ahead of the swarm event just ingested), before a later
    /// event can replace or close its connection (see
    /// `ConnectEngine::resolve_paths`). A circuit's relay was recorded when
    /// it settled; a direct connection only needs NAT's punch record, which
    /// still holds for one whose close is queued, as NAT has not seen it.
    fn resolve_settled_paths(&mut self) {
        #[cfg(feature = "_nat-driver")]
        let nat = self.nat.as_ref();
        self.connect.resolve_paths(|conn_id| {
            #[cfg(feature = "_nat-driver")]
            {
                nat.is_some_and(|nat| nat.is_punched(conn_id))
            }
            #[cfg(not(feature = "_nat-driver"))]
            {
                let _ = conn_id;
                false
            }
        });
    }

    #[cfg(feature = "_circuit-driver")]
    pub(crate) fn active_reservation(&self) -> Option<minip2p_nat::ReservationInfo> {
        self.nat
            .as_ref()
            .and_then(|nat| nat.active_reservation().cloned())
    }

    /// Sends mDNS goodbyes and cancels discovery-owned attempts; their
    /// `ConnectSettled` terminals reach the application from the next batch.
    ///
    /// A goodbye that could not be sent is returned and also queued at once
    /// as a final `MdnsFailed`, so a caller that treats goodbyes as best
    /// effort still sees it on the event stream.
    #[cfg(feature = "_mdns-driver")]
    pub(crate) fn shutdown_mdns(&mut self, now: Now) -> Result<(), minip2p_mdns::MdnsError> {
        let result = match self.mdns.as_mut() {
            Some(mdns) => mdns.shutdown(now),
            None => Ok(()),
        };
        self.collect_mdns_events(now);
        self.events.extend(self.mdns_events.drain(..));
        if let Some(discovery) = self.discovery.as_mut() {
            let work = discovery.shutdown(
                &mut self.connect,
                #[cfg(feature = "_nat-driver")]
                self.nat.as_mut(),
                &mut self.core,
                now,
            );
            #[cfg(feature = "_nat-driver")]
            if let Some(nat) = self.nat.as_mut() {
                nat.apply_sweep_work(work, &self.connect, &mut self.core, now);
            }
            #[cfg(not(feature = "_nat-driver"))]
            drop(work);
        }
        result
    }

    /// Moves Gossipsub events still inside the agent into the queue, for a
    /// final drain that has no further turn.
    #[cfg(feature = "pubsub")]
    pub(crate) fn collect_agent_events(&mut self) {
        if let Some(pubsub) = self.gossipsub.as_mut() {
            pubsub.collect_agent_events();
        }
    }

    // ---------------------------------------------------------------------
    // Driving
    // ---------------------------------------------------------------------

    /// Settles attempts whose deadline passed. [`Self::drive`] does this
    /// first; std calls it before applying Name-resolution answers, so a
    /// late answer cannot turn a Timeout into another outcome.
    pub(crate) fn expire_attempts(&mut self, now: Now) {
        self.connect.tick(&mut self.core, now.monotonic_ms);
        self.resolve_settled_paths();
    }

    /// Runs one drive batch (see the module docs) and queues its output.
    ///
    /// An error discards nothing: what this batch already queued stays
    /// queued, and the next batch finishes the rest.
    pub(crate) fn drive(
        &mut self,
        now: Now,
        expand: &mut dyn FnMut(&PeerAddr) -> Expansion,
    ) -> Result<(), DriverError> {
        self.expire_attempts(now);
        self.ingest_transport(now)?;
        #[cfg(feature = "_mdns-driver")]
        self.tick_mdns(now)?;
        self.capability_pass(now, expand);
        self.settle(now);
        Ok(())
    }

    /// One transport poll's worth of swarm events.
    fn ingest_transport(&mut self, now: Now) -> Result<(), DriverError> {
        for event in self.core.poll(now)? {
            self.ingest(event, now);
        }
        Ok(())
    }

    /// Ticks mDNS, polls a shared transport again, and feeds mDNS
    /// observations to the book. An mDNS failure is an event, never an
    /// error: only the shared transport poll can fail here.
    #[cfg(feature = "_mdns-driver")]
    fn tick_mdns(&mut self, now: Now) -> Result<(), DriverError> {
        let Some(mdns) = self.mdns.as_mut() else {
            return Ok(());
        };
        mdns.tick(now, self.core.local_addresses());
        self.collect_mdns_events(now);
        if self.mdns_shares_transport {
            // The carrier drives the shared interface, which may have put
            // bytes into a socket after the transport was serviced.
            self.ingest_transport(now)?;
        }
        Ok(())
    }

    /// Feeds mDNS observations to the book and stages its failure and
    /// recovery events for the application.
    #[cfg(feature = "_mdns-driver")]
    fn collect_mdns_events(&mut self, now: Now) {
        use minip2p_mdns::MdnsEvent;

        let Some(mdns) = self.mdns.as_mut() else {
            return;
        };
        while let Some(event) = mdns.poll_event() {
            match event {
                MdnsEvent::Failed { error } => {
                    self.mdns_events.push(EndpointEvent::MdnsFailed { error });
                }
                MdnsEvent::Recovered => self.mdns_events.push(EndpointEvent::MdnsRecovered),
                observation => {
                    if let Some(discovery) = self.discovery.as_mut() {
                        discovery.handle_mdns_event(observation, now.monotonic_ms);
                    }
                }
            }
        }
    }

    /// Feeds one swarm event to the Connection engine and the drivers, and
    /// queues it unless one of them claimed it. Its capability and
    /// Connection-attempt output follows at the end of the batch.
    pub(crate) fn ingest(&mut self, event: SwarmEvent, now: Now) {
        let consumed = self
            .connect
            .observe(&event, &mut self.core, now.monotonic_ms)
            || self.ingest_into_drivers(&event, now);
        if !consumed {
            self.events.push_back(event.into());
        }
        // NAT output reaches the Connection engine in step with the swarm
        // events that caused it.
        self.route_nat(now);
    }

    /// Feeds one swarm event through relay-server, NAT, then Gossipsub.
    ///
    /// Relay service owns inbound HOP before NAT considers its client-side
    /// streams. Neither claims connection lifecycle or `PeerReady`, so both
    /// still observe the shared connection state. A stale `PeerReady`
    /// (queued before its connection was replaced) reaches only the
    /// application: drivers act peer-scoped and would start work on the
    /// not-yet-ready replacement. Returns `true` when a driver claimed it.
    fn ingest_into_drivers(&mut self, event: &SwarmEvent, now: Now) -> bool {
        let _ = now;
        #[cfg(feature = "_discovery-driver")]
        if let Some(discovery) = self.discovery.as_mut() {
            discovery.observe(event, &self.core, now.monotonic_ms);
        }
        if self.core.is_stale_peer_ready(event) {
            return false;
        }
        let claimed = false;
        #[cfg(feature = "relay-server")]
        let claimed = claimed
            || self
                .relay_server
                .as_mut()
                .is_some_and(|relay_server| relay_server.ingest(event, &mut self.core, now));
        #[cfg(feature = "_nat-driver")]
        let claimed = claimed
            || self
                .nat
                .as_mut()
                .is_some_and(|nat| nat.ingest(event, &mut self.core, now));
        #[cfg(feature = "pubsub")]
        let claimed = claimed
            || self
                .gossipsub
                .as_mut()
                .is_some_and(|pubsub| pubsub.ingest(event, &mut self.core, now.monotonic_ms));
        claimed
    }

    /// The batch's one capability pass: driver timers, the discovery sweep,
    /// and the external-address refresh when an input moved.
    #[cfg_attr(
        not(feature = "_discovery-driver"),
        expect(
            unused_variables,
            reason = "only the discovery sweep expands candidates"
        )
    )]
    fn capability_pass(&mut self, now: Now, expand: &mut dyn FnMut(&PeerAddr) -> Expansion) {
        #[cfg(test)]
        {
            self.stats.capability_passes += 1;
        }
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_mut() {
            relay_server.tick(&mut self.core, now);
        }
        #[cfg(feature = "_nat-driver")]
        if let Some(nat) = self.nat.as_mut() {
            nat.tick(&mut self.core, now);
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.gossipsub.as_mut() {
            pubsub.tick(&mut self.core, now);
        }
        self.route_nat(now);
        #[cfg(feature = "_discovery-driver")]
        if let Some(discovery) = self.discovery.as_mut() {
            let work = discovery.sweep(
                #[cfg(feature = "pubsub")]
                self.gossipsub.as_mut(),
                #[cfg(feature = "_nat-driver")]
                self.nat.as_mut(),
                &mut self.connect,
                &mut self.core,
                expand,
                now,
            );
            #[cfg(feature = "_nat-driver")]
            if let Some(nat) = self.nat.as_mut() {
                nat.apply_sweep_work(work, &self.connect, &mut self.core, now);
            }
            #[cfg(not(feature = "_nat-driver"))]
            drop(work);
            self.route_nat(now);
        }
        self.refresh_addresses(false);
    }

    /// Routes NAT output: the Connection engine, then discovery's ownership
    /// filter, then application staging. Then names the paths of what
    /// settled meanwhile: every step that can settle an attempt but
    /// `expire_attempts` ends here.
    fn route_nat(&mut self, now: Now) {
        #[cfg(feature = "_nat-driver")]
        if let Some(nat) = self.nat.as_mut() {
            #[cfg(feature = "_discovery-driver")]
            let discovery = self.discovery.as_ref();
            nat.route(
                &mut self.connect,
                &mut self.core,
                now.monotonic_ms,
                |event| {
                    #[cfg(feature = "_discovery-driver")]
                    {
                        discovery.is_some_and(|discovery| discovery.owns_nat_event(event))
                    }
                    #[cfg(not(feature = "_discovery-driver"))]
                    {
                        let _ = event;
                        false
                    }
                },
            );
        }
        #[cfg(not(feature = "_nat-driver"))]
        let _ = now;
        self.resolve_settled_paths();
    }

    /// Collects Connection-attempt terminals and queues everything staged:
    /// capability events (relay-server, NAT, Gossipsub, Discovery), then the
    /// terminals.
    ///
    /// Every terminal settles its NAT leg, which can produce more NAT
    /// events; those are routed before the drain. Discovery-owned
    /// terminals are claimed (and update the book) before the book's events
    /// are drained, so the updates surface in the same batch.
    pub(crate) fn settle(&mut self, now: Now) {
        let settled = self.collect_terminals(now);
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_mut() {
            self.events.extend(
                relay_server
                    .events
                    .drain(..)
                    .map(EndpointEvent::RelayServer),
            );
        }
        #[cfg(feature = "_nat-driver")]
        if let Some(nat) = self.nat.as_mut() {
            self.events
                .extend(nat.drain_application_events().map(EndpointEvent::Nat));
        }
        #[cfg(feature = "pubsub")]
        if let Some(pubsub) = self.gossipsub.as_mut() {
            self.events
                .extend(pubsub.events.drain(..).map(EndpointEvent::Gossipsub));
        }
        #[cfg(feature = "_discovery-driver")]
        if let Some(discovery) = self.discovery.as_mut() {
            discovery.drain_events(&mut self.events);
        }
        #[cfg(feature = "_mdns-driver")]
        self.events.extend(self.mdns_events.drain(..));
        self.events.extend(settled);
    }

    /// Takes every Connection-attempt terminal the application should see,
    /// routing NAT output until none is left.
    pub(crate) fn collect_terminals(&mut self, now: Now) -> Vec<EndpointEvent> {
        let mut settled = Vec::new();
        loop {
            self.route_nat(now);
            let Some(event) = self.connect.pop_event() else {
                break;
            };
            #[cfg(feature = "_nat-driver")]
            if let Some(nat) = self.nat.as_mut() {
                nat.settle_leg_on_terminal(&event, &mut self.core, now);
            }
            #[cfg(feature = "_discovery-driver")]
            if let Some(discovery) = self.discovery.as_mut()
                && discovery.claim_settled(&event, now.monotonic_ms)
            {
                continue;
            }
            settled.push(event);
        }
        settled
    }

    /// Recomputes the external address set Identify advertises, only when
    /// an input moved: the caller's set (`force`), NAT's contribution, or
    /// (with a relay server) the transport's listener addresses.
    fn refresh_addresses(&mut self, force: bool) {
        #[cfg(feature = "_nat-driver")]
        let nat_moved = self
            .nat
            .as_mut()
            .is_some_and(NatDriver::take_address_change);
        #[cfg(not(feature = "_nat-driver"))]
        let nat_moved = false;
        #[cfg(feature = "relay-server")]
        let listeners_moved = self.relay_server.is_some() && {
            let revision = self.core.transport().local_addresses_revision();
            let moved = revision.is_none() || revision != self.relay_listeners_revision;
            self.relay_listeners_revision = revision;
            moved
        };
        #[cfg(not(feature = "relay-server"))]
        let listeners_moved = false;
        if !(force || nat_moved || listeners_moved) {
            return;
        }
        #[cfg(test)]
        {
            self.stats.address_refreshes += 1;
        }
        #[cfg(feature = "relay-server")]
        if let Some(relay_server) = self.relay_server.as_mut() {
            let listeners = concrete_relay_listener_addrs(self.core.transport().local_addresses());
            // A rejected source keeps its previous addresses; the agent
            // queues `AddrsRejected` (and later `AddrsRestored`) instead.
            drop(relay_server.agent.set_listener_addrs(listeners));
            #[cfg(feature = "_nat-driver")]
            if let Some(nat) = self.nat.as_ref() {
                drop(
                    relay_server
                        .agent
                        .set_confirmed_addrs(nat.confirmed_public_addrs()),
                );
            }
            relay_server.collect_agent_events();
        }
        let addresses = self.caller_external_addresses.clone();
        #[cfg(feature = "_nat-driver")]
        let addresses = match self.nat.as_ref() {
            Some(nat) => merge_addresses(addresses, nat.advertised_addrs()),
            None => addresses,
        };
        #[cfg(feature = "relay-server")]
        let addresses = match self.relay_server.as_ref() {
            Some(relay_server) => merge_addresses(
                addresses,
                relay_server.agent.selected_addrs().iter().cloned(),
            ),
            None => addresses,
        };
        self.core.set_external_addresses(addresses);
    }

    /// When the Connection engine or a capability driver next has work, if
    /// either has a timer.
    pub(crate) fn driver_deadline(
        &self,
        #[cfg_attr(
            not(any(
                feature = "relay-server",
                feature = "_nat-driver",
                feature = "pubsub",
                feature = "_discovery-driver",
                feature = "_mdns-driver"
            )),
            expect(
                unused_variables,
                reason = "the connect engine's timer is already absolute"
            )
        )]
        now: Now,
    ) -> Option<Deadline> {
        [
            self.connect.next_deadline(),
            #[cfg(feature = "relay-server")]
            self.relay_server
                .as_ref()
                .and_then(|relay_server| relay_server.agent.next_deadline(now)),
            #[cfg(feature = "_nat-driver")]
            self.nat.as_ref().and_then(|nat| nat.next_deadline(now)),
            #[cfg(feature = "pubsub")]
            self.gossipsub
                .as_ref()
                .and_then(|pubsub| pubsub.next_deadline(now)),
            #[cfg(feature = "_discovery-driver")]
            self.discovery
                .as_ref()
                .and_then(|discovery| discovery.next_deadline(now)),
            #[cfg(feature = "_mdns-driver")]
            self.mdns.as_ref().and_then(|mdns| mdns.next_deadline(now)),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// When the engine next needs a batch: immediately while events wait to
    /// be pulled, else the earliest swarm, attempt, or driver timer.
    pub(crate) fn next_deadline(&self, now: Now) -> Option<Deadline> {
        if !self.events.is_empty() {
            return Some(Deadline::IMMEDIATE);
        }
        Deadline::earliest_opt(self.core.next_deadline(now), self.driver_deadline(now))
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;

/// `conn_id`'s path: Relayed for a circuit, through the relay its swarm
/// address names; otherwise Punched or Direct. Only a circuit needs its
/// swarm record, and one whose address does not name its relay is a bug,
/// reporting no path rather than a wrong one.
fn path_of<T: Transport, E: EntropySource>(
    core: &SwarmCore<T, E>,
    punched: bool,
    conn_id: ConnectionId,
) -> Option<Path> {
    if conn_id.is_circuit() {
        return circuit_relay(core, conn_id).map(|relay| Path::Relayed { relay });
    }
    Some(if punched { Path::Punched } else { Path::Direct })
}

/// Appends the contributions `addresses` does not already hold, keeping
/// first-wins order.
#[cfg(any(feature = "_nat-driver", feature = "relay-server"))]
fn merge_addresses(
    mut addresses: Vec<Multiaddr>,
    contributions: impl IntoIterator<Item = Multiaddr>,
) -> Vec<Multiaddr> {
    for address in contributions {
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses
}
