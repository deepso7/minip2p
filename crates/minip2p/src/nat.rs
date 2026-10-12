//! Caller-driven NAT capability shared by standard and portable Endpoints.
//! Time and entropy are supplied by the host; I/O runs through `SwarmCore`.

#[cfg(feature = "_circuit-driver")]
use alloc::{collections::BTreeMap, string::ToString};
use alloc::{collections::VecDeque, vec, vec::Vec};
#[cfg(not(feature = "_circuit-driver"))]
use core::marker::PhantomData;
use minip2p_platform::{EntropySource, Now};

#[cfg(feature = "_circuit-driver")]
use minip2p_circuit::{AdoptError, BridgeAdoption, CircuitRole, CircuitTransport};
use minip2p_core::{Bytes, ConnectId, Multiaddr, PeerAddr, PeerId, Protocol, select_direct_addrs};
#[cfg(feature = "_circuit-driver")]
use minip2p_nat::BridgeRole;
use minip2p_nat::{
    ConnectLegs, DialStart, NatAction, NatAgent, NatEvent, NatSwarm, NatSwarmError, NatToken,
    PromoteError, ReachabilityState,
};
use minip2p_swarm::{DriverError, HeldWrites, SwarmCore, SwarmEvent};
#[cfg(feature = "_circuit-driver")]
use minip2p_transport::TransportError;
use minip2p_transport::{ConnectionId, StreamId, Transport};

use crate::EndpointEvent;
use crate::portable::connect::ConnectEngine;
use crate::stream_conns::StreamConns;

/// `ConnectFailed` and `FellBackToRelay` are attempt terminals the
/// Connection-attempt engine already reports as `ConnectSettled`, so they
/// are not repeated to the application.
fn nat_event_reaches_application(event: &NatEvent) -> bool {
    !matches!(
        event,
        NatEvent::ConnectFailed { .. } | NatEvent::FellBackToRelay { .. }
    )
}

/// Most bytes the NAT host holds for one stream before resetting it.
const MAX_HELD_PER_STREAM: usize = 64 * 1024;

/// Joins held tails into one payload; a single tail is passed through.
#[cfg(feature = "_circuit-driver")]
fn concat(mut tails: VecDeque<Bytes>) -> Bytes {
    if tails.len() <= 1 {
        return tails.pop_front().unwrap_or_default();
    }
    Bytes::from(tails.into_iter().flatten().collect::<Vec<u8>>())
}

/// The circuit operations relay paths need from a transport: adopting a
/// relay bridge as a circuit connection and feeding that bridge's stream
/// events through. Captured as plain functions when the endpoint is built
/// over a [`CircuitTransport`], so the endpoint itself stays generic over
/// any `Transport`; a transport without them gets no relay configuration.
#[cfg(feature = "_circuit-driver")]
pub(crate) struct CircuitOps<T> {
    contains_circuit: fn(&T, ConnectionId) -> bool,
    inject_bridge_closed: fn(&mut T, ConnectionId, StreamId),
    inject_bridge_remote_write_closed: fn(&mut T, ConnectionId, StreamId),
    inject_bridge_write_stopped: fn(&mut T, ConnectionId, StreamId),
    inject_bridge_data: fn(&mut T, ConnectionId, StreamId, Bytes),
    adopt_bridge: fn(&mut T, BridgeAdoption) -> Result<ConnectionId, AdoptError>,
    reset_bridge: fn(&mut T, ConnectionId, StreamId) -> Result<(), TransportError>,
}

#[cfg(feature = "_circuit-driver")]
impl<I: Transport, R: EntropySource> CircuitOps<CircuitTransport<I, R>> {
    /// The operations of a [`CircuitTransport`] over any inner transport.
    pub(crate) fn circuit_transport() -> Self {
        Self {
            contains_circuit: |transport, id| transport.contains_circuit(id),
            inject_bridge_closed: |transport, conn, stream| {
                transport.inject_bridge_closed(conn, stream);
            },
            inject_bridge_remote_write_closed: |transport, conn, stream| {
                transport.inject_bridge_remote_write_closed(conn, stream);
            },
            inject_bridge_write_stopped: |transport, conn, stream| {
                transport.inject_bridge_write_stopped(conn, stream);
            },
            inject_bridge_data: |transport, conn, stream, data| {
                transport.inject_bridge_data(conn, stream, data);
            },
            adopt_bridge: |transport, adoption| transport.adopt_bridge(adoption),
            // The bridge is a stream of the wrapped relay connection.
            reset_bridge: |transport, conn, stream| {
                transport.inner_mut().reset_stream(conn, stream)
            },
        }
    }
}

/// Drives a [`NatAgent`] against the endpoint's swarm.
pub(crate) struct NatDriver<T> {
    agent: NatAgent,
    /// Agent output not yet routed; see [`Self::route`].
    unrouted: VecDeque<NatEvent>,
    /// Routed events bound for the Endpoint event stream.
    staged: VecDeque<NatEvent>,
    addresses_changed: bool,
    /// Relays we hold a reservation on, for circuit-address advertising.
    reserved_relays: Vec<(PeerId, Multiaddr)>,
    /// Relay transport addresses by peer, captured at construction.
    relay_addrs: Vec<(PeerId, Multiaddr)>,
    /// Direct public addresses confirmed by AutoNAT.
    public_addrs: Vec<Multiaddr>,
    /// Exact adopted bridge keys mapped to their promoted circuit ids.
    #[cfg(feature = "_circuit-driver")]
    promoted: BTreeMap<(ConnectionId, StreamId), ConnectionId>,
    /// The transport's circuit operations; `None` refuses promotions.
    #[cfg(feature = "_circuit-driver")]
    circuits: Option<CircuitOps<T>>,
    #[cfg(not(feature = "_circuit-driver"))]
    transport: PhantomData<fn(T)>,
    /// What the driver keeps around the swarm for the agent's commands.
    io: HostIo,
    /// The bound-address revision the agent's `listen_addrs` were seeded
    /// from; callers can bind through any swarm path between driver turns.
    listen_addrs_revision: u64,
    #[cfg(all(test, feature = "nat", feature = "quic"))]
    pub(crate) bridge_reset_attempts: Vec<(ConnectionId, StreamId)>,
}

impl<T: Transport> NatDriver<T> {
    /// Creates a driver over `agent`. `relay_addrs` are the transport
    /// addresses of configured relays, retained so reservations can be
    /// advertised as circuit addresses. `entropy` seeds the agent's jitter;
    /// later random bytes come from the swarm's own source.
    pub(crate) fn new(
        mut agent: NatAgent,
        relay_addrs: Vec<(PeerId, Multiaddr)>,
        entropy: &mut impl EntropySource,
    ) -> Self {
        // A failed draw keeps the agent's peer-id seed.
        let mut seed = [0u8; 8];
        if entropy.fill_bytes(&mut seed).is_ok() {
            agent.seed_jitter(u64::from_le_bytes(seed));
        }
        Self {
            agent,
            unrouted: VecDeque::new(),
            staged: VecDeque::new(),
            addresses_changed: false,
            reserved_relays: Vec::new(),
            relay_addrs,
            public_addrs: Vec::new(),
            #[cfg(feature = "_circuit-driver")]
            promoted: BTreeMap::new(),
            #[cfg(feature = "_circuit-driver")]
            circuits: None,
            #[cfg(not(feature = "_circuit-driver"))]
            transport: PhantomData,
            io: HostIo::default(),
            // Matches a fresh runtime: seed only after a real `listen*`
            // call bumped the revision. Some transports report bound-but-
            // not-listening sockets from `local_addresses`, so syncing on
            // an untouched revision would advertise a dial-back address
            // that drops packets.
            listen_addrs_revision: 0,
            #[cfg(all(test, feature = "nat", feature = "quic"))]
            bridge_reset_attempts: Vec::new(),
        }
    }

    /// Lets relay bridges become circuit connections over this transport.
    #[cfg(feature = "_circuit-driver")]
    pub(crate) fn with_circuits(mut self, circuits: CircuitOps<T>) -> Self {
        self.circuits = Some(circuits);
        self
    }

    /// Parks relay and AutoNAT dials to `/dns*` hosts for the caller to
    /// resolve off the driver; see [`Self::take_named_dials`].
    #[cfg(feature = "nat")]
    pub(crate) fn park_named_dials(mut self) -> Self {
        self.io.parked = Some(Vec::new());
        self
    }

    /// Moves out the parked `/dns*` dials. Each must come back through
    /// [`Self::named_dial_resolved`] once its name has an answer.
    #[cfg(feature = "nat")]
    pub(crate) fn take_named_dials(&mut self) -> Vec<(NatToken, PeerAddr)> {
        self.io
            .parked
            .as_mut()
            .map(core::mem::take)
            .unwrap_or_default()
    }

    /// Whether the agent still waits on a parked dial; retires it when not.
    /// See [`NatAgent::deferred_dial_wanted`].
    #[cfg(feature = "nat")]
    pub(crate) fn named_dial_wanted(&mut self, token: NatToken, sample: Now) -> bool {
        self.agent.deferred_dial_wanted(token, sample)
    }

    /// Finishes a parked dial: dials the first resolved address the swarm
    /// accepts, or reports the resolution failure, then pumps the agent. An
    /// answer for a dial the agent no longer waits on is dropped.
    #[cfg(feature = "nat")]
    pub(crate) fn named_dial_resolved<R: EntropySource>(
        &mut self,
        token: NatToken,
        resolved: crate::portable::connect::NameAnswer,
        swarm: &mut SwarmCore<T, R>,
        sample: Now,
    ) {
        if !self.named_dial_wanted(token, sample) {
            return;
        }
        let result = resolved.and_then(|targets| {
            let mut last = alloc::string::String::from("name resolved to no address");
            for target in targets {
                match swarm.dial(&target) {
                    Ok(conn_id) => return Ok(conn_id),
                    Err(error) => last = error.to_string(),
                }
            }
            Err(last)
        });
        let mut io = EndpointSwarm::new(swarm, &mut self.io);
        self.agent.dial_result(&mut io, token, result, sample);
        self.pump(swarm, sample);
    }

    /// Cancels a pending connect's NAT leg; settled or unknown ids are a
    /// no-op.
    pub(crate) fn cancel<R: EntropySource>(
        &mut self,
        id: ConnectId,
        swarm: &mut SwarmCore<T, R>,
        now: Now,
    ) {
        let mut io = EndpointSwarm::new(swarm, &mut self.io);
        self.agent.cancel(&mut io, id, now);
    }

    /// Cancels `id` in the Connection-attempt engine and, while the attempt
    /// is still pending, its NAT leg. Returns `true` when the leg was
    /// cancelled and the caller must `pump` the queued actions.
    ///
    /// The pending check runs before the engine cancel: `ConnectEngine`
    /// forgets the attempt once it settles, but the agent would still close
    /// a provisional relayed path the engine already settled on.
    pub(crate) fn cancel_leg<R: EntropySource>(
        &mut self,
        connect: &mut ConnectEngine,
        id: ConnectId,
        swarm: &mut SwarmCore<T, R>,
        now: Now,
    ) -> bool {
        let pending = connect.is_pending(id);
        connect.cancel(id, swarm);
        if pending {
            self.cancel(id, swarm, now);
        }
        pending
    }

    /// Registers a pending connect with the agent and immediately executes
    /// any resulting actions, so dial legs leave in the same driver turn.
    pub(crate) fn connect<R: EntropySource>(
        &mut self,
        id: ConnectId,
        peer: PeerId,
        legs: ConnectLegs,
        swarm: &mut SwarmCore<T, R>,
        sample: Now,
    ) {
        let mut io = EndpointSwarm::new(swarm, &mut self.io);
        self.agent.connect(&mut io, id, peer, legs, sample);
        self.pump(swarm, sample);
    }

    /// How long the caller may idle before [`NatDriver::tick`] has work: `0`
    /// when queued events or agent timers are due, `None` when nothing is.
    pub(crate) fn next_timeout(&self, now: Now) -> Option<u64> {
        if !self.unrouted.is_empty() || !self.staged.is_empty() {
            Some(0)
        } else {
            self.agent.next_timeout(now.monotonic_ms)
        }
    }

    /// Returns the current AutoNAT reachability verdict.
    pub(crate) fn reachability(&self) -> ReachabilityState {
        self.agent.reachability()
    }

    /// Returns the currently held relay reservation, when any.
    #[cfg(feature = "_circuit-driver")]
    pub(crate) fn active_reservation(&self) -> Option<&minip2p_nat::ReservationInfo> {
        self.agent.active_reservation()
    }

    /// Whether the advertised address set changed since the last call. The
    /// endpoint refreshes Identify's external addresses only when it did.
    pub(crate) fn take_address_change(&mut self) -> bool {
        core::mem::take(&mut self.addresses_changed)
    }

    /// Re-seeds the agent's advertised listen addresses when the listened
    /// set moved since the last driver turn. Revision-checked, so an
    /// unchanged set costs one integer compare and no transport read. Uses
    /// the runtime's recorded listen results rather than bound addresses —
    /// a transport can report sockets it never listened on.
    fn sync_listen_addrs<R: EntropySource>(&mut self, swarm: &SwarmCore<T, R>) {
        let revision = swarm.listened_addrs_revision();
        if revision == self.listen_addrs_revision {
            return;
        }
        self.agent
            .set_listen_addrs(&select_direct_addrs(swarm.listened_addrs(), None, None));
        self.listen_addrs_revision = revision;
    }

    /// Feeds one swarm event to the agent and executes its cascade.
    ///
    /// Returns `true` when the event belongs to the NAT control plane and
    /// must not be forwarded to the application. The agent's disposition is
    /// authoritative even when handling claims or releases the stream.
    pub(crate) fn ingest<R: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        swarm: &mut SwarmCore<T, R>,
        now: Now,
    ) -> bool {
        self.sync_listen_addrs(swarm);
        self.io.held.observe(event);
        self.io.stream_conns.observe(event);
        #[cfg(feature = "_circuit-driver")]
        if self.inject_straggler(event, swarm) {
            self.pump(swarm, now);
            return true;
        }
        if let SwarmEvent::StreamWritable {
            peer_id,
            conn_id,
            stream_id,
        } = event
            && self.io.stream_conns.get(peer_id, *stream_id) == Some(*conn_id)
        {
            EndpointSwarm::new(swarm, &mut self.io).replay_held(
                peer_id,
                *conn_id,
                *stream_id,
                now.monotonic_ms,
            );
            self.pump(swarm, now);
            return true;
        }
        let is_circuit = match event {
            SwarmEvent::ConnectionEstablished { conn_id, .. }
            | SwarmEvent::ConnectionClosed { conn_id, .. }
            | SwarmEvent::ConnectionReplaced { new: conn_id, .. } => conn_id.is_circuit(),
            _ => false,
        };
        let mut io = EndpointSwarm::new(swarm, &mut self.io);
        let handled = self.agent.handle_event(&mut io, event, is_circuit, now);
        if !handled {
            self.io.stream_conns.unclaimed(event);
        }
        // The agent consumes what it claims as it reads it, including bytes
        // past a CONNECT response that a promoted bridge's circuit takes
        // as adoption data: the circuit acknowledges only what it reads
        // itself.
        if handled
            && let SwarmEvent::StreamData {
                conn_id,
                stream_id,
                data,
                ..
            } = event
        {
            match swarm.ack_stream(*conn_id, *stream_id, data.len()) {
                Ok(()) | Err(_) => {}
            }
        }
        // A gone carrier connection (closed, or replaced: its streams end
        // with it) closes the bridges it carried.
        #[cfg(feature = "_circuit-driver")]
        if let SwarmEvent::ConnectionClosed { conn_id, .. }
        | SwarmEvent::ConnectionReplaced { old: conn_id, .. } = event
            && let Some(circuits) = self.circuits.as_ref()
        {
            for &(inner_conn, stream_id) in self
                .promoted
                .keys()
                .filter(|(inner_conn, _)| inner_conn == conn_id)
            {
                (circuits.inject_bridge_closed)(swarm.transport_mut(), inner_conn, stream_id);
            }
            self.promoted
                .retain(|(inner_conn, _), circuit| inner_conn != conn_id && circuit != conn_id);
        }
        self.pump(swarm, now);
        handled
    }

    /// Advances timers only when the agent reports a due deadline, then
    /// executes any resulting work.
    ///
    /// Also the bounded safety sweep over promoted bridges: one whose circuit
    /// vanished without a lifecycle event is forgotten here, once per
    /// endpoint batch rather than on every swarm event. Closures that do
    /// surface reach `ingest`'s `ConnectionClosed` branch regardless.
    pub(crate) fn tick<R: EntropySource>(&mut self, swarm: &mut SwarmCore<T, R>, now: Now) {
        #[cfg(feature = "_circuit-driver")]
        if let Some(circuits) = self.circuits.as_ref() {
            self.promoted
                .retain(|_, id| (circuits.contains_circuit)(swarm.transport(), *id));
        }
        // A fresh listen must seed even when the agent has no due work —
        // the seed is what arms the probe timers that would otherwise
        // keep this tick early-returning forever.
        self.sync_listen_addrs(swarm);
        if self.agent.next_timeout(now.monotonic_ms) != Some(0) {
            return;
        }
        let mut io = EndpointSwarm::new(swarm, &mut self.io);
        self.agent.handle_tick(&mut io, now);
        self.pump(swarm, now);
    }

    /// Executes queued agent actions (echoing promotion results back) and
    /// collects application-visible NAT events.
    pub(crate) fn pump<R: EntropySource>(&mut self, swarm: &mut SwarmCore<T, R>, sample: Now) {
        self.sync_listen_addrs(swarm);
        loop {
            let mut progressed = false;
            while let Some(action) = self.agent.poll_action() {
                progressed = true;
                self.execute(action, swarm, sample);
            }
            while let Some(event) = self.agent.poll_event() {
                progressed = true;
                self.observe(&event);
                self.unrouted.push_back(event);
            }
            if !progressed {
                break;
            }
        }
    }

    /// Routes every event the agent produced since the last call, each
    /// exactly once: the Connection-attempt engine observes it first, then
    /// `owned` (discovery's ownership filter) consumes events that belong
    /// to automatic dials, and the rest is staged for the Endpoint event
    /// stream unless the engine reports it as `ConnectSettled` instead.
    ///
    /// Observing can settle attempts, whose terminals the endpoint collects
    /// next; their cleanup can produce more events, so the endpoint routes
    /// again until nothing is left before its final drain.
    pub(crate) fn route<R: EntropySource>(
        &mut self,
        connect: &mut ConnectEngine,
        swarm: &mut SwarmCore<T, R>,
        now_ms: u64,
        owned: impl Fn(&NatEvent) -> bool,
    ) {
        while let Some(event) = self.unrouted.pop_front() {
            connect.observe_nat(&event, swarm, now_ms);
            if !owned(&event) && nat_event_reaches_application(&event) {
                self.staged.push_back(event);
            }
        }
    }

    /// Attaches the attempt's NAT leg while it is still pending. The endpoint
    /// calls this right after `admit_connect`, which itself knows nothing of
    /// NAT. `target_addrs` are the addresses known for `peer`; circuit
    /// addresses among them steer the relay leg toward relays the peer is
    /// reserved at.
    #[expect(
        clippy::too_many_arguments,
        reason = "one flat call per admission site; a bundle type would only move the fields"
    )]
    pub(crate) fn attach_leg<R: EntropySource>(
        &mut self,
        connect: &ConnectEngine,
        id: ConnectId,
        peer: PeerId,
        allow_relay: bool,
        target_addrs: Vec<Multiaddr>,
        swarm: &mut SwarmCore<T, R>,
        sample: Now,
    ) {
        if connect.is_pending(id) {
            self.connect(
                id,
                peer,
                ConnectLegs {
                    direct_racing: connect.dialed_direct(id),
                    allow_relay,
                    target_addrs,
                    deadline_ms: connect.expires_ms(id),
                },
                swarm,
                sample,
            );
        }
    }

    /// Applies the work a `DiscoveryDriver` sweep queued: attaches legs for
    /// attempts automatic dialing admitted, then pumps once when a leg was
    /// cancelled. Call it right after the sweep.
    #[cfg(feature = "_discovery-driver")]
    pub(crate) fn apply_sweep_work<R: EntropySource>(
        &mut self,
        work: crate::discovery::DiscoveryNatWork,
        connect: &ConnectEngine,
        swarm: &mut SwarmCore<T, R>,
        sample: Now,
    ) {
        for leg in work.legs {
            self.attach_leg(
                connect,
                leg.id,
                leg.peer,
                leg.allow_relay,
                leg.addrs,
                swarm,
                sample,
            );
        }
        if work.pump {
            self.pump(swarm, sample);
        }
    }

    /// Cancels the attempt's NAT leg when `event` is a failed or cancelled
    /// Connection-attempt terminal. Connected and unrelated events are a
    /// no-op: a settled provisional path is the leg to keep.
    pub(crate) fn cancel_leg_on_terminal<R: EntropySource>(
        &mut self,
        event: &EndpointEvent,
        swarm: &mut SwarmCore<T, R>,
        sample: Now,
    ) {
        let EndpointEvent::ConnectSettled {
            connect_id,
            outcome: crate::ConnectOutcome::Failed(_) | crate::ConnectOutcome::Cancelled,
            ..
        } = event
        else {
            return;
        };
        self.cancel(*connect_id, swarm, sample);
        self.pump(swarm, sample);
    }

    /// Queues an event as if the agent emitted it; the next route sends it
    /// through the Connection engine and on to the application.
    #[cfg(all(test, any(feature = "nat", feature = "portable-relay")))]
    pub(crate) fn push_event(&mut self, event: NatEvent) {
        self.unrouted.push_back(event);
    }

    /// Drains the routed events bound for the Endpoint event stream.
    pub(crate) fn drain_application_events(&mut self) -> impl Iterator<Item = NatEvent> + '_ {
        self.staged.drain(..)
    }

    /// Whether any relay is configured for reservations or circuit dialing.
    pub(crate) fn has_relay(&self) -> bool {
        self.agent.has_relay()
    }

    /// Whether connects skip direct racing and DCUtR.
    pub(crate) fn force_relay(&self) -> bool {
        self.agent.force_relay()
    }

    /// Returns the NAT-orchestrated path of `peer`'s current connection; see
    /// [`NatAgent::path`].
    #[cfg(feature = "_circuit-driver")]
    pub(crate) fn path<R: EntropySource>(
        &self,
        swarm: &SwarmCore<T, R>,
        peer: &PeerId,
    ) -> Option<minip2p_nat::Path> {
        self.agent.path(swarm, peer).cloned()
    }

    /// Confirmed public addresses plus circuit addresses for every held
    /// relay reservation — the set Identify should advertise.
    pub(crate) fn advertised_addrs(&self) -> Vec<Multiaddr> {
        let mut addrs = self.public_addrs.clone();
        for (_, addr) in &self.reserved_relays {
            if !addrs.contains(addr) {
                addrs.push(addr.clone());
            }
        }
        addrs
    }

    /// Returns only the AutoNAT-confirmed public addresses, for relay-server
    /// advertisement.
    #[cfg(feature = "relay-server")]
    pub(crate) fn confirmed_public_addrs(&self) -> Vec<Multiaddr> {
        self.public_addrs.clone()
    }

    #[cfg(all(test, feature = "relay-server"))]
    pub(crate) fn set_test_public_addrs(&mut self, addrs: Vec<Multiaddr>) {
        self.public_addrs = addrs;
        self.addresses_changed = true;
    }

    /// The listen addresses AutoNAT currently offers for dial-back.
    #[cfg(all(test, feature = "nat", feature = "quic"))]
    pub(crate) fn listen_addrs(&self) -> &[Multiaddr] {
        self.agent.listen_addrs()
    }

    /// The adopted-bridge to promoted-circuit map, for test assertions.
    #[cfg(all(test, feature = "nat", feature = "quic"))]
    pub(crate) fn promoted(&self) -> &BTreeMap<(ConnectionId, StreamId), ConnectionId> {
        &self.promoted
    }

    /// Executes one agent action and echoes a promotion result back. These
    /// need the transport underneath the swarm; the agent issues swarm
    /// commands itself. Best-effort actions swallow errors; the agent's
    /// timeouts and the swarm's lifecycle events surface failures.
    pub(crate) fn execute<R: EntropySource>(
        &mut self,
        action: NatAction,
        swarm: &mut SwarmCore<T, R>,
        now: Now,
    ) {
        match action {
            NatAction::SendRandomUdp {
                target,
                payload_len,
            } => {
                let mut payload = vec![0u8; payload_len];
                // A failed entropy now simply skips this one best-effort
                // hole-punch datagram.
                if let Ok(()) = swarm.entropy_mut().fill_bytes(&mut payload) {
                    match swarm.transport_mut().send_datagram(&target, &payload) {
                        Ok(()) | Err(_) => {}
                    }
                }
            }
            NatAction::PromoteBridge {
                token,
                inner_conn,
                relay,
                stream_id,
                remote_peer,
                role,
                pending_data,
                remote_write_closed,
            } => {
                #[cfg(not(feature = "_circuit-driver"))]
                {
                    let _ = (
                        inner_conn,
                        stream_id,
                        relay,
                        remote_peer,
                        role,
                        pending_data,
                        remote_write_closed,
                    );
                    let mut io = EndpointSwarm::new(swarm, &mut self.io);
                    self.agent.promote_result(
                        &mut io,
                        token,
                        Err(PromoteError::Failed("portable relay is not enabled".into())),
                        now,
                    );
                }
                #[cfg(feature = "_circuit-driver")]
                {
                    let key = (inner_conn, stream_id);
                    if let Some(existing) = self.promoted.get(&key).copied() {
                        let mut io = EndpointSwarm::new(swarm, &mut self.io);
                        self.agent.promote_result(&mut io, token, Ok(existing), now);
                        return;
                    }
                    // The endpoint refuses relay configuration over a
                    // transport without circuit operations, so this is only
                    // reached by a relay the agent was never given.
                    let Some(circuits) = self.circuits.as_ref() else {
                        let mut io = EndpointSwarm::new(swarm, &mut self.io);
                        self.agent.promote_result(
                            &mut io,
                            token,
                            Err(PromoteError::Failed(
                                "the transport has no circuit operations".into(),
                            )),
                            now,
                        );
                        return;
                    };
                    // Bytes refused as Full are still owed to the peer: the
                    // core's (a negotiation reply, say), then ours (a STOP
                    // STATUS). The circuit takes Writable for the stream now,
                    // so it sends them first, in that order.
                    let mut owed = swarm.forget_stream(inner_conn, stream_id);
                    if let Some(held) = self.io.held.take(inner_conn, stream_id) {
                        owed.extend(held.tails);
                    }
                    let unsent_prefix = concat(owed);
                    let adoption = BridgeAdoption {
                        inner_conn,
                        bridge_stream: stream_id,
                        relay,
                        remote_peer,
                        role: match role {
                            BridgeRole::Initiator => CircuitRole::Initiator,
                            BridgeRole::Responder => CircuitRole::Responder,
                        },
                        pending_data: pending_data.into(),
                        unsent_prefix,
                        remote_write_closed,
                    };
                    match (circuits.adopt_bridge)(swarm.transport_mut(), adoption) {
                        Ok(conn_id) => {
                            self.promoted.insert(key, conn_id);
                            let mut io = EndpointSwarm::new(swarm, &mut self.io);
                            self.agent.promote_result(&mut io, token, Ok(conn_id), now);
                        }
                        Err(error) => {
                            let promote_error = match &error {
                                AdoptError::PeerAlreadyDirect => PromoteError::PeerAlreadyDirect,
                                AdoptError::UnknownConnection => PromoteError::UnknownConnection,
                                _ => PromoteError::Failed(error.to_string()),
                            };
                            let mut io = EndpointSwarm::new(swarm, &mut self.io);
                            self.agent
                                .promote_result(&mut io, token, Err(promote_error), now);
                            if !matches!(error, AdoptError::UnknownConnection) {
                                #[cfg(all(test, feature = "nat", feature = "quic"))]
                                self.bridge_reset_attempts.push((inner_conn, stream_id));
                                match (circuits.reset_bridge)(
                                    swarm.transport_mut(),
                                    inner_conn,
                                    stream_id,
                                ) {
                                    Ok(()) | Err(_) => {}
                                }
                            }
                        }
                    }
                }
            }
            NatAction::CloseCircuit { conn_id } => {
                match swarm.transport_mut().close(conn_id) {
                    Ok(()) | Err(minip2p_transport::TransportError::ConnectionNotFound { .. }) => {
                        #[cfg(feature = "_circuit-driver")]
                        self.promoted.retain(|_, id| *id != conn_id);
                    }
                    // A transport failure will emerge through its normal
                    // event path; retain the promotion until then.
                    Err(_) => {}
                }
            }
        }
    }

    #[cfg(feature = "_circuit-driver")]
    fn inject_straggler<R: EntropySource>(
        &mut self,
        event: &SwarmEvent,
        swarm: &mut SwarmCore<T, R>,
    ) -> bool {
        let key = match event {
            SwarmEvent::StreamData {
                conn_id, stream_id, ..
            }
            | SwarmEvent::StreamWritable {
                conn_id, stream_id, ..
            }
            | SwarmEvent::StreamRemoteWriteClosed {
                conn_id, stream_id, ..
            }
            | SwarmEvent::StreamWriteStopped {
                conn_id, stream_id, ..
            }
            | SwarmEvent::StreamClosed {
                conn_id, stream_id, ..
            } => (*conn_id, *stream_id),
            _ => return false,
        };
        let Some(circuits) = self.circuits.as_ref() else {
            return false;
        };
        if !self.promoted.contains_key(&key) {
            return false;
        }
        let transport = swarm.transport_mut();
        match event {
            SwarmEvent::StreamData { data, .. } => {
                (circuits.inject_bridge_data)(transport, key.0, key.1, data.clone());
            }
            // The circuit sees the bridge's Writable straight from the
            // transport; the swarm's copy is a straggler with nothing to do.
            SwarmEvent::StreamWritable { .. } => {}
            SwarmEvent::StreamRemoteWriteClosed { .. } => {
                (circuits.inject_bridge_remote_write_closed)(transport, key.0, key.1);
            }
            SwarmEvent::StreamWriteStopped { .. } => {
                (circuits.inject_bridge_write_stopped)(transport, key.0, key.1);
            }
            SwarmEvent::StreamClosed { .. } => {
                (circuits.inject_bridge_closed)(transport, key.0, key.1);
                self.promoted.remove(&key);
            }
            // `key` was extracted above only for these stream events.
            // Keep this defensive if a new swarm event reaches this path.
            _ => return false,
        }
        true
    }

    /// Updates NAT's address contribution after a lifecycle event.
    pub(crate) fn observe(&mut self, event: &NatEvent) {
        match event {
            NatEvent::RelayReserved { relay, .. } => {
                if self.reserved_relays.iter().any(|(peer, _)| peer == relay) {
                    return; // renewal — already advertised
                }
                let Some((_, transport)) = self.relay_addrs.iter().find(|(p, _)| p == relay) else {
                    return;
                };
                let mut circuit = transport.clone();
                circuit.push(Protocol::P2p(relay.clone()));
                circuit.push(Protocol::P2pCircuit);
                self.reserved_relays.push((relay.clone(), circuit));
                self.addresses_changed = true;
            }
            NatEvent::RelayReservationLost { relay } => {
                let before = self.reserved_relays.len();
                self.reserved_relays.retain(|(peer, _)| peer != relay);
                self.addresses_changed |= before != self.reserved_relays.len();
            }
            NatEvent::ReachabilityChanged {
                confirmed_addrs: addrs,
                ..
            }
            | NatEvent::PublicAddressesChanged { addrs }
                if self.public_addrs != *addrs =>
            {
                self.public_addrs = addrs.clone();
                self.addresses_changed = true;
            }
            _ => {}
        }
    }
}

/// What the NAT driver keeps around the swarm for the agent's commands.
#[derive(Default)]
struct HostIo {
    /// Connection of each stream the agent opened or claimed, so the
    /// driver can tell the agent's `StreamWritable` events apart.
    stream_conns: StreamConns,
    /// Unsent tails of the agent's writes, resent on the stream's Writable
    /// so a full stream delays control messages instead of losing them.
    held: HeldWrites,
    /// Dials to `/dns*` hosts parked for the composition to resolve, when it
    /// owns Name resolution (the std Endpoint); `None` rejects them.
    parked: Option<Vec<(NatToken, PeerAddr)>>,
}

/// The [`NatSwarm`] the driver hands the agent: the swarm, plus parking for
/// named dials and held write tails. Borrowed for one agent call.
struct EndpointSwarm<'a, T: Transport, R: EntropySource> {
    swarm: &'a mut SwarmCore<T, R>,
    io: &'a mut HostIo,
}

impl<'a, T: Transport, R: EntropySource> EndpointSwarm<'a, T, R> {
    fn new(swarm: &'a mut SwarmCore<T, R>, io: &'a mut HostIo) -> Self {
        Self { swarm, io }
    }

    /// Writes `data`, or holds it behind the stream's unsent tail. A Full
    /// holds what the stream did not take.
    fn send_or_hold(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        let counted = data.len();
        let held = &mut self.io.held;
        if held.is_held(conn_id, stream_id) {
            held.push(conn_id, stream_id, data, counted);
        } else {
            match self
                .swarm
                .send_stream(peer, conn_id, stream_id, data, now_ms)
            {
                Ok(()) => {}
                Err(DriverError::Full { unsent, .. }) => {
                    held.push(conn_id, stream_id, unsent, counted);
                }
                Err(error) => return Err(error),
            }
        }
        // NAT messages are a few hundred bytes; a peer that leaves this much
        // unread is not completing the exchange, so the stream goes.
        if held.held_bytes(conn_id, stream_id) > MAX_HELD_PER_STREAM {
            held.forget_stream(conn_id, stream_id);
            match self.swarm.reset_stream(peer, conn_id, stream_id, now_ms) {
                Ok(()) | Err(_) => {}
            }
        }
        Ok(())
    }

    /// Closes the write side once nothing is held for the stream.
    fn close_or_hold(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), DriverError> {
        if self.io.held.close_after(conn_id, stream_id) {
            return Ok(());
        }
        self.swarm
            .close_stream_write(peer, conn_id, stream_id, now_ms)
    }

    /// Resends a writable stream's held tails, then its deferred close.
    fn replay_held(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) {
        let Some(held) = self.io.held.take(conn_id, stream_id) else {
            return;
        };
        // Failures surface through the agent's own timeouts and the swarm's
        // events, as for the first write.
        for data in held.tails {
            match self.send_or_hold(peer, conn_id, stream_id, data, now_ms) {
                Ok(()) | Err(_) => {}
            }
        }
        if held.close {
            match self.close_or_hold(peer, conn_id, stream_id, now_ms) {
                Ok(()) | Err(_) => {}
            }
        }
    }
}

impl<T: Transport, R: EntropySource> NatSwarm for EndpointSwarm<'_, T, R> {
    fn connection(&self, peer: &PeerId) -> Option<ConnectionId> {
        NatSwarm::connection(&*self.swarm, peer)
    }

    fn readiness(&self, peer: &PeerId) -> Option<(ConnectionId, &[alloc::string::String])> {
        NatSwarm::readiness(&*self.swarm, peer)
    }

    /// Parks a dial to a named host for the composition's resolver, so the
    /// agent's token is already registered when the answer comes back.
    fn dial(&mut self, addr: &PeerAddr, token: NatToken) -> Result<DialStart, NatSwarmError> {
        if let Some(parked) = self.io.parked.as_mut()
            && minip2p_nat::is_named(addr)
        {
            parked.push((token, addr.clone()));
            return Ok(DialStart::Deferred);
        }
        NatSwarm::dial(&mut *self.swarm, addr, token)
    }

    fn open_stream(
        &mut self,
        peer: &PeerId,
        protocol_id: &str,
        now_ms: u64,
    ) -> Result<(ConnectionId, StreamId), NatSwarmError> {
        let (conn_id, stream_id) = self.swarm.open_stream(peer, protocol_id, now_ms)?;
        self.io.stream_conns.opened(peer, conn_id, stream_id);
        Ok((conn_id, stream_id))
    }

    fn send_stream(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(self.send_or_hold(peer, conn_id, stream_id, data, now_ms)?)
    }

    fn close_stream_write(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(self.close_or_hold(peer, conn_id, stream_id, now_ms)?)
    }

    fn reset_stream(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) -> Result<(), NatSwarmError> {
        Ok(self.swarm.reset_stream(peer, conn_id, stream_id, now_ms)?)
    }

    fn ping(&mut self, peer: &PeerId, now_ms: u64) -> Result<(), NatSwarmError> {
        Ok(self.swarm.ping(peer, now_ms)?)
    }
}
