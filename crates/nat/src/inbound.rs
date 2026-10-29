//! Inbound circuit and hole-punch coordination for a listener holding a
//! relay reservation. The STOP bridge is promoted first. Once the Relayed
//! path is usable, this reserved peer opens `/libp2p/dcutr` and sends CONNECT
//! and SYNC. The original circuit dialer performs the QUIC dial while this
//! peer sends random UDP to open its NAT mapping.
//!
//! ```text
//! relay opens STOP stream ──▶ CONNECT ──▶ auto-Accept (STATUS:OK)
//!   ──▶ promote bridge ──▶ circuit Connected
//!   ──▶ InboundPathEstablished(Relayed)
//!   ──▶ round: open DCUtR ──▶ send CONNECT, then SYNC ──▶ punch window
//!   ──▶ no direct connection: next round, up to MAX_DCUTR_ROUNDS
//! circuit dialer's punch lands ──▶ InboundDirectUpgrade
//! ```
//!
//! Each round is a fresh exchange on a fresh stream with its own RTT, timed
//! from when CONNECT is fully written. Rounds are bounded by
//! `dcutr_exchange_timeout_ms` each and `upgrade_timeout_ms` overall.
//!
//! This peer dials nothing, so the deadline is its only evidence that a
//! direct connection is the dialer's punch. Once a round sends SYNC, the
//! machine opens a punch window for the source in the path ledger until
//! the upgrade deadline, and the ledger attributes direct connections from
//! the source in it as `Punched`. The window outlives the machine: the
//! dialer may land a second punch that replaces the first after this side's
//! punch window, and that one is a punch too.

use alloc::vec::Vec;

use minip2p_core::platform::Now;
use minip2p_core::{Multiaddr, PeerId, Protocol, select_direct_addrs};
use minip2p_dcutr::{DcutrError, DcutrInitiator, DcutrInitiatorOutput, InitiatorOutcome};
use minip2p_relay::{RelayError, Status, StopResponder, StopResponderOutput};
use minip2p_transport::{ConnectionId, StreamId};

use crate::agent::{Shared, StreamInput, StreamRole, close_write, reset, send};
use crate::config::MAX_DCUTR_ROUNDS;
use crate::events::{NatAction, NatEvent};
use crate::ledger::{Claim, Owner};
use crate::swarm::{BridgeHandoff, BridgeRole, NatSwarm};

/// Responder-side UDP blast schedule during the punch window.
struct BlastSchedule {
    addrs: Vec<Multiaddr>,
    next_at: u64,
    until: u64,
}

/// One inbound relay circuit: STOP acceptance, DCUtR responder exchange,
/// and the punch-window UDP blasts.
pub(crate) struct InboundCircuit {
    id: u64,
    inner_conn: ConnectionId,
    /// The peer that opened the STOP stream to us (the relay).
    relay: PeerId,
    stream: StreamId,
    /// The initiating peer, once the STOP CONNECT names it.
    source: Option<PeerId>,
    stop: Option<StopResponder>,
    /// The initiator for the opened DCUtR stream, or the error that kept it
    /// from being built, reported once the stream is ready.
    dcutr: Option<Result<DcutrInitiator, DcutrError>>,
    /// The DCUtR stream this peer opened, on the promoted circuit.
    dcutr_stream: Option<(ConnectionId, StreamId)>,
    /// The current round's CONNECT was handed to the swarm.
    dcutr_connect_queued: bool,
    /// Monotonic time when the current round's CONNECT was fully written
    /// (held tail included), used to synchronize the first QUIC blast at
    /// half the measured relay RTT.
    dcutr_connect_sent_at: Option<u64>,
    /// The current round's exchange must reach the remote's CONNECT by then.
    dcutr_deadline: Option<u64>,
    /// DCUtR rounds started on this circuit.
    rounds: u32,
    /// The whole upgrade ends then; armed once the Relayed path is usable.
    upgrade_deadline: Option<u64>,
    remote_addrs: Vec<Multiaddr>,
    /// Secure-mux bytes coalesced behind the STOP success response. These
    /// must accompany circuit promotion.
    pending_data: Vec<u8>,
    /// Deadline for STOP acceptance and handing the bridge to circuit promotion.
    exchange_deadline: u64,
    blast: Option<BlastSchedule>,
    /// End of the current round's punch window; the next round starts then.
    round_until: Option<u64>,
    /// The bridge stream has been handed to the circuit transport.
    released: bool,
    promoted: Option<ConnectionId>,
    handshake_deadline: Option<u64>,
    /// Whether the usable inbound relay path was announced.
    path_announced: bool,
    done: bool,
}

impl InboundCircuit {
    /// Claims a freshly negotiated inbound STOP stream.
    pub(crate) fn new(
        id: u64,
        inner_conn: ConnectionId,
        relay: PeerId,
        stream: StreamId,
        shared: &Shared,
        now: Now,
    ) -> Self {
        Self {
            id,
            inner_conn,
            relay,
            stream,
            source: None,
            stop: Some(StopResponder::new()),
            dcutr: None,
            dcutr_stream: None,
            dcutr_connect_queued: false,
            dcutr_connect_sent_at: None,
            dcutr_deadline: None,
            rounds: 0,
            upgrade_deadline: None,
            remote_addrs: Vec::new(),
            pending_data: Vec::new(),
            exchange_deadline: now.monotonic_ms + shared.config.relay_timeout_ms,
            blast: None,
            round_until: None,
            released: false,
            promoted: None,
            handshake_deadline: None,
            path_announced: false,
            done: false,
        }
    }

    pub(crate) fn promotes(&self, conn_id: ConnectionId) -> bool {
        self.promoted == Some(conn_id)
    }

    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    /// Accepted, and not yet adopted by the host (which then counts the
    /// circuit itself) nor given up.
    pub(crate) fn holds_circuit_slot(&self) -> bool {
        !self.done && self.source.is_some() && self.promoted.is_none()
    }

    pub(crate) fn next_deadline(&self) -> Option<u64> {
        if self.done {
            return None;
        }
        let mut due: Option<u64> = None;
        if !self.released {
            due = Some(self.exchange_deadline);
        }
        if let Some(blast) = &self.blast {
            let next = blast.next_at.min(blast.until);
            due = Some(due.map_or(next, |d| d.min(next)));
        }
        [
            due,
            self.round_until,
            self.handshake_deadline,
            self.dcutr_deadline,
            self.upgrade_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub(crate) fn on_stream_input(
        &mut self,
        conn_id: ConnectionId,
        stream: StreamId,
        input: StreamInput<'_>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done || conn_id != self.inner_conn || stream != self.stream {
            return;
        }
        match input {
            StreamInput::Data(data) => {
                if self.source.is_none() {
                    self.on_stop_input(|stop| stop.on_data(data), swarm, shared, now);
                }
            }
            StreamInput::RemoteWriteClosed => {
                // A peer can stop sending while the local write half remains
                // usable. Let the protocol parser consume that boundary and
                // retain the circuit until its normal exchange deadline.
                if self.source.is_none() {
                    self.on_stop_input(StopResponder::on_remote_write_closed, swarm, shared, now);
                }
            }
            StreamInput::Closed => {
                // The circuit died before the app took over.
                self.abandon(false, swarm, shared, now);
            }
            StreamInput::Ready => {}
        }
    }

    /// Feeds the STOP responder until the CONNECT request is decoded, then
    /// auto-accepts and hands the bridge to circuit promotion.
    fn on_stop_input(
        &mut self,
        feed: impl FnOnce(&mut StopResponder) -> Result<(), RelayError>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let Some(stop) = self.stop.as_mut() else {
            return;
        };
        if feed(stop).is_err() {
            self.abandon(true, swarm, shared, now);
            return;
        }
        let request = loop {
            match stop.poll_output() {
                Some(StopResponderOutput::Request(request)) => break Some(request),
                Some(_) => {}
                None => break None,
            }
        };
        let Some(request) = request else {
            return;
        };

        let Ok(source) = PeerId::from_bytes(&request.source_peer_id) else {
            // Unusable source identity: reject and drop the circuit.
            self.refuse(Status::MalformedMessage, swarm, shared, now);
            return;
        };
        // Reserved before acceptance: past the circuit limit, refuse.
        if !shared.reserve_circuit(swarm) {
            self.refuse(Status::ResourceLimitExceeded, swarm, shared, now);
            return;
        }

        let Some(stop) = self.stop.as_mut() else {
            return;
        };
        if stop.accept().is_err() {
            self.abandon(true, swarm, shared, now);
            return;
        }
        self.source = Some(source);

        // STATUS:OK first, then preserve any secure-mux bytes the relay
        // pipelined behind CONNECT for circuit promotion.
        let mut outbound = Vec::new();
        let mut pipelined = Vec::new();
        while let Some(output) = stop.poll_output() {
            match output {
                StopResponderOutput::Outbound(bytes) => outbound.push(bytes),
                StopResponderOutput::BridgeData(bytes) => pipelined.extend(bytes),
                StopResponderOutput::Request(_) => {}
            }
        }
        self.stop = None;
        for bytes in outbound {
            send(swarm, &self.relay, self.inner_conn, self.stream, bytes, now);
        }

        // Bytes behind STOP STATUS belong to the circuit's secure-mux
        // handshake. DCUtR is opened later on the promoted connection.
        self.pending_data = pipelined;
        self.promote(swarm, shared, now);
    }

    /// Answers the STOP CONNECT with `status` and drops the circuit. The
    /// stream is half-closed, not reset: a FIN follows the status (and any
    /// tail of it the stream refused), where a reset would discard it.
    fn refuse(&mut self, status: Status, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        let Some(stop) = self.stop.as_mut() else {
            return;
        };
        if stop.reject(status).is_err() {
            self.abandon(true, swarm, shared, now);
            return;
        }
        let mut outbound = Vec::new();
        while let Some(output) = stop.poll_output() {
            if let StopResponderOutput::Outbound(bytes) = output {
                outbound.push(bytes);
            }
        }
        for bytes in outbound {
            send(swarm, &self.relay, self.inner_conn, self.stream, bytes, now);
        }
        close_write(swarm, &self.relay, self.inner_conn, self.stream, now);
        self.abandon(false, swarm, shared, now);
        // Still owned until it closes: whatever the relay sends meanwhile is
        // NAT's to consume, never an application stream's.
        shared.own_stream(
            &self.relay,
            self.inner_conn,
            self.stream,
            StreamRole::RejectedControl,
        );
    }

    /// Hands the exact bridge stream to the circuit transport, exactly once,
    /// and applies its answer. The STOP STATUS is already written (or held,
    /// and so carried in the handoff), and the bytes pipelined behind
    /// CONNECT are in `pending_data`.
    fn promote(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if self.released {
            return;
        }
        self.released = true;
        shared.release_stream(self.inner_conn, self.stream);
        let Some(source) = self.source.clone() else {
            return;
        };
        let handoff = BridgeHandoff {
            inner_conn: self.inner_conn,
            stream_id: self.stream,
            relay: self.relay.clone(),
            remote_peer: source,
            role: BridgeRole::Responder,
            pending_data: core::mem::take(&mut self.pending_data),
            unsent_data: Vec::new(),
            // CONNECT completion promotes in the same input cascade, so no
            // later half-close can arrive while NAT owns the bridge.
            remote_write_closed: false,
        };
        match swarm.promote_bridge(handoff, now.monotonic_ms) {
            Ok(conn_id) => {
                self.promoted = Some(conn_id);
                self.handshake_deadline =
                    Some(now.monotonic_ms + shared.config.circuit_handshake_timeout_ms);
            }
            Err(_) => self.done = true,
        }
    }

    pub(crate) fn on_tick(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if self.done {
            return;
        }
        if !self.released && now.monotonic_ms >= self.exchange_deadline {
            if self.source.is_some() {
                // STOP completed but promotion did not run. Preserve the
                // accepted bridge rather than abandoning it.
                self.promote(swarm, shared, now);
            } else {
                // The relay never even sent CONNECT.
                self.abandon(true, swarm, shared, now);
                return;
            }
        }
        if let Some(deadline) = self.upgrade_deadline
            && now.monotonic_ms >= deadline
        {
            // The whole upgrade is over, before any late blast goes out; the
            // Relayed path stays.
            self.finish_dcutr(swarm, shared, now);
            self.blast = None;
            self.done = true;
            return;
        }
        if let Some(blast) = &mut self.blast {
            let interval = shared.config.blast_interval_ms.max(1);
            let mut exhausted = false;
            while now.monotonic_ms >= blast.next_at && blast.next_at <= blast.until {
                for addr in &blast.addrs {
                    shared.push_action(NatAction::SendRandomUdp {
                        target: addr.clone(),
                        payload_len: shared.config.blast_payload_len,
                    });
                }
                match blast.next_at.checked_add(interval) {
                    Some(next_at) => blast.next_at = next_at,
                    None => {
                        exhausted = true;
                        break;
                    }
                }
            }
            if now.monotonic_ms >= blast.until || exhausted {
                self.blast = None;
            }
        }
        if let Some(until) = self.round_until
            && now.monotonic_ms >= until
        {
            // The round's punch window passed without a direct connection.
            self.round_until = None;
            self.blast = None;
            self.start_round(swarm, shared, now);
        }
        if let Some(deadline) = self.handshake_deadline
            && now.monotonic_ms >= deadline
        {
            self.handshake_deadline = None;
            if let Some(conn_id) = self.promoted.take() {
                shared.push_action(NatAction::CloseCircuit { conn_id });
            }
            self.done = true;
        }
        if let Some(deadline) = self.dcutr_deadline
            && now.monotonic_ms >= deadline
        {
            self.finish_dcutr(swarm, shared, now);
            self.start_round(swarm, shared, now);
        }
    }

    /// What this machine claims about the establishing circuit `conn_id`:
    /// that it is the one it promoted, Relayed through its relay.
    pub(crate) fn circuit_claim(&self, conn_id: ConnectionId) -> Option<Claim> {
        (!self.done && self.promoted == Some(conn_id)).then(|| Claim::Circuit {
            relay: self.relay.clone(),
            owner: Owner::Inbound,
        })
    }

    /// A connection from `peer` established; the ledger has attributed it.
    /// Returns whether this machine took it: its own circuit, or a direct
    /// connection from the source, which ends the hole punch.
    pub(crate) fn on_connection_established(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        is_circuit: bool,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) -> bool {
        if self.done || self.source.as_ref() != Some(peer) {
            return false;
        }
        if is_circuit {
            if self.promoted != Some(conn_id) {
                return false;
            }
            self.handshake_deadline = None;
            if !self.path_announced {
                self.path_announced = true;
                shared.push_event(NatEvent::InboundPathEstablished {
                    peer: peer.clone(),
                    path: crate::Path::Relayed {
                        relay: self.relay.clone(),
                    },
                    conn_id,
                });
                if !shared.config.upgrades() {
                    self.done = true;
                } else {
                    self.upgrade_deadline =
                        Some(now.monotonic_ms + shared.config.upgrade_timeout_ms);
                    self.start_round(swarm, shared, now);
                }
            }
            return true;
        }
        self.blast = None;
        self.round_until = None;
        if let Some(old_conn_id) = self.promoted {
            shared.push_event(NatEvent::InboundDirectUpgrade {
                peer: peer.clone(),
                old_conn_id,
                new_conn_id: conn_id,
            });
        }
        if self.released {
            self.finish_dcutr(swarm, shared, now);
            self.done = true;
        }
        true
    }

    /// The relay connection died. Before release the circuit is gone; after
    /// release the app owns the (now dead) stream and the initiator's punch
    /// dial may still land, so the circuit lingers.
    pub(crate) fn on_connection_closed(&mut self, peer: &PeerId, conn_id: ConnectionId) {
        if self.done {
            return;
        }
        if self.promoted == Some(conn_id) {
            self.done = true;
            return;
        }
        if &self.relay != peer || conn_id != self.inner_conn {
            return;
        }
        if !self.released {
            // Registry entries for the dead connection are dropped by the
            // agent; nothing to reset.
            self.done = true;
        }
    }

    /// Drops the circuit before the app ever saw it, resetting the STOP
    /// stream when its connection is still alive.
    fn abandon(
        &mut self,
        reset_stream: bool,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        if !self.released {
            if reset_stream {
                reset(swarm, &self.relay, self.inner_conn, self.stream, now);
            }
            shared.release_stream(self.inner_conn, self.stream);
        }
        self.done = true;
    }

    /// Starts the next DCUtR round: opens `/libp2p/dcutr` on the promoted
    /// circuit and queues CONNECT. Only the stream allocation is shared with
    /// the other NAT exchanges: the circuit is already ready.
    ///
    /// Ends coordination instead when every round ran, the upgrade budget is
    /// spent, or the peer's current connection is no longer the circuit (a
    /// replacement's own event reports any upgrade), closing the source's
    /// punch window.
    fn start_round(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        let (Some(peer), Some(circuit)) = (self.source.clone(), self.promoted) else {
            self.done = true;
            return;
        };
        let budget_left = self
            .upgrade_deadline
            .is_some_and(|deadline| now.monotonic_ms < deadline);
        // `open_stream` opens on the current connection, just checked to be
        // the circuit.
        let opened = if self.rounds < MAX_DCUTR_ROUNDS
            && budget_left
            && swarm.connection(&peer) == Some(circuit)
        {
            swarm
                .open_stream(&peer, minip2p_dcutr::DCUTR_PROTOCOL_ID, now.monotonic_ms)
                .ok()
        } else {
            None
        };
        let Some((conn, stream)) = opened else {
            // No round left to punch in: direct connections from the
            // source are no longer this side's punches.
            shared.ledger.end_punches(&peer);
            self.done = true;
            return;
        };
        self.rounds += 1;
        self.dcutr_stream = Some((conn, stream));
        self.dcutr = Some(DcutrInitiator::new(&shared.punch_candidates()));
        self.dcutr_connect_queued = false;
        self.dcutr_connect_sent_at = None;
        let exchange_end = now.monotonic_ms + shared.config.dcutr_exchange_timeout_ms;
        self.dcutr_deadline = Some(
            self.upgrade_deadline
                .map_or(exchange_end, |deadline| deadline.min(exchange_end)),
        );
        shared.own_stream(&peer, conn, stream, StreamRole::DcutrInbound(self.id));
    }

    /// The host finished writing what it held on `stream`: a CONNECT
    /// waiting on that starts its RTT clock now.
    pub(crate) fn on_write_completed(&mut self, conn: ConnectionId, stream: StreamId, now: Now) {
        if self.dcutr_stream == Some((conn, stream))
            && self.dcutr_connect_queued
            && self.dcutr_connect_sent_at.is_none()
        {
            self.dcutr_connect_sent_at = Some(now.monotonic_ms);
        }
    }

    pub(crate) fn on_dcutr_stream_input(
        &mut self,
        stream: StreamId,
        input: StreamInput<'_>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        let Some((conn, _)) = self.dcutr_stream.filter(|(_, s)| *s == stream) else {
            return;
        };
        // Input can arrive before the tick that expires the exchange or the
        // upgrade: expire them first, as that tick would have.
        let expired = [self.dcutr_deadline, self.upgrade_deadline]
            .into_iter()
            .flatten()
            .any(|deadline| now.monotonic_ms >= deadline);
        if expired {
            self.on_tick(swarm, shared, now);
            if self.done || self.dcutr_stream != Some((conn, stream)) {
                return;
            }
        }
        let rtt_ms = self
            .dcutr_connect_sent_at
            .map_or(0, |sent_at| now.monotonic_ms.saturating_sub(sent_at));
        let remote_closed = matches!(&input, StreamInput::RemoteWriteClosed | StreamInput::Closed);
        let dcutr = match self.dcutr.as_mut() {
            Some(Ok(dcutr)) => dcutr,
            Some(Err(_)) => {
                self.fail_round(swarm, shared, now);
                return;
            }
            None => return,
        };
        // CONNECT is queued at construction and drained below on any input;
        // a remote close is judged by whether the exchange completed.
        if let StreamInput::Data(bytes) = input
            && dcutr.on_data(bytes, rtt_ms).is_err()
        {
            self.fail_round(swarm, shared, now);
            return;
        }
        let mut outputs = Vec::new();
        while let Some(output) = dcutr.poll_output() {
            outputs.push(output);
        }
        let mut completed = false;
        for output in outputs {
            match output {
                DcutrInitiatorOutput::Outbound(data) => {
                    if let Some(peer) = self.source.as_ref() {
                        send(swarm, peer, conn, stream, data, now);
                    }
                    if !self.dcutr_connect_queued {
                        self.dcutr_connect_queued = true;
                        // A held tail starts the clock once the host reports
                        // it written (`on_write_completed`).
                        if !swarm.write_pending(conn, stream) {
                            self.dcutr_connect_sent_at = Some(now.monotonic_ms);
                        }
                    }
                }
                DcutrInitiatorOutput::Outcome(InitiatorOutcome::DialNow {
                    remote_addrs,
                    rtt_ms,
                    ..
                }) => {
                    self.remote_addrs = select_punch_candidates(
                        &remote_addrs,
                        shared.config.allow_private_punch_targets,
                    );
                    completed = true;
                    let blast_start = now.monotonic_ms.saturating_add(rtt_ms.div_ceil(2));
                    let window_end = blast_start.saturating_add(shared.config.punch_deadline_ms);
                    let blast_until = self
                        .upgrade_deadline
                        .map_or(window_end, |deadline| deadline.min(window_end));
                    if !self.remote_addrs.is_empty() {
                        let next_at = if rtt_ms == 0 {
                            for addr in &self.remote_addrs {
                                shared.push_action(NatAction::SendRandomUdp {
                                    target: addr.clone(),
                                    payload_len: shared.config.blast_payload_len,
                                });
                            }
                            blast_start
                                .checked_add(shared.config.blast_interval_ms.max(1))
                                .filter(|next| *next <= blast_until)
                        } else {
                            Some(blast_start)
                        };
                        self.blast = next_at.map(|next_at| BlastSchedule {
                            addrs: self.remote_addrs.clone(),
                            next_at,
                            until: blast_until,
                        });
                    }
                    if dcutr.send_sync().is_ok() {
                        // The source punches once it reads SYNC.
                        if let (Some(source), Some(until)) =
                            (self.source.clone(), self.upgrade_deadline)
                        {
                            shared.ledger.expect_punches(source, until);
                        }
                        while let Some(DcutrInitiatorOutput::Outbound(data)) = dcutr.poll_output() {
                            if let Some(peer) = self.source.as_ref() {
                                send(swarm, peer, conn, stream, data, now);
                            }
                        }
                    }
                    self.round_until = Some(blast_until);
                }
            }
        }
        if completed {
            self.finish_dcutr(swarm, shared, now);
        } else if remote_closed {
            self.fail_round(swarm, shared, now);
        }
    }

    /// The round's exchange failed: the next round starts at once.
    fn fail_round(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        self.finish_dcutr(swarm, shared, now);
        self.start_round(swarm, shared, now);
    }

    fn finish_dcutr(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        self.dcutr = None;
        self.dcutr_deadline = None;
        self.dcutr_connect_queued = false;
        if let Some((conn, stream)) = self.dcutr_stream.take() {
            shared.reset_owned_stream(swarm, conn, stream, now);
        }
    }
}

/// The most DCUtR punch candidates kept, whether accepted from a peer's
/// CONNECT or advertised in ours. Every one is dialed or blasted in each punch
/// window, so the peer's 4 KiB message (room for some 300) must not set it.
pub const MAX_PUNCH_CANDIDATES: usize = 8;
/// The most punch candidates kept per IP family, so neither crowds out the
/// other.
const MAX_PUNCH_CANDIDATES_PER_FAMILY: usize = MAX_PUNCH_CANDIDATES / 2;
/// The most punch candidates kept per IP address: a host has a mapping or two
/// worth trying, not a port range.
const MAX_PUNCH_CANDIDATES_PER_IP: usize = 2;

/// Bounds a punch candidate list, keeping the first that fit: drops
/// non-IP hosts, port 0, and privileged ports (below 1024, never a NAT
/// mapping worth punching),
/// then applies the per-IP, per-family, and total caps.
pub(crate) fn bound_punch_candidates(addrs: impl IntoIterator<Item = Multiaddr>) -> Vec<Multiaddr> {
    let mut kept: Vec<Multiaddr> = Vec::new();
    for addr in addrs {
        if kept.len() == MAX_PUNCH_CANDIDATES {
            break;
        }
        let protocols = addr.protocols();
        // Only concrete IPs are punched; a name must not take an IP
        // family's quota, and the receiver drops it anyway.
        let (Some(ip @ (Protocol::Ip4(_) | Protocol::Ip6(_))), Some(Protocol::Udp(port))) =
            (protocols.first(), protocols.get(1))
        else {
            continue;
        };
        if *port < 1024 {
            continue;
        }
        let v4 = matches!(ip, Protocol::Ip4(_));
        let same_family = kept
            .iter()
            .filter(|other| matches!(other.protocols().first(), Some(Protocol::Ip4(_))) == v4)
            .count();
        let same_ip = kept
            .iter()
            .filter(|other| other.protocols().first() == Some(ip))
            .count();
        if same_family < MAX_PUNCH_CANDIDATES_PER_FAMILY && same_ip < MAX_PUNCH_CANDIDATES_PER_IP {
            kept.push(addr);
        }
    }
    kept
}

/// Selects peer-supplied DCUtR targets that are safe to dial or blast.
///
/// The general direct-candidate selector accepts DNS and LAN addresses,
/// because those are useful when configured by the local application, and any
/// transport, because a host dials what it bound. DCUtR addresses are neither:
/// they come from an untrusted remote peer, and the DCUtR role decides what
/// happens to them -- the initiator dials them, the responder blasts UDP at
/// them to open its own mapping. Resolving or sending traffic to
/// private/special-use targets would turn the NAT agent into an SSRF
/// primitive, and a hole punch aimed at a `/tcp` address would put UDP on a
/// port whose owner never consented to receive it. Keep only strict QUIC-v1
/// addresses whose first component is a globally routable unicast IP (any
/// unicast IP when [`NatConfig::allow_private_punch_targets`] is set), then
/// bound them with [`bound_punch_candidates`].
///
/// [`NatConfig::allow_private_punch_targets`]: crate::NatConfig::allow_private_punch_targets
pub(crate) fn select_punch_candidates(addrs: &[Multiaddr], allow_private: bool) -> Vec<Multiaddr> {
    bound_punch_candidates(
        select_direct_addrs(addrs, None, None)
            .into_iter()
            .filter(|addr| is_punchable_quic(addr, allow_private)),
    )
}

fn is_punchable_quic(addr: &Multiaddr, allow_private: bool) -> bool {
    if !addr.is_quic_transport() {
        return false;
    }
    match addr.protocols().first() {
        Some(Protocol::Ip4(octets)) if allow_private => is_unicast_v4((*octets).into()),
        Some(Protocol::Ip6(octets)) if allow_private => {
            let ip = core::net::Ipv6Addr::from(*octets);
            // A mapped IPv4 address is judged as the address it carries.
            match ip.to_ipv4_mapped() {
                Some(v4) => is_unicast_v4(v4),
                None => !(ip.is_unspecified() || ip.is_multicast()),
            }
        }
        Some(Protocol::Ip4(octets)) => is_global_unicast_v4(*octets),
        Some(Protocol::Ip6(octets)) => is_global_unicast_v6(*octets),
        Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)) | None => false,
        Some(_) => false,
    }
}

fn is_unicast_v4(ip: core::net::Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast())
}

fn is_global_unicast_v4([a, b, c, d]: [u8; 4]) -> bool {
    !(a == 0
        // RFC 1918 private space.
        || a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        // RFC 6598 shared carrier-grade NAT space.
        || (a == 100 && (64..=127).contains(&b))
        || a == 127
        || (a == 169 && b == 254)
        // IETF protocol assignments. .9 and .10 are globally reachable
        // anycast addresses and therefore remain eligible.
        || (a == 192 && b == 0 && c == 0 && d != 9 && d != 10)
        // Documentation ranges.
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        // Benchmarking, multicast, reserved, and broadcast space.
        || (a == 198 && (b == 18 || b == 19))
        || a >= 224)
}

fn is_global_unicast_v6(octets: [u8; 16]) -> bool {
    let segments = core::net::Ipv6Addr::from(octets).segments();
    // The currently allocated global-unicast block is 2000::/3.
    if segments[0] & 0xe000 != 0x2000 {
        return false;
    }

    // Special-purpose allocations within 2000::/3 are not ordinary global
    // unicast destinations. Keep the small set explicitly designated global
    // by IANA inside 2001::/23.
    if segments[0] == 0x2001 && segments[1] < 0x0200 {
        let value = u128::from_be_bytes(octets);
        let globally_reachable_exception = value == 0x2001_0001_0000_0000_0000_0000_0000_0001
            || value == 0x2001_0001_0000_0000_0000_0000_0000_0002
            || segments[1] == 0x0003
            || (segments[1] == 0x0004 && segments[2] == 0x0112)
            || (0x0020..=0x003f).contains(&segments[1]);
        if !globally_reachable_exception {
            return false;
        }
    }

    // 6to4 and documentation ranges are not globally reachable endpoints.
    segments[0] != 0x2002
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
}
