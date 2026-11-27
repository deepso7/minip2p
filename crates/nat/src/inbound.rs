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

use crate::dcutr::{DcutrError, DcutrInitiator, DcutrInitiatorOutput, InitiatorOutcome};
use minip2p_core::platform::Now;
use minip2p_core::{Multiaddr, PeerAddr, PeerAddrError, PeerId, Protocol, select_direct_addrs};
use minip2p_relay::{RelayError, Status, StopResponder, StopResponderOutput};
use minip2p_transport::{ConnectionId, StreamId};

use crate::agent::{Shared, StreamInput, StreamRole, close_write, reset, send};
use crate::budget::UpgradeBudget;
use crate::events::{NatAction, NatEvent};
use crate::ledger::{Claim, Owner};
use crate::swarm::{BridgeHandoff, BridgeRole, NatSwarm};
use crate::types::UpgradeStop;

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
    phase: Phase,
}

/// Where an inbound circuit is. STOP acceptance hands the bridge to the
/// circuit transport in the same input, so every phase after `AwaitStop`
/// has a promoted circuit and a known source.
enum Phase {
    /// Reading the relay's STOP CONNECT; NAT owns the stream until
    /// `deadline`.
    AwaitStop { stop: StopResponder, deadline: u64 },
    /// The bridge was promoted as `circuit`, whose secure-mux handshake must
    /// finish by `deadline`.
    Handshaking {
        source: PeerId,
        circuit: ConnectionId,
        deadline: u64,
    },
    /// The circuit carries the Relayed path; DCUtR rounds run on it.
    Upgrading {
        source: PeerId,
        circuit: ConnectionId,
        budget: UpgradeBudget,
        round: Round,
    },
    /// Finished. A circuit it promoted stays its own until the agent reaps
    /// the machine, so a replacement in the same input is not adopted.
    Done { promoted: Option<ConnectionId> },
}

/// The current DCUtR round of an upgrading circuit.
enum Round {
    /// The round's exchange, on a stream this peer opened.
    Exchange(Exchange),
    /// SYNC was sent: the source punches until `until` while this side
    /// blasts UDP at its addresses.
    Punching {
        until: u64,
        blast: Option<BlastSchedule>,
    },
}

/// One round's DCUtR exchange.
struct Exchange {
    conn: ConnectionId,
    stream: StreamId,
    /// The initiator, or the error that kept it from being built, reported
    /// once the stream is ready.
    initiator: Result<DcutrInitiator, DcutrError>,
    connect: ConnectWrite,
}

/// How far the round's CONNECT got. The time it was fully written (held
/// tail included) times the relay RTT that synchronizes the first blast.
#[derive(Clone, Copy)]
enum ConnectWrite {
    Unsent,
    /// Handed to the swarm, which still holds part of it.
    Held,
    Sent {
        at: u64,
    },
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
            phase: Phase::AwaitStop {
                stop: StopResponder::new(),
                deadline: now.monotonic_ms + shared.config.relay_timeout_ms,
            },
        }
    }

    /// The circuit this machine promoted, if any.
    fn promoted(&self) -> Option<ConnectionId> {
        match self.phase {
            Phase::Handshaking { circuit, .. } | Phase::Upgrading { circuit, .. } => Some(circuit),
            Phase::Done { promoted } => promoted,
            Phase::AwaitStop { .. } => None,
        }
    }

    /// Ends the machine, keeping its claim on the promoted circuit.
    fn finish(&mut self) {
        self.phase = Phase::Done {
            promoted: self.promoted(),
        };
    }

    /// The peer that dialed through the circuit, once STOP named it.
    pub(crate) fn source(&self) -> Option<&PeerId> {
        match &self.phase {
            Phase::Handshaking { source, .. } | Phase::Upgrading { source, .. } => Some(source),
            Phase::AwaitStop { .. } | Phase::Done { .. } => None,
        }
    }

    pub(crate) fn promotes(&self, conn_id: ConnectionId) -> bool {
        self.promoted() == Some(conn_id)
    }

    pub(crate) fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Done { .. })
    }

    pub(crate) fn next_deadline(&self) -> Option<u64> {
        match &self.phase {
            Phase::AwaitStop { deadline, .. } | Phase::Handshaking { deadline, .. } => {
                Some(*deadline)
            }
            Phase::Upgrading { budget, round, .. } => {
                let round = match round {
                    Round::Exchange(_) => None,
                    Round::Punching { until, blast } => Some(
                        blast
                            .as_ref()
                            .map_or(*until, |blast| blast.next_at.min(blast.until).min(*until)),
                    ),
                };
                Some(round.map_or(budget.next_deadline(), |at| at.min(budget.next_deadline())))
            }
            Phase::Done { .. } => None,
        }
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
        if self.is_done() || conn_id != self.inner_conn || stream != self.stream {
            return;
        }
        match input {
            StreamInput::Data(data) => {
                self.on_stop_input(|stop| stop.on_data(data), swarm, shared, now);
            }
            StreamInput::RemoteWriteClosed => {
                self.on_stop_input(StopResponder::on_remote_write_closed, swarm, shared, now);
            }
            StreamInput::Closed => {
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
        let Phase::AwaitStop { stop, .. } = &mut self.phase else {
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
            self.refuse(Status::MalformedMessage, swarm, shared, now);
            return;
        };
        if !shared.reserve_circuit(swarm) {
            self.refuse(Status::ResourceLimitExceeded, swarm, shared, now);
            return;
        }

        let Phase::AwaitStop { stop, .. } = &mut self.phase else {
            return;
        };
        if stop.accept().is_err() {
            self.abandon(true, swarm, shared, now);
            return;
        }

        let mut outbound = Vec::new();
        let mut pipelined = Vec::new();
        while let Some(output) = stop.poll_output() {
            match output {
                StopResponderOutput::Outbound(bytes) => outbound.push(bytes),
                StopResponderOutput::BridgeData(bytes) => pipelined.extend(bytes),
                StopResponderOutput::Request(_) => {}
            }
        }
        for bytes in outbound {
            send(swarm, &self.relay, self.inner_conn, self.stream, bytes, now);
        }

        self.promote(source, pipelined, swarm, shared, now);
    }

    /// Answers the STOP CONNECT with `status` and drops the circuit. The
    /// stream is half-closed, not reset: a FIN follows the status (and any
    /// tail of it the stream refused), where a reset would discard it.
    fn refuse(&mut self, status: Status, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        let Phase::AwaitStop { stop, .. } = &mut self.phase else {
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
        shared.own_stream(
            &self.relay,
            self.inner_conn,
            self.stream,
            StreamRole::RejectedControl,
        );
    }

    /// Hands the exact bridge stream to the circuit transport and applies
    /// its answer. The STOP STATUS is already written (or held, and so
    /// carried in the handoff), and `pending_data` holds the bytes pipelined
    /// behind CONNECT.
    fn promote(
        &mut self,
        source: PeerId,
        pending_data: Vec<u8>,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        shared.release_stream(self.inner_conn, self.stream);
        let handoff = BridgeHandoff {
            inner_conn: self.inner_conn,
            stream_id: self.stream,
            relay: self.relay,
            remote_peer: source,
            role: BridgeRole::Responder,
            pending_data,
            unsent_data: Vec::new(),
            remote_write_closed: false,
        };
        self.phase = match swarm.promote_bridge(handoff, now.monotonic_ms) {
            Ok(circuit) => Phase::Handshaking {
                source,
                circuit,
                deadline: now.monotonic_ms + shared.config.circuit_handshake_timeout_ms,
            },
            Err(_) => Phase::Done { promoted: None },
        };
    }

    pub(crate) fn on_tick(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        match &mut self.phase {
            Phase::AwaitStop { deadline, .. } if now.monotonic_ms >= *deadline => {
                self.abandon(true, swarm, shared, now);
            }
            Phase::Handshaking {
                circuit, deadline, ..
            } if now.monotonic_ms >= *deadline => {
                shared.push_action(NatAction::CloseConnection { conn_id: *circuit });
                self.phase = Phase::Done { promoted: None };
            }
            Phase::Upgrading {
                source,
                budget,
                round,
                ..
            } => {
                let upgrading = now.monotonic_ms < budget.deadline();
                match budget.due(now.monotonic_ms) {
                    Some(UpgradeStop::ExchangeTimeout { .. }) if upgrading => {
                        self.fail_round(swarm, shared, now);
                        return;
                    }
                    Some(_) => {
                        self.end_exchange(swarm, shared, now);
                        self.finish();
                        return;
                    }
                    None => {}
                }
                let Round::Punching { until, blast } = round else {
                    return;
                };
                if let Some(schedule) = blast {
                    let interval = shared.config.blast_interval_ms.max(1);
                    let mut exhausted = false;
                    while now.monotonic_ms >= schedule.next_at && schedule.next_at <= schedule.until
                    {
                        for addr in &schedule.addrs {
                            shared.push_action(NatAction::SendRandomUdp {
                                peer: *source,
                                attempt: budget.rounds(),
                                target: addr.clone(),
                                payload_len: shared.config.blast_payload_len,
                            });
                        }
                        match schedule.next_at.checked_add(interval) {
                            Some(next_at) => schedule.next_at = next_at,
                            None => {
                                exhausted = true;
                                break;
                            }
                        }
                    }
                    if now.monotonic_ms >= schedule.until || exhausted {
                        *blast = None;
                    }
                }
                if now.monotonic_ms >= *until {
                    self.next_round(swarm, shared, now);
                }
            }
            _ => {}
        }
    }

    /// What this machine claims about the establishing circuit `conn_id`:
    /// that it is the one it promoted, Relayed through its relay.
    pub(crate) fn circuit_claim(&self, conn_id: ConnectionId) -> Option<Claim> {
        (!self.is_done() && self.promoted() == Some(conn_id)).then_some(Claim::Circuit {
            relay: self.relay,
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
        let (Phase::Handshaking {
            source, circuit, ..
        }
        | Phase::Upgrading {
            source, circuit, ..
        }) = &self.phase
        else {
            return false;
        };
        if source != peer {
            return false;
        }
        let circuit = *circuit;
        if is_circuit {
            if circuit != conn_id {
                return false;
            }
            if let Phase::Handshaking { source, .. } = &self.phase {
                let source = *source;
                self.announce_path(source, circuit, swarm, shared, now);
            }
            return true;
        }
        shared.push_event(NatEvent::InboundDirectUpgrade {
            peer: *peer,
            old_conn_id: circuit,
            new_conn_id: conn_id,
        });
        self.end_exchange(swarm, shared, now);
        self.finish();
        true
    }

    /// The handshaking circuit carries the Relayed path: announce it and,
    /// when upgrades are on, start the first DCUtR round.
    fn announce_path(
        &mut self,
        source: PeerId,
        circuit: ConnectionId,
        swarm: &mut dyn NatSwarm,
        shared: &mut Shared,
        now: Now,
    ) {
        shared.push_event(NatEvent::InboundPathEstablished {
            peer: source,
            path: crate::Path::Relayed { relay: self.relay },
            conn_id: circuit,
        });
        if !shared.config.upgrades() {
            self.finish();
            return;
        }
        let mut budget = UpgradeBudget::arm(now.monotonic_ms, &shared.config, None);
        self.phase = match open_round(self.id, &source, circuit, &mut budget, swarm, shared, now) {
            Some(round) => Phase::Upgrading {
                source,
                circuit,
                budget,
                round,
            },
            None => Phase::Done {
                promoted: Some(circuit),
            },
        };
    }

    /// The relay connection died. Before promotion the circuit is gone;
    /// after it the app owns the (now dead) stream and the initiator's punch
    /// dial may still land, so the circuit lingers.
    pub(crate) fn on_connection_closed(&mut self, peer: &PeerId, conn_id: ConnectionId) {
        if self.is_done() {
            return;
        }
        let relay_conn_lost = &self.relay == peer && conn_id == self.inner_conn;
        if self.promoted() == Some(conn_id)
            || (relay_conn_lost && matches!(self.phase, Phase::AwaitStop { .. }))
        {
            self.finish();
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
        if matches!(self.phase, Phase::AwaitStop { .. }) {
            if reset_stream {
                reset(swarm, &self.relay, self.inner_conn, self.stream, now);
            }
            shared.release_stream(self.inner_conn, self.stream);
        }
        self.finish();
    }

    /// Starts the next DCUtR round of an upgrading circuit, or ends
    /// coordination when none can start (see [`open_round`]).
    fn next_round(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        let Phase::Upgrading {
            source,
            circuit,
            budget,
            round,
        } = &mut self.phase
        else {
            return;
        };
        match open_round(self.id, source, *circuit, budget, swarm, shared, now) {
            Some(next) => *round = next,
            None => self.finish(),
        }
    }

    /// The host finished writing what it held on `stream`: a CONNECT
    /// waiting on that starts its RTT clock now.
    pub(crate) fn on_write_completed(&mut self, conn: ConnectionId, stream: StreamId, now: Now) {
        if let Some(exchange) = self.exchange_mut(stream)
            && exchange.conn == conn
            && matches!(exchange.connect, ConnectWrite::Held)
        {
            exchange.connect = ConnectWrite::Sent {
                at: now.monotonic_ms,
            };
        }
    }

    /// The current round's exchange, when it runs on `stream`.
    fn exchange_mut(&mut self, stream: StreamId) -> Option<&mut Exchange> {
        match &mut self.phase {
            Phase::Upgrading {
                round: Round::Exchange(exchange),
                ..
            } if exchange.stream == stream => Some(exchange),
            _ => None,
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
        let Some(conn) = self.exchange_mut(stream).map(|exchange| exchange.conn) else {
            return;
        };
        let expired = matches!(
            &self.phase,
            Phase::Upgrading { budget, .. } if budget.due(now.monotonic_ms).is_some()
        );
        if expired {
            self.on_tick(swarm, shared, now);
            if self
                .exchange_mut(stream)
                .is_none_or(|exchange| exchange.conn != conn)
            {
                return;
            }
        }
        let Phase::Upgrading {
            source,
            budget,
            round: Round::Exchange(exchange),
            ..
        } = &mut self.phase
        else {
            return;
        };
        let rtt_ms = match exchange.connect {
            ConnectWrite::Sent { at } => now.monotonic_ms.saturating_sub(at),
            ConnectWrite::Unsent | ConnectWrite::Held => 0,
        };
        let remote_closed = matches!(&input, StreamInput::RemoteWriteClosed | StreamInput::Closed);
        let Ok(dcutr) = exchange.initiator.as_mut() else {
            self.fail_round(swarm, shared, now);
            return;
        };
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
        let mut punching = None;
        for output in outputs {
            match output {
                DcutrInitiatorOutput::Outbound(data) => {
                    send(swarm, source, conn, stream, data, now);
                    if matches!(exchange.connect, ConnectWrite::Unsent) {
                        exchange.connect = if swarm.write_pending(conn, stream) {
                            ConnectWrite::Held
                        } else {
                            ConnectWrite::Sent {
                                at: now.monotonic_ms,
                            }
                        };
                    }
                }
                DcutrInitiatorOutput::Outcome(InitiatorOutcome::DialNow {
                    remote_addrs,
                    rtt_ms,
                    ..
                }) => {
                    let remote_addrs = select_punch_candidates(
                        &remote_addrs,
                        source,
                        shared.config.allow_private_punch_targets,
                    );
                    let blast_start = now.monotonic_ms.saturating_add(rtt_ms.div_ceil(2));
                    let blast_until = budget.punch_window_end(blast_start);
                    let mut blast = None;
                    if !remote_addrs.is_empty() {
                        let next_at = if rtt_ms == 0 {
                            for addr in &remote_addrs {
                                shared.push_action(NatAction::SendRandomUdp {
                                    peer: *source,
                                    attempt: budget.rounds(),
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
                        blast = next_at.map(|next_at| BlastSchedule {
                            addrs: remote_addrs,
                            next_at,
                            until: blast_until,
                        });
                    }
                    if dcutr.send_sync().is_ok() {
                        shared.ledger.expect_punches(*source, budget.deadline());
                        while let Some(DcutrInitiatorOutput::Outbound(data)) = dcutr.poll_output() {
                            send(swarm, source, conn, stream, data, now);
                        }
                    }
                    punching = Some(Round::Punching {
                        until: blast_until,
                        blast,
                    });
                }
            }
        }
        if let Some(punching) = punching {
            self.end_exchange(swarm, shared, now);
            if let Phase::Upgrading { round, .. } = &mut self.phase {
                *round = punching;
            }
        } else if remote_closed {
            self.fail_round(swarm, shared, now);
        }
    }

    /// The round's exchange failed: the next round starts at once.
    fn fail_round(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        self.end_exchange(swarm, shared, now);
        self.next_round(swarm, shared, now);
    }

    /// Ends the current round's exchange, if one runs, resetting its stream.
    fn end_exchange(&mut self, swarm: &mut dyn NatSwarm, shared: &mut Shared, now: Now) {
        if let Phase::Upgrading {
            budget,
            round: Round::Exchange(exchange),
            ..
        } = &mut self.phase
        {
            budget.end_exchange();
            shared.reset_owned_stream(swarm, exchange.conn, exchange.stream, now);
        }
    }
}

/// Opens the next DCUtR round's stream on `circuit` and queues CONNECT.
/// Only the stream allocation is shared with the other NAT exchanges: the
/// circuit is already ready.
///
/// Returns `None` instead when every round ran, the upgrade budget is
/// spent, or the peer's current connection is no longer the circuit (a
/// replacement's own event reports any upgrade), closing the source's punch
/// window.
fn open_round(
    id: u64,
    source: &PeerId,
    circuit: ConnectionId,
    budget: &mut UpgradeBudget,
    swarm: &mut dyn NatSwarm,
    shared: &mut Shared,
    now: Now,
) -> Option<Round> {
    let opened =
        if swarm.connection(source) == Some(circuit) && budget.begin_round(now.monotonic_ms) {
            swarm
                .open_stream(source, crate::dcutr::DCUTR_PROTOCOL_ID, now.monotonic_ms)
                .ok()
        } else {
            None
        };
    let Some((conn, stream)) = opened else {
        shared.ledger.end_punches(source);
        return None;
    };
    shared.own_stream(source, conn, stream, StreamRole::DcutrInbound(id));
    if budget.rounds() == 1 {
        shared.punch_send_failures.remove(source);
    }
    Some(Round::Exchange(Exchange {
        conn,
        stream,
        initiator: DcutrInitiator::new(&shared.punch_candidates()),
        connect: ConnectWrite::Unsent,
    }))
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
/// happens to them -- the initiator blasts UDP at them to open its own
/// mapping, and the responder dials them. Resolving or sending traffic to
/// private/special-use targets would turn the NAT agent into an SSRF
/// primitive, and a hole punch aimed at a `/tcp` address would put UDP on a
/// port whose owner never consented to receive it. Keep only strict QUIC-v1
/// addresses whose first component is a globally routable unicast IP (any
/// unicast IP when [`NatConfig::allow_private_punch_targets`] is set), then
/// bound them with [`bound_punch_candidates`].
///
/// A terminal `/p2p/<peer-id>` is kept when it names `peer` and the address is
/// dialed without it; rust-libp2p advertises its DCUtR candidates that way.
/// An address naming anyone else is dropped rather than dialed: the peer we
/// are punching with is the only one that consented to this traffic.
///
/// [`NatConfig::allow_private_punch_targets`]: crate::NatConfig::allow_private_punch_targets
pub(crate) fn select_punch_candidates(
    addrs: &[Multiaddr],
    peer: &PeerId,
    allow_private: bool,
) -> Vec<Multiaddr> {
    let transports: Vec<Multiaddr> = addrs
        .iter()
        .filter_map(|addr| transport_for(addr, peer))
        .collect();
    bound_punch_candidates(
        select_direct_addrs(&transports, None, None)
            .into_iter()
            .filter(|addr| is_punchable_quic(addr, allow_private)),
    )
}

/// Strips a terminal `/p2p/<peer-id>` that names `peer`, drops an address that
/// names another peer, and leaves an address without one untouched.
///
/// This runs before [`select_direct_addrs`], which recognises only bare
/// transport shapes: a suffixed address has no [`TransportKind`] and would be
/// dropped there before it could be stripped.
///
/// [`TransportKind`]: minip2p_core::TransportKind
fn transport_for(addr: &Multiaddr, peer: &PeerId) -> Option<Multiaddr> {
    match PeerAddr::from_multiaddr(addr) {
        Ok(peer_addr) if peer_addr.peer_id() == peer => Some(peer_addr.into_parts().0),
        Ok(_) => None,
        Err(PeerAddrError::MissingPeerId) => Some(addr.clone()),
        Err(_) => None,
    }
}

fn is_punchable_quic(addr: &Multiaddr, allow_private: bool) -> bool {
    if !addr.is_quic_transport() {
        return false;
    }
    match addr.protocols().first() {
        Some(Protocol::Ip4(octets)) if allow_private => is_unicast_v4((*octets).into()),
        Some(Protocol::Ip6(octets)) if allow_private => {
            let ip = core::net::Ipv6Addr::from(*octets);
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
        || a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 100 && (64..=127).contains(&b))
        || a == 127
        || (a == 169 && b == 254)
        || (a == 192 && b == 0 && c == 0 && d != 9 && d != 10)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 224)
}

fn is_global_unicast_v6(octets: [u8; 16]) -> bool {
    let segments = core::net::Ipv6Addr::from(octets).segments();
    if segments[0] & 0xe000 != 0x2000 {
        return false;
    }

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

    segments[0] != 0x2002
        && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
        && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
}
