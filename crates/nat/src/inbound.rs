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
//!   ──▶ open DCUtR ──▶ send CONNECT, then SYNC
//! circuit dialer's punch lands ──▶ InboundDirectUpgrade
//! ```

use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerId, Protocol, SansIoProtocol, select_direct_addrs};
use minip2p_dcutr::{DcutrInitiator, DcutrInitiatorInput, DcutrInitiatorOutput, InitiatorOutcome};
use minip2p_relay::{Status, StopResponder, StopResponderInput, StopResponderOutput};
use minip2p_transport::{ConnectionId, StreamId};

use crate::agent::TokenPurpose;
use crate::agent::{Shared, StreamInput};
use crate::events::{BridgeRole, NatAction, NatEvent};
use crate::types::{Now, PromoteError};

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
    dcutr: Option<DcutrInitiator>,
    dcutr_stream: Option<StreamId>,
    /// Monotonic time when the initial DCUtR CONNECT was queued to the
    /// transport, used to synchronize the first QUIC blast at half the
    /// measured relay RTT.
    dcutr_connect_sent_at: Option<u64>,
    dcutr_deadline: Option<u64>,
    remote_addrs: Vec<Multiaddr>,
    /// Secure-mux bytes coalesced behind the STOP success response. These
    /// must accompany circuit promotion.
    pending_data: Vec<u8>,
    /// Deadline for STOP acceptance and handing the bridge to circuit promotion.
    exchange_deadline: u64,
    blast: Option<BlastSchedule>,
    /// Keep the circuit alive for upgrade detection until this instant
    /// (covers the initiator's full retry window, not just our blasts).
    linger_until: Option<u64>,
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
            dcutr_connect_sent_at: None,
            dcutr_deadline: None,
            remote_addrs: Vec::new(),
            pending_data: Vec::new(),
            exchange_deadline: now.mono_ms + shared.config.relay_leg_deadline_ms,
            blast: None,
            linger_until: None,
            released: false,
            promoted: None,
            handshake_deadline: None,
            path_announced: false,
            done: false,
        }
    }

    pub(crate) fn is_done(&self) -> bool {
        self.done
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
        if let Some(linger) = self.linger_until {
            due = Some(due.map_or(linger, |d| d.min(linger)));
        }
        if let Some(handshake) = self.handshake_deadline {
            due = Some(due.map_or(handshake, |d| d.min(handshake)));
        }
        if let Some(deadline) = self.dcutr_deadline {
            due = Some(due.map_or(deadline, |d| d.min(deadline)));
        }
        due
    }

    pub(crate) fn on_stream_input(
        &mut self,
        conn_id: ConnectionId,
        stream: StreamId,
        input: StreamInput<'_>,
        shared: &mut Shared,
    ) {
        if self.done || conn_id != self.inner_conn || stream != self.stream {
            return;
        }
        match input {
            StreamInput::Data(data) => {
                if self.source.is_none() {
                    self.on_stop_data(data, shared);
                }
            }
            StreamInput::RemoteWriteClosed => {
                // A peer can stop sending while the local write half remains
                // usable. Let the protocol parser consume that boundary and
                // retain the circuit until its normal exchange deadline.
                if self.source.is_none() {
                    self.on_stop_input(StopResponderInput::RemoteWriteClosed, shared);
                }
            }
            StreamInput::Closed => {
                // The circuit died before the app took over.
                self.abandon(shared, false);
            }
            StreamInput::Ready => {}
        }
    }

    /// Feeds bytes into the STOP responder until the CONNECT request is
    /// decoded, then auto-accepts and hands the bridge to circuit promotion.
    fn on_stop_data(&mut self, data: &[u8], shared: &mut Shared) {
        self.on_stop_input(StopResponderInput::Data(data.to_vec()), shared);
    }

    fn on_stop_input(&mut self, input: StopResponderInput, shared: &mut Shared) {
        let Some(stop) = self.stop.as_mut() else {
            return;
        };
        if stop.handle_input(input).is_err() {
            self.abandon(shared, true);
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
            if stop
                .handle_input(StopResponderInput::Reject(Status::MalformedMessage))
                .is_err()
            {
                self.abandon(shared, true);
                return;
            }
            let mut outbound = Vec::new();
            while let Some(output) = stop.poll_output() {
                if let StopResponderOutput::Outbound(bytes) = output {
                    outbound.push(bytes);
                }
            }
            for bytes in outbound {
                shared.push_action(NatAction::SendStream {
                    peer: self.relay.clone(),
                    stream_id: self.stream,
                    data: bytes,
                });
            }
            self.abandon(shared, true);
            return;
        };

        if stop.handle_input(StopResponderInput::Accept).is_err() {
            self.abandon(shared, true);
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
            shared.push_action(NatAction::SendStream {
                peer: self.relay.clone(),
                stream_id: self.stream,
                data: bytes,
            });
        }

        // Bytes behind STOP STATUS belong to the circuit's secure-mux
        // handshake. DCUtR is opened later on the promoted connection.
        self.pending_data = pipelined;
        self.promote(shared);
    }

    /// Hands the exact bridge stream to the circuit transport, exactly once.
    fn promote(&mut self, shared: &mut Shared) {
        if self.released {
            return;
        }
        self.released = true;
        shared.release_stream(&self.relay, self.stream);
        if let Some(source) = &self.source {
            let token = shared.alloc_token(TokenPurpose::PromoteInbound(self.id));
            shared.push_action(NatAction::PromoteBridge {
                token,
                inner_conn: self.inner_conn,
                relay: self.relay.clone(),
                stream_id: self.stream,
                remote_peer: source.clone(),
                role: BridgeRole::Responder,
                pending_data: core::mem::take(&mut self.pending_data),
                // CONNECT completion promotes in the same input cascade, so
                // no later half-close can arrive while NAT owns the bridge.
                remote_write_closed: false,
            });
        }
    }

    pub(crate) fn on_tick(&mut self, shared: &mut Shared, now: Now) {
        if self.done {
            return;
        }
        if !self.released && now.mono_ms >= self.exchange_deadline {
            if self.source.is_some() {
                // STOP completed but promotion did not run. Preserve the
                // accepted bridge rather than abandoning it.
                self.promote(shared);
            } else {
                // The relay never even sent CONNECT.
                self.abandon(shared, true);
                return;
            }
        }
        if let Some(blast) = &mut self.blast {
            let interval = shared.config.blast_interval_ms.max(1);
            let mut exhausted = false;
            while now.mono_ms >= blast.next_at && blast.next_at <= blast.until {
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
            if now.mono_ms >= blast.until || exhausted {
                self.blast = None;
            }
        }
        if let Some(linger) = self.linger_until
            && now.mono_ms >= linger
        {
            self.linger_until = None;
            self.blast = None;
            // A promoted circuit awaiting ConnectionEstablished remains
            // correlated until its separate handshake deadline.
            if self.released && (self.path_announced || self.handshake_deadline.is_none()) {
                self.done = true;
            }
        }
        if let Some(deadline) = self.handshake_deadline
            && now.mono_ms >= deadline
        {
            self.handshake_deadline = None;
            if let Some(conn_id) = self.promoted.take() {
                shared.push_action(NatAction::CloseCircuit { conn_id });
            }
            self.done = true;
        }
        if let Some(deadline) = self.dcutr_deadline
            && now.mono_ms >= deadline
        {
            self.finish_dcutr(shared);
            self.done = true;
        }
    }

    pub(crate) fn on_connection_established(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        is_circuit: bool,
        shared: &mut Shared,
        _now: Now,
    ) {
        if self.done || self.source.as_ref() != Some(peer) {
            return;
        }
        if is_circuit {
            if self.promoted == Some(conn_id) {
                self.handshake_deadline = None;
                let directly_connected = shared.is_directly_connected(peer);
                if !self.path_announced && !directly_connected {
                    self.path_announced = true;
                    shared.push_event(NatEvent::InboundPathEstablished {
                        peer: peer.clone(),
                        path: crate::Path::Relayed {
                            relay: self.relay.clone(),
                        },
                    });
                    if !shared.config.force_relay {
                        let token = shared
                            .alloc_token(TokenPurpose::OpenDcutrInbound(self.id, peer.clone()));
                        shared.push_action(NatAction::OpenStream {
                            token,
                            peer: peer.clone(),
                            protocol_id: minip2p_dcutr::DCUTR_PROTOCOL_ID.into(),
                        });
                    }
                }
                if directly_connected {
                    self.blast = None;
                    self.linger_until = None;
                    self.done = true;
                } else if shared.config.force_relay
                    && self.blast.is_none()
                    && self.linger_until.is_none()
                {
                    self.done = true;
                }
            }
            return;
        }
        self.blast = None;
        self.linger_until = None;
        shared.push_event(NatEvent::InboundDirectUpgrade { peer: peer.clone() });
        if self.released {
            self.done = true;
        }
    }

    /// The relay connection died. Before release the circuit is gone; after
    /// release the app owns the (now dead) stream and the initiator's punch
    /// dial may still land, so the circuit lingers.
    pub(crate) fn on_connection_closed(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        _shared: &mut Shared,
    ) {
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

    /// Drops the circuit before the app ever saw it.
    fn abandon(&mut self, shared: &mut Shared, reset: bool) {
        if !self.released {
            if reset {
                shared.push_action(NatAction::ResetStream {
                    peer: self.relay.clone(),
                    stream_id: self.stream,
                });
            }
            shared.release_stream(&self.relay, self.stream);
        }
        self.done = true;
    }

    pub(crate) fn on_promote_result(
        &mut self,
        result: Result<ConnectionId, PromoteError>,
        shared: &mut Shared,
        now: Now,
    ) {
        match result {
            Ok(conn_id) => {
                self.promoted = Some(conn_id);
                self.handshake_deadline =
                    Some(now.mono_ms + shared.config.circuit_handshake_timeout_ms);
            }
            Err(_) => self.done = true,
        }
    }

    pub(crate) fn on_dcutr_open_result(
        &mut self,
        peer: &PeerId,
        result: Result<StreamId, alloc::string::String>,
        shared: &mut Shared,
        now: Now,
    ) {
        match result {
            Ok(stream) => {
                self.dcutr_stream = Some(stream);
                self.dcutr = Some(DcutrInitiator::new(&shared.punch_candidates()));
                self.dcutr_deadline = Some(now.mono_ms + shared.config.relay_leg_deadline_ms);
                shared.own_stream(
                    peer,
                    stream,
                    crate::agent::StreamRole::DcutrInbound(self.id),
                );
            }
            Err(_) => {
                self.linger_until = None;
                self.done = true;
            }
        }
    }

    pub(crate) fn on_dcutr_stream_input(
        &mut self,
        stream: StreamId,
        input: StreamInput<'_>,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.dcutr_stream != Some(stream) {
            return;
        }
        let Some(dcutr) = self.dcutr.as_mut() else {
            return;
        };
        let remote_closed = matches!(&input, StreamInput::RemoteWriteClosed | StreamInput::Closed);
        let machine_input = match input {
            StreamInput::Ready => DcutrInitiatorInput::Flush,
            StreamInput::Data(bytes) => DcutrInitiatorInput::Data {
                bytes: bytes.to_vec(),
                rtt_ms: self
                    .dcutr_connect_sent_at
                    .map_or(0, |sent_at| now.mono_ms.saturating_sub(sent_at)),
            },
            StreamInput::RemoteWriteClosed | StreamInput::Closed => {
                DcutrInitiatorInput::RemoteWriteClosed
            }
        };
        if dcutr.handle_input(machine_input).is_err() {
            self.finish_dcutr(shared);
            self.done = true;
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
                    self.dcutr_connect_sent_at.get_or_insert(now.mono_ms);
                    if let Some(peer) = self.source.as_ref() {
                        shared.push_action(NatAction::SendStream {
                            peer: peer.clone(),
                            stream_id: stream,
                            data,
                        });
                    }
                }
                DcutrInitiatorOutput::Outcome(InitiatorOutcome::DialNow {
                    remote_addrs,
                    rtt_ms,
                    ..
                }) => {
                    self.remote_addrs = select_global_punch_candidates(&remote_addrs);
                    completed = true;
                    let blast_start = now.mono_ms.saturating_add(rtt_ms.div_ceil(2));
                    let blast_until = blast_start.saturating_add(shared.config.punch_deadline_ms);
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
                    if dcutr.handle_input(DcutrInitiatorInput::SendSync).is_ok() {
                        while let Some(DcutrInitiatorOutput::Outbound(data)) = dcutr.poll_output() {
                            if let Some(peer) = self.source.as_ref() {
                                shared.push_action(NatAction::SendStream {
                                    peer: peer.clone(),
                                    stream_id: stream,
                                    data,
                                });
                            }
                        }
                    }
                    self.linger_until = Some(
                        blast_start.saturating_add(
                            shared
                                .config
                                .punch_deadline_ms
                                .saturating_mul(1 + u64::from(shared.config.punch_max_retries)),
                        ),
                    );
                }
            }
        }
        if remote_closed && !completed {
            self.finish_dcutr(shared);
            self.done = true;
            return;
        }
        if completed {
            self.finish_dcutr(shared);
        }
    }

    fn finish_dcutr(&mut self, shared: &mut Shared) {
        self.dcutr = None;
        self.dcutr_deadline = None;
        let Some(stream_id) = self.dcutr_stream.take() else {
            return;
        };
        let Some(peer) = self.source.as_ref() else {
            return;
        };
        shared.push_action(NatAction::ResetStream {
            peer: peer.clone(),
            stream_id,
        });
        shared.release_stream(peer, stream_id);
    }
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
/// addresses whose first component is a globally routable unicast IP.
pub(crate) fn select_global_punch_candidates(addrs: &[Multiaddr]) -> Vec<Multiaddr> {
    select_direct_addrs(addrs, None, None)
        .into_iter()
        .filter(is_global_unicast_quic)
        .collect()
}

fn is_global_unicast_quic(addr: &Multiaddr) -> bool {
    if !addr.is_quic_transport() {
        return false;
    }
    match addr.protocols().first() {
        Some(Protocol::Ip4(octets)) => is_global_unicast_v4(*octets),
        Some(Protocol::Ip6(octets)) => is_global_unicast_v6(*octets),
        Some(Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_)) | None => false,
        Some(_) => false,
    }
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
