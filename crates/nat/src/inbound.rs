//! Responder-side hole punching: a NAT'd listener holding a relay
//! reservation accepts inbound STOP circuits, answers the initiator's DCUtR
//! exchange, and blasts random UDP datagrams at the initiator's observed
//! addresses to open its own NAT mapping. Only the initiator dials (DCUtR
//! for QUIC): the blasts make that dial land.
//!
//! ```text
//! relay opens STOP stream ──▶ CONNECT ──▶ auto-Accept (STATUS:OK)
//!   ──▶ DCUtR CONNECT arrives ──▶ reply with our observed addresses
//!   ──▶ SYNC arrives ──▶ schedule UDP blasts,
//!       release the bridge to the app (InboundRelayCircuit)
//! initiator's dial lands ──▶ cancel blasts, InboundDirectUpgrade
//! ```

use alloc::vec::Vec;

use minip2p_core::{Multiaddr, PeerId, SansIoProtocol, select_direct_candidates};
use minip2p_dcutr::{DcutrResponder, DcutrResponderInput, DcutrResponderOutput, ResponderEvent};
use minip2p_relay::{Status, StopResponder, StopResponderInput, StopResponderOutput};
use minip2p_transport::StreamId;

use crate::agent::{Shared, StreamInput};
use crate::events::{NatAction, NatEvent};
use crate::types::Now;

/// Responder-side UDP blast schedule during the punch window.
struct BlastSchedule {
    addrs: Vec<Multiaddr>,
    next_at: u64,
    until: u64,
}

/// One inbound relay circuit: STOP acceptance, DCUtR responder exchange,
/// and the punch-window UDP blasts.
pub(crate) struct InboundCircuit {
    /// The peer that opened the STOP stream to us (the relay).
    relay: PeerId,
    stream: StreamId,
    /// The initiating peer, once the STOP CONNECT names it.
    source: Option<PeerId>,
    stop: Option<StopResponder>,
    dcutr: Option<DcutrResponder>,
    remote_addrs: Vec<Multiaddr>,
    /// Application bytes received after the final DCUtR SYNC frame in the
    /// same stream read. These must accompany the raw bridge handoff.
    pending_data: Vec<u8>,
    /// The remote write half reached EOF while the control plane still owned
    /// the bridge. The transport will not repeat that event after handoff.
    remote_write_closed: bool,
    /// Deadline for the STOP + DCUtR exchange to finish; after it the
    /// bridge is released to the app punch-less rather than abandoned.
    exchange_deadline: u64,
    blast: Option<BlastSchedule>,
    /// Keep the circuit alive for upgrade detection until this instant
    /// (covers the initiator's full retry window, not just our blasts).
    linger_until: Option<u64>,
    /// The bridge stream has been handed to the application.
    released: bool,
    done: bool,
}

impl InboundCircuit {
    /// Claims a freshly negotiated inbound STOP stream.
    pub(crate) fn new(relay: PeerId, stream: StreamId, shared: &Shared, now: Now) -> Self {
        Self {
            relay,
            stream,
            source: None,
            stop: Some(StopResponder::new()),
            dcutr: None,
            remote_addrs: Vec::new(),
            pending_data: Vec::new(),
            remote_write_closed: false,
            exchange_deadline: now.mono_ms + shared.config.relay_leg_deadline_ms,
            blast: None,
            linger_until: None,
            released: false,
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
        due
    }

    pub(crate) fn on_stream_input(
        &mut self,
        stream: StreamId,
        input: StreamInput<'_>,
        shared: &mut Shared,
        now: Now,
    ) {
        if self.done || stream != self.stream {
            return;
        }
        match input {
            StreamInput::Data(data) => {
                if self.source.is_none() {
                    self.on_stop_data(data, shared, now);
                } else {
                    self.on_bridge_data(data, shared, now);
                }
            }
            StreamInput::RemoteWriteClosed => {
                self.remote_write_closed = true;
                // A peer can stop sending while the local write half remains
                // usable. Let the protocol parser consume that boundary and
                // retain the circuit until its normal exchange deadline.
                if self.source.is_none() {
                    self.on_stop_input(StopResponderInput::RemoteWriteClosed, shared, now);
                } else {
                    self.on_dcutr_input(DcutrResponderInput::RemoteWriteClosed, shared, now);
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
    /// decoded, then auto-accepts and starts the DCUtR responder.
    fn on_stop_data(&mut self, data: &[u8], shared: &mut Shared, now: Now) {
        self.on_stop_input(StopResponderInput::Data(data.to_vec()), shared, now);
    }

    fn on_stop_input(&mut self, input: StopResponderInput, shared: &mut Shared, now: Now) {
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
            let _ = stop.handle_input(StopResponderInput::Reject(Status::MalformedMessage));
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

        // STATUS:OK first, then any bytes the relay pipelined behind the
        // CONNECT — those already belong to the DCUtR exchange and must
        // reach the machine inside this same cascade.
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

        self.dcutr = Some(DcutrResponder::new(&shared.punch_candidates()));
        if !pipelined.is_empty() {
            self.on_bridge_data(&pipelined, shared, now);
        }
    }

    /// Feeds bridge bytes into the DCUtR responder.
    fn on_bridge_data(&mut self, data: &[u8], shared: &mut Shared, now: Now) {
        self.on_dcutr_input(DcutrResponderInput::Data(data.to_vec()), shared, now);
    }

    fn on_dcutr_input(&mut self, input: DcutrResponderInput, shared: &mut Shared, now: Now) {
        let Some(dcutr) = self.dcutr.as_mut() else {
            return;
        };
        if dcutr.handle_input(input).is_err() {
            // The punch cannot proceed (malformed exchange or our own
            // oversized reply), but the bridge itself is fine: hand it to
            // the app without punching.
            self.dcutr = None;
            self.release_to_app(shared);
            return;
        }
        let mut outputs = Vec::new();
        while let Some(output) = dcutr.poll_output() {
            outputs.push(output);
        }
        let mut sync_received = false;
        for output in outputs {
            match output {
                DcutrResponderOutput::Outbound(bytes) => {
                    shared.push_action(NatAction::SendStream {
                        peer: self.relay.clone(),
                        stream_id: self.stream,
                        data: bytes,
                    });
                }
                DcutrResponderOutput::Event(ResponderEvent::ConnectReceived {
                    remote_addrs,
                    ..
                }) => {
                    self.remote_addrs =
                        select_direct_candidates(&remote_addrs, None, None).into_addrs();
                }
                DcutrResponderOutput::Event(ResponderEvent::SyncReceived) => {
                    sync_received = true;
                }
            }
        }
        if sync_received {
            self.pending_data = dcutr.take_trailing_data().unwrap_or_default();
            self.on_sync(shared, now);
        }
    }

    /// SYNC arrived: open our NAT mapping with random-UDP blasts and hand
    /// the bridge to the application.
    ///
    /// Per the DCUtR spec for QUIC, only the initiator dials. A responder
    /// dial would race the initiator's — when both land (guaranteed
    /// without NATs, common with cone NATs) the second connection
    /// supersedes the first and the supersede scrubs every stream the
    /// application just opened on the announced path.
    fn on_sync(&mut self, shared: &mut Shared, now: Now) {
        self.dcutr = None;
        if self.source.is_none() {
            return;
        }

        if !self.remote_addrs.is_empty() {
            self.blast = Some(BlastSchedule {
                addrs: self.remote_addrs.clone(),
                // The spec says wait ~RTT/2 after SYNC; without a measured
                // RTT this configured floor stands in for it.
                next_at: now.mono_ms + shared.config.responder_sync_delay_ms,
                until: now.mono_ms + shared.config.punch_deadline_ms,
            });
        }
        // Stay alive for upgrade detection across the initiator's full
        // retry window.
        let window =
            shared.config.punch_deadline_ms * (1 + u64::from(shared.config.punch_max_retries));
        self.linger_until = Some(now.mono_ms + window);
        self.release_to_app(shared);
    }

    /// Hands the bridge stream to the application, exactly once.
    fn release_to_app(&mut self, shared: &mut Shared) {
        if self.released {
            return;
        }
        self.released = true;
        shared.release_stream(&self.relay, self.stream);
        if let Some(source) = &self.source {
            shared.push_event(NatEvent::InboundRelayCircuit {
                peer: source.clone(),
                relay: self.relay.clone(),
                stream_id: self.stream,
                pending_data: core::mem::take(&mut self.pending_data),
                remote_write_closed: self.remote_write_closed,
            });
        }
        if self.blast.is_none() && self.linger_until.is_none() {
            self.done = true;
        }
    }

    pub(crate) fn on_tick(&mut self, shared: &mut Shared, now: Now) {
        if self.done {
            return;
        }
        if !self.released && now.mono_ms >= self.exchange_deadline {
            if self.source.is_some() {
                // The punch exchange stalled, but the accepted bridge is
                // perfectly usable: give it to the app without punching.
                self.dcutr = None;
                self.release_to_app(shared);
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
            if self.released {
                self.done = true;
            }
        }
    }

    /// The initiator's (or our) punch landed: the peer is directly
    /// connected.
    pub(crate) fn on_peer_connected(&mut self, peer: &PeerId, shared: &mut Shared, _now: Now) {
        if self.done || self.source.as_ref() != Some(peer) {
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
    pub(crate) fn on_relay_disconnected(&mut self, peer: &PeerId, _shared: &mut Shared) {
        if self.done || &self.relay != peer {
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
}
