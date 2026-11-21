//! Multistream-select negotiation of inbound and outbound streams, and its
//! deadlines.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use minip2p_core::Bytes;
use minip2p_identify::IDENTIFY_PROTOCOL_ID;
use minip2p_multistream_select::MultistreamOutput;
use minip2p_ping::PING_PROTOCOL_ID;
use minip2p_transport::{ConnectionId, StreamId};

use crate::events::{IdentifyFailure, PingFailure, SwarmErrorKind, SwarmEvent};

use super::{Action, FirstIdentify, ProtocolKind, SwarmState};

impl SwarmState {
    // -----------------------------------------------------------------------
    // Negotiation deadlines
    // -----------------------------------------------------------------------

    /// Gives up the outbound negotiations past their deadline: each is
    /// reported once and its stream reset, whose close then adds nothing.
    pub(super) fn expire_outbound_negotiations(&mut self, now_ms: u64) {
        let expired: Vec<(ConnectionId, StreamId)> = self
            .outbound_negotiators
            .iter()
            .filter(|(_, pending)| pending.deadline_ms.is_some_and(|due| due <= now_ms))
            .map(|(key, _)| *key)
            .collect();
        for (conn_id, stream_id) in expired {
            let pending = self.outbound_negotiators.remove(&(conn_id, stream_id));
            if pending.is_some_and(|p| p.target == ProtocolKind::IdentifyInitiator) {
                self.fail_first_identify(conn_id, IdentifyFailure::TimedOut);
            } else {
                self.emit_error_for_stream(
                    SwarmErrorKind::OpenStreamFailed,
                    self.established_peer_for_conn(conn_id),
                    Some(conn_id),
                    Some(stream_id),
                    format!(
                        "outbound stream {stream_id} did not finish negotiating within {} ms",
                        self.timeouts.negotiation_ms
                    ),
                );
            }
            if self.reset_pending.insert((conn_id, stream_id)) {
                self.actions
                    .push_back(Action::ResetStream { conn_id, stream_id });
            }
        }
    }

    /// Gives up the inbound negotiations past their deadline: each is
    /// reported like a failed negotiation and its stream reset, so a peer
    /// cannot hold a stream slot by never finishing.
    pub(super) fn expire_inbound_negotiations(&mut self, now_ms: u64) {
        let expired: Vec<(ConnectionId, StreamId)> = self
            .inbound_negotiators
            .iter()
            .filter(|(_, pending)| pending.deadline_ms <= now_ms)
            .map(|(key, _)| *key)
            .collect();
        for (conn_id, stream_id) in expired {
            self.inbound_negotiators.remove(&(conn_id, stream_id));
            self.emit_error_for_stream(
                SwarmErrorKind::Multistream,
                self.established_peer_for_conn(conn_id),
                Some(conn_id),
                Some(stream_id),
                format!(
                    "inbound stream {stream_id} did not finish negotiating within {} ms",
                    self.timeouts.negotiation_ms
                ),
            );
            if self.reset_pending.insert((conn_id, stream_id)) {
                self.actions
                    .push_back(Action::ResetStream { conn_id, stream_id });
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: state helpers
    // -----------------------------------------------------------------------

    /// Whether the outbound stream for `target` on `conn_id` is bounded by
    /// its protocol's own deadline, which covers its negotiation too: a ping
    /// attempt's, or the connection's first Identify. The negotiation
    /// deadline does not apply to it.
    pub(super) fn has_own_deadline(&self, conn_id: ConnectionId, target: &ProtocolKind) -> bool {
        match target {
            ProtocolKind::Ping => true,
            ProtocolKind::IdentifyInitiator => matches!(
                self.first_identify.get(&conn_id),
                Some(FirstIdentify::Running { .. })
            ),
            _ => false,
        }
    }

    // -----------------------------------------------------------------------
    // Internal: multistream-select negotiation
    // -----------------------------------------------------------------------

    /// Feeds an inbound negotiation. Returns how many bytes past it went to
    /// the application.
    pub(super) fn feed_inbound_negotiator(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: &[u8],
        now_ms: u64,
    ) -> usize {
        let key = (conn_id, stream_id);
        let negotiator = match self.inbound_negotiators.get_mut(&key) {
            Some(pending) => &mut pending.negotiator,
            None => return 0,
        };

        let mut negotiated_protocol = None;
        negotiator.on_data(data);

        while let Some(output) = self
            .inbound_negotiators
            .get_mut(&key)
            .and_then(|pending| pending.negotiator.poll_output())
        {
            if self.handle_multistream_output(conn_id, stream_id, output, &mut negotiated_protocol)
            {
                self.inbound_negotiators.remove(&key);
                self.actions
                    .push_back(Action::ResetStream { conn_id, stream_id });
                return 0;
            }
        }

        if let Some(protocol) = negotiated_protocol {
            let remaining = self
                .inbound_negotiators
                .get_mut(&key)
                .map(|pending| pending.negotiator.take_remaining_buffer())
                .unwrap_or_default();

            self.inbound_negotiators.remove(&key);
            self.on_inbound_negotiated(conn_id, stream_id, &protocol);

            if !remaining.is_empty() {
                return self.dispatch_protocol_data(
                    conn_id,
                    stream_id,
                    Bytes::from(remaining),
                    now_ms,
                );
            }
        }
        0
    }

    /// Feeds an outbound negotiation. Returns how many bytes past it went to
    /// the application.
    pub(super) fn feed_outbound_negotiator(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: &[u8],
        now_ms: u64,
    ) -> usize {
        let key = (conn_id, stream_id);
        let pending = match self.outbound_negotiators.get_mut(&key) {
            Some(p) => p,
            None => return 0,
        };

        pending.negotiator.on_data(data);
        let target = pending.target.clone();
        let mut negotiated = false;

        while let Some(output) = self
            .outbound_negotiators
            .get_mut(&key)
            .and_then(|pending| pending.negotiator.poll_output())
        {
            match output {
                MultistreamOutput::Negotiated { .. } => negotiated = true,
                MultistreamOutput::NotAvailable => {
                    self.outbound_negotiators.remove(&key);
                    if !self.fail_identify_stream(&target, conn_id, IdentifyFailure::Rejected)
                        && !self.fail_ping_stream(&target, conn_id, PingFailure::Rejected)
                    {
                        self.emit_error_for_stream(
                            SwarmErrorKind::UnsupportedProtocol,
                            self.established_peer_for_conn(conn_id),
                            Some(conn_id),
                            Some(stream_id),
                            format!("remote peer does not support protocol for stream {stream_id}"),
                        );
                    }
                    self.actions
                        .push_back(Action::ResetStream { conn_id, stream_id });
                    return 0;
                }
                MultistreamOutput::ProtocolError { .. }
                    if self.fail_identify_stream(&target, conn_id, IdentifyFailure::Malformed)
                        || self.fail_ping_stream(&target, conn_id, PingFailure::Rejected) =>
                {
                    self.outbound_negotiators.remove(&key);
                    // A failed ping already queued this stream's reset.
                    if self.reset_pending.insert((conn_id, stream_id)) {
                        self.actions
                            .push_back(Action::ResetStream { conn_id, stream_id });
                    }
                    return 0;
                }
                other => {
                    if self.handle_multistream_output(conn_id, stream_id, other, &mut None) {
                        self.outbound_negotiators.remove(&key);
                        self.actions
                            .push_back(Action::ResetStream { conn_id, stream_id });
                        self.fail_ping_stream(&target, conn_id, PingFailure::Rejected);
                        return 0;
                    }
                }
            }
        }

        if negotiated {
            let (remaining, write_stopped) = self
                .outbound_negotiators
                .remove(&key)
                .map(|mut p| (p.negotiator.take_remaining_buffer(), p.write_stopped))
                .unwrap_or_default();

            self.on_outbound_negotiated(conn_id, stream_id, target, now_ms);
            if let Some(error_code) = write_stopped {
                self.handle_stream_write_stopped(conn_id, stream_id, error_code);
            }

            if !remaining.is_empty() {
                return self.dispatch_protocol_data(
                    conn_id,
                    stream_id,
                    Bytes::from(remaining),
                    now_ms,
                );
            }
        }
        0
    }

    pub(super) fn handle_multistream_output(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        output: MultistreamOutput,
        negotiated_protocol: &mut Option<String>,
    ) -> bool {
        match output {
            MultistreamOutput::OutboundData(bytes) => {
                self.actions.push_back(Action::SendStream {
                    conn_id,
                    stream_id,
                    data: Bytes::from(bytes),
                });
                false
            }
            MultistreamOutput::Negotiated { protocol } => {
                *negotiated_protocol = Some(protocol);
                false
            }
            // Inbound listeners remain open after replying `na` so dialers
            // can offer their next protocol on the same stream. Outbound
            // dialers handle `NotAvailable` as terminal in
            // `feed_outbound_negotiator` above.
            MultistreamOutput::NotAvailable => false,
            MultistreamOutput::ProtocolError { reason } => {
                self.emit_error_for_stream(
                    SwarmErrorKind::Multistream,
                    self.established_peer_for_conn(conn_id),
                    Some(conn_id),
                    Some(stream_id),
                    format!("multistream error on stream {stream_id}: {reason}"),
                );
                true
            }
        }
    }

    pub(super) fn on_inbound_negotiated(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        protocol: &str,
    ) {
        let peer_id = self.ensure_peer_id_for_conn(conn_id);

        if protocol == PING_PROTOCOL_ID {
            self.insert_stream_owner(conn_id, stream_id, ProtocolKind::Ping);
            self.ping.register_inbound_stream(peer_id, stream_id);
            self.drain_ping_outputs();
            return;
        }

        if protocol == IDENTIFY_PROTOCOL_ID {
            // Populate Identify's observedAddr field with the transport
            // address we recorded for this connection. The address is
            // cached when TransportEvent::Connected /
            // TransportEvent::IncomingConnection / PeerIdentityVerified
            // arrives; a missing entry means the transport never reported an
            // endpoint for this conn_id, in which case we legitimately
            // can't fill observedAddr and the field is omitted.
            let observed_addr = self.conn_to_remote_addr.get(&conn_id).cloned();
            // Snapshot of the transport's listening addresses at this
            // moment; the core keeps `local_addresses` refreshed.
            let listen_addrs = self.local_addresses.clone();
            let responder_peer_id = peer_id;
            match self.identify.register_outbound_stream(
                peer_id,
                stream_id,
                observed_addr,
                &listen_addrs,
            ) {
                Ok(()) => {
                    // Only record ownership on success, so a rejected
                    // registration doesn't leave the stream tracked here
                    // with no owning handler.
                    self.insert_stream_owner(conn_id, stream_id, ProtocolKind::IdentifyResponder);
                    self.drain_identify_outputs();
                }
                Err(e) => {
                    // Registration refused (e.g. identify already has a
                    // responder stream for this peer). Don't leak the
                    // underlying transport stream -- reset it so the
                    // remote knows we're not going to respond.
                    self.emit_error(
                        SwarmErrorKind::IdentifyStreamRejected,
                        Some(responder_peer_id),
                        Some(conn_id),
                        format!("identify responder error: {e}"),
                    );
                    self.actions
                        .push_back(Action::ResetStream { conn_id, stream_id });
                }
            }
            return;
        }

        if self.inbound_protocols.iter().any(|p| p == protocol) {
            self.insert_stream_owner(conn_id, stream_id, ProtocolKind::User(protocol.to_string()));
            self.mark_control(conn_id, stream_id, false);
            self.events.push_back(SwarmEvent::StreamReady {
                peer_id,
                conn_id,
                stream_id,
                protocol_id: protocol.to_string(),
                initiated_locally: false,
            });
        }
    }

    pub(super) fn on_outbound_negotiated(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        target: ProtocolKind,
        now_ms: u64,
    ) {
        let peer_id = self.ensure_peer_id_for_conn(conn_id);
        self.insert_stream_owner(conn_id, stream_id, target.clone());

        match target {
            ProtocolKind::Ping => {
                if let Err(e) = self.ping.register_outbound_stream(peer_id, stream_id) {
                    self.emit_error(
                        SwarmErrorKind::Ping,
                        Some(peer_id),
                        Some(conn_id),
                        format!("ping register error: {e}"),
                    );
                    self.remove_stream_owner(conn_id, stream_id);
                    self.actions
                        .push_back(Action::ResetStream { conn_id, stream_id });
                    return;
                }
                self.drain_ping_outputs();

                if let Some(payload) = self
                    .pings
                    .get_mut(&peer_id)
                    .and_then(|attempt| attempt.queued.take())
                {
                    match self.ping.send_ping(&peer_id, &payload, now_ms) {
                        Ok(()) => self.drain_ping_outputs(),
                        Err(e) => self.emit_error(
                            SwarmErrorKind::Ping,
                            Some(peer_id),
                            Some(conn_id),
                            format!("deferred ping send failed: {e}"),
                        ),
                    }
                }
            }
            ProtocolKind::IdentifyInitiator => {
                self.identify.register_inbound_stream(peer_id, stream_id);
                self.drain_identify_outputs();
            }
            ProtocolKind::IdentifyResponder => {}
            ProtocolKind::User(protocol_id) => {
                self.mark_control(conn_id, stream_id, false);
                self.events.push_back(SwarmEvent::StreamReady {
                    peer_id,
                    conn_id,
                    stream_id,
                    protocol_id,
                    initiated_locally: true,
                });
            }
        }
    }
}
