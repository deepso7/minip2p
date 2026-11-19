//! Ping: the application's ping intent, ping attempts and their deadlines,
//! and the handler's actions and events.

use alloc::format;
use alloc::vec::Vec;

use minip2p_core::{Bytes, PeerId};
use minip2p_ping::{PING_PAYLOAD_LEN, PING_PROTOCOL_ID, PingAction, PingEvent, PingOutput};
use minip2p_transport::{ConnectionId, StreamId};

use crate::events::{PingFailure, SwarmError, SwarmErrorKind, SwarmEvent};

use super::{Action, PingAttempt, ProtocolKind, SwarmState};

impl SwarmState {
    // -----------------------------------------------------------------------
    // Application-facing intents
    // -----------------------------------------------------------------------

    /// Queues a ping to `peer_id` with the supplied random payload at
    /// `now_ms`.
    ///
    /// If a ping stream is already negotiated for this peer, the ping fires
    /// immediately (emits a `SendStream` action). If a ping stream is still
    /// negotiating, the payload is buffered and fires when the stream
    /// becomes ready; the attempt already running keeps its deadline.
    /// Otherwise a new ping stream is opened and the payload is buffered.
    ///
    /// The attempt's deadline ([`SwarmTimeouts::ping_ms`](super::SwarmTimeouts::ping_ms)) starts now and
    /// covers the open, the negotiation and the echo; the attempt ends in
    /// one `PingRttMeasured` or `PingFailed` unless its connection ends.
    ///
    /// The payload should come from a cryptographic RNG; the core draws it
    /// from its injected entropy source.
    pub fn ping(
        &mut self,
        peer_id: &PeerId,
        payload: [u8; PING_PAYLOAD_LEN],
        now_ms: u64,
    ) -> Result<(), SwarmError> {
        if !self.peer_to_conn.contains_key(peer_id) {
            return Err(SwarmError::NotConnected { peer_id: *peer_id });
        }

        // Case 1: a ping stream is already negotiated -- fire now.
        if self.find_negotiated_ping_stream(peer_id).is_some() {
            self.ping
                .send_ping(peer_id, &payload, now_ms)
                .map_err(|e| SwarmError::PingError {
                    reason: format!("{e}"),
                })?;
            self.start_ping_attempt(peer_id, None, now_ms);
            self.drain_ping_outputs();
            return Ok(());
        }

        // Case 2: a ping stream is negotiating -- update the queued payload.
        if self.has_pending_ping_stream(peer_id) {
            self.start_ping_attempt(peer_id, Some(payload), now_ms);
            return Ok(());
        }

        // Case 3: no stream yet -- open one and queue the payload.
        self.queue_open_protocol_stream(peer_id, PING_PROTOCOL_ID, ProtocolKind::Ping)?;
        self.start_ping_attempt(peer_id, Some(payload), now_ms);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internal: state helpers
    // -----------------------------------------------------------------------

    pub(super) fn find_negotiated_ping_stream(&self, peer_id: &PeerId) -> Option<StreamId> {
        self.ping.outbound_stream(peer_id)
    }

    /// Starts a ping attempt to `peer_id` at `now_ms`, unless one is
    /// already running: that one keeps its deadline. `queued` is the payload
    /// waiting for the ping stream to negotiate, replacing any queued
    /// before; `None` when the ping was sent already.
    pub(super) fn start_ping_attempt(
        &mut self,
        peer_id: &PeerId,
        queued: Option<[u8; PING_PAYLOAD_LEN]>,
        now_ms: u64,
    ) {
        let deadline_ms = now_ms.saturating_add(self.timeouts.ping_ms);
        let attempt = self.pings.entry(*peer_id).or_insert(PingAttempt {
            deadline_ms,
            queued: None,
        });
        attempt.queued = queued;
    }

    /// Ends `peer_id`'s ping attempt as failed for `cause`: reports
    /// [`SwarmEvent::PingFailed`] on its current connection and drops what
    /// the attempt still holds (the queued payload, a queued open, a
    /// negotiating stream, or the echo in flight), resetting its stream.
    /// Returns whether an attempt was running.
    pub(super) fn fail_ping(&mut self, peer_id: &PeerId, cause: PingFailure) -> bool {
        if self.pings.remove(peer_id).is_none() {
            return false;
        }
        let Some(conn_id) = self.connection_id(peer_id) else {
            return true;
        };
        self.actions.retain(|action| {
            !matches!(
                action,
                Action::OpenStream { conn_id: c, target: ProtocolKind::Ping, .. } if *c == conn_id
            )
        });
        let mut streams: Vec<StreamId> = self
            .outbound_negotiators
            .iter()
            .filter(|((c, _), pending)| *c == conn_id && pending.target == ProtocolKind::Ping)
            .map(|((_, stream_id), _)| *stream_id)
            .collect();
        for stream_id in &streams {
            self.outbound_negotiators.remove(&(conn_id, *stream_id));
        }
        if self.ping.in_flight_payload(peer_id).is_some()
            && let Some(stream_id) = self.ping.outbound_stream(peer_id)
        {
            // Forgets the stream and its echo; the next ping opens a new one.
            self.ping.on_stream_closed(peer_id, stream_id);
            streams.push(stream_id);
        }
        for stream_id in streams {
            if self.reset_pending.insert((conn_id, stream_id)) {
                self.actions
                    .push_back(Action::ResetStream { conn_id, stream_id });
            }
        }
        self.events.push_back(SwarmEvent::PingFailed {
            peer_id: *peer_id,
            conn_id,
            cause,
        });
        true
    }

    /// [`Self::fail_ping`] for a failed stream whose `target` is our ping
    /// stream on `conn_id`; `false` for any other stream.
    pub(super) fn fail_ping_stream(
        &mut self,
        target: &ProtocolKind,
        conn_id: ConnectionId,
        cause: PingFailure,
    ) -> bool {
        *target == ProtocolKind::Ping
            && self
                .conn_to_peer
                .get(&conn_id)
                .cloned()
                .is_some_and(|peer_id| self.fail_ping(&peer_id, cause))
    }

    pub(super) fn has_pending_ping_stream(&self, peer_id: &PeerId) -> bool {
        let Some(&conn) = self.peer_to_conn.get(peer_id) else {
            return false;
        };
        let negotiating = self
            .outbound_negotiators
            .iter()
            .any(|((c, _), pending)| *c == conn && matches!(pending.target, ProtocolKind::Ping));
        if negotiating {
            return true;
        }
        // Also check for a Ping open still queued (common shortly after
        // calling ping()).
        self.actions.iter().any(|action| {
            matches!(
                action,
                Action::OpenStream { conn_id, target: ProtocolKind::Ping, .. } if *conn_id == conn
            )
        })
    }

    // -----------------------------------------------------------------------
    // Internal: execute protocol-handler actions
    // -----------------------------------------------------------------------

    pub(super) fn execute_ping_action(&mut self, action: PingAction) {
        match action {
            PingAction::Send {
                ref peer_id,
                stream_id,
                data,
            } => {
                if let Some(conn_id) =
                    self.conn_for_owned_stream(peer_id, stream_id, ProtocolKind::Ping)
                {
                    self.actions.push_back(Action::SendStream {
                        conn_id,
                        stream_id,
                        data: Bytes::copy_from_slice(&data),
                    });
                }
            }
            PingAction::CloseStreamWrite {
                ref peer_id,
                stream_id,
            } => {
                if let Some(conn_id) =
                    self.conn_for_owned_stream(peer_id, stream_id, ProtocolKind::Ping)
                {
                    self.actions
                        .push_back(Action::CloseStreamWrite { conn_id, stream_id });
                }
            }
            PingAction::ResetStream {
                ref peer_id,
                stream_id,
            } => {
                if let Some(conn_id) =
                    self.conn_for_owned_stream(peer_id, stream_id, ProtocolKind::Ping)
                {
                    self.actions
                        .push_back(Action::ResetStream { conn_id, stream_id });
                }
            }
        }
    }

    /// Runs the ping protocol's outputs, then fails as `StreamClosed` every
    /// attempt the protocol dropped without an event: its stream closed, or
    /// broke the protocol, with the echo still due.
    pub(super) fn drain_ping_outputs(&mut self) {
        while let Some(output) = self.ping.poll_output() {
            match output {
                PingOutput::Action(action) => self.execute_ping_action(action),
                PingOutput::Event(event) => self.handle_ping_event(event),
            }
        }
        let lost: Vec<PeerId> = self
            .pings
            .iter()
            .filter(|(peer_id, attempt)| {
                attempt.queued.is_none() && self.ping.in_flight_payload(peer_id).is_none()
            })
            .map(|(peer_id, _)| *peer_id)
            .collect();
        for peer_id in lost {
            self.fail_ping(&peer_id, PingFailure::StreamClosed);
        }
    }

    pub(super) fn handle_ping_event(&mut self, event: PingEvent) {
        match event {
            PingEvent::RttMeasured {
                peer_id, rtt_ms, ..
            } => {
                self.pings.remove(&peer_id);
                if let Some(conn_id) = self.connection_id(&peer_id) {
                    self.events.push_back(SwarmEvent::PingRttMeasured {
                        peer_id,
                        conn_id,
                        rtt_ms,
                    });
                }
            }
            // The attempt's own deadline always comes first; this is the
            // protocol's backstop.
            PingEvent::Timeout { peer_id, .. } => {
                self.fail_ping(&peer_id, PingFailure::TimedOut);
            }
            PingEvent::ProtocolViolation {
                peer_id, reason, ..
            } => {
                self.emit_error(
                    SwarmErrorKind::Ping,
                    Some(peer_id),
                    self.connection_id(&peer_id),
                    format!("ping protocol violation from {peer_id}: {reason}"),
                );
            }
            _ => {}
        }
    }
}
