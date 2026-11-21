//! Streams: application stream intents, write backpressure (ADR 0012), the
//! stream-owner index, and transport stream events.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::ToString;

use minip2p_core::{Bytes, PeerId};
use minip2p_identify::IDENTIFY_PROTOCOL_ID;
use minip2p_multistream_select::MultistreamSelect;
use minip2p_ping::PING_PROTOCOL_ID;
#[cfg(doc)]
use minip2p_transport::TransportEvent;
use minip2p_transport::{ConnectionId, StreamId};

use crate::events::{IdentifyFailure, PingFailure, SwarmError, SwarmErrorKind, SwarmEvent};

use super::{
    Action, MAX_HELD_PER_STREAM, OwnedStream, PendingInbound, PendingOutbound, ProtocolKind,
    SwarmState, stream_action_matches, stream_write_key,
};

impl SwarmState {
    /// Queues a write or close behind the stream's held bytes. Returns the
    /// action back when it may be dispatched now.
    pub(super) fn hold_action(&mut self, action: Action) -> Option<Action> {
        if let Action::SetControlStream {
            conn_id,
            stream_id,
            control: false,
        } = action
            && self.held.is_held(conn_id, stream_id)
        {
            self.pending_demotions.insert((conn_id, stream_id));
            return None;
        }
        let Some((conn_id, stream_id)) = stream_write_key(&action) else {
            return Some(action);
        };
        if !self.held.is_held(conn_id, stream_id) {
            return Some(action);
        }
        match action {
            Action::SendStream { data, .. } => {
                let len = data.len();
                self.held.push(conn_id, stream_id, data, len);
                self.bound_held(conn_id, stream_id);
            }
            _ => {
                self.held.close_after(conn_id, stream_id);
                self.user_writable_wanted.remove(&(conn_id, stream_id));
            }
        }
        None
    }

    /// Resets a stream whose peer makes the core hold more than
    /// [`MAX_HELD_PER_STREAM`] without reading it.
    pub(super) fn bound_held(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        if self.held.held_bytes(conn_id, stream_id) <= MAX_HELD_PER_STREAM {
            return;
        }
        self.held.forget_stream(conn_id, stream_id);
        self.user_writable_wanted.remove(&(conn_id, stream_id));
        self.pending_demotions.remove(&(conn_id, stream_id));
        let is_write = |action: &Action| stream_write_key(action) == Some((conn_id, stream_id));
        self.actions.retain(|action| !is_write(action));
        if self.reset_pending.insert((conn_id, stream_id)) {
            self.actions
                .push_back(Action::ResetStream { conn_id, stream_id });
        }
    }

    /// Records that the transport answered one of the state's own
    /// [`Action::SendStream`] writes with Full: the state keeps the unsent
    /// tail and resends it, ahead of any later write or close for the stream,
    /// on the stream's [`TransportEvent::StreamWritable`]. `counted` is the
    /// length of the action's payload, so a short tail can be copied out of
    /// it.
    pub fn handle_send_full(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        unsent: Bytes,
        counted: usize,
    ) {
        if !self.conn_to_peer.contains_key(&conn_id) {
            return;
        }
        self.held.push(conn_id, stream_id, unsent, counted);
        self.bound_held(conn_id, stream_id);
    }

    /// Replays the stream's held writes and close, in order, then tells a
    /// waiting user stream it may write.
    pub(super) fn handle_stream_writable(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let key = (conn_id, stream_id);
        if let Some(held) = self.held.take(conn_id, stream_id) {
            for data in held.tails {
                self.actions.push_back(Action::SendStream {
                    conn_id,
                    stream_id,
                    data,
                });
            }
            if self.pending_demotions.remove(&key) {
                self.mark_control(conn_id, stream_id, false);
            }
            if held.close {
                self.actions
                    .push_back(Action::CloseStreamWrite { conn_id, stream_id });
            }
            if held.close || !self.user_writable_wanted.remove(&key) {
                return;
            }
        }
        if self.abandoned_streams.contains(&key) || self.user_write_ended.contains(&key) {
            return;
        }
        if let Some(ProtocolKind::User(_)) = self.stream_protocol(conn_id, stream_id) {
            let peer_id = self.ensure_peer_id_for_conn(conn_id);
            self.events.push_back(SwarmEvent::StreamWritable {
                peer_id,
                conn_id,
                stream_id,
            });
        }
    }

    /// The stream's write side ended: drop whatever it held.
    pub(super) fn forget_held(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        self.held.forget_stream(conn_id, stream_id);
        self.user_writable_wanted.remove(&(conn_id, stream_id));
        self.pending_demotions.remove(&(conn_id, stream_id));
    }

    /// Validates an application open of `protocol_id` to `peer_id` and
    /// returns the connection to open it on.
    ///
    /// The protocol must be registered for outbound opens and the peer
    /// connected; once the peer is ready, it must also have advertised the
    /// protocol. The core then opens the stream itself and hands it to
    /// [`Self::start_outbound`].
    pub fn admit_user_open(
        &self,
        peer_id: &PeerId,
        protocol_id: &str,
    ) -> Result<ConnectionId, SwarmError> {
        if !self.outbound_protocols.iter().any(|p| p == protocol_id) {
            return Err(SwarmError::ProtocolNotRegistered {
                protocol_id: protocol_id.to_string(),
            });
        }
        if !self.peer_to_conn.contains_key(peer_id) {
            return Err(SwarmError::NotConnected { peer_id: *peer_id });
        }
        if self.ready_peers.contains(peer_id)
            && !self
                .peer_info
                .get(peer_id)
                .map(|info| info.protocols.iter().any(|p| p == protocol_id))
                .unwrap_or(false)
        {
            return Err(SwarmError::RemoteDoesNotSupport {
                peer_id: *peer_id,
                protocol_id: protocol_id.to_string(),
            });
        }
        self.require_conn(peer_id)
    }

    /// Validates an application write on a negotiated user stream and hands
    /// `data` back for the core to send directly.
    ///
    /// While the state still holds its own negotiation bytes for the stream
    /// this returns [`SwarmError::Full`] with the whole payload instead, and
    /// a [`SwarmEvent::StreamWritable`] follows. Like every user-stream
    /// operation, the stream is addressed by connection as well as id,
    /// because stream ids are only unique per connection: an operation for a
    /// connection that is no longer `peer_id`'s fails with
    /// [`SwarmError::StreamNotFound`] instead of reaching a same-numbered
    /// stream on its replacement.
    pub fn admit_user_write(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<Bytes, SwarmError> {
        self.require_user_stream(peer_id, conn_id, stream_id)?;
        if self.held.is_closing(conn_id, stream_id) {
            return Err(SwarmError::WriteClosed { conn_id, stream_id });
        }
        if self.held.is_held(conn_id, stream_id) {
            self.user_writable_wanted.insert((conn_id, stream_id));
            return Err(SwarmError::Full {
                conn_id,
                stream_id,
                unsent: data,
            });
        }
        Ok(data)
    }

    /// Half-closes our write side of a user stream.
    ///
    /// The FIN follows every write the transport accepted. A caller holding
    /// an unsent tail of its own must send it before closing.
    pub fn close_stream_write(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), SwarmError> {
        self.require_user_stream(peer_id, conn_id, stream_id)?;
        self.end_user_writes(conn_id, stream_id);
        self.actions
            .push_back(Action::CloseStreamWrite { conn_id, stream_id });
        Ok(())
    }

    /// Resets (abruptly closes) a user stream.
    pub fn reset_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), SwarmError> {
        self.require_user_stream(peer_id, conn_id, stream_id)?;
        self.end_user_writes(conn_id, stream_id);
        if self.reset_pending.insert((conn_id, stream_id)) {
            self.actions
                .push_back(Action::ResetStream { conn_id, stream_id });
        }
        Ok(())
    }

    /// The application closed or reset the stream's write side: drop its
    /// queued `StreamWritable` notices and disarm later ones.
    pub(super) fn end_user_writes(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let key = (conn_id, stream_id);
        self.user_writable_wanted.remove(&key);
        self.user_write_ended.insert(key);
        self.events.retain(|event| {
            !matches!(
                event,
                SwarmEvent::StreamWritable { conn_id: c, stream_id: s, .. }
                    if (*c, *s) == key
            )
        });
    }

    /// Reports that the transport rejected a queued stream reset.
    ///
    /// The core calls this after dispatching an [`Action::ResetStream`]
    /// unsuccessfully. The acknowledgment clears the pending marker so
    /// a later [`reset_stream`](Self::reset_stream) or
    /// [`abandon_stream`](Self::abandon_stream) call can queue another reset.
    /// Successful resets need no acknowledgment; their marker is cleared when
    /// the transport reports that the stream or connection closed.
    pub fn reset_stream_failed(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        self.reset_pending.remove(&(conn_id, stream_id));
    }

    /// Forgets all swarm bookkeeping for a transport stream.
    ///
    /// Unlike [`abandon_stream`](Self::abandon_stream), this does not reset
    /// the stream and does not remove application events that are already
    /// queued. Pending half-close and reset actions for the stream are
    /// discarded, and pending sends are handed back, so ownership transfers
    /// without a later swarm-side mutation.
    /// It is intended for callers that transfer ownership of a raw stream to
    /// another Sans-I/O protocol layer.
    ///
    /// Returns the bytes the core still owes the stream, oldest first: tails
    /// held after a Full (a negotiation reply, say), then queued sends. The
    /// new owner must send them before anything of its own.
    pub fn forget_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId) -> VecDeque<Bytes> {
        let key = (conn_id, stream_id);
        self.remove_stream_owner(conn_id, stream_id);
        self.inbound_negotiators.remove(&key);
        self.outbound_negotiators.remove(&key);
        self.reset_pending.remove(&key);
        self.abandoned_streams.remove(&key);
        self.user_writable_wanted.remove(&key);
        self.user_write_ended.remove(&key);
        let mut demote = self.pending_demotions.remove(&key);
        let mut owed = self
            .held
            .take(conn_id, stream_id)
            .map(|held| held.tails)
            .unwrap_or_default();
        self.actions.retain(|action| {
            if !stream_action_matches(action, conn_id, stream_id) {
                return true;
            }
            match action {
                Action::SendStream { data, .. } => owed.push_back(data.clone()),
                Action::SetControlStream { control: false, .. } => demote = true,
                _ => {}
            }
            false
        });
        if demote {
            self.mark_control(conn_id, stream_id, false);
        }
        self.release_inbound(conn_id, Some(stream_id));
        self.promote_inbound();
        owed
    }

    /// Resets and forgets a stream whose consumer will never read it again.
    ///
    /// A reset is queued at most once, and it settles the buffered data this
    /// drops. Already-buffered events and all later data, EOF, and close
    /// events for the stream are suppressed.
    ///
    /// A stream the transport has already closed has nothing left to reset, so
    /// its dropped data is acknowledged instead and the transport does not
    /// keep the stream. That case succeeds only while the stream's
    /// [`SwarmEvent::StreamClosed`] is still queued, since that event is what
    /// identifies the stream as one this connection owned. Once it has been
    /// delivered, or dropped by an earlier call, the stream is
    /// indistinguishable from one that never existed and both are
    /// [`SwarmError::StreamNotFound`].
    ///
    /// After the stream's connection ended -- its `ConnectionClosed` or
    /// `ConnectionReplaced` may long have been delivered -- no terminal event
    /// is needed: the swarm drops what it still queues for the stream and the
    /// transport settles it outright, giving up its unacknowledged bytes
    /// (ADR 0012). That always succeeds; a transport holding nothing for the
    /// stream makes it a no-op.
    pub fn abandon_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), SwarmError> {
        let mut dropped_data = 0usize;
        let mut dropped_terminal = false;
        self.events.retain(|event| {
            if !event.matches_stream(peer_id, conn_id, stream_id) {
                return true;
            }
            match event {
                SwarmEvent::StreamData { data, .. } => dropped_data += data.len(),
                SwarmEvent::StreamClosed { .. } => dropped_terminal = true,
                _ => {}
            }
            false
        });
        let key = (conn_id, stream_id);
        let peer_conn = self.conn_to_peer.get(&conn_id) == Some(peer_id);
        let abandoned = peer_conn && self.abandoned_streams.contains(&key);
        if !abandoned
            && !(peer_conn && self.outbound_negotiators.contains_key(&key))
            && let Err(unknown) = self.require_user_stream(peer_id, conn_id, stream_id)
        {
            if !self.conn_to_peer.contains_key(&conn_id) {
                self.actions
                    .push_back(Action::SettleStream { conn_id, stream_id });
                return Ok(());
            }
            if !dropped_terminal {
                return Err(unknown);
            }
            if dropped_data > 0 {
                self.actions.push_back(Action::AckStream {
                    conn_id,
                    stream_id,
                    bytes: dropped_data,
                });
            }
            return Ok(());
        }
        if self.reset_pending.insert(key) {
            self.actions
                .push_back(Action::ResetStream { conn_id, stream_id });
        }
        if abandoned {
            return Ok(());
        }
        self.abandoned_streams.insert(key);
        self.release_inbound(conn_id, Some(stream_id));
        self.promote_inbound();
        self.forget_held(conn_id, stream_id);
        self.remove_stream_owner(conn_id, stream_id);
        self.inbound_negotiators.remove(&key);
        self.outbound_negotiators.remove(&key);
        Ok(())
    }

    /// Abandons a stream of a connection that already ended, for a caller
    /// that no longer knows its peer: every event naming it was delivered.
    /// The transport settles it outright (ADR 0012); one holding nothing for
    /// it makes this a no-op. A connection the swarm still routes is
    /// [`SwarmError::StreamNotFound`]: use
    /// [`abandon_stream`](Self::abandon_stream) there.
    pub fn abandon_ended_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), SwarmError> {
        if let Some(peer_id) = self.conn_to_peer.get(&conn_id) {
            return Err(SwarmError::StreamNotFound {
                peer_id: *peer_id,
                conn_id,
                stream_id,
            });
        }
        self.events.retain(|event| {
            !event
                .peer_id()
                .is_some_and(|peer| event.matches_stream(peer, conn_id, stream_id))
        });
        self.actions
            .push_back(Action::SettleStream { conn_id, stream_id });
        Ok(())
    }

    /// Starts multistream-select negotiation of `protocol` on an outbound
    /// stream the core just opened on `conn_id`. Its deadline is armed by the
    /// transport's `StreamOpened`.
    pub fn start_outbound(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        protocol: &str,
        target: ProtocolKind,
    ) {
        self.mark_control(conn_id, stream_id, true);
        let mut negotiator = MultistreamSelect::dialer(protocol);
        negotiator.start();
        while let Some(output) = negotiator.poll_output() {
            self.handle_multistream_output(conn_id, stream_id, output, &mut None);
        }

        self.outbound_negotiators.insert(
            (conn_id, stream_id),
            PendingOutbound {
                negotiator,
                target,
                deadline_ms: None,
                write_stopped: None,
            },
        );
    }

    /// Reports that the transport refused to open a stream for one of the
    /// swarm's own protocols.
    pub fn open_failed(&mut self, conn_id: ConnectionId, protocol: &str, reason: &str) {
        if protocol == IDENTIFY_PROTOCOL_ID
            && self.fail_first_identify(conn_id, IdentifyFailure::OpenFailed)
        {
            return;
        }
        if protocol == PING_PROTOCOL_ID
            && self.fail_ping_stream(&ProtocolKind::Ping, conn_id, PingFailure::OpenFailed)
        {
            return;
        }
        self.emit_error(
            SwarmErrorKind::OpenStreamFailed,
            self.established_peer_for_conn(conn_id),
            Some(conn_id),
            format!(
                "open_stream for protocol '{protocol}' on connection {conn_id} failed: {reason}"
            ),
        );
    }

    /// Checks that `conn_id` is `peer_id`'s connection and holds the
    /// negotiated user stream `stream_id`. Streams of a replaced or closed
    /// connection are forgotten with it, so they never match; an outbound
    /// stream still negotiating is [`SwarmError::StreamNotReady`].
    pub(super) fn require_user_stream(
        &self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), SwarmError> {
        let peer_conn = self.conn_to_peer.get(&conn_id) == Some(peer_id);
        if peer_conn
            && matches!(
                self.stream_protocol(conn_id, stream_id),
                Some(ProtocolKind::User(_))
            )
        {
            Ok(())
        } else if peer_conn
            && self
                .outbound_negotiators
                .contains_key(&(conn_id, stream_id))
        {
            Err(SwarmError::StreamNotReady { conn_id, stream_id })
        } else {
            Err(SwarmError::StreamNotFound {
                peer_id: *peer_id,
                conn_id,
                stream_id,
            })
        }
    }

    pub(super) fn conn_for_owned_stream(
        &self,
        peer_id: &PeerId,
        stream_id: StreamId,
        expected: ProtocolKind,
    ) -> Option<ConnectionId> {
        self.peer_streams(peer_id, stream_id)
            .find_map(|(conn_id, protocol)| (*protocol == expected).then_some(conn_id))
    }

    /// Negotiated streams with id `stream_id` on any of `peer_id`'s
    /// connections, in connection-id order. Usually at most one.
    pub(super) fn peer_streams(
        &self,
        peer_id: &PeerId,
        stream_id: StreamId,
    ) -> impl Iterator<Item = (ConnectionId, &ProtocolKind)> {
        self.stream_owner
            .range(OwnedStream::peer_range(peer_id, stream_id, stream_id))
            .map(|(key, protocol)| (key.conn_id, protocol))
    }

    /// The `stream_owner` key for a stream on `conn_id`, if the connection
    /// has a peer (every owned stream's connection does).
    pub(super) fn owned_stream(
        &self,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Option<OwnedStream> {
        let peer_id = *self.conn_to_peer.get(&conn_id)?;
        Some(OwnedStream {
            peer_id,
            stream_id,
            conn_id,
        })
    }

    /// Records `protocol` as the owner of a negotiated stream. Keys it under
    /// the connection's current peer, synthesizing one if needed.
    pub(super) fn insert_stream_owner(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        protocol: ProtocolKind,
    ) {
        let peer_id = self.ensure_peer_id_for_conn(conn_id);
        self.stream_owner.insert(
            OwnedStream {
                peer_id,
                stream_id,
                conn_id,
            },
            protocol,
        );
    }

    pub(super) fn stream_protocol(
        &self,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Option<&ProtocolKind> {
        self.stream_owner
            .get(&self.owned_stream(conn_id, stream_id)?)
    }

    pub(super) fn remove_stream_owner(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Option<ProtocolKind> {
        let key = self.owned_stream(conn_id, stream_id)?;
        self.stream_owner.remove(&key)
    }

    pub(super) fn queue_open_protocol_stream(
        &mut self,
        peer_id: &PeerId,
        protocol_id: &str,
        target: ProtocolKind,
    ) -> Result<(), SwarmError> {
        let conn_id = self.require_conn(peer_id)?;
        debug_assert_eq!(
            self.conn_to_peer.get(&conn_id),
            Some(peer_id),
            "protocol opens must use a connection mapped to the requested peer"
        );
        self.actions.push_back(Action::OpenStream {
            conn_id,
            protocol: protocol_id.to_string(),
            target,
        });
        Ok(())
    }

    /// Queues the mark that lets a stream write into the transport's control
    /// reserve, or takes it away ([`Action::SetControlStream`]).
    pub(super) fn mark_control(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        control: bool,
    ) {
        self.actions.push_back(Action::SetControlStream {
            conn_id,
            stream_id,
            control,
        });
    }

    /// Starts negotiating an inbound stream, with its deadline armed from
    /// arrival.
    pub(super) fn handle_incoming_stream(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        now_ms: u64,
    ) {
        self.mark_control(conn_id, stream_id, true);
        let mut negotiator = MultistreamSelect::listener(self.inbound_protocols.clone());
        negotiator.start();
        self.inbound_negotiators.insert(
            (conn_id, stream_id),
            PendingInbound {
                negotiator,
                deadline_ms: now_ms.saturating_add(self.timeouts.negotiation_ms),
            },
        );

        while let Some(output) = self
            .inbound_negotiators
            .get_mut(&(conn_id, stream_id))
            .and_then(|pending| pending.negotiator.poll_output())
        {
            self.handle_multistream_output(conn_id, stream_id, output, &mut None);
        }
    }

    /// Routes received bytes, and acknowledges every byte the core consumed
    /// rather than handed to the application (ADR 0012): negotiation,
    /// ping, Identify, and data for streams it no longer routes.
    pub(super) fn handle_stream_data(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        now_ms: u64,
    ) {
        let key = (conn_id, stream_id);
        let len = data.len();

        let handed_out = if self.inbound_negotiators.contains_key(&key) {
            self.feed_inbound_negotiator(conn_id, stream_id, &data, now_ms)
        } else if self.outbound_negotiators.contains_key(&key) {
            self.feed_outbound_negotiator(conn_id, stream_id, &data, now_ms)
        } else {
            self.dispatch_protocol_data(conn_id, stream_id, data, now_ms)
        };

        if len > handed_out {
            self.actions.push_back(Action::AckStream {
                conn_id,
                stream_id,
                bytes: len - handed_out,
            });
        }
    }

    /// Delivers negotiated-stream bytes to their protocol. Returns how many
    /// went to the application, which acknowledges them itself.
    pub(super) fn dispatch_protocol_data(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        now_ms: u64,
    ) -> usize {
        let Some(protocol) = self.stream_protocol(conn_id, stream_id).cloned() else {
            return 0;
        };
        let peer_id = self.ensure_peer_id_for_conn(conn_id);

        match protocol {
            ProtocolKind::Ping => {
                self.ping.on_stream_data(&peer_id, stream_id, &data, now_ms);
                self.drain_ping_outputs();
            }
            ProtocolKind::IdentifyInitiator => {
                self.identify.on_stream_data(peer_id, stream_id, &data);
                self.drain_identify_outputs();
            }
            ProtocolKind::IdentifyResponder => {}
            ProtocolKind::User(_) => {
                let len = data.len();
                self.queue_inbound_event(
                    conn_id,
                    stream_id,
                    SwarmEvent::StreamData {
                        peer_id,
                        conn_id,
                        stream_id,
                        data,
                    },
                );
                return len;
            }
        }
        0
    }

    pub(super) fn handle_stream_remote_write_closed(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) {
        let Some(protocol) = self.stream_protocol(conn_id, stream_id).cloned() else {
            let key = (conn_id, stream_id);
            if let Some(target) = self
                .outbound_negotiators
                .get(&key)
                .map(|p| p.target.clone())
                && (self.fail_identify_stream(&target, conn_id, IdentifyFailure::ClosedEarly)
                    || self.fail_ping_stream(&target, conn_id, PingFailure::StreamClosed))
                && self.outbound_negotiators.remove(&key).is_some()
            {
                self.actions
                    .push_back(Action::ResetStream { conn_id, stream_id });
            }
            return;
        };
        let peer_id = self.ensure_peer_id_for_conn(conn_id);

        match protocol {
            ProtocolKind::Ping => {
                self.ping.on_stream_remote_write_closed(&peer_id, stream_id);
                self.drain_ping_outputs();
            }
            ProtocolKind::IdentifyInitiator => {
                self.identify
                    .on_stream_remote_write_closed(peer_id, stream_id);
                self.drain_identify_outputs();
            }
            ProtocolKind::IdentifyResponder => {}
            ProtocolKind::User(_) => {
                self.queue_inbound_event(
                    conn_id,
                    stream_id,
                    SwarmEvent::StreamRemoteWriteClosed {
                        peer_id,
                        conn_id,
                        stream_id,
                    },
                );
            }
        }
    }

    /// User streams surface the stop to the application. Internal protocols
    /// and in-flight negotiations that still have to write cannot finish, so
    /// their stream is reset; the resulting `StreamClosed` tears them down.
    ///
    /// Two only read on: an Identify request, and an outbound negotiation
    /// whose proposal is out (drained and not held after a Full), which
    /// waits for the reply and then handles the stop as its protocol would. A peer that answers and closes at once
    /// (go-libp2p's WebTransport `Close` also stops our sending) must not
    /// lose its answer.
    pub(super) fn handle_stream_write_stopped(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        error_code: u64,
    ) {
        let key = (conn_id, stream_id);
        let proposal_held = self.held.is_held(conn_id, stream_id);
        self.forget_held(conn_id, stream_id);
        if self.abandoned_streams.contains(&key) {
            return;
        }
        if let Some(pending) = self.outbound_negotiators.get_mut(&key)
            && pending.negotiator.awaits_response()
            && !proposal_held
        {
            pending.write_stopped = Some(error_code);
            return;
        }
        if let Some(ProtocolKind::IdentifyInitiator) = self.stream_protocol(conn_id, stream_id) {
            return;
        }
        if let Some(ProtocolKind::User(_)) = self.stream_protocol(conn_id, stream_id) {
            let peer_id = self.ensure_peer_id_for_conn(conn_id);
            self.queue_inbound_event(
                conn_id,
                stream_id,
                SwarmEvent::StreamWriteStopped {
                    peer_id,
                    conn_id,
                    stream_id,
                    error_code,
                },
            );
            return;
        }
        let known = self.stream_protocol(conn_id, stream_id).is_some()
            || self.inbound_negotiators.contains_key(&key)
            || self.outbound_negotiators.contains_key(&key);
        if known && self.reset_pending.insert(key) {
            self.actions
                .push_back(Action::ResetStream { conn_id, stream_id });
        }
    }

    pub(super) fn handle_stream_closed(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        let key = (conn_id, stream_id);
        let queued = self.inbound_is_queued(conn_id, stream_id);

        self.reset_pending.remove(&key);
        self.user_write_ended.remove(&key);
        self.forget_held(conn_id, stream_id);
        if self.abandoned_streams.remove(&key) {
            self.inbound_negotiators.remove(&key);
            self.outbound_negotiators.remove(&key);
            return;
        }

        if let Some(key) = self.owned_stream(conn_id, stream_id)
            && let Some(protocol) = self.stream_owner.remove(&key)
        {
            let peer_id = key.peer_id;
            match protocol {
                ProtocolKind::Ping => {
                    self.ping.on_stream_closed(&peer_id, stream_id);
                    self.drain_ping_outputs();
                }
                ProtocolKind::IdentifyInitiator | ProtocolKind::IdentifyResponder => {
                    self.identify.on_stream_closed(peer_id, stream_id);
                    self.drain_identify_outputs();
                    self.fail_identify_stream(&protocol, conn_id, IdentifyFailure::ClosedEarly);
                }
                ProtocolKind::User(_) => {
                    if !queued {
                        self.events.push_back(SwarmEvent::StreamClosed {
                            peer_id,
                            conn_id,
                            stream_id,
                        });
                    }
                }
            }
        }

        self.inbound_negotiators.remove(&key);
        self.release_inbound(conn_id, Some(stream_id));
        self.promote_inbound();
        if let Some(pending) = self.outbound_negotiators.remove(&key) {
            if self.fail_identify_stream(&pending.target, conn_id, IdentifyFailure::ClosedEarly)
                || self.fail_ping_stream(&pending.target, conn_id, PingFailure::StreamClosed)
            {
                return;
            }
            self.emit_error_for_stream(
                SwarmErrorKind::OpenStreamFailed,
                self.established_peer_for_conn(conn_id),
                Some(conn_id),
                Some(stream_id),
                format!("outbound stream {stream_id} closed before negotiation finished"),
            );
        }
    }
}
