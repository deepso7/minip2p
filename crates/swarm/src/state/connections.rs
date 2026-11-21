//! Connection lifecycle: dials, establishment, connection races, Connection
//! replacement, identity upgrades, closes, and the connection / peer lookups
//! [`SwarmCore`](crate::SwarmCore) exposes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use minip2p_core::{Multiaddr, Path, PeerAddr, PeerId, Protocol};
use minip2p_identify::IDENTIFY_PROTOCOL_ID;
use minip2p_ping::{PING_PAYLOAD_LEN, PING_PROTOCOL_ID};
#[cfg(doc)]
use minip2p_transport::TransportEvent;
use minip2p_transport::{ConnectionCloseReason, ConnectionId, ConnectionToken, StreamId};

use crate::events::{PingFailure, SwarmError, SwarmErrorKind, SwarmEvent};

use super::{
    Action, ConnPhase, FirstIdentify, OwnedStream, PendingDial, ProtocolKind, Registration,
    SwarmState, dropped_on_replacement,
};

/// Mutable form of [`SwarmEvent::peer_id`].
fn event_peer_mut(event: &mut SwarmEvent) -> Option<&mut PeerId> {
    match event {
        SwarmEvent::ConnectionEstablished { peer_id, .. }
        | SwarmEvent::ConnectionClosed { peer_id, .. }
        | SwarmEvent::ConnectionReplaced { peer_id, .. }
        | SwarmEvent::IdentifyReceived { peer_id, .. }
        | SwarmEvent::PeerReady { peer_id, .. }
        | SwarmEvent::IdentifyFailed { peer_id, .. }
        | SwarmEvent::PingRttMeasured { peer_id, .. }
        | SwarmEvent::PingFailed { peer_id, .. }
        | SwarmEvent::StreamReady { peer_id, .. }
        | SwarmEvent::StreamData { peer_id, .. }
        | SwarmEvent::StreamWritable { peer_id, .. }
        | SwarmEvent::StreamRemoteWriteClosed { peer_id, .. }
        | SwarmEvent::StreamWriteStopped { peer_id, .. }
        | SwarmEvent::StreamClosed { peer_id, .. } => Some(peer_id),
        SwarmEvent::Error(error) => error.peer_id.as_mut(),
        SwarmEvent::DialFailed { .. } | SwarmEvent::ListenAddressesChanged { .. } => None,
    }
}

impl SwarmState {
    /// Closes the connection to `peer_id`.
    pub fn disconnect(&mut self, peer_id: &PeerId) -> Result<(), SwarmError> {
        let conn_id = self.require_conn(peer_id)?;
        self.actions.push_back(Action::CloseConnection { conn_id });
        Ok(())
    }

    /// Returns the peers that have been surfaced to the application as connected.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.established_peers.iter().cloned().collect()
    }

    /// Returns whether `peer_id` has been surfaced to the application as
    /// connected. Unlike [`Self::connection_id`], pending dials and
    /// other pre-established mappings do not count.
    pub fn is_peer_connected(&self, peer_id: &PeerId) -> bool {
        self.established_peers.contains(peer_id)
    }

    /// Returns every established connection with its peer, in ascending id
    /// order. Each connected peer holds exactly one: a Connection
    /// replacement retires the old connection immediately. Pending dials
    /// and replaced connections never appear.
    pub fn established_connections(&self) -> impl Iterator<Item = (ConnectionId, &PeerId)> {
        self.conn_to_peer
            .iter()
            .filter(|(_, peer)| self.established_peers.contains(*peer))
            .map(|(conn_id, peer)| (*conn_id, peer))
    }

    /// The peer whose established connection `conn_id` is; `None` for a
    /// pending, replaced, or closed connection.
    pub fn connection_peer(&self, conn_id: ConnectionId) -> Option<&PeerId> {
        self.conn_to_peer.get(&conn_id).filter(|peer| {
            self.established_peers.contains(*peer) && self.peer_to_conn.get(*peer) == Some(&conn_id)
        })
    }

    /// Returns whether a transport connection is still tracked, including
    /// outbound dials and inbound handshakes that have not yet emitted
    /// [`SwarmEvent::ConnectionEstablished`].
    pub fn has_tracked_connections(&self) -> bool {
        !self.conn_to_remote_addr.is_empty() || self.pending_dials().next().is_some()
    }

    /// Every tracked transport connection, pending dials included, with its
    /// peer if known: a dial's is the one it targets, and an inbound
    /// handshake that has not yet identified one has `None`.
    pub fn tracked_connections(&self) -> impl Iterator<Item = (ConnectionId, Option<&PeerId>)> {
        let dials_only = self
            .pending_dials()
            .map(|(conn_id, _)| conn_id)
            .filter(|conn_id| !self.conn_to_remote_addr.contains_key(conn_id));
        self.conn_to_remote_addr
            .keys()
            .copied()
            .chain(dials_only)
            .map(|conn_id| (conn_id, self.tracked_peer(conn_id)))
    }

    /// Our dials that have not established.
    pub(super) fn pending_dials(&self) -> impl Iterator<Item = (ConnectionId, &PendingDial)> {
        self.conn_phases
            .iter()
            .filter_map(|(conn_id, phase)| Some((*conn_id, phase.dial()?)))
    }

    /// Takes `conn_id`'s pending dial, if it has one, leaving it
    /// [`ConnPhase::Closing`].
    pub(super) fn take_dial(&mut self, conn_id: ConnectionId) -> Option<PendingDial> {
        let phase = self.conn_phases.get_mut(&conn_id)?;
        match core::mem::replace(phase, ConnPhase::Closing) {
            ConnPhase::Dialing(dial) | ConnPhase::Vetoed(dial) => Some(dial),
            ConnPhase::Closing => None,
        }
    }

    /// The peer behind tracked `conn_id`: a pending dial's target, else its
    /// established peer. A handshake's placeholder peer is not one.
    pub(super) fn tracked_peer(&self, conn_id: ConnectionId) -> Option<&PeerId> {
        if let Some(dial) = self.conn_phases.get(&conn_id).and_then(ConnPhase::dial) {
            return Some(dial.addr.peer_id());
        }
        self.conn_to_peer
            .get(&conn_id)
            .filter(|peer| self.established_peers.contains(*peer))
    }

    /// Returns the active transport connection selected for `peer_id`.
    pub fn connection_id(&self, peer_id: &PeerId) -> Option<ConnectionId> {
        self.peer_to_conn.get(peer_id).copied()
    }

    /// Whether `conn_id`, while it is some peer's current connection, came
    /// from one of our dials. `None` once it no longer holds a slot.
    pub fn is_outbound(&self, conn_id: ConnectionId) -> Option<bool> {
        self.registrations
            .get(&conn_id)
            .map(|registration| registration.outbound)
    }

    /// Returns the remote transport address recorded for an exact connection.
    pub fn connection_remote_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr> {
        self.conn_to_remote_addr.get(&conn_id)
    }

    /// Records an outbound dial so a later close before establishment emits
    /// [`SwarmEvent::DialFailed`] with `addr`.
    pub fn note_dial(&mut self, conn_id: ConnectionId, addr: PeerAddr) {
        self.conn_phases.insert(
            conn_id,
            ConnPhase::Dialing(PendingDial {
                addr,
                last_error: None,
            }),
        );
    }

    /// Whether `conn_id` is one of our dials that has not established.
    pub fn is_pending_dial(&self, conn_id: ConnectionId) -> bool {
        self.conn_phases
            .get(&conn_id)
            .is_some_and(|phase| phase.dial().is_some())
    }

    /// Takes a pending dial to abort it and returns `(addr, last_error)`, if
    /// any. The connection closes silently from here on, and never
    /// establishes.
    pub fn take_pending_dial(
        &mut self,
        conn_id: ConnectionId,
    ) -> Option<(PeerAddr, Option<String>)> {
        let pending = self.take_dial(conn_id)?;
        Some((pending.addr, pending.last_error))
    }

    /// Marks pending dial `conn_id` so establish-stage events cannot
    /// register or replace; a no-op for any other connection.
    ///
    /// Used after a failed [`crate::SwarmCore::abort_dial`]: the dial is
    /// restored as pending, but must not displace an existing peer connection
    /// if the transport still completes. The first establish-stage event,
    /// [`TransportEvent::Connected`] or
    /// [`TransportEvent::PeerIdentityVerified`], reports the dial as
    /// `DialFailed` and closes it; the connection ignores everything after.
    pub fn veto_establish(&mut self, conn_id: ConnectionId) {
        if matches!(self.conn_phases.get(&conn_id), Some(ConnPhase::Dialing(_)))
            && let Some(dial) = self.take_dial(conn_id)
        {
            self.conn_phases.insert(conn_id, ConnPhase::Vetoed(dial));
        }
    }

    pub(super) fn require_conn(&self, peer_id: &PeerId) -> Result<ConnectionId, SwarmError> {
        self.peer_to_conn
            .get(peer_id)
            .copied()
            .ok_or_else(|| SwarmError::NotConnected { peer_id: *peer_id })
    }

    /// Maps `conn_id` to `peer_id`, moving the connection's owned streams
    /// from any previous peer so `stream_owner` keys stay in sync.
    pub(super) fn set_conn_peer(&mut self, conn_id: ConnectionId, peer_id: PeerId) {
        let Some(old) = self.conn_to_peer.insert(conn_id, peer_id) else {
            return;
        };
        if old == peer_id {
            return;
        }
        let moved: Vec<OwnedStream> = self
            .stream_owner
            .range(OwnedStream::peer_range(
                &old,
                StreamId::new(0),
                StreamId::new(u64::MAX),
            ))
            .filter(|(key, _)| key.conn_id == conn_id)
            .map(|(key, _)| key.clone())
            .collect();
        for mut key in moved {
            if let Some(protocol) = self.stream_owner.remove(&key) {
                key.peer_id = peer_id;
                self.stream_owner.insert(key, protocol);
            }
        }
    }

    pub(super) fn established_peer_for_conn(&self, conn_id: ConnectionId) -> Option<PeerId> {
        let peer_id = self.conn_to_peer.get(&conn_id)?;
        if self.established_peers.contains(peer_id) {
            Some(*peer_id)
        } else {
            None
        }
    }

    /// Returns the PeerId for a connection, creating a synthetic one if
    /// needed. Synthetic PeerIds are only ever seen internally -- the
    /// application does not see a `ConnectionEstablished` event for them.
    pub(super) fn ensure_peer_id_for_conn(&mut self, conn_id: ConnectionId) -> PeerId {
        if let Some(peer_id) = self.conn_to_peer.get(&conn_id) {
            return *peer_id;
        }

        let synthetic_key = format!("minip2p-synthetic-conn-{}", conn_id.as_u64());
        let peer_id = PeerId::from_public_key_protobuf(synthetic_key.as_bytes());
        self.conn_to_peer.insert(conn_id, peer_id);
        self.peer_to_conn.insert(peer_id, conn_id);
        peer_id
    }

    /// Tears down a vetoed dial without a Connection replacement.
    ///
    /// Emits [`SwarmEvent::DialFailed`] when the dial was still pending, queues
    /// a transport close for `conn_id` only, and leaves any other connection
    /// for the same peer untouched.
    pub(super) fn reject_pending_establish(&mut self, conn_id: ConnectionId) {
        if let Some(pending) = self.take_dial(conn_id) {
            let reason = pending
                .last_error
                .unwrap_or_else(|| String::from("connection closed before establishment"));
            self.events.push_back(SwarmEvent::DialFailed {
                conn_id,
                addr: pending.addr,
                reason,
            });
        }
        self.close_unannounced(conn_id);
    }

    /// Whether `new` (carrying `new_token`) loses a connection race to
    /// `current`, `peer_id`'s current connection: both are direct, `current`
    /// registered within the simultaneous-dial window, and `current` is
    /// the one both peers keep -- the lower peer id's dial when they go in
    /// opposite directions, the lower token when they go the same way.
    pub(super) fn loses_connection_race(
        &self,
        peer_id: &PeerId,
        current: ConnectionId,
        new: ConnectionId,
        new_token: Option<ConnectionToken>,
        now_ms: u64,
    ) -> bool {
        if current.is_circuit() || new.is_circuit() {
            return false;
        }
        let Some(current) = self.registrations.get(&current) else {
            return false;
        };
        if now_ms.saturating_sub(current.at_ms) >= self.simultaneous_dial_window_ms {
            return false;
        }
        let new_outbound = matches!(self.conn_phases.get(&new), Some(ConnPhase::Dialing(_)));
        if current.outbound == new_outbound {
            return matches!(
                (current.token, new_token),
                (Some(kept), Some(new)) if kept < new
            );
        }
        current.outbound == (self.local_peer_id < *peer_id)
    }

    /// Closes `conn_id`, the losing half of a connection race, without
    /// announcing it: the peer is already connected over the winner. If it
    /// was our dial, the dial still completes as `DialFailed`, as every dial
    /// that ends before `ConnectionEstablished` does; a Connection attempt
    /// the winner already settled consumes it. Like a replaced connection,
    /// it stays retired until the transport reports it closed.
    pub(super) fn reject_race_loser(&mut self, conn_id: ConnectionId) {
        if let Some(pending) = self.take_dial(conn_id) {
            self.events.push_back(SwarmEvent::DialFailed {
                conn_id,
                addr: pending.addr,
                reason: String::from(
                    "lost a connection race: the peer is connected over the connection both sides keep",
                ),
            });
        }
        self.close_unannounced(conn_id);
    }

    /// Drops what an unannounced connection gathered, including a placeholder
    /// peer, and queues its transport close. It is [`ConnPhase::Closing`]
    /// until the transport reports it closed.
    pub(super) fn close_unannounced(&mut self, conn_id: ConnectionId) {
        self.conn_phases.insert(conn_id, ConnPhase::Closing);
        if let Some(peer_id) = self.conn_to_peer.remove(&conn_id) {
            if self.peer_to_conn.get(&peer_id) == Some(&conn_id) {
                self.peer_to_conn.remove(&peer_id);
            }
            self.discard_placeholder(&peer_id);
        }
        self.conn_to_remote_addr.remove(&conn_id);
        self.forget_connection_streams(conn_id);
        self.actions.push_back(Action::CloseConnection { conn_id });
        self.promote_inbound();
    }

    /// Clears Ping and Identify state for `peer_id`, including a ping
    /// attempt, which ends without a ping event: the connection's own event
    /// ends it.
    pub(super) fn reset_peer_protocols(&mut self, peer_id: &PeerId) {
        self.pings.remove(peer_id);
        self.ping.remove_peer(peer_id);
        self.identify.remove_peer(peer_id);
        self.drain_ping_outputs();
        self.drain_identify_outputs();
    }

    /// Drops the synthetic placeholder peer of a connection that never
    /// established, with every event it produced that is still queued.
    /// Established peers are left alone.
    pub(super) fn discard_placeholder(&mut self, peer_id: &PeerId) {
        if self.established_peers.contains(peer_id) {
            return;
        }
        self.reset_peer_protocols(peer_id);
        self.peer_info.remove(peer_id);
        let actions = &mut self.actions;
        self.events.retain(|event| {
            if event.peer_id() != Some(peer_id) {
                return true;
            }
            if let SwarmEvent::StreamData {
                conn_id,
                stream_id,
                data,
                ..
            } = event
            {
                actions.push_back(Action::AckStream {
                    conn_id: *conn_id,
                    stream_id: *stream_id,
                    bytes: data.len(),
                });
            }
            false
        });
    }

    /// Starts the swarm's own protocols on a peer's new current connection,
    /// established at `now_ms`: Identify, whose deadline starts now, and a
    /// ping stream when a ping is waiting to be sent.
    pub(super) fn start_connection_protocols(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        now_ms: u64,
    ) {
        match self.queue_open_protocol_stream(
            peer_id,
            IDENTIFY_PROTOCOL_ID,
            ProtocolKind::IdentifyInitiator,
        ) {
            Ok(()) if !self.ready_peers.contains(peer_id) => {
                let deadline_ms = now_ms.saturating_add(self.timeouts.identify_ms);
                self.first_identify
                    .insert(conn_id, FirstIdentify::Running { deadline_ms });
            }
            Ok(()) => {}
            Err(e) => self.emit_error(
                SwarmErrorKind::Identify,
                Some(*peer_id),
                Some(conn_id),
                format!("failed to queue identify stream to {peer_id}: {e}"),
            ),
        }

        if self
            .pings
            .get(peer_id)
            .is_some_and(|attempt| attempt.queued.is_some())
            && self.find_negotiated_ping_stream(peer_id).is_none()
            && !self.has_pending_ping_stream(peer_id)
            && let Err(e) =
                self.queue_open_protocol_stream(peer_id, PING_PROTOCOL_ID, ProtocolKind::Ping)
        {
            self.emit_error(
                SwarmErrorKind::Ping,
                Some(*peer_id),
                Some(conn_id),
                format!("failed to requeue pending ping stream to {peer_id}: {e}"),
            );
        }
    }

    /// Takes `old` out of `peer_id`'s connection slot ahead of a Connection
    /// replacement.
    ///
    /// Everything that belonged to `old` ends: its streams, pending opens,
    /// queued actions, and the peer's readiness and Identify info. `old` is
    /// retired until the transport reports it closed, and its close is
    /// ordered after the events queued so far. Returns the payload of a ping
    /// pending or in flight on `old`, which the caller re-sends on the new
    /// connection; its deadline restarts then, so no `PingFailed` is reported
    /// for the hand-over. A ping already past its deadline at `now_ms` times
    /// out instead of being re-sent.
    pub(super) fn retire_for_replacement(
        &mut self,
        peer_id: &PeerId,
        old: ConnectionId,
        now_ms: u64,
    ) -> Option<[u8; PING_PAYLOAD_LEN]> {
        let overdue = self
            .pings
            .get(peer_id)
            .is_some_and(|attempt| attempt.deadline_ms <= now_ms);
        let ping_intent = if overdue {
            self.pings.remove(peer_id);
            self.events.push_back(SwarmEvent::PingFailed {
                peer_id: *peer_id,
                conn_id: old,
                cause: PingFailure::TimedOut,
            });
            None
        } else {
            self.ping
                .in_flight_payload(peer_id)
                .or_else(|| self.pings.get(peer_id).and_then(|attempt| attempt.queued))
        };
        self.reset_peer_protocols(peer_id);
        self.peer_info.remove(peer_id);
        self.ready_peers.remove(peer_id);

        self.conn_to_peer.remove(&old);
        self.conn_to_remote_addr.remove(&old);
        self.registrations.remove(&old);
        self.forget_connection_streams(old);
        self.actions
            .retain(|action| !dropped_on_replacement(action, old));
        self.conn_phases.insert(old, ConnPhase::Closing);
        self.deferred_closes.retain(|conn_id| *conn_id != old);
        self.deferred_closes.push_back(old);
        ping_intent
    }

    /// A connection's path as far as the swarm can tell from its remote
    /// address: Relayed for a circuit, through the relay the address names;
    /// otherwise Direct (only the host knows which direct connections a hole
    /// punch made). A circuit transport always names the relay; a circuit
    /// address that does not reads as Direct.
    pub(super) fn connection_path(&self, conn_id: ConnectionId) -> Path {
        if conn_id.is_circuit()
            && let Some([.., Protocol::P2p(relay), Protocol::P2pCircuit]) = self
                .conn_to_remote_addr
                .get(&conn_id)
                .map(Multiaddr::protocols)
        {
            return Path::Relayed { relay: *relay };
        }
        Path::Direct
    }

    /// Makes `conn_id` the peer's current connection and reports it: as
    /// `ConnectionReplaced` when it takes the slot from `old` (with `old`'s
    /// path, read before it was retired) of an already connected peer,
    /// otherwise as `ConnectionEstablished`.
    pub(super) fn announce_connection(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        old: Option<(ConnectionId, Path)>,
        ping_intent: Option<[u8; PING_PAYLOAD_LEN]>,
        token: Option<ConnectionToken>,
        now_ms: u64,
    ) {
        self.set_conn_peer(conn_id, *peer_id);
        self.peer_to_conn.insert(*peer_id, conn_id);
        let outbound = matches!(
            self.conn_phases.remove(&conn_id),
            Some(ConnPhase::Dialing(_))
        );
        self.registrations.insert(
            conn_id,
            Registration {
                outbound,
                at_ms: now_ms,
                token,
            },
        );
        if let Some(payload) = ping_intent {
            self.start_ping_attempt(peer_id, Some(payload), now_ms);
        }
        match old {
            Some((old, old_path)) if self.established_peers.contains(peer_id) => {
                let new_path = self.connection_path(conn_id);
                self.events.push_back(SwarmEvent::ConnectionReplaced {
                    peer_id: *peer_id,
                    old,
                    new: conn_id,
                    old_path,
                    new_path,
                });
            }
            _ => {
                self.established_peers.insert(*peer_id);
                self.events.push_back(SwarmEvent::ConnectionEstablished {
                    peer_id: *peer_id,
                    conn_id,
                });
            }
        }
        self.promote_inbound();
    }

    pub(super) fn register_connection(
        &mut self,
        id: ConnectionId,
        peer_id: PeerId,
        token: Option<ConnectionToken>,
        now_ms: u64,
    ) {
        if self.conn_to_peer.contains_key(&id) {
            return;
        }
        let old = self
            .peer_to_conn
            .get(&peer_id)
            .copied()
            .filter(|old| *old != id);
        if old.is_some_and(|old| self.loses_connection_race(&peer_id, old, id, token, now_ms)) {
            self.reject_race_loser(id);
            return;
        }
        let old = old.map(|old| (old, self.connection_path(old)));
        let ping_intent =
            old.and_then(|(old, _)| self.retire_for_replacement(&peer_id, old, now_ms));
        self.announce_connection(&peer_id, id, old, ping_intent, token, now_ms);
        self.start_connection_protocols(&peer_id, id, now_ms);
    }

    pub(super) fn upgrade_connection_identity(
        &mut self,
        conn_id: ConnectionId,
        new_peer_id: PeerId,
        token: Option<ConnectionToken>,
        now_ms: u64,
    ) {
        let existing = self.conn_to_peer.get(&conn_id).cloned();
        if existing.as_ref() == Some(&new_peer_id) {
            return;
        }

        let old = self
            .peer_to_conn
            .get(&new_peer_id)
            .copied()
            .filter(|old| *old != conn_id);
        if old.is_some_and(|old| {
            self.loses_connection_race(&new_peer_id, old, conn_id, token, now_ms)
        }) {
            self.reject_race_loser(conn_id);
            return;
        }
        let old = old.map(|old| (old, self.connection_path(old)));
        let ping_intent =
            old.and_then(|(old, _)| self.retire_for_replacement(&new_peer_id, old, now_ms));

        if let Some(stale) = existing {
            self.peer_to_conn.remove(&stale);
            self.ping.migrate_peer(&stale, &new_peer_id);
            self.identify.migrate_peer(&stale, &new_peer_id);
            if let Some(attempt) = self.pings.remove(&stale) {
                self.pings.insert(new_peer_id, attempt);
            }
            self.drain_ping_outputs();
            self.drain_identify_outputs();
            if let Some(info) = self.peer_info.remove(&stale) {
                self.peer_info.insert(new_peer_id, info);
            }
            self.ready_peers.remove(&stale);
            self.established_peers.remove(&stale);
            self.migrate_buffered_events(&stale, &new_peer_id);
        }

        self.announce_connection(&new_peer_id, conn_id, old, ping_intent, token, now_ms);
        self.try_emit_peer_ready(&new_peer_id);
        self.start_connection_protocols(&new_peer_id, conn_id, now_ms);
    }

    pub(super) fn migrate_buffered_events(&mut self, old: &PeerId, new: &PeerId) {
        for event in self.events.iter_mut().chain(
            self.queued_inbound
                .values_mut()
                .flat_map(|queued| queued.events.iter_mut()),
        ) {
            if let Some(peer_id) = event_peer_mut(event)
                && peer_id == old
            {
                *peer_id = *new;
            }
        }
    }

    /// Ends a connection with at most one event: `DialFailed` for our
    /// pending dial, `ConnectionClosed` for an established connection, and
    /// otherwise -- a connection that failed before it ever established, such
    /// as an inbound handshake -- a [`SwarmErrorKind::Transport`] error with
    /// the reason, unless we closed it ourselves or aborted its dial.
    pub(super) fn handle_connection_closed(
        &mut self,
        conn_id: ConnectionId,
        reason: ConnectionCloseReason,
    ) {
        let reason = match self.first_identify.remove(&conn_id) {
            Some(FirstIdentify::Failed(cause)) if reason == ConnectionCloseReason::Local => {
                ConnectionCloseReason::Error(format!("{cause}"))
            }
            _ => reason,
        };
        self.conn_to_remote_addr.remove(&conn_id);
        self.registrations.remove(&conn_id);
        let mut reported = match self.conn_phases.remove(&conn_id) {
            Some(ConnPhase::Dialing(pending) | ConnPhase::Vetoed(pending)) => {
                let reason = pending
                    .last_error
                    .unwrap_or_else(|| format!("connection closed before establishment: {reason}"));
                self.events.push_back(SwarmEvent::DialFailed {
                    conn_id,
                    addr: pending.addr,
                    reason,
                });
                true
            }
            Some(ConnPhase::Closing) => true,
            None => false,
        };

        if let Some(peer_id) = self.conn_to_peer.remove(&conn_id)
            && self.peer_to_conn.get(&peer_id) == Some(&conn_id)
        {
            self.peer_to_conn.remove(&peer_id);
            if self.established_peers.remove(&peer_id) {
                self.reset_peer_protocols(&peer_id);
                self.peer_info.remove(&peer_id);
                self.ready_peers.remove(&peer_id);
                self.events.push_back(SwarmEvent::ConnectionClosed {
                    peer_id,
                    conn_id,
                    reason: reason.clone(),
                });
                reported = true;
            } else {
                self.discard_placeholder(&peer_id);
            }
        }

        if !reported && reason != ConnectionCloseReason::Local {
            self.emit_error(
                SwarmErrorKind::Transport,
                None,
                Some(conn_id),
                format!("connection {conn_id} failed before it was established: {reason}"),
            );
        }
        self.forget_connection_streams(conn_id);
        self.promote_inbound();
    }

    /// Drops the per-stream state of `conn_id`, which is leaving, and its
    /// first-Identify bookkeeping.
    pub(super) fn forget_connection_streams(&mut self, conn_id: ConnectionId) {
        self.release_inbound(conn_id, None);
        self.first_identify.remove(&conn_id);
        self.held.forget_connection(conn_id);
        self.user_writable_wanted.retain(|(cid, _)| *cid != conn_id);
        self.user_write_ended.retain(|(cid, _)| *cid != conn_id);
        self.pending_demotions.retain(|(cid, _)| *cid != conn_id);
        self.stream_owner.retain(|key, _| key.conn_id != conn_id);
        self.reset_pending.retain(|(cid, _)| *cid != conn_id);
        self.abandoned_streams.retain(|(cid, _)| *cid != conn_id);
        self.inbound_negotiators
            .retain(|(cid, _), _| *cid != conn_id);
        self.outbound_negotiators
            .retain(|(cid, _), _| *cid != conn_id);
        self.actions.retain(
            |action| !matches!(action, Action::OpenStream { conn_id: c, .. } if *c == conn_id),
        );
    }
}
