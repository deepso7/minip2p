//! Identify: running the handler's actions and events, the first-Identify
//! deadline, and peer readiness.

use alloc::format;

use minip2p_core::{Bytes, PeerId};
use minip2p_identify::{IdentifyAction, IdentifyEvent, IdentifyMessage, IdentifyOutput};
use minip2p_transport::ConnectionId;

use crate::events::{IdentifyFailure, SwarmErrorKind, SwarmEvent};

use super::{Action, FirstIdentify, ProtocolKind, SwarmState};

impl SwarmState {
    /// Returns the latest Identify information received for `peer_id`.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&IdentifyMessage> {
        self.peer_info.get(peer_id)
    }

    /// Returns whether `peer_id`'s current connection has reached the
    /// application-ready state.
    pub fn is_peer_ready(&self, peer_id: &PeerId) -> bool {
        self.ready_peers.contains(peer_id)
    }

    /// Returns the peer's current connection and its Identify info when that
    /// connection is ready, as one coherent snapshot.
    ///
    /// Ready waits use this instead of separate readiness, connection, and
    /// Identify getters, which could each describe a different connection
    /// around a Connection replacement.
    pub fn peer_readiness(&self, peer_id: &PeerId) -> Option<(ConnectionId, &IdentifyMessage)> {
        if !self.ready_peers.contains(peer_id) {
            return None;
        }
        Some((
            *self.peer_to_conn.get(peer_id)?,
            self.peer_info.get(peer_id)?,
        ))
    }

    /// Whether `event` is a `PeerReady` for a connection that is no longer
    /// the peer's current one.
    ///
    /// A `PeerReady(old)` queued before `old` was replaced is still delivered
    /// in order, but a host processing a batch sees the core's state after
    /// it. Hosts pass such an event to the application only: protocol drivers
    /// act peer-scoped and would start work on the not-yet-ready replacement.
    pub fn is_stale_peer_ready(&self, event: &SwarmEvent) -> bool {
        matches!(
            event,
            SwarmEvent::PeerReady { peer_id, conn_id, .. }
                if self.connection_id(peer_id) != Some(*conn_id)
        )
    }

    /// Ends `conn_id`'s first Identify exchange as failed for `cause`:
    /// reports [`SwarmEvent::IdentifyFailed`] and closes the connection, which
    /// can no longer become ready. Returns whether it did; when the exchange
    /// is not running (it succeeded, already failed, or the connection is
    /// gone) it does nothing, and the caller reports the failure itself.
    pub(super) fn fail_first_identify(
        &mut self,
        conn_id: ConnectionId,
        cause: IdentifyFailure,
    ) -> bool {
        if !matches!(
            self.first_identify.get(&conn_id),
            Some(FirstIdentify::Running { .. })
        ) {
            return false;
        }
        let Some(peer_id) = self.established_peer_for_conn(conn_id) else {
            return false;
        };
        self.first_identify
            .insert(conn_id, FirstIdentify::Failed(cause));
        self.events.push_back(SwarmEvent::IdentifyFailed {
            peer_id,
            conn_id,
            cause,
        });
        self.actions.push_back(Action::CloseConnection { conn_id });
        true
    }

    /// [`Self::fail_first_identify`] for a failed stream whose `target` is our
    /// Identify request; `false` for any other stream.
    pub(super) fn fail_identify_stream(
        &mut self,
        target: &ProtocolKind,
        conn_id: ConnectionId,
        cause: IdentifyFailure,
    ) -> bool {
        *target == ProtocolKind::IdentifyInitiator && self.fail_first_identify(conn_id, cause)
    }

    /// Whether `conn_id` is closing because its first Identify failed.
    pub(super) fn identify_failed(&self, conn_id: ConnectionId) -> bool {
        matches!(
            self.first_identify.get(&conn_id),
            Some(FirstIdentify::Failed(_))
        )
    }

    /// Emits `PeerReady` for the peer's current connection once it is
    /// established and identified. Placeholder peers are never ready.
    pub(super) fn try_emit_peer_ready(&mut self, peer_id: &PeerId) {
        if self.ready_peers.contains(peer_id) || !self.established_peers.contains(peer_id) {
            return;
        }
        let Some(info) = self.peer_info.get(peer_id) else {
            return;
        };
        let Some(&conn_id) = self.peer_to_conn.get(peer_id) else {
            return;
        };
        if self.identify_failed(conn_id) {
            return;
        }

        self.ready_peers.insert(*peer_id);
        self.events.push_back(SwarmEvent::PeerReady {
            peer_id: *peer_id,
            conn_id,
            protocols: info.protocols.clone(),
        });
    }

    pub(super) fn execute_identify_action(&mut self, action: IdentifyAction) {
        match action {
            IdentifyAction::Send {
                ref peer_id,
                stream_id,
                ref data,
            } => {
                if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                    self.actions.push_back(Action::SendStream {
                        conn_id,
                        stream_id,
                        data: Bytes::from(data.clone()),
                    });
                }
            }
            IdentifyAction::CloseStreamWrite {
                ref peer_id,
                stream_id,
            } => {
                if let Some(&conn_id) = self.peer_to_conn.get(peer_id) {
                    self.actions
                        .push_back(Action::CloseStreamWrite { conn_id, stream_id });
                }
            }
            IdentifyAction::ResetStream {
                ref peer_id,
                stream_id,
            } => {
                if let Some(conn_id) =
                    self.conn_for_owned_stream(peer_id, stream_id, ProtocolKind::IdentifyInitiator)
                {
                    self.actions
                        .push_back(Action::ResetStream { conn_id, stream_id });
                }
            }
        }
    }

    pub(super) fn drain_identify_outputs(&mut self) {
        while let Some(output) = self.identify.poll_output() {
            match output {
                IdentifyOutput::Action(action) => self.execute_identify_action(action),
                IdentifyOutput::Event(event) => self.handle_identify_event(event),
            }
        }
    }

    pub(super) fn handle_identify_event(&mut self, event: IdentifyEvent) {
        match event {
            IdentifyEvent::Received { peer_id, info } => {
                let conn_id = self.connection_id(&peer_id);
                if let Some(conn_id) = conn_id {
                    if self.identify_failed(conn_id) {
                        return;
                    }
                    self.first_identify.remove(&conn_id);
                }
                self.peer_info.insert(peer_id, info.clone());
                if let Some(conn_id) = conn_id {
                    self.events.push_back(SwarmEvent::IdentifyReceived {
                        peer_id,
                        conn_id,
                        info,
                    });
                }
                self.try_emit_peer_ready(&peer_id);
            }
            IdentifyEvent::Error {
                peer_id,
                stream_id,
                error,
            } => {
                let conn_id = self
                    .conn_for_owned_stream(&peer_id, stream_id, ProtocolKind::IdentifyInitiator)
                    .or_else(|| self.connection_id(&peer_id));
                if conn_id
                    .is_some_and(|conn| self.fail_first_identify(conn, IdentifyFailure::Malformed))
                {
                    return;
                }
                self.emit_error_for_stream(
                    SwarmErrorKind::Identify,
                    Some(peer_id),
                    conn_id,
                    Some(stream_id),
                    format!("identify error: {error}"),
                );
            }
        }
    }
}
