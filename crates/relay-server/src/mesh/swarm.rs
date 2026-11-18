//! [`MeshSwarm`]: one [`RelaySwarm`] over a mesh node's public and backbone
//! swarms.

use minip2p_core::{Bytes, Multiaddr, PeerId};
use minip2p_transport::ConnectionId;

use super::{DIRECTORY_PROTOCOL_ID, FORWARD_PROTOCOL_ID, is_backbone_connection};
use crate::{RelaySwarm, RelaySwarmError, StreamKey};

/// A mesh node's two swarms behind the one [`RelaySwarm`] the agent drives.
///
/// Built per agent call from borrows of both swarms. Opens go to the
/// backbone for the mesh protocols (directory and forward) and to the public
/// swarm otherwise (STOP); every other command goes by its connection's
/// namespace ([`is_backbone_connection`]). Feed both swarms' events to the
/// same agent, with `is_circuit = false` for backbone events.
pub struct MeshSwarm<'a, P, B> {
    public: &'a mut P,
    backbone: &'a mut B,
}

impl<'a, P: RelaySwarm, B: RelaySwarm> MeshSwarm<'a, P, B> {
    /// Joins the public and backbone swarms for one agent call.
    pub fn new(public: &'a mut P, backbone: &'a mut B) -> Self {
        Self { public, backbone }
    }

    fn by_conn(&mut self, conn_id: ConnectionId) -> &mut dyn RelaySwarm {
        if is_backbone_connection(conn_id) {
            self.backbone
        } else {
            self.public
        }
    }
}

impl<P: RelaySwarm, B: RelaySwarm> RelaySwarm for MeshSwarm<'_, P, B> {
    fn connection_remote_addr(&self, conn_id: ConnectionId) -> Option<&Multiaddr> {
        if is_backbone_connection(conn_id) {
            self.backbone.connection_remote_addr(conn_id)
        } else {
            self.public.connection_remote_addr(conn_id)
        }
    }

    fn open_stream(
        &mut self,
        peer: &PeerId,
        protocol_id: &str,
        now_ms: u64,
    ) -> Result<StreamKey, RelaySwarmError> {
        if protocol_id == DIRECTORY_PROTOCOL_ID || protocol_id == FORWARD_PROTOCOL_ID {
            self.backbone.open_stream(peer, protocol_id, now_ms)
        } else {
            self.public.open_stream(peer, protocol_id, now_ms)
        }
    }

    fn send_stream(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        data: Bytes,
        now_ms: u64,
    ) -> Result<(), RelaySwarmError> {
        self.by_conn(stream.conn_id)
            .send_stream(peer, stream, data, now_ms)
    }

    fn ack_stream(&mut self, stream: StreamKey, bytes: usize) {
        self.by_conn(stream.conn_id).ack_stream(stream, bytes);
    }

    fn close_stream_write(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        now_ms: u64,
    ) -> Result<(), RelaySwarmError> {
        self.by_conn(stream.conn_id)
            .close_stream_write(peer, stream, now_ms)
    }

    fn reset_stream(
        &mut self,
        peer: &PeerId,
        stream: StreamKey,
        now_ms: u64,
    ) -> Result<(), RelaySwarmError> {
        self.by_conn(stream.conn_id)
            .reset_stream(peer, stream, now_ms)
    }

    fn close_connection(
        &mut self,
        peer: &PeerId,
        conn_id: ConnectionId,
        now_ms: u64,
    ) -> Result<(), RelaySwarmError> {
        self.by_conn(conn_id)
            .close_connection(peer, conn_id, now_ms)
    }
}
