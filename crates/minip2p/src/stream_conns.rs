//! Connection lookup for the internal agents that name streams by peer and
//! stream id only.

use alloc::collections::BTreeMap;

use minip2p_core::PeerId;
use minip2p_swarm::SwarmEvent;
use minip2p_transport::{ConnectionId, StreamId};

/// The connection each stream an internal agent may act on was observed on.
///
/// The NAT and Gossipsub agents address streams by `(peer, stream id)`, but
/// swarm stream operations also take the connection, because stream ids are
/// only unique per connection. Their drivers record where every stream was
/// opened or announced (`StreamReady`) and address operations with that
/// connection, so a stale operation fails instead of reaching a
/// same-numbered stream on the peer's newer connection.
#[derive(Default)]
pub(crate) struct StreamConns(BTreeMap<(PeerId, StreamId), ConnectionId>);

impl StreamConns {
    /// Records the connection a synchronous `open_stream` returned.
    pub(crate) fn opened(&mut self, peer_id: &PeerId, conn_id: ConnectionId, stream_id: StreamId) {
        self.0.insert((peer_id.clone(), stream_id), conn_id);
    }

    /// Tracks stream and connection lifecycle. Call before the agent sees
    /// `event`, so actions it takes in response can already be addressed.
    pub(crate) fn observe(&mut self, event: &SwarmEvent) {
        match event {
            SwarmEvent::StreamReady {
                peer_id,
                conn_id,
                stream_id,
                ..
            } => self.opened(peer_id, *conn_id, *stream_id),
            SwarmEvent::StreamClosed {
                peer_id,
                conn_id,
                stream_id,
            } => {
                let key = (peer_id.clone(), *stream_id);
                if self.0.get(&key) == Some(conn_id) {
                    self.0.remove(&key);
                }
            }
            // Streams end with their connection without per-stream events.
            SwarmEvent::ConnectionClosed { conn_id, .. }
            | SwarmEvent::ConnectionReplaced { old: conn_id, .. } => {
                self.0.retain(|_, conn| conn != conn_id);
            }
            _ => {}
        }
    }

    /// Forgets the stream a `StreamReady` announced when the agent did not
    /// claim it: an application stream is never the agent's to act on.
    pub(crate) fn unclaimed(&mut self, event: &SwarmEvent) {
        if let SwarmEvent::StreamReady {
            peer_id,
            conn_id,
            stream_id,
            ..
        } = event
        {
            let key = (peer_id.clone(), *stream_id);
            if self.0.get(&key) == Some(conn_id) {
                self.0.remove(&key);
            }
        }
    }

    /// The connection `peer_id`'s stream `stream_id` was observed on, if it
    /// is still live.
    pub(crate) fn get(&self, peer_id: &PeerId, stream_id: StreamId) -> Option<ConnectionId> {
        self.0.get(&(peer_id.clone(), stream_id)).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stream_id_follows_only_the_connection_it_was_observed_on() {
        let peer_id = PeerId::from_public_key_protobuf(b"stream-conns-peer");
        let (old, new, stream_id) = (ConnectionId::new(1), ConnectionId::new(2), StreamId::new(3));
        let mut conns = StreamConns::default();
        conns.opened(&peer_id, old, stream_id);

        conns.observe(&SwarmEvent::ConnectionReplaced {
            peer_id: peer_id.clone(),
            old,
            new,
        });
        assert_eq!(conns.get(&peer_id, stream_id), None);

        conns.opened(&peer_id, new, stream_id);
        // A late close for the old connection's stream 3 leaves the new one.
        conns.observe(&SwarmEvent::StreamClosed {
            peer_id: peer_id.clone(),
            conn_id: old,
            stream_id,
        });
        assert_eq!(conns.get(&peer_id, stream_id), Some(new));
    }

    #[test]
    fn a_stream_the_agent_did_not_claim_is_forgotten() {
        let peer_id = PeerId::from_public_key_protobuf(b"stream-conns-app");
        let ready = SwarmEvent::StreamReady {
            peer_id: peer_id.clone(),
            conn_id: ConnectionId::new(1),
            stream_id: StreamId::new(3),
            protocol_id: "/app/1".into(),
            initiated_locally: false,
        };
        let mut conns = StreamConns::default();
        conns.observe(&ready);
        assert_eq!(
            conns.get(&peer_id, StreamId::new(3)),
            Some(ConnectionId::new(1))
        );

        conns.unclaimed(&ready);
        assert_eq!(conns.get(&peer_id, StreamId::new(3)), None);
    }
}
