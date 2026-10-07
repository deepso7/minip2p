//! Acknowledging user-stream data as the application pulls it (ADR 0012).

use alloc::collections::BTreeSet;
use alloc::string::String;

use minip2p_transport::{ConnectionId, StreamId};

use super::EndpointEvent;

/// Which pulled [`EndpointEvent::StreamData`] an Endpoint acknowledges on the
/// application's behalf.
///
/// Data on a stream whose protocol was registered for manual acknowledgement
/// is the application's to acknowledge; any other data is acknowledged as it
/// is pulled. Feed it every event in the order the application pulls them, so
/// a stream's `StreamReady` (which names its protocol) is seen before its
/// data.
#[derive(Debug, Default)]
pub(crate) struct StreamAcks {
    manual_protocols: BTreeSet<String>,
    /// Pulled streams of a manual protocol that have not ended yet.
    manual_streams: BTreeSet<(ConnectionId, StreamId)>,
    /// Streams of a manual protocol that became ready before it was made
    /// manual, whose `StreamReady` is not pulled yet: they stay automatic.
    pinned_auto: BTreeSet<(ConnectionId, StreamId)>,
}

impl StreamAcks {
    /// Leaves data on `protocol_id`'s streams for the application to
    /// acknowledge, for streams that become ready from now on. `already_ready`
    /// names the streams whose `StreamReady` was produced but not pulled yet:
    /// they keep automatic acknowledgement.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn set_manual(
        &mut self,
        protocol_id: String,
        already_ready: impl IntoIterator<Item = (ConnectionId, StreamId)>,
    ) {
        self.pinned_auto.extend(already_ready);
        self.manual_protocols.insert(protocol_id);
    }

    /// Observes an event the application is pulling, and returns the
    /// acknowledgement the Endpoint owes for it, if any.
    pub(crate) fn pulled(
        &mut self,
        event: &EndpointEvent,
    ) -> Option<(ConnectionId, StreamId, usize)> {
        match event {
            EndpointEvent::StreamReady {
                conn_id,
                stream_id,
                protocol_id,
                ..
            } => {
                let key = (*conn_id, *stream_id);
                if !self.pinned_auto.remove(&key) && self.manual_protocols.contains(protocol_id) {
                    self.manual_streams.insert(key);
                }
            }
            EndpointEvent::StreamData {
                conn_id,
                stream_id,
                data,
                ..
            } if !data.is_empty() && !self.manual_streams.contains(&(*conn_id, *stream_id)) => {
                return Some((*conn_id, *stream_id, data.len()));
            }
            EndpointEvent::StreamClosed {
                conn_id, stream_id, ..
            } => self.forget(*conn_id, *stream_id),
            EndpointEvent::ConnectionClosed { conn_id, .. }
            | EndpointEvent::ConnectionReplaced { old: conn_id, .. } => {
                self.manual_streams.retain(|(conn, _)| conn != conn_id);
            }
            _ => {}
        }
        None
    }

    /// Forgets a stream the application gave up (`abandon_stream`), whose
    /// later events it never pulls.
    pub(crate) fn forget(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        self.manual_streams.remove(&(conn_id, stream_id));
        self.pinned_auto.remove(&(conn_id, stream_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minip2p_core::{Bytes, PeerId};

    fn peer() -> PeerId {
        PeerId::from_public_key_protobuf(b"stream-acks")
    }

    fn ready(protocol_id: &str, stream: u64) -> EndpointEvent {
        EndpointEvent::StreamReady {
            peer_id: peer(),
            conn_id: ConnectionId::new(1),
            stream_id: StreamId::new(stream),
            protocol_id: protocol_id.into(),
            initiated_locally: false,
        }
    }

    fn data(stream: u64, len: usize) -> EndpointEvent {
        EndpointEvent::StreamData {
            peer_id: peer(),
            conn_id: ConnectionId::new(1),
            stream_id: StreamId::new(stream),
            data: Bytes::from(alloc::vec![0; len]),
        }
    }

    #[test]
    fn streams_already_ready_keep_auto_acknowledgement() {
        let mut acks = StreamAcks::default();
        // Stream 1 became ready before the registration, but is pulled after.
        acks.set_manual(
            "/later/1".into(),
            [(ConnectionId::new(1), StreamId::new(1))],
        );
        assert_eq!(acks.pulled(&ready("/later/1", 1)), None);
        assert_eq!(
            acks.pulled(&data(1, 3)),
            Some((ConnectionId::new(1), StreamId::new(1), 3))
        );
        acks.pulled(&ready("/later/1", 2));
        assert_eq!(acks.pulled(&data(2, 3)), None);
    }

    #[test]
    fn pulled_data_is_acknowledged_unless_its_protocol_is_manual() {
        let mut acks = StreamAcks::default();
        acks.set_manual("/manual/1".into(), []);
        assert_eq!(acks.pulled(&ready("/auto/1", 1)), None);
        assert_eq!(acks.pulled(&ready("/manual/1", 2)), None);

        assert_eq!(
            acks.pulled(&data(1, 5)),
            Some((ConnectionId::new(1), StreamId::new(1), 5))
        );
        assert_eq!(acks.pulled(&data(2, 5)), None);
        assert_eq!(acks.pulled(&data(1, 0)), None, "nothing to acknowledge");

        // An ended manual stream is forgotten with its connection.
        acks.pulled(&EndpointEvent::ConnectionClosed {
            peer_id: peer(),
            conn_id: ConnectionId::new(1),
        });
        assert!(acks.manual_streams.is_empty());
    }
}
