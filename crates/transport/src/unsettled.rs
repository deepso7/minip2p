use alloc::collections::BTreeMap;

use crate::{ConnectionId, StreamId, TransportError};

/// Ended connections whose delivered stream bytes are not yet all
/// acknowledged or abandoned: ADR 0012's **unsettled connections**.
///
/// A transport hands a connection's per-stream unacknowledged counts over
/// here when it tears the connection down, and keeps counting the entry
/// against its connection limit until every stream settles. Only the counts
/// survive; sockets, timers, crypto and send buffers go as before. That is
/// what keeps the receive bound -- connection limit times stream limit times
/// stream window -- across close-and-reconnect churn.
///
/// [`ack`](Self::ack) and [`abandon`](Self::abandon) are how
/// [`Transport::ack_stream`](crate::Transport::ack_stream) and
/// [`Transport::reset_stream`](crate::Transport::reset_stream) settle a
/// stream of a connection that already reported `Closed`. Neither emits an
/// event: nothing follows `Closed`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnsettledConnections {
    /// Unacknowledged bytes by stream, for each held connection. Neither map
    /// keeps an empty entry.
    connections: BTreeMap<ConnectionId, BTreeMap<StreamId, usize>>,
}

impl UnsettledConnections {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes over the counts of connection `id`, which is being torn down.
    ///
    /// Streams with nothing unacknowledged are already settled and skipped;
    /// a connection with no unsettled stream is not held at all. Returns
    /// whether it is.
    pub fn insert(
        &mut self,
        id: ConnectionId,
        streams: impl IntoIterator<Item = (StreamId, usize)>,
    ) -> bool {
        let streams: BTreeMap<_, _> = streams.into_iter().filter(|(_, n)| *n != 0).collect();
        if streams.is_empty() {
            return false;
        }
        self.connections.insert(id, streams);
        true
    }

    /// Whether connection `id` is held, waiting for its streams to settle.
    pub fn contains(&self, id: ConnectionId) -> bool {
        self.connections.contains_key(&id)
    }

    /// How many connections are held: each still occupies a connection slot.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Whether no connection is held.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Releases `bytes` of a held stream's unacknowledged bytes, settling the
    /// stream with the last of them and the connection with its last stream.
    ///
    /// Returns whether `id` was held when called, so a transport can tell a
    /// settled connection (held, and no longer [`contains`](Self::contains))
    /// from one it never kept. A settled or unknown stream of a held
    /// connection is a no-op; acknowledging more than the stream holds is
    /// [`TransportError::AckExceedsDelivered`] and releases nothing.
    pub fn ack(
        &mut self,
        id: ConnectionId,
        stream_id: StreamId,
        bytes: usize,
    ) -> Result<bool, TransportError> {
        let Some(streams) = self.connections.get_mut(&id) else {
            return Ok(false);
        };
        let Some(unacked) = streams.get_mut(&stream_id) else {
            return Ok(true);
        };
        if bytes > *unacked {
            return Err(TransportError::AckExceedsDelivered {
                id,
                stream_id,
                acked: bytes,
                unacked: *unacked,
            });
        }
        *unacked -= bytes;
        if *unacked == 0 {
            self.abandon(id, stream_id);
        }
        Ok(true)
    }

    /// Settles a held stream outright, giving up its unacknowledged bytes.
    ///
    /// Returns whether `id` was held when called, as [`ack`](Self::ack) does.
    pub fn abandon(&mut self, id: ConnectionId, stream_id: StreamId) -> bool {
        let Some(streams) = self.connections.get_mut(&id) else {
            return false;
        };
        streams.remove(&stream_id);
        if streams.is_empty() {
            self.connections.remove(&id);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(n: u64) -> ConnectionId {
        ConnectionId::new(n)
    }

    #[test]
    fn a_connection_is_held_until_its_last_stream_settles() {
        let mut ledger = UnsettledConnections::new();
        let (a, b) = (StreamId::new(1), StreamId::new(3));
        assert!(ledger.insert(conn(1), [(a, 10), (b, 4), (StreamId::new(5), 0)]));
        assert_eq!(ledger.len(), 1);

        assert_eq!(ledger.ack(conn(1), a, 6), Ok(true));
        assert_eq!(ledger.ack(conn(1), a, 4), Ok(true), "a settles");
        assert_eq!(ledger.ack(conn(1), a, 0), Ok(true), "settled: a no-op");
        assert!(ledger.contains(conn(1)), "b still holds the slot");

        assert!(ledger.abandon(conn(1), b));
        assert!(!ledger.contains(conn(1)));
        assert_eq!(ledger.ack(conn(1), b, 1), Ok(false), "no longer held");
        assert!(!ledger.abandon(conn(1), b));
    }

    #[test]
    fn over_acknowledging_releases_nothing() {
        let mut ledger = UnsettledConnections::new();
        let stream_id = StreamId::new(1);
        ledger.insert(conn(1), [(stream_id, 3)]);
        assert_eq!(
            ledger.ack(conn(1), stream_id, 4),
            Err(TransportError::AckExceedsDelivered {
                id: conn(1),
                stream_id,
                acked: 4,
                unacked: 3,
            })
        );
        assert_eq!(ledger.ack(conn(1), stream_id, 3), Ok(true));
        assert!(ledger.is_empty());
    }

    #[test]
    fn a_connection_with_nothing_unacknowledged_is_not_held() {
        let mut ledger = UnsettledConnections::new();
        assert!(!ledger.insert(conn(1), [(StreamId::new(1), 0)]));
        assert!(ledger.is_empty());
    }
}
