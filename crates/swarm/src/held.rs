//! Caller-side holding of unsent tails (ADR 0012).
//!
//! A write that does not fit returns Full with its unsent tail, and the
//! caller -- not the layer that refused it -- keeps that tail until the
//! stream is writable again. [`HeldWrites`] is that bookkeeping for callers
//! that write on many streams: the swarm core for its own protocols, and
//! Endpoint hosts for theirs.

use alloc::collections::{BTreeMap, VecDeque};

use minip2p_core::Bytes;
use minip2p_transport::{ConnectionId, StreamId};

/// Writes waiting on one stream, in order.
#[derive(Debug, Default)]
pub struct HeldStream {
    /// Payloads to send again, oldest first. The first is the unsent tail of
    /// the write that came back Full.
    pub tails: VecDeque<Bytes>,
    /// A write-side close requested after the held writes. It must follow
    /// them, so it waits too.
    pub close: bool,
    bytes: usize,
}

impl HeldStream {
    /// Bytes held on this stream.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// Unsent tails per stream, held by the caller of `send_stream`.
///
/// The flow for a caller:
///
/// 1. Before writing or closing, check [`is_held`](Self::is_held). While a
///    stream is held, [`push`](Self::push) the write or
///    [`close_after`](Self::close_after) the close instead, so nothing
///    overtakes the held bytes.
/// 2. When a write comes back Full, [`push`](Self::push) its unsent tail.
/// 3. On the stream's Writable, [`take`](Self::take) everything and replay it
///    in order through step 1 -- a replay that is Full again simply holds
///    the stream again.
/// 4. When the stream's write side ends (write stopped, reset, closed, or
///    its connection closed), [`forget_stream`](Self::forget_stream) or
///    [`forget_connection`](Self::forget_connection) drops the tails.
#[derive(Debug, Default)]
pub struct HeldWrites {
    streams: BTreeMap<(ConnectionId, StreamId), HeldStream>,
}

impl HeldWrites {
    /// Creates an empty holder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether writes on the stream must wait behind held bytes.
    pub fn is_held(&self, conn_id: ConnectionId, stream_id: StreamId) -> bool {
        self.streams.contains_key(&(conn_id, stream_id))
    }

    /// Bytes held on the stream, so a caller can bound what one stream may
    /// make it keep.
    pub fn held_bytes(&self, conn_id: ConnectionId, stream_id: StreamId) -> usize {
        self.streams
            .get(&(conn_id, stream_id))
            .map_or(0, HeldStream::bytes)
    }

    /// Holds `data` behind whatever the stream already holds.
    ///
    /// `counted` is the length of the payload `data` was cut from. A tail
    /// shorter than half of it is copied, so a held slice never pins a much
    /// larger allocation (ADR 0012). Pass `data.len()` for a whole payload.
    pub fn push(
        &mut self,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        counted: usize,
    ) {
        let data = if data.len().saturating_mul(2) < counted {
            Bytes::copy_from_slice(&data)
        } else {
            data
        };
        let held = self.streams.entry((conn_id, stream_id)).or_default();
        held.bytes += data.len();
        held.tails.push_back(data);
    }

    /// Defers a write-side close until the held bytes have been accepted.
    ///
    /// Returns `false` when nothing is held, in which case the caller should
    /// close now.
    pub fn close_after(&mut self, conn_id: ConnectionId, stream_id: StreamId) -> bool {
        match self.streams.get_mut(&(conn_id, stream_id)) {
            Some(held) => {
                held.close = true;
                true
            }
            None => false,
        }
    }

    /// Removes and returns everything held on the stream, for replay.
    pub fn take(&mut self, conn_id: ConnectionId, stream_id: StreamId) -> Option<HeldStream> {
        self.streams.remove(&(conn_id, stream_id))
    }

    /// Drops the stream's held writes; its write side has ended.
    pub fn forget_stream(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        self.streams.remove(&(conn_id, stream_id));
    }

    /// Drops every held write on a connection that ended.
    pub fn forget_connection(&mut self, conn_id: ConnectionId) {
        self.streams.retain(|(conn, _), _| *conn != conn_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONN: ConnectionId = ConnectionId::new(1);

    fn stream() -> StreamId {
        StreamId::new(3)
    }

    #[test]
    fn a_short_tail_of_a_large_payload_is_copied_out() {
        let payload = Bytes::from(alloc::vec![7u8; 100]);
        let mut held = HeldWrites::new();
        held.push(CONN, stream(), payload.slice(90..), payload.len());
        let tail = &held.take(CONN, stream()).expect("held").tails[0];
        assert_eq!(tail.as_ref(), &[7u8; 10]);
        assert!(
            !core::ptr::eq(tail.as_ptr(), payload.as_ptr().wrapping_add(90)),
            "a 10-byte tail must not pin the 100-byte payload"
        );
    }

    #[test]
    fn close_waits_only_while_something_is_held() {
        let mut held = HeldWrites::new();
        assert!(!held.close_after(CONN, stream()), "nothing held: close now");
        held.push(CONN, stream(), Bytes::from_static(b"tail"), 4);
        assert!(held.close_after(CONN, stream()));
        let stream = held.take(CONN, stream()).expect("held");
        assert!(stream.close);
        assert_eq!(stream.bytes(), 4);
    }
}
