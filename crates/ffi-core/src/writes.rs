//! Pending stream writes held on behalf of the bindings (ADR 0012).
//!
//! A binding hands over one whole payload per write. ffi-core sends as much
//! as the stream accepts, holds the unsent tail, resends it on the stream's
//! Writable, and reports [`P2pEvent::StreamWriteAccepted`] once every byte
//! has been accepted. Each stream holds at most one pending write; the
//! binding serializes its writes behind that event.

use std::collections::BTreeMap;

use minip2p::{Bytes, ConnectionId, Endpoint, EndpointEvent, Error, PeerId, StreamId};

use crate::{FfiError, P2pEvent};

struct Pending {
    peer: PeerId,
    tail: Bytes,
    /// A close-write requested while the tail was pending; the FIN follows
    /// once the tail has been accepted.
    close_after: bool,
}

/// The unsent tail of at most one write per stream.
#[derive(Default)]
pub(crate) struct PendingWrites {
    streams: BTreeMap<(ConnectionId, StreamId), Pending>,
}

impl PendingWrites {
    /// Sends one payload. Returns `true` when every byte was accepted, and
    /// `false` when the rest is held: [`P2pEvent::StreamWriteAccepted`]
    /// follows once it has been accepted.
    ///
    /// A second write while one is pending fails with
    /// [`FfiError::Backpressure`]; so does any write after a close request.
    pub(crate) fn send(
        &mut self,
        endpoint: &mut Endpoint,
        peer: PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Vec<u8>,
    ) -> Result<bool, FfiError> {
        if let Some(pending) = self.streams.get(&(conn_id, stream_id)) {
            return Err(if pending.close_after {
                FfiError::InvalidState {
                    detail: format!("stream {stream_id} write side is closing"),
                }
            } else {
                FfiError::Backpressure
            });
        }
        let counted = data.len();
        match endpoint.send_stream(&peer, conn_id, stream_id, data) {
            Ok(()) => Ok(true),
            Err(Error::Full { unsent, .. }) => {
                self.streams.insert(
                    (conn_id, stream_id),
                    Pending {
                        peer,
                        tail: retain(unsent, counted),
                        close_after: false,
                    },
                );
                Ok(false)
            }
            Err(error) => Err(crate::endpoint::map_driver_error(error)),
        }
    }

    /// Half-closes the write side, after the pending tail if there is one.
    pub(crate) fn close_write(
        &mut self,
        endpoint: &mut Endpoint,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), FfiError> {
        if let Some(pending) = self.streams.get_mut(&(conn_id, stream_id)) {
            pending.close_after = true;
            return Ok(());
        }
        endpoint
            .close_stream_write(peer, conn_id, stream_id)
            .map_err(crate::endpoint::map_driver_error)
    }

    /// Drops the stream's tail; the stream is being reset or abandoned.
    pub(crate) fn forget(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        self.streams.remove(&(conn_id, stream_id));
    }

    /// Follows one endpoint event before it is converted for the binding.
    ///
    /// A Writable resends the stream's tail and returns
    /// [`P2pEvent::StreamWriteAccepted`] once all of it is accepted. Events
    /// that end the write side drop the tail; the binding fails the pending
    /// write from that event.
    pub(crate) fn observe(
        &mut self,
        endpoint: &mut Endpoint,
        event: &EndpointEvent,
    ) -> Option<P2pEvent> {
        match event {
            EndpointEvent::StreamWritable {
                conn_id, stream_id, ..
            } => self.retry(endpoint, *conn_id, *stream_id),
            EndpointEvent::StreamWriteStopped {
                conn_id, stream_id, ..
            }
            | EndpointEvent::StreamClosed {
                conn_id, stream_id, ..
            } => {
                self.forget(*conn_id, *stream_id);
                None
            }
            EndpointEvent::ConnectionClosed { conn_id, .. }
            | EndpointEvent::ConnectionReplaced { old: conn_id, .. } => {
                self.streams.retain(|(conn, _), _| conn != conn_id);
                None
            }
            _ => None,
        }
    }

    fn retry(
        &mut self,
        endpoint: &mut Endpoint,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Option<P2pEvent> {
        let key = (conn_id, stream_id);
        let pending = self.streams.get_mut(&key)?;
        let counted = pending.tail.len();
        match endpoint.send_stream(&pending.peer, conn_id, stream_id, pending.tail.clone()) {
            Ok(()) => {}
            Err(Error::Full { unsent, .. }) => {
                pending.tail = retain(unsent, counted);
                return None;
            }
            // The stream is gone; its terminal event fails the write.
            Err(_) => {
                self.streams.remove(&key);
                return None;
            }
        }
        let pending = self.streams.remove(&key)?;
        if pending.close_after {
            // A failed FIN means the stream already ended, which its own
            // terminal event reports.
            match endpoint.close_stream_write(&pending.peer, conn_id, stream_id) {
                Ok(()) | Err(_) => {}
            }
        }
        Some(P2pEvent::StreamWriteAccepted {
            peer_id: pending.peer.to_base58(),
            conn_id: conn_id.as_u64(),
            stream_id: stream_id.as_u64(),
        })
    }
}

/// Keeps a tail, copying it out once it is shorter than half of what it was
/// counted at so it cannot pin the binding's whole payload (ADR 0012).
fn retain(tail: Bytes, counted: usize) -> Bytes {
    if tail.len().saturating_mul(2) < counted {
        Bytes::copy_from_slice(&tail)
    } else {
        tail
    }
}
