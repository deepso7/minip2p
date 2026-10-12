//! The bindings' stream writes, held by `minip2p`'s shared [`StreamWriter`]
//! (ADR 0012).
//!
//! A binding hands over one whole payload per write. The writer sends as
//! much as the stream accepts, holds the unsent tail, resends it on the
//! stream's Writable, and ffi-core reports [`P2pEvent::StreamWriteAccepted`]
//! once every byte has been accepted. Each stream holds at most one pending
//! write; the binding serializes its writes behind that event.

use minip2p::{StreamWriteError, StreamWriter, WriteAccepted};

use crate::{FfiError, P2pEvent};

/// A writer for the bindings. Its budget is unbounded because the bindings
/// already bound what reaches it: the SDK admits writes per stream up to a
/// high-water mark, each stream holds at most one pending write, and the
/// stream limit caps the streams. A refusal here would have no wakeup the
/// SDK waits for.
pub(crate) fn writer() -> StreamWriter {
    StreamWriter::new(usize::MAX)
}

/// Maps a writer refusal to the binding's error: a second write while one is
/// pending is [`FfiError::Backpressure`], a write behind a deferred close is
/// [`FfiError::InvalidState`].
pub(crate) fn map_write_error(error: StreamWriteError) -> FfiError {
    match error {
        StreamWriteError::Closing { stream_id, .. } => FfiError::InvalidState {
            detail: format!("stream {stream_id} write side is closing"),
        },
        StreamWriteError::Endpoint(error) => crate::endpoint::map_driver_error(error),
        // Busy and OverBudget; the writer has no other refusal.
        _ => FfiError::Backpressure,
    }
}

/// The binding's settlement of a held write.
pub(crate) fn accepted_event(accepted: WriteAccepted) -> P2pEvent {
    P2pEvent::StreamWriteAccepted {
        peer_id: accepted.peer_id.to_base58(),
        conn_id: accepted.conn_id.as_u64(),
        stream_id: accepted.stream_id.as_u64(),
    }
}
