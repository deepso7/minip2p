//! The stream writer: "send all of this" on top of the partial-accept
//! [`Endpoint::send_stream`] contract (ADR 0012).
//!
//! `send_stream` accepts what fits and hands the rest back in
//! [`Error::Full`]. [`StreamWriter`] holds that tail, resends it when the
//! stream reports [`EndpointEvent::StreamWritable`], and reports
//! [`WriteAccepted`] once every byte has been accepted. The ffi-core
//! bindings use the same writer for their stream writes.

use std::collections::BTreeMap;

use minip2p_core::{Bytes, PeerId, retain_slice};

use crate::{ConnectionId, Endpoint, EndpointEvent, Error, StreamId};

/// What a [`StreamWriter::write`] did with its payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteProgress {
    /// The stream accepted every byte.
    Accepted,
    /// The stream accepted a prefix (possibly empty); the writer holds the
    /// rest and reports [`WriteAccepted`] from [`StreamWriter::observe`]
    /// once it has been accepted too.
    Pending,
}

/// A held write whose last byte was accepted, reported by
/// [`StreamWriter::observe`].
///
/// Accepted means accepted locally, never delivered: the bytes are queued in
/// the stack, and ending the connection still discards whatever has not been
/// sent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteAccepted {
    /// The stream's peer.
    pub peer_id: PeerId,
    /// The stream's connection.
    pub conn_id: ConnectionId,
    /// The stream.
    pub stream_id: StreamId,
}

/// Why a [`StreamWriter`] refused a write or close.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StreamWriteError {
    /// The stream already has a pending write. Retryable once its
    /// [`WriteAccepted`] arrives; `unsent` is the whole payload.
    #[error("stream {stream_id} on connection {conn_id} already has a pending write")]
    Busy {
        conn_id: ConnectionId,
        stream_id: StreamId,
        unsent: Bytes,
    },
    /// The payload does not fit in what is left of the writer's budget.
    /// Retryable once held writes complete; `unsent` is the whole payload.
    #[error("stream writer budget exceeded: {} bytes, {available} available", unsent.len())]
    OverBudget { unsent: Bytes, available: usize },
    /// The payload is larger than the writer's whole budget, so it can never
    /// be admitted; split it. `unsent` is the whole payload.
    #[error("{} bytes exceed the stream writer's {budget}-byte budget", unsent.len())]
    TooLarge { unsent: Bytes, budget: usize },
    /// The write side is closing behind a pending write and takes no more.
    #[error("stream {stream_id} on connection {conn_id} is closing its write side")]
    Closing {
        conn_id: ConnectionId,
        stream_id: StreamId,
    },
    /// The endpoint refused the operation.
    #[error(transparent)]
    Endpoint(#[from] Error),
}

impl StreamWriteError {
    /// Whether the same write can succeed later: [`Self::Busy`] and
    /// [`Self::OverBudget`]. An endpoint `Full` never surfaces here, because
    /// the writer holds that tail itself.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Busy { .. } | Self::OverBudget { .. } => true,
            Self::TooLarge { .. } | Self::Closing { .. } => false,
            Self::Endpoint(error) => error.is_retryable(),
        }
    }

    /// Whether the stream or its connection no longer exists; see
    /// [`Error::is_stream_gone`]. A closing write side is not gone.
    pub fn is_stream_gone(&self) -> bool {
        match self {
            Self::Endpoint(error) => error.is_stream_gone(),
            _ => false,
        }
    }
}

struct Pending {
    tail: Bytes,
    /// What the tail is charged against the budget: the length of the
    /// allocation it views (the payload's at first, the tail's own once
    /// `retain_slice` copied it out).
    counted: usize,
    /// A write-side close requested behind the tail; the FIN follows once
    /// the tail has been accepted.
    close_after: bool,
}

/// Holds the unsent tail of at most one write per stream, within a byte
/// budget, and finishes it as the stream drains.
///
/// Feed every [`EndpointEvent`] from `poll`/`wait` through
/// [`observe`](Self::observe): a [`StreamWritable`](EndpointEvent::StreamWritable)
/// resends the stream's tail, and the event that ends a write side,
/// stream, or connection (including `ConnectionReplaced`) drops what was
/// held for it. Completion means the bytes were accepted locally, never
/// that they were delivered.
///
/// ```rust,no_run
/// # fn demo(endpoint: &mut minip2p::Endpoint, conn_id: minip2p::ConnectionId, stream_id: minip2p::StreamId) -> Result<(), Box<dyn std::error::Error>> {
/// use minip2p::{EndpointWaitOutcome, StreamWriter, WriteProgress};
///
/// let mut writer = StreamWriter::new(8 * 1024 * 1024);
/// let progress = writer.write(endpoint, conn_id, stream_id, vec![0; 1 << 20])?;
/// // The FIN goes out after the whole payload, however long that takes.
/// writer.close_write(endpoint, conn_id, stream_id)?;
/// while progress == WriteProgress::Pending && writer.is_pending(conn_id, stream_id) {
///     if let EndpointWaitOutcome::Event(event) = endpoint.wait(minip2p::WaitDeadline::NEVER)? {
///         if let Some(done) = writer.observe(endpoint, &event) {
///             println!("stream {} accepted every byte", done.stream_id);
///         }
///         // ... handle `event` as usual ...
///     }
/// }
/// # Ok(()) }
/// ```
pub struct StreamWriter {
    budget: usize,
    held: usize,
    streams: BTreeMap<(ConnectionId, StreamId), Pending>,
}

impl StreamWriter {
    /// A writer holding at most `budget` bytes of unsent tails across all
    /// streams. A write is admitted only if its whole payload fits in what
    /// is left, so the writer never holds more than `budget`.
    ///
    /// The budget counts payload lengths, as the ADR 0012 retained-slice
    /// rule does: a `Bytes` slice of a larger buffer keeps that buffer alive
    /// until the tail shrinks below half the slice and is copied out. Pass
    /// owned payloads when the budget must bound the memory pinned.
    pub fn new(budget: usize) -> Self {
        Self {
            budget,
            held: 0,
            streams: BTreeMap::new(),
        }
    }

    /// Bytes of unsent tails currently held, as charged against the budget.
    pub fn held_bytes(&self) -> usize {
        self.held
    }

    /// Whether the stream has a write that is not yet fully accepted.
    pub fn is_pending(&self, conn_id: ConnectionId, stream_id: StreamId) -> bool {
        self.streams.contains_key(&(conn_id, stream_id))
    }

    /// Sends one payload, holding whatever the stream does not accept yet.
    ///
    /// Fails with [`StreamWriteError::Busy`] while the stream has a pending
    /// write, [`StreamWriteError::Closing`] after a deferred
    /// [`close_write`](Self::close_write), [`StreamWriteError::OverBudget`]
    /// when the payload does not fit what is left of the budget, and
    /// [`StreamWriteError::TooLarge`] when it exceeds the whole budget; none
    /// of them sends anything.
    pub fn write(
        &mut self,
        endpoint: &mut Endpoint,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: impl Into<Bytes>,
    ) -> Result<WriteProgress, StreamWriteError> {
        let data = data.into();
        if let Some(pending) = self.streams.get(&(conn_id, stream_id)) {
            return Err(if pending.close_after {
                StreamWriteError::Closing { conn_id, stream_id }
            } else {
                StreamWriteError::Busy {
                    conn_id,
                    stream_id,
                    unsent: data,
                }
            });
        }
        if data.len() > self.budget {
            return Err(StreamWriteError::TooLarge {
                unsent: data,
                budget: self.budget,
            });
        }
        let available = self.budget - self.held;
        if data.len() > available {
            return Err(StreamWriteError::OverBudget {
                unsent: data,
                available,
            });
        }
        let mut counted = data.len();
        match endpoint.send_stream(conn_id, stream_id, data) {
            Ok(()) => Ok(WriteProgress::Accepted),
            Err(Error::Full { mut unsent, .. }) => {
                retain_slice(&mut unsent, &mut counted);
                self.held += counted;
                self.streams.insert(
                    (conn_id, stream_id),
                    Pending {
                        tail: unsent,
                        counted,
                        close_after: false,
                    },
                );
                Ok(WriteProgress::Pending)
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Half-closes the write side: now, or once the pending write's tail
    /// has been accepted. Later writes are refused either way.
    pub fn close_write(
        &mut self,
        endpoint: &mut Endpoint,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Result<(), StreamWriteError> {
        if let Some(pending) = self.streams.get_mut(&(conn_id, stream_id)) {
            pending.close_after = true;
            return Ok(());
        }
        Ok(endpoint.close_stream_write(conn_id, stream_id)?)
    }

    /// Drops the stream's pending write, if any, without sending it; for a
    /// stream being reset or abandoned.
    pub fn forget(&mut self, conn_id: ConnectionId, stream_id: StreamId) {
        if let Some(pending) = self.streams.remove(&(conn_id, stream_id)) {
            self.held -= pending.counted;
        }
    }

    /// Follows one endpoint event; call it for every event, before or after
    /// handling it yourself.
    ///
    /// A Writable resends the stream's tail and returns [`WriteAccepted`]
    /// once all of it is accepted, sending a deferred FIN right after.
    /// `StreamWriteStopped`, `StreamClosed`, `ConnectionClosed`, and
    /// `ConnectionReplaced` drop what was held for them; that event is how
    /// the application learns the write will not complete.
    pub fn observe(
        &mut self,
        endpoint: &mut Endpoint,
        event: &EndpointEvent,
    ) -> Option<WriteAccepted> {
        match event {
            EndpointEvent::StreamWritable {
                peer_id,
                conn_id,
                stream_id,
            } => self.retry(endpoint, peer_id, *conn_id, *stream_id),
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
                let held = &mut self.held;
                self.streams.retain(|(conn, _), pending| {
                    let keep = conn != conn_id;
                    if !keep {
                        *held -= pending.counted;
                    }
                    keep
                });
                None
            }
            _ => None,
        }
    }

    fn retry(
        &mut self,
        endpoint: &mut Endpoint,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) -> Option<WriteAccepted> {
        let pending = self.streams.get_mut(&(conn_id, stream_id))?;
        match endpoint.send_stream(conn_id, stream_id, pending.tail.clone()) {
            Ok(()) => {}
            Err(Error::Full { mut unsent, .. }) => {
                self.held -= pending.counted;
                retain_slice(&mut unsent, &mut pending.counted);
                self.held += pending.counted;
                pending.tail = unsent;
                return None;
            }
            // The stream is gone; its terminal event tells the application.
            Err(_) => {
                self.forget(conn_id, stream_id);
                return None;
            }
        }
        let close_after = pending.close_after;
        self.forget(conn_id, stream_id);
        if close_after {
            // A refused FIN means the stream already ended, which its own
            // terminal event reports.
            match endpoint.close_stream_write(conn_id, stream_id) {
                Ok(()) | Err(_) => {}
            }
        }
        Some(WriteAccepted {
            peer_id: peer_id.clone(),
            conn_id,
            stream_id,
        })
    }
}
