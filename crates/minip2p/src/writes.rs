//! The endpoint's write queue: "send all of this" on top of the
//! partial-accept stream contract (ADR 0012, ADR 0030).
//!
//! [`Endpoint::try_send_stream`](crate::Endpoint::try_send_stream) accepts
//! what fits and hands the rest back as [`SendOutcome::Full`].
//! [`Endpoint::send_stream`](crate::Endpoint::send_stream) queues that rest
//! here instead, within the endpoint's write budget: the engine resends it
//! when the swarm reports the stream writable, sends a deferred FIN behind
//! it, and queues [`EndpointEvent::StreamWriteAccepted`] once it has all
//! been accepted, or [`EndpointEvent::StreamWriteAborted`] when the stream
//! or its connection ends first.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use minip2p_core::{Bytes, PeerId, retain_slice};
use minip2p_swarm::{DriverError, SwarmCore, SwarmEvent};
use minip2p_transport::{ConnectionId, StreamKey, Transport};

use crate::{EndpointEvent, EntropySource};

/// The default [write budget](crate::EndpointBuilder::write_budget): 8 MiB of
/// queued bytes across all of an endpoint's streams.
pub const DEFAULT_WRITE_BUDGET: usize = 8 * 1024 * 1024;

/// How much of a [`try_send_stream`](crate::Endpoint::try_send_stream) write
/// the stream accepted.
///
/// A write that did not fit is an outcome, not an error, so `?` on
/// `try_send_stream` propagates only real failures and never drops the
/// unsent tail.
#[must_use = "a Full write leaves `unsent` for you to resend after StreamWritable"]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// Every byte was accepted locally (not yet delivered).
    Accepted,
    /// The stream could not take the whole write: every byte before
    /// `unsent` was accepted, and `unsent` is yours to resend once
    /// [`EndpointEvent::StreamWritable`] fires for the stream.
    Full {
        /// The tail the stream did not accept.
        unsent: Bytes,
    },
}

impl SendOutcome {
    /// Splits a swarm send result: a Full write becomes an outcome, every
    /// other failure stays an error.
    pub(crate) fn from_send(result: Result<(), DriverError>) -> Result<Self, DriverError> {
        match result {
            Ok(()) => Ok(Self::Accepted),
            Err(DriverError::Full { unsent, .. }) => Ok(Self::Full { unsent }),
            Err(error) => Err(error),
        }
    }

    /// Whether every byte was accepted.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Why [`send_stream`](crate::Endpoint::send_stream) or a deferred
/// [`close_stream_write`](crate::Endpoint::close_stream_write) refused.
/// A refused write sent nothing: `unsent`, where present, is the whole
/// payload.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    /// The payload does not fit in what is left of the write budget.
    /// Retryable once queued bytes are accepted (a `StreamWriteAccepted`).
    #[error("write budget exceeded: {} bytes, {available} available", unsent.len())]
    OverBudget { unsent: Bytes, available: usize },
    /// The payload is larger than the whole write budget, so it can never be
    /// queued: split it, raise the budget, or use `try_send_stream`.
    #[error("{} bytes exceed the {budget}-byte write budget", unsent.len())]
    TooLarge { unsent: Bytes, budget: usize },
    /// The write side is closing behind queued bytes and takes no more.
    #[error("stream {stream} is closing its write side")]
    Closing { stream: StreamKey, unsent: Bytes },
    /// The endpoint refused the operation.
    #[error(transparent)]
    Driver(#[from] DriverError),
}

impl SendError {
    /// Whether the same write can succeed later: [`Self::OverBudget`], or a
    /// retryable driver error. A stream's `Full` never surfaces here: the
    /// queue holds that tail itself.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::OverBudget { .. } => true,
            Self::TooLarge { .. } | Self::Closing { .. } => false,
            Self::Driver(error) => error.is_retryable(),
        }
    }

    /// Whether the stream or its connection no longer exists; see
    /// [`DriverError::is_stream_gone`]. A closing write side is not gone.
    pub fn is_stream_gone(&self) -> bool {
        match self {
            Self::Driver(error) => error.is_stream_gone(),
            _ => false,
        }
    }

    /// The payload a refused write hands back; `None` for a driver error,
    /// whose payload (if any) is the error's own.
    pub fn into_unsent(self) -> Option<Bytes> {
        match self {
            Self::OverBudget { unsent, .. }
            | Self::TooLarge { unsent, .. }
            | Self::Closing { unsent, .. } => Some(unsent),
            Self::Driver(_) => None,
        }
    }
}

/// One stream's queued bytes, oldest first.
struct Held {
    peer_id: PeerId,
    /// Each chunk with what it is charged against the budget: the length of
    /// the allocation it views (the payload's at first, the chunk's own once
    /// `retain_slice` copied it out).
    chunks: VecDeque<(Bytes, usize)>,
    /// A write-side close requested behind the chunks; the FIN follows once
    /// they have all been accepted.
    close_after: bool,
}

impl Held {
    fn counted(&self) -> usize {
        self.chunks.iter().map(|(_, counted)| counted).sum()
    }

    fn unsent(&self) -> usize {
        self.chunks.iter().map(|(chunk, _)| chunk.len()).sum()
    }
}

/// The endpoint's bounded write queue.
///
/// The budget counts payload lengths, as the ADR 0012 retained-slice rule
/// does: a `Bytes` slice of a larger buffer keeps that buffer alive until the
/// tail shrinks below half the slice and is copied out. A budget of `0`
/// queues nothing, and costs nothing beyond an empty map.
pub(crate) struct WriteQueue {
    budget: usize,
    held: usize,
    streams: BTreeMap<StreamKey, Held>,
    /// Streams whose `try_send_stream` returned Full: their caller holds a
    /// tail and waits for a Writable, which the queue must not swallow.
    pub(crate) wake: BTreeSet<StreamKey>,
    /// Queued streams whose resend failed: the stream is gone. Its own
    /// terminal event later in the batch reports the abort, or
    /// [`WriteQueue::take_failed`] does at the batch's end.
    failed: Vec<StreamKey>,
}

impl Default for WriteQueue {
    fn default() -> Self {
        Self::new(DEFAULT_WRITE_BUDGET)
    }
}

impl WriteQueue {
    pub(crate) fn new(budget: usize) -> Self {
        Self {
            budget,
            held: 0,
            streams: BTreeMap::new(),
            wake: BTreeSet::new(),
            failed: Vec::new(),
        }
    }

    /// Bytes currently queued, as charged against the budget.
    pub(crate) fn held_bytes(&self) -> usize {
        self.held
    }

    /// Whether the stream has queued bytes (or a FIN behind them).
    pub(crate) fn is_pending(&self, stream: StreamKey) -> bool {
        self.streams.contains_key(&stream)
    }

    /// Records that a bare write to `stream` returned Full, so its caller
    /// gets a `StreamWritable` even if queued bytes take the next one. A zero
    /// budget never queues, so it never takes a Writable and tracks nothing.
    pub(crate) fn want_writable(&mut self, stream: StreamKey) {
        if self.budget > 0 {
            self.wake.insert(stream);
        }
    }

    /// Forgets a waiting bare writer once the write side is closed: no
    /// Writable follows to clear it.
    pub(crate) fn unwant_writable(&mut self, stream: StreamKey) {
        self.wake.remove(&stream);
    }

    /// Whether a write-side close is deferred behind the stream's queue.
    pub(crate) fn is_closing(&self, stream: StreamKey) -> bool {
        self.streams
            .get(&stream)
            .is_some_and(|held| held.close_after)
    }

    /// Admits one payload for `stream` against the budget, or hands it back.
    fn admit(&self, stream: StreamKey, data: Bytes) -> Result<Bytes, SendError> {
        if let Some(held) = self.streams.get(&stream)
            && held.close_after
        {
            return Err(SendError::Closing {
                stream,
                unsent: data,
            });
        }
        if data.len() > self.budget {
            return Err(SendError::TooLarge {
                unsent: data,
                budget: self.budget,
            });
        }
        let available = self.budget - self.held;
        if data.len() > available {
            return Err(SendError::OverBudget {
                unsent: data,
                available,
            });
        }
        Ok(data)
    }

    /// Sends one payload through `send`, queueing what the stream does not
    /// accept. Behind already-queued bytes it is queued whole, so bytes stay
    /// in order.
    pub(crate) fn send(
        &mut self,
        stream: StreamKey,
        peer_id: PeerId,
        data: Bytes,
        send: impl FnOnce(Bytes) -> Result<(), DriverError>,
    ) -> Result<(), SendError> {
        let data = self.admit(stream, data)?;
        let mut counted = data.len();
        let tail = match self.streams.get(&stream) {
            // Nothing to queue, and nothing to charge.
            Some(_) if data.is_empty() => return Ok(()),
            Some(_) => data,
            None => match SendOutcome::from_send(send(data))? {
                SendOutcome::Accepted => return Ok(()),
                SendOutcome::Full { mut unsent } => {
                    retain_slice(&mut unsent, &mut counted);
                    unsent
                }
            },
        };
        self.held += counted;
        self.streams
            .entry(stream)
            .or_insert_with(|| Held {
                peer_id,
                chunks: VecDeque::new(),
                close_after: false,
            })
            .chunks
            .push_back((tail, counted));
        Ok(())
    }

    /// Defers a write-side close behind the stream's queued bytes; `false`
    /// when nothing is queued, so the caller closes now.
    pub(crate) fn defer_close(&mut self, stream: StreamKey) -> bool {
        match self.streams.get_mut(&stream) {
            Some(held) => {
                held.close_after = true;
                true
            }
            None => false,
        }
    }

    /// Drops the stream's queued bytes: the abort event to queue, if any
    /// were held.
    pub(crate) fn forget(&mut self, stream: StreamKey) -> Option<EndpointEvent> {
        self.wake.remove(&stream);
        self.failed.retain(|failed| *failed != stream);
        let held = self.streams.remove(&stream)?;
        self.held -= held.counted();
        Some(EndpointEvent::StreamWriteAborted {
            peer_id: held.peer_id,
            stream,
            unsent: held.unsent(),
        })
    }

    /// Aborts every queue whose resend failed with no terminal event for it
    /// in the batch; the engine calls it once a batch is ingested.
    pub(crate) fn take_failed(&mut self) -> Vec<EndpointEvent> {
        core::mem::take(&mut self.failed)
            .into_iter()
            .filter_map(|stream| self.forget(stream))
            .collect()
    }

    /// Aborts every queue: the endpoint is closing, and a connection whose
    /// close the transport has not reported yet drops its bytes all the same.
    pub(crate) fn abort_all(&mut self) -> Vec<EndpointEvent> {
        let streams: Vec<StreamKey> = self.streams.keys().copied().collect();
        streams
            .into_iter()
            .filter_map(|stream| self.forget(stream))
            .collect()
    }

    /// Follows one swarm event before the engine queues it, and returns
    /// whether to drop it plus what to queue right after it.
    ///
    /// A Writable for a stream with queued bytes resends them (and is
    /// consumed: the queue, not the application, owned that tail), yielding
    /// `StreamWriteAccepted` once they are all accepted, then the Writable
    /// itself if a `try_send_stream` caller is waiting on it. The events that
    /// end a write side, stream or connection (including
    /// `ConnectionReplaced`) drop what was queued for it, yielding
    /// `StreamWriteAborted`.
    pub(crate) fn observe<T: Transport, E: EntropySource>(
        &mut self,
        core: &mut SwarmCore<T, E>,
        event: &SwarmEvent,
        now_ms: u64,
    ) -> (bool, Vec<EndpointEvent>) {
        if self.streams.is_empty() && self.wake.is_empty() {
            return (false, Vec::new());
        }
        match event {
            SwarmEvent::StreamWritable {
                conn_id, stream_id, ..
            } => {
                let stream = StreamKey::new(*conn_id, *stream_id);
                if !self.is_pending(stream) {
                    self.wake.remove(&stream);
                    return (false, Vec::new());
                }
                let mut follow: Vec<EndpointEvent> =
                    self.retry(core, stream, now_ms).into_iter().collect();
                if !follow.is_empty() && self.wake.remove(&stream) {
                    follow.push(event.clone().into());
                }
                (true, follow)
            }
            SwarmEvent::StreamWriteStopped {
                conn_id, stream_id, ..
            }
            | SwarmEvent::StreamClosed {
                conn_id, stream_id, ..
            } => (
                false,
                self.forget(StreamKey::new(*conn_id, *stream_id))
                    .into_iter()
                    .collect(),
            ),
            SwarmEvent::ConnectionClosed { conn_id, .. }
            | SwarmEvent::ConnectionReplaced { old: conn_id, .. } => {
                (false, self.forget_connection(*conn_id))
            }
            _ => (false, Vec::new()),
        }
    }

    fn forget_connection(&mut self, conn_id: ConnectionId) -> Vec<EndpointEvent> {
        self.wake.retain(|stream| stream.conn_id() != conn_id);
        let streams: Vec<StreamKey> = self
            .streams
            .keys()
            .filter(|stream| stream.conn_id() == conn_id)
            .copied()
            .collect();
        streams
            .into_iter()
            .filter_map(|stream| self.forget(stream))
            .collect()
    }

    /// Resends the stream's queued chunks until one does not fit, yielding
    /// `StreamWriteAccepted` once the queue drains. A write side closed
    /// behind the queue takes no wakeup.
    fn retry<T: Transport, E: EntropySource>(
        &mut self,
        core: &mut SwarmCore<T, E>,
        stream: StreamKey,
        now_ms: u64,
    ) -> Option<EndpointEvent> {
        if self.failed.contains(&stream) {
            return None;
        }
        let held = self.streams.get_mut(&stream)?;
        let peer_id = held.peer_id;
        while let Some((chunk, counted)) = held.chunks.front_mut() {
            let sent = core.send_stream(
                &peer_id,
                stream.conn_id(),
                stream.stream_id(),
                chunk.clone(),
                now_ms,
            );
            match SendOutcome::from_send(sent) {
                Ok(SendOutcome::Accepted) => {
                    self.held -= *counted;
                    held.chunks.pop_front();
                }
                Ok(SendOutcome::Full { mut unsent }) => {
                    self.held -= *counted;
                    retain_slice(&mut unsent, counted);
                    self.held += *counted;
                    *chunk = unsent;
                    return None;
                }
                // The stream is gone; its own terminal event says why, and
                // aborts the queue after it.
                Err(_) => {
                    self.failed.push(stream);
                    return None;
                }
            }
        }
        let close_after = held.close_after;
        self.streams.remove(&stream);
        if close_after {
            self.wake.remove(&stream);
            // A refused FIN means the stream already ended, which its own
            // terminal event reports.
            match core.close_stream_write(&peer_id, stream.conn_id(), stream.stream_id(), now_ms) {
                Ok(()) | Err(_) => {}
            }
        }
        Some(EndpointEvent::StreamWriteAccepted { peer_id, stream })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use minip2p_identity::Ed25519Keypair;
    use minip2p_transport::StreamId;

    #[test]
    fn an_empty_write_behind_a_queue_stores_nothing() {
        let stream = StreamKey::new(ConnectionId::new(1), StreamId::new(1));
        let peer_id = Ed25519Keypair::from_secret_key_bytes([1; 32]).peer_id();
        let mut queue = WriteQueue::new(16);
        let full = |data: Bytes| {
            Err(DriverError::Full {
                conn_id: stream.conn_id(),
                stream_id: stream.stream_id(),
                unsent: data,
            })
        };
        queue
            .send(stream, peer_id, Bytes::from(vec![1; 4]), full)
            .expect("queued");
        for _ in 0..3 {
            queue
                .send(stream, peer_id, Bytes::new(), |_| {
                    panic!("a queued stream is not sent to")
                })
                .expect("empty write");
        }
        assert_eq!(queue.streams[&stream].chunks.len(), 1);
        assert_eq!(queue.held_bytes(), 4);

        // A deferred close still refuses it.
        assert!(queue.defer_close(stream));
        assert!(matches!(
            queue.send(stream, peer_id, Bytes::new(), |_| panic!(
                "a queued stream is not sent to"
            )),
            Err(SendError::Closing { .. })
        ));
    }

    #[test]
    fn a_zero_budget_tracks_no_waiting_writer() {
        let stream = StreamKey::new(ConnectionId::new(1), StreamId::new(1));
        let mut queue = WriteQueue::new(0);
        queue.want_writable(stream);
        assert!(queue.wake.is_empty());
    }
}
