//! One-way bulk transfers between two Endpoints: a sink that counts what
//! arrives, and a sender that keeps a bounded amount ahead of it.

use std::collections::HashSet;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

use minip2p::{Bytes, Endpoint, EndpointEvent, PeerId};

use super::{Driven, SETUP_TIMEOUT, next_event, send_chunk};

/// Bytes per write.
pub const CHUNK: usize = 64 * 1024;
/// Upper bound for one transfer.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(300);

/// The shape of one transfer.
#[derive(Clone, Copy, Debug)]
pub struct Load {
    /// Bytes moved, split evenly over the streams; a multiple of
    /// `streams × CHUNK`.
    pub total: u64,
    /// Streams written in parallel.
    pub streams: usize,
    /// Bytes the sender may have written ahead of what the sink received;
    /// keep it past the transport's windows so they, not the bench, bound
    /// the rate.
    pub in_flight: u64,
}

/// The client's view of the sink: the current transfer's size, the bytes
/// received so far, and a mark (`M`) sent once all of them arrived.
pub struct Sink<M> {
    expected: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    done: mpsc::Receiver<M>,
}

/// Drives `target` on its own thread as the sink for `protocol` streams. It
/// counts bytes across every inbound stream of the protocol, publishes the
/// count, wakes `client`, and once the current transfer's bytes arrived
/// sends `mark()` and starts counting the next transfer. `on_event` sees every event first, so
/// a caller can, for example, ping from the target while a transfer runs.
pub fn spawn_sink<M: Send + 'static>(
    target: Endpoint,
    client: &Endpoint,
    protocol: &'static str,
    mark: impl Fn() -> M + Send + 'static,
    mut on_event: impl FnMut(&mut Endpoint, &EndpointEvent) + Send + 'static,
) -> (Driven, Sink<M>) {
    let expected = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let (done_tx, done) = mpsc::channel();
    let wake = client.wait_handle();
    let (total, shared) = (Arc::clone(&expected), Arc::clone(&received));
    let mut streams = HashSet::new();
    let mut count = 0;
    let driven = Driven::spawn(target, move |endpoint, event| {
        on_event(endpoint, &event);
        match event {
            EndpointEvent::StreamReady {
                stream_id,
                protocol_id,
                initiated_locally: false,
                ..
            } if protocol_id == protocol => {
                streams.insert(stream_id);
            }
            EndpointEvent::StreamData {
                stream_id, data, ..
            } if streams.contains(&stream_id) => {
                count += data.len() as u64;
                let total = total.load(Ordering::Acquire);
                assert!(count <= total, "sink received more than the transfer");
                // Publish before reporting the end, so the client's reset for
                // the next transfer cannot be overwritten by this one's count.
                shared.store(count, Ordering::Release);
                if count == total {
                    done_tx.send(mark()).expect("report transfer end");
                    count = 0;
                }
                wake.interrupt();
            }
            _ => {}
        }
    });
    (
        driven,
        Sink {
            expected,
            received,
            done,
        },
    )
}

/// Opens `load.streams` streams to `peer` and moves `load.total` bytes over
/// them, returning `mark()` taken just before the first write and the
/// sink's mark taken when the last byte arrived.
pub fn transfer<M>(
    client: &mut Endpoint,
    peer: &PeerId,
    protocol: &str,
    sink: &Sink<M>,
    load: Load,
    mark: impl Fn() -> M,
) -> (M, M) {
    let per_stream = load.total / load.streams as u64;
    assert!(
        per_stream * load.streams as u64 == load.total && per_stream.is_multiple_of(CHUNK as u64),
        "the total splits into whole chunks per stream"
    );
    sink.expected.store(load.total, Ordering::Release);
    sink.received.store(0, Ordering::Release);
    let mut pending = Vec::new();
    for _ in 0..load.streams {
        pending.push(client.open_stream(peer, protocol).expect("open stream"));
    }
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let mut ready = 0;
    while ready < pending.len() {
        assert!(Instant::now() < deadline, "stream negotiation timed out");
        if let Some(EndpointEvent::StreamReady {
            conn_id,
            stream_id,
            initiated_locally: true,
            ..
        }) = next_event(client, Duration::from_millis(10))
            && pending.contains(&(conn_id, stream_id))
        {
            ready += 1;
        }
    }

    let chunk = Bytes::from(vec![0x5a; CHUNK]);
    // Per stream: bytes accepted, and the unsent tail of a Full write.
    let mut streams: Vec<(u64, Option<Bytes>)> = vec![(0, None); pending.len()];
    let start = mark();
    let started = Instant::now();
    let mut sent = 0;
    let end = loop {
        if let Ok(end) = sink.done.try_recv() {
            break end;
        }
        assert!(
            started.elapsed() < TRANSFER_TIMEOUT,
            "transfer timed out at {sent} bytes"
        );
        // Round-robin, a chunk per stream per turn, until every stream is
        // done or Full, or the sender is too far ahead.
        let mut progressed = true;
        while progressed {
            progressed = false;
            for (stream, (stream_sent, held)) in pending.iter().zip(&mut streams) {
                if *stream_sent >= per_stream
                    || sent - sink.received.load(Ordering::Acquire) >= load.in_flight
                {
                    continue;
                }
                let (accepted, full) = send_chunk(client, *stream, &chunk, held);
                *stream_sent += accepted;
                sent += accepted;
                progressed |= !full;
            }
        }
        // Flushes queued bytes. The sink's progress interrupts this wait,
        // which returns so the window refills at once (`next_event` would
        // swallow the interrupt and sleep out the deadline). The sender has
        // no use for the outcome or any event.
        let _outcome = client.wait(Duration::from_millis(5)).expect("drive client");
    };
    for (conn, stream) in pending {
        client
            .close_stream_write(conn, stream)
            .expect("close write");
    }
    (start, end)
}
