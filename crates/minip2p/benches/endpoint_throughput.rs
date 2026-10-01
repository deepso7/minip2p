//! One-way sustained throughput over TCP, QUIC and a forced relayed circuit,
//! plus allocation traffic per MB transferred.
//!
//! Each case connects a client to a target, then moves a fixed
//! [`TOTAL`] bytes over one application stream in one direction. The client
//! writes [`CHUNK`]-sized chunks and keeps up to [`IN_FLIGHT`] chunks ahead of
//! what the target has received. A write the stream refuses (transport
//! backpressure) is not counted and is retried once the endpoint has been
//! driven. The target counts bytes until the total arrives.
//!
//! Every case runs two transfers on fresh streams of the same connection:
//!
//! - a timing pass: `mb_per_s`, from the first write to the target receiving
//!   the last byte;
//! - an allocation pass: `allocs_per_mb` and `bytes_allocated_per_mb`, from
//!   counters snapshotted immediately before the first write and when the
//!   target reaches the total. Setup, handshakes and the relayed circuit-close
//!   check stay outside that interval.
//!
//! Allocations come from `stats_alloc`, installed as this binary's global
//! allocator, and cover every thread in the process (sender, target and, for
//! `relayed`, relay). A reallocation counts as one allocation, and only its
//! growth counts toward bytes allocated. Allocations made by native code
//! outside the Rust allocator, such as BoringSSL's inside QUIC, are not seen.
//! The figures are informational: over real transports they vary with
//! scheduling and read chunking. The sender's own `CHUNK` buffer per write is
//! included, since `send_stream` takes an owned `Vec`.
//!
//! `relayed` uses three Endpoints (`support::Relayed`): the target and the
//! client reach each other only through a relay server over QUIC, with
//! `force_relay` set. After both passes the client closes the circuit and the
//! relay's `CircuitClosed` totals must show the payload went through it.
//!
//! An MB here is 2^20 bytes. Rows go to
//! `target/bench-results/custom/endpoint_throughput.json` for the `custom`
//! collector in `scripts/bench_results.py`.

mod support;

use std::alloc::System;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

use minip2p::{Endpoint, EndpointEvent, Error, PeerId, RelayServerEvent, TransportError};
use stats_alloc::{INSTRUMENTED_SYSTEM, Stats, StatsAlloc};
use support::{Driven, Relayed, SETUP_TIMEOUT, bind_on, bind_relay, next_event};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const PROTOCOL: &str = "/minip2p/bench/sink/1";
/// Bytes moved per transfer.
const TOTAL: u64 = 64 * MB;
/// Bytes per write.
const CHUNK: usize = 64 * 1024;
/// Chunks the client may have written ahead of what the target received.
const IN_FLIGHT: u64 = 8;
/// Upper bound for one transfer.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);
const MB: u64 = 1 << 20;

/// A point in a transfer: wall clock and process allocation counters.
struct Mark {
    at: Instant,
    allocs: Stats,
}

impl Mark {
    fn now() -> Self {
        Self {
            allocs: GLOBAL.stats(),
            at: Instant::now(),
        }
    }
}

/// The client's view of the target's receive progress on the current stream.
struct Progress {
    received: Arc<AtomicU64>,
    done: mpsc::Receiver<Mark>,
}

/// Drives `target` on its own thread as the sink: it counts bytes on the
/// newest inbound stream, publishes the count, wakes the client, and sends a
/// [`Mark`] once [`TOTAL`] bytes arrived.
fn spawn_sink(target: Endpoint, client: &Endpoint) -> (Driven, Progress) {
    let received = Arc::new(AtomicU64::new(0));
    let (done_tx, done) = mpsc::channel();
    let wake = client.wait_handle();
    let shared = Arc::clone(&received);
    let mut stream = None;
    let mut count = 0;
    let driven = Driven::spawn(target, move |_, event| match event {
        EndpointEvent::StreamReady {
            stream_id,
            protocol_id,
            initiated_locally: false,
            ..
        } if protocol_id == PROTOCOL => {
            stream = Some(stream_id);
            count = 0;
        }
        EndpointEvent::StreamData {
            stream_id, data, ..
        } if Some(stream_id) == stream => {
            count += data.len() as u64;
            assert!(count <= TOTAL, "sink received more than the transfer");
            // Publish before reporting the end, so the client's reset for the
            // next transfer cannot be overwritten by this one's final count.
            shared.store(count, Ordering::Release);
            if count == TOTAL {
                done_tx.send(Mark::now()).expect("report transfer end");
            }
            wake.interrupt();
        }
        _ => {}
    });
    (driven, Progress { received, done })
}

/// Whether a refused write is backpressure (retry later) rather than failure.
fn is_backpressure(error: &Error) -> bool {
    matches!(
        error,
        Error::Transport(
            TransportError::ResourceExhausted { .. } | TransportError::StreamSendFailed { .. }
        )
    )
}

/// Opens a stream and moves [`TOTAL`] bytes over it, returning the marks
/// taken just before the first write and when the sink got the last byte.
fn transfer(client: &mut Endpoint, peer: &PeerId, progress: &Progress) -> (Mark, Mark) {
    progress.received.store(0, Ordering::Release);
    let stream = client.open_stream(peer, PROTOCOL).expect("open stream");
    let deadline = Instant::now() + SETUP_TIMEOUT;
    loop {
        assert!(Instant::now() < deadline, "stream negotiation timed out");
        if let Some(EndpointEvent::StreamReady {
            stream_id,
            initiated_locally: true,
            ..
        }) = next_event(client, Duration::from_millis(10))
            && stream_id == stream
        {
            break;
        }
    }

    let chunk = vec![0x5a; CHUNK];
    let start = Mark::now();
    let deadline = start.at + TRANSFER_TIMEOUT;
    let mut sent = 0;
    let end = loop {
        if let Ok(end) = progress.done.try_recv() {
            break end;
        }
        assert!(
            Instant::now() < deadline,
            "transfer timed out at {sent} bytes"
        );
        while sent < TOTAL
            && sent - progress.received.load(Ordering::Acquire) < IN_FLIGHT * CHUNK as u64
        {
            match client.send_stream(peer, stream, chunk.clone()) {
                Ok(()) => sent += CHUNK as u64,
                Err(error) => {
                    assert!(is_backpressure(&error), "send failed: {error}");
                    break;
                }
            }
        }
        // Flushes queued bytes. The sink's progress interrupts this wait,
        // which returns so the window refills at once (`next_event` would
        // swallow the interrupt and sleep out the deadline). The sender has
        // no use for the outcome or any event.
        let _outcome = client.wait(Duration::from_millis(5)).expect("drive client");
    };
    client
        .close_stream_write(peer, stream)
        .expect("close write");
    (start, end)
}

/// The rows for one case: throughput from the timing pass, allocations from
/// the allocation pass.
fn rows(case: &str, timing: (Mark, Mark), allocation: (Mark, Mark)) -> Vec<String> {
    let megabytes = (TOTAL / MB) as f64;
    let mb_per_s = megabytes / (timing.1.at - timing.0.at).as_secs_f64();
    let allocs = allocation.1.allocs - allocation.0.allocs;
    let allocs_per_mb = (allocs.allocations + allocs.reallocations) as f64 / megabytes;
    let bytes_allocated_per_mb = allocs.bytes_allocated as f64 / megabytes;
    println!(
        "endpoint_throughput/{case}: {mb_per_s:.1} MB/s, {allocs_per_mb:.1} allocs/MB \
         ({} allocations + {} reallocations), {bytes_allocated_per_mb:.0} bytes allocated/MB",
        allocs.allocations, allocs.reallocations,
    );
    [
        ("mb_per_s", mb_per_s),
        ("allocs_per_mb", allocs_per_mb),
        ("bytes_allocated_per_mb", bytes_allocated_per_mb),
    ]
    .into_iter()
    .map(|(metric, value)| {
        format!(
            r#"{{"tier":"rust-wall","name":"endpoint_throughput/{case}","metric":"{metric}","value":{value}}}"#
        )
    })
    .collect()
}

/// A client connected directly to a target over one transport.
fn direct(listen: &str) -> Vec<String> {
    let mut target = bind_on(Endpoint::builder().protocol(PROTOCOL), listen);
    let target_addr = target.listen().expect("target listens");
    let mut client = bind_on(Endpoint::builder().protocol(PROTOCOL), listen);
    client.connect(&target_addr).expect("connect");
    let peer = target_addr.peer_id().clone();
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let mut ready = false;
    while !ready {
        assert!(Instant::now() < deadline, "direct connect timed out");
        next_event(&mut target, Duration::from_millis(1));
        ready = matches!(
            next_event(&mut client, Duration::from_millis(1)),
            Some(EndpointEvent::PeerReady { peer_id, .. }) if peer_id == peer
        );
    }

    let (_sink, progress) = spawn_sink(target, &client);
    let timing = transfer(&mut client, &peer, &progress);
    let allocation = transfer(&mut client, &peer, &progress);
    let case = if listen.contains("/tcp/") {
        "tcp"
    } else {
        "quic"
    };
    rows(case, timing, allocation)
}

fn relayed() -> Vec<String> {
    let (mut relay, relay_addr) = bind_relay();
    let Relayed {
        target,
        mut client,
        target_peer,
    } = Relayed::connect(&mut relay, &relay_addr, PROTOCOL);
    let (closed_tx, closed) = mpsc::channel();
    let _relay = Driven::spawn(relay, move |_, event| {
        if let EndpointEvent::RelayServer(RelayServerEvent::CircuitClosed { bytes, .. }) = event {
            closed_tx.send(bytes).expect("report circuit close");
        }
    });
    let (_sink, progress) = spawn_sink(target, &client);
    let timing = transfer(&mut client, &target_peer, &progress);
    let allocation = transfer(&mut client, &target_peer, &progress);

    client.disconnect(&target_peer).expect("close circuit");
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let bytes = loop {
        if let Ok(bytes) = closed.try_recv() {
            break bytes;
        }
        assert!(
            Instant::now() < deadline,
            "relay did not report the circuit closed"
        );
        next_event(&mut client, Duration::from_millis(10));
    };
    assert!(
        bytes.source_to_destination >= 2 * TOTAL,
        "relay forwarded {} bytes, less than the {} byte payload",
        bytes.source_to_destination,
        2 * TOTAL
    );
    rows("relayed", timing, allocation)
}

fn main() {
    let mut rows = direct("/ip4/127.0.0.1/tcp/0");
    rows.extend(direct("/ip4/127.0.0.1/udp/0/quic-v1"));
    rows.extend(relayed());

    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/bench-results/custom"
    );
    std::fs::create_dir_all(dir).expect("create custom results directory");
    std::fs::write(
        format!("{dir}/endpoint_throughput.json"),
        format!("[{}]\n", rows.join(",")),
    )
    .expect("write custom rows");
}
