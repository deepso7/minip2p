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
//! The QUIC-carried cases (`quic`, and `relayed`, whose circuit runs over two
//! QUIC legs through the relay) also report, from the timing pass, each
//! Endpoint's UDP datagrams per direction: `datagrams_per_mb` and
//! `avg_datagram_bytes`, under `endpoint_throughput/{case}/{endpoint}/{sent,
//! received}` for the client, the target and, in `relayed`, the relay (both
//! of its legs together). They count datagrams the Endpoint's QUIC sockets
//! actually sent or received, not packets quiche generated, from the
//! `diagnostics` counters of `minip2p-quic` that the `bench` feature enables.
//!
//! Allocations come from `stats_alloc`, installed as this binary's global
//! allocator, and cover every thread in the process (sender, target and, for
//! `relayed`, relay). A reallocation counts as one allocation, and only its
//! growth counts toward bytes allocated. Allocations made by native code
//! outside the Rust allocator, such as BoringSSL's inside QUIC, are not seen.
//! The figures are informational: over real transports they vary with
//! scheduling and read chunking. The sender allocates its `CHUNK` once: each
//! write passes a `Bytes` handle to it, and a Full resends the unsent tail.
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

use minip2p::{Bytes, Endpoint, EndpointEvent, PeerId, RelayServerEvent};
use minip2p_quic::{DatagramCounters, datagram_counters};
use stats_alloc::{INSTRUMENTED_SYSTEM, Stats, StatsAlloc};
use support::{Driven, Relayed, SETUP_TIMEOUT, bind_on, bind_relay, next_event, send_chunk};

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

/// The Endpoints of a case whose datagrams are counted, by role: at most
/// three, the capacity of a [`Mark`].
#[derive(Clone)]
struct Roles(Vec<(&'static str, PeerId)>);

impl Roles {
    fn new(roles: Vec<(&'static str, PeerId)>) -> Self {
        assert!(roles.len() <= 3, "a mark counts at most three roles");
        Self(roles)
    }
}

/// A point in a transfer: wall clock, process allocation counters, and each
/// role's datagram counters (in [`Roles`] order, at most three).
struct Mark {
    at: Instant,
    allocs: Stats,
    datagrams: [DatagramCounters; 3],
}

impl Mark {
    fn now(roles: &Roles) -> Self {
        // A fixed array, so taking the mark allocates nothing.
        let mut datagrams = [DatagramCounters::default(); 3];
        for (slot, (_, peer)) in datagrams.iter_mut().zip(&roles.0) {
            *slot = datagram_counters(peer);
        }
        Self {
            allocs: GLOBAL.stats(),
            datagrams,
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
fn spawn_sink(target: Endpoint, client: &Endpoint, roles: Roles) -> (Driven, Progress) {
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
                done_tx
                    .send(Mark::now(&roles))
                    .expect("report transfer end");
            }
            wake.interrupt();
        }
        _ => {}
    });
    (driven, Progress { received, done })
}

/// Opens a stream and moves [`TOTAL`] bytes over it, returning the marks
/// taken just before the first write and when the sink got the last byte.
fn transfer(
    client: &mut Endpoint,
    peer: &PeerId,
    progress: &Progress,
    roles: &Roles,
) -> (Mark, Mark) {
    progress.received.store(0, Ordering::Release);
    let (conn, stream) = client.open_stream(peer, PROTOCOL).expect("open stream");
    let deadline = Instant::now() + SETUP_TIMEOUT;
    loop {
        assert!(Instant::now() < deadline, "stream negotiation timed out");
        if let Some(EndpointEvent::StreamReady {
            conn_id,
            stream_id,
            initiated_locally: true,
            ..
        }) = next_event(client, Duration::from_millis(10))
            && (conn_id, stream_id) == (conn, stream)
        {
            break;
        }
    }

    let chunk = Bytes::from(vec![0x5a; CHUNK]);
    let mut held = None;
    let start = Mark::now(roles);
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
            let (accepted, full) = send_chunk(client, peer, (conn, stream), &chunk, &mut held);
            sent += accepted;
            if full {
                break;
            }
        }
        // Flushes queued bytes. The sink's progress interrupts this wait,
        // which returns so the window refills at once (`next_event` would
        // swallow the interrupt and sleep out the deadline). The sender has
        // no use for the outcome or any event.
        let _outcome = client.wait(Duration::from_millis(5)).expect("drive client");
    };
    client
        .close_stream_write(peer, conn, stream)
        .expect("close write");
    (start, end)
}

/// The rows for one case: throughput and datagrams from the timing pass,
/// allocations from the allocation pass.
fn rows(case: &str, roles: &Roles, timing: (Mark, Mark), allocation: (Mark, Mark)) -> Vec<String> {
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
    let mut rows: Vec<(String, &str, f64)> = [
        ("mb_per_s", mb_per_s),
        ("allocs_per_mb", allocs_per_mb),
        ("bytes_allocated_per_mb", bytes_allocated_per_mb),
    ]
    .into_iter()
    .map(|(metric, value)| (format!("endpoint_throughput/{case}"), metric, value))
    .collect();

    let marks = timing.0.datagrams.iter().zip(&timing.1.datagrams);
    for ((role, _), (start, end)) in roles.0.iter().zip(marks) {
        let counts = end.since(start);
        for (direction, datagrams, bytes) in [
            ("sent", counts.sent, counts.sent_bytes),
            ("received", counts.received, counts.received_bytes),
        ] {
            assert!(datagrams > 0, "{case}: the {role} {direction} no datagrams");
            let datagrams_per_mb = datagrams as f64 / megabytes;
            let avg_datagram_bytes = bytes as f64 / datagrams as f64;
            println!(
                "endpoint_throughput/{case}/{role}/{direction}: {datagrams_per_mb:.1} datagrams/MB, \
                 {avg_datagram_bytes:.0} bytes/datagram"
            );
            let name = format!("endpoint_throughput/{case}/{role}/{direction}");
            rows.push((name.clone(), "datagrams_per_mb", datagrams_per_mb));
            rows.push((name, "avg_datagram_bytes", avg_datagram_bytes));
        }
    }

    rows.into_iter()
        .map(|(name, metric, value)| {
            format!(r#"{{"tier":"rust-wall","name":"{name}","metric":"{metric}","value":{value}}}"#)
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

    let (case, roles) = if listen.contains("/tcp/") {
        ("tcp", Roles::new(Vec::new()))
    } else {
        let client_peer = client.peer_id().clone();
        (
            "quic",
            Roles::new(vec![("client", client_peer), ("target", peer.clone())]),
        )
    };
    let (_sink, progress) = spawn_sink(target, &client, roles.clone());
    let timing = transfer(&mut client, &peer, &progress, &roles);
    let allocation = transfer(&mut client, &peer, &progress, &roles);
    rows(case, &roles, timing, allocation)
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
    let roles = Roles::new(vec![
        ("client", client.peer_id().clone()),
        ("target", target_peer.clone()),
        ("relay", relay_addr.peer_id().clone()),
    ]);
    let (_sink, progress) = spawn_sink(target, &client, roles.clone());
    let timing = transfer(&mut client, &target_peer, &progress, &roles);
    let allocation = transfer(&mut client, &target_peer, &progress, &roles);

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
    rows("relayed", &roles, timing, allocation)
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
