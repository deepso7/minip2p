//! One-way sustained throughput over TCP, QUIC and a forced relayed circuit,
//! plus allocation traffic per MB transferred.
//!
//! Each case connects a client to a target, then moves a fixed
//! [`TOTAL`] bytes over one application stream in one direction
//! (`support::bulk`). The client writes 64 KiB chunks and keeps up to [`IN_FLIGHT`] bytes ahead of
//! what the target has received, well past the transports' own windows, so
//! transport backpressure rather than the bench bounds the rate. A write the
//! stream refuses (that backpressure) is not counted and is retried once the
//! endpoint has been driven. The target counts bytes until the total arrives.
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
//! actually sent or received, not packets the QUIC engine generated, from the
//! `diagnostics` counters of `minip2p-quic` that the `bench` feature enables.
//! Each such Endpoint's granted socket buffer sizes are printed alongside.
//!
//! Allocations come from `stats_alloc`, installed as this binary's global
//! allocator, and cover every thread in the process (sender, target and, for
//! `relayed`, relay). A reallocation counts as one allocation, and only its
//! growth counts toward bytes allocated. Allocations made by native code
//! outside the Rust allocator are not seen; QUIC's TLS runs on rustls, so its
//! allocations are counted.
//! The figures are informational: over real transports they vary with
//! scheduling and read chunking. The sender allocates its chunk once: each
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
use std::sync::mpsc;
use std::time::{Duration, Instant};

use minip2p::{Endpoint, EndpointEvent, PeerId, RelayServerEvent};
use minip2p_quic::{DatagramCounters, datagram_counters, socket_buffers};
use stats_alloc::{INSTRUMENTED_SYSTEM, Stats, StatsAlloc};
use support::bulk::{self, Load, Sink};
use support::{Driven, Relayed, SETUP_TIMEOUT, bind_on, bind_relay, next_event};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const PROTOCOL: &str = "/minip2p/bench/sink/1";
/// Bytes moved per transfer.
const TOTAL: u64 = 256 * MB;
/// Bytes the client may have written ahead of what the target received: more
/// than QUIC's connection and send windows (5 MiB and 1216 KiB by default)
/// plus the adapter's pending-send queue per connection
/// (`max_pending_connection_bytes`, 1 MiB) can hold.
const IN_FLIGHT: u64 = 32 * MB;
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

/// Drives `target` as the sink, marking the end of each transfer.
fn spawn_sink(target: Endpoint, client: &Endpoint, roles: Roles) -> (Driven, Sink<Mark>) {
    bulk::spawn_sink(
        target,
        client,
        PROTOCOL,
        move || Mark::now(&roles),
        |_, _| {},
    )
}

/// Moves [`TOTAL`] bytes over a fresh stream, returning the marks taken just
/// before the first write and when the sink got the last byte.
fn transfer(
    client: &mut Endpoint,
    peer: &PeerId,
    sink: &Sink<Mark>,
    roles: &Roles,
) -> (Mark, Mark) {
    let load = Load {
        total: TOTAL,
        streams: 1,
        in_flight: IN_FLIGHT,
    };
    bulk::transfer(client, peer, PROTOCOL, sink, load, || Mark::now(roles))
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
    for ((role, peer), (start, end)) in roles.0.iter().zip(marks) {
        if let Some(buffers) = socket_buffers(peer) {
            println!(
                "endpoint_throughput/{case}/{role}: socket buffers {} B send, {} B receive",
                buffers.send_bytes, buffers.recv_bytes
            );
        }
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
    let (_sink, sink) = spawn_sink(target, &client, roles.clone());
    let timing = transfer(&mut client, &peer, &sink, &roles);
    let allocation = transfer(&mut client, &peer, &sink, &roles);
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
    let (_sink, sink) = spawn_sink(target, &client, roles.clone());
    let timing = transfer(&mut client, &target_peer, &sink, &roles);
    let allocation = transfer(&mut client, &target_peer, &sink, &roles);

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
