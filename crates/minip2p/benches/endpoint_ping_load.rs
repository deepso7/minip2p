//! Application-observed ping latency of an Endpoint that is idle, forwarding
//! relay traffic, or forwarding pubsub traffic.
//!
//! The measured Endpoint M binds QUIC and TCP and pings a probe peer P,
//! connected directly over one of them. A sample is the wall time from
//! calling `ping()` to M's event loop receiving the matching
//! `PingRttMeasured` (whose own `rtt_ms` is millisecond-quantized and unused).
//! M's loop runs on the bench's main thread and also handles the load, as an
//! application's would. After [`WARMUP`] pings open the ping stream, the bench
//! takes [`SAMPLES`] samples with at most one ping outstanding, each sent
//! [`INTERVAL`] after the previous one or as soon as it completes, whichever
//! is later. A sample that takes longer than [`SAMPLE_TIMEOUT`], or a
//! `PingTimeout`, fails the run.
//!
//! Loads, running on M throughout the sampling window, with the load peers on
//! loopback QUIC:
//!
//! - `idle`: none;
//! - `relay`: M is the relay of `support::Relayed` and forwards an unbounded
//!   one-way transfer (64 KiB writes, up to 8 ahead of the receiver) over a
//!   forced circuit;
//! - `pubsub`: M is the gossipsub hub between a publisher and a subscriber
//!   that are not connected to each other, forwarding [`MSGS_PER_S`]
//!   messages of [`MSG_LEN`] bytes per second.
//!
//! Each loaded case reads the load's progress (bytes or messages the far end
//! received) when the first sample is sent and when the last one completes,
//! and asserts it advanced in between and again afterwards, so the load ran
//! across the whole window.
//!
//! Rows (`rtt_us_p50`, `rtt_us_p99`, nearest rank, informational) go to
//! `target/bench-results/custom/endpoint_ping_load.json` for the `custom`
//! collector in `scripts/bench_results.py`.

mod support;

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use minip2p::{Endpoint, EndpointEvent, GossipsubError, GossipsubEvent, PeerId, PublishError};
use support::{
    Driven, Relayed, SETUP_TIMEOUT, bind_on, is_backpressure, next_event, relay_builder,
};

const QUIC: &str = "/ip4/127.0.0.1/udp/0/quic-v1";
const TCP: &str = "/ip4/127.0.0.1/tcp/0";
/// Pings before sampling, opening and settling the ping stream.
const WARMUP: usize = 5;
const SAMPLES: usize = 200;
/// Minimum spacing between consecutive pings.
const INTERVAL: Duration = Duration::from_millis(50);
/// Upper bound for one sample.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(2);

const PROTOCOL: &str = "/minip2p/bench/sink/1";
/// Bytes per relay-load write.
const CHUNK: usize = 64 * 1024;
/// Relay-load chunks the sender may have written ahead of the sink.
const IN_FLIGHT: u64 = 8;

const TOPIC: &str = "bench-load";
const MSGS_PER_S: u64 = 500;
const MSG_LEN: usize = 1024;

#[derive(Clone, Copy)]
enum LoadKind {
    Idle,
    Relay,
    Pubsub,
}

impl LoadKind {
    fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Relay => "relay",
            Self::Pubsub => "pubsub",
        }
    }
}

/// Load peers running on their own threads until dropped, and the far end's
/// received count in `unit`s. `None` progress means no load.
struct Load {
    _peers: Vec<Driven>,
    progress: Option<Arc<AtomicU64>>,
    unit: &'static str,
}

impl Load {
    fn progress(&self) -> Option<u64> {
        self.progress.as_ref().map(|p| p.load(Ordering::Acquire))
    }

    /// Drives `m` until the load's progress exceeds `from`, failing after
    /// [`SETUP_TIMEOUT`]. Does nothing without a load.
    fn wait_past(&self, m: &mut Endpoint, from: u64) {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        while self.progress().is_some_and(|progress| progress <= from) {
            assert!(Instant::now() < deadline, "load stalled at {from}");
            next_event(m, Duration::from_millis(1));
        }
    }
}

/// M, built from `builder` with QUIC and TCP bound and listening. Returns the
/// QUIC listen address too.
fn bind_measured(builder: minip2p::EndpointBuilder) -> (Endpoint, minip2p::PeerAddr) {
    let mut m = bind_on(builder.listen_on(TCP).expect("tcp listen address"), QUIC);
    let quic = m
        .listen_all()
        .expect("measured listens")
        .into_iter()
        .find(|addr| addr.to_string().contains("/quic-v1"))
        .expect("measured QUIC address");
    (m, quic)
}

/// M relaying an unbounded one-way transfer between two forced-relay peers.
fn relay_load() -> (Endpoint, Load) {
    let (mut m, m_addr) = bind_measured(relay_builder());
    let Relayed {
        target,
        mut client,
        target_peer,
    } = Relayed::connect(&mut m, &m_addr, PROTOCOL);

    // The sink counts bytes on the inbound stream and wakes the sender.
    let received = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&received);
    let wake = client.wait_handle();
    let sink = Driven::spawn(target, move |_, event| {
        if let EndpointEvent::StreamData { data, .. } = event {
            counted.fetch_add(data.len() as u64, Ordering::Release);
            wake.interrupt();
        }
    });

    let (conn, stream) = client
        .open_stream(&target_peer, PROTOCOL)
        .expect("open stream");
    let deadline = Instant::now() + SETUP_TIMEOUT;
    loop {
        assert!(Instant::now() < deadline, "stream negotiation timed out");
        next_event(&mut m, Duration::from_millis(1));
        if let Some(EndpointEvent::StreamReady {
            conn_id,
            stream_id,
            initiated_locally: true,
            ..
        }) = next_event(&mut client, Duration::from_millis(1))
            && (conn_id, stream_id) == (conn, stream)
        {
            break;
        }
    }

    let chunk = vec![0x5a; CHUNK];
    let acked = Arc::clone(&received);
    let mut sent = 0;
    let sender = Driven::run(client, move |client| {
        while sent - acked.load(Ordering::Acquire) < IN_FLIGHT * CHUNK as u64 {
            match client.send_stream(&target_peer, conn, stream, chunk.clone()) {
                Ok(()) => sent += CHUNK as u64,
                Err(error) => {
                    assert!(is_backpressure(&error), "send failed: {error}");
                    break;
                }
            }
        }
        // Flushes queued bytes; the sink's progress interrupts the wait.
        let _outcome = client.wait(Duration::from_millis(5)).expect("drive client");
    });

    let load = Load {
        _peers: vec![sender, sink],
        progress: Some(received),
        unit: "bytes",
    };
    load.wait_past(&mut m, 0);
    (m, load)
}

/// M as the gossipsub hub forwarding a fixed-rate stream from a publisher to
/// a subscriber.
fn pubsub_load() -> (Endpoint, Load) {
    let (mut m, m_addr) = bind_measured(Endpoint::builder().gossipsub());
    m.subscribe(TOPIC).expect("measured subscribes");
    let leaf = || {
        let mut leaf = bind_on(Endpoint::builder().gossipsub(), QUIC);
        leaf.subscribe(TOPIC).expect("leaf subscribes");
        leaf.connect(&m_addr).expect("leaf connects");
        leaf
    };
    let (mut publisher, mut subscriber) = (leaf(), leaf());

    // Every node must know its neighbours' subscriptions before publishing.
    let subscribed = |event| {
        matches!(
            event,
            Some(EndpointEvent::Gossipsub(GossipsubEvent::PeerSubscribed { topic, .. })) if topic == TOPIC
        )
    };
    let deadline = Instant::now() + SETUP_TIMEOUT;
    let (mut hub_seen, mut publisher_ready, mut subscriber_ready) = (0, false, false);
    while !(hub_seen >= 2 && publisher_ready && subscriber_ready) {
        assert!(Instant::now() < deadline, "pubsub setup timed out");
        let tick = Duration::from_millis(1);
        hub_seen += usize::from(subscribed(next_event(&mut m, tick)));
        publisher_ready |= subscribed(next_event(&mut publisher, tick));
        subscriber_ready |= subscribed(next_event(&mut subscriber, tick));
    }

    let received = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&received);
    let sink = Driven::spawn(subscriber, move |_, event| {
        if let EndpointEvent::Gossipsub(GossipsubEvent::Message { .. }) = event {
            counted.fetch_add(1, Ordering::Release);
        }
    });

    let period = Duration::from_secs(1) / MSGS_PER_S as u32;
    let start = Instant::now();
    let mut published = 0u32;
    let source = Driven::run(publisher, move |publisher| {
        while start + period * published <= Instant::now() {
            // The sequence number keeps every message distinct.
            let mut data = published.to_be_bytes().to_vec();
            data.resize(MSG_LEN, 0x5a);
            if let Err(error) = publisher.publish(TOPIC, data) {
                // A full outbound queue is retried on the next step.
                assert!(
                    matches!(error, GossipsubError::Publish(PublishError::Backpressure)),
                    "publish failed: {error}"
                );
                break;
            }
            published += 1;
        }
        let due = (start + period * published).min(Instant::now() + Duration::from_millis(5));
        next_event(publisher, due);
    });

    let load = Load {
        _peers: vec![source, sink],
        progress: Some(received),
        unit: "messages",
    };
    // The first messages may predate the hub's mesh; wait for delivery.
    load.wait_past(&mut m, 0);
    (m, load)
}

/// Pings `peer` once from `m` and returns the application-observed latency.
fn sample(m: &mut Endpoint, peer: &PeerId) -> Duration {
    let start = Instant::now();
    m.ping(peer).expect("ping");
    loop {
        let event = next_event(m, start + SAMPLE_TIMEOUT).expect("ping sample timed out");
        match event {
            EndpointEvent::PingRttMeasured { peer_id, .. } if &peer_id == peer => {
                return start.elapsed();
            }
            EndpointEvent::PingTimeout { peer_id } => {
                assert!(&peer_id != peer, "ping timed out");
            }
            _ => {}
        }
    }
}

/// The `rtt_us_p50` and `rtt_us_p99` rows for one load over one transport.
fn case(kind: LoadKind, listen: &str) -> Vec<String> {
    let (mut m, load) = match kind {
        LoadKind::Idle => (
            bind_measured(Endpoint::builder()).0,
            Load {
                _peers: Vec::new(),
                progress: None,
                unit: "",
            },
        ),
        LoadKind::Relay => relay_load(),
        LoadKind::Pubsub => pubsub_load(),
    };

    let mut probe = bind_on(Endpoint::builder(), listen);
    let probe_addr = probe.listen().expect("probe listens");
    let probe_peer = probe_addr.peer_id().clone();
    let _probe = Driven::spawn(probe, |_, _| {});
    m.connect(&probe_addr).expect("connect probe");
    let deadline = Instant::now() + SETUP_TIMEOUT;
    loop {
        assert!(Instant::now() < deadline, "probe connect timed out");
        if let Some(EndpointEvent::PeerReady { peer_id, .. }) =
            next_event(&mut m, Duration::from_millis(1))
            && peer_id == probe_peer
        {
            break;
        }
    }

    for _ in 0..WARMUP {
        sample(&mut m, &probe_peer);
    }
    let first = load.progress();
    let mut rtts = Vec::with_capacity(SAMPLES);
    let mut sent_at = Instant::now();
    for index in 0..SAMPLES {
        if index > 0 {
            // Keep driving M (and so its load) until the next ping is due.
            sent_at = (sent_at + INTERVAL).max(Instant::now());
            while Instant::now() < sent_at {
                next_event(&mut m, sent_at);
            }
        }
        rtts.push(sample(&mut m, &probe_peer));
    }
    let last = load.progress();
    let mut advanced = String::new();
    if let (Some(first), Some(last)) = (first, last) {
        assert!(last > first, "load made no progress while sampling");
        load.wait_past(&mut m, last);
        advanced = format!(", load advanced {} {}", last - first, load.unit);
    }
    drop(load);

    rtts.sort_unstable();
    let rank = |p: usize| {
        let rtt = rtts.get((SAMPLES * p).div_ceil(100) - 1).expect("rank");
        rtt.as_secs_f64() * 1e6
    };
    let (p50, p99) = (rank(50), rank(99));
    let transport = if listen.contains("/tcp/") {
        "tcp"
    } else {
        "quic"
    };
    let name = format!("endpoint_ping_load/{}/{transport}", kind.name());
    println!("{name}: p50 {p50:.0} us, p99 {p99:.0} us over {SAMPLES} samples{advanced}");
    [("rtt_us_p50", p50), ("rtt_us_p99", p99)]
        .into_iter()
        .map(|(metric, value)| {
            format!(r#"{{"tier":"rust-wall","name":"{name}","metric":"{metric}","value":{value}}}"#)
        })
        .collect()
}

fn main() {
    let mut rows = Vec::new();
    for kind in [LoadKind::Idle, LoadKind::Relay, LoadKind::Pubsub] {
        for listen in [TCP, QUIC] {
            rows.extend(case(kind, listen));
        }
    }

    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/bench-results/custom"
    );
    std::fs::create_dir_all(dir).expect("create custom results directory");
    std::fs::write(
        format!("{dir}/endpoint_ping_load.json"),
        format!("[{}]\n", rows.join(",")),
    )
    .expect("write custom rows");
}
