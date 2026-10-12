use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use minip2p_platform::{Clock, StdClock};
use minip2p_quic::{QuicLimits, QuicNodeConfig, QuicTransport};
use minip2p_transport::{SharedPoll, Transport, TransportEvent};

const COUNTS: &[usize] = &[1, 64, 256, 512];
const CONNECT_BATCH: usize = 32;
const DEFAULT_SETUP_TIMEOUT: Duration = Duration::from_secs(20);

fn idle_poll(c: &mut Criterion) {
    let mut group = c.benchmark_group("quic/idle_poll");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for &count in COUNTS {
        let (mut server, _client) = establish(count);
        // Measured as a std host drives it (ADR 0013): attached to a shared
        // poll, with a zero-timeout harvest before each poll. Unattached, the
        // transport would treat its socket as always possibly ready.
        let mut readiness = SharedPoll::new().expect("open readiness poll");
        readiness.attach(&mut server).expect("attach server");

        let mut clock = StdClock::with_epoch(Instant::now());
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, move |b, _| {
            b.iter(|| {
                readiness
                    .harvest(&mut server, Duration::ZERO)
                    .expect("harvest readiness");
                let events = server.poll(clock.now()).expect("idle poll");
                assert!(events.is_empty(), "idle benchmark must not emit events");
                black_box(events);
            });
        });
    }
    group.finish();
}

fn loopback(limits: QuicLimits) -> QuicTransport {
    let addr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("multiaddr");
    QuicTransport::bind(QuicNodeConfig::generate().with_limits(limits), &[addr])
        .expect("bind loopback")
}

/// Counts `Connected` events, failing setup on any connection error or close.
fn count_connected(events: Vec<TransportEvent>, connected: &mut usize) {
    for event in events {
        assert!(
            !matches!(
                event,
                TransportEvent::Error { .. } | TransportEvent::Closed { .. }
            ),
            "a setup connection failed: {event:?}"
        );
        *connected += usize::from(matches!(event, TransportEvent::Connected { .. }));
    }
}

/// `count` established connections from a client to a server.
fn establish(count: usize) -> (QuicTransport, QuicTransport) {
    let setup_timeout = std::env::var("MINIP2P_BENCH_SETUP_TIMEOUT_SECS")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .map_or(DEFAULT_SETUP_TIMEOUT, Duration::from_secs);
    let limits = QuicLimits {
        idle_timeout_ms: 3_600_000,
        ..QuicLimits::default()
    };
    let mut server = loopback(limits.clone());
    let mut client = loopback(limits);
    server.listen_on_bound_addrs().expect("listen");
    let server_peer_addr = server.local_peer_addrs().expect("server address").remove(0);

    let started = Instant::now();
    let mut clock = StdClock::with_epoch(started);
    let mut started_connections = 0;
    let (mut server_connected, mut client_connected) = (0, 0);
    while started_connections != count {
        let batch_target = (started_connections + CONNECT_BATCH).min(count);
        while started_connections != batch_target {
            client.dial(&server_peer_addr).expect("start dial");
            started_connections += 1;
        }
        while server_connected != batch_target || client_connected != batch_target {
            count_connected(
                server.poll(clock.now()).expect("server setup poll"),
                &mut server_connected,
            );
            count_connected(
                client.poll(clock.now()).expect("client setup poll"),
                &mut client_connected,
            );
            assert!(
                started.elapsed() < setup_timeout,
                "only established {server_connected}/{count} server and \
                 {client_connected}/{count} client connections after starting \
                 {started_connections}/{count}",
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    (server, client)
}

criterion_group!(benches, idle_poll);
criterion_main!(benches);
