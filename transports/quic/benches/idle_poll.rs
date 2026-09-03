use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use minip2p_core::PeerId;
use minip2p_platform::{Clock, StdClock};
use minip2p_quic::{QuicLimits, QuicNodeConfig, QuicTransport};
use minip2p_transport::Transport;

const COUNTS: &[usize] = &[1, 64, 256, 512];
const CONNECT_BATCH: usize = 32;
const DEFAULT_SETUP_TIMEOUT: Duration = Duration::from_secs(20);

fn idle_poll(c: &mut Criterion) {
    let mut group = c.benchmark_group("quic/idle_poll");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for &count in COUNTS {
        let (mut server, client, server_peer, client_peer) = establish(count);
        assert_eq!(server.connection_ids_for_peer(&client_peer).len(), count);
        assert_eq!(client.connection_ids_for_peer(&server_peer).len(), count);

        let mut clock = StdClock::with_epoch(Instant::now());
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, move |b, _| {
            b.iter(|| {
                let events = server.poll(clock.now()).expect("idle poll");
                assert!(events.is_empty(), "idle benchmark must not emit events");
                black_box(events);
            });
        });
    }
    group.finish();
}

fn establish(count: usize) -> (QuicTransport, QuicTransport, PeerId, PeerId) {
    let setup_timeout = std::env::var("MINIP2P_BENCH_SETUP_TIMEOUT_SECS")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .map_or(DEFAULT_SETUP_TIMEOUT, Duration::from_secs);
    let limits = QuicLimits {
        idle_timeout_ms: 3_600_000,
        ..QuicLimits::default()
    };
    let mut server = QuicTransport::new(
        QuicNodeConfig::generate().with_limits(limits.clone()),
        "127.0.0.1:0",
    )
    .expect("bind server");
    let mut client = QuicTransport::new(
        QuicNodeConfig::generate().with_limits(limits),
        "127.0.0.1:0",
    )
    .expect("bind client");
    server.listen_on_bound_addr().expect("listen");
    let server_peer_addr = server.local_peer_addr().expect("server address");
    let server_peer = server_peer_addr.peer_id().clone();
    let client_peer = client.local_peer_id();

    let started = Instant::now();
    let mut clock = StdClock::with_epoch(started);
    let mut started_connections = 0;
    while started_connections != count {
        let batch_target = (started_connections + CONNECT_BATCH).min(count);
        while started_connections != batch_target {
            client.dial(&server_peer_addr).expect("start dial");
            started_connections += 1;
        }
        while server.connection_ids_for_peer(&client_peer).len() != batch_target
            || client.connection_ids_for_peer(&server_peer).len() != batch_target
        {
            let server_events = server.poll(clock.now()).expect("server setup poll");
            let client_events = client.poll(clock.now()).expect("client setup poll");
            black_box((server_events, client_events));
            assert!(
                started.elapsed() < setup_timeout,
                "only established {}/{} server and {}/{} client connections after starting {started_connections}/{count}",
                server.connection_ids_for_peer(&client_peer).len(),
                count,
                client.connection_ids_for_peer(&server_peer).len(),
                count,
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    (server, client, server_peer, client_peer)
}

criterion_group!(benches, idle_poll);
criterion_main!(benches);
