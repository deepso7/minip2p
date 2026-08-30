use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use minip2p_core::PeerId;
use minip2p_platform::{Clock, StdClock};
use minip2p_quic::{QuicLimits, QuicNodeConfig, QuicTransport};
use minip2p_transport::Transport;

const COUNTS: &[usize] = &[1, 64, 256, 512];
const SETUP_TIMEOUT: Duration = Duration::from_secs(20);

fn idle_poll(c: &mut Criterion) {
    let mut group = c.benchmark_group("quic/idle_poll");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for &count in COUNTS {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            let (mut server, client, server_peer, client_peer) = establish(count);
            assert_eq!(server.connection_ids_for_peer(&client_peer).len(), count);
            assert_eq!(client.connection_ids_for_peer(&server_peer).len(), count);

            let mut clock = StdClock::with_epoch(Instant::now());
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

    for _ in 0..count {
        client.dial(&server_peer_addr).expect("start dial");
    }

    let started = Instant::now();
    let mut clock = StdClock::with_epoch(started);
    loop {
        let server_events = server.poll(clock.now()).expect("server setup poll");
        let client_events = client.poll(clock.now()).expect("client setup poll");
        black_box((server_events, client_events));
        if server.connection_ids_for_peer(&client_peer).len() == count
            && client.connection_ids_for_peer(&server_peer).len() == count
        {
            return (server, client, server_peer, client_peer);
        }
        assert!(
            started.elapsed() < SETUP_TIMEOUT,
            "connection setup timed out"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

criterion_group!(benches, idle_poll);
criterion_main!(benches);
