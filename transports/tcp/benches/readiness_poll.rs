use std::hint::black_box;
use std::io::{ErrorKind, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use minip2p_core::Multiaddr;
use minip2p_platform::Now;
use minip2p_tcp::{StdTcpProvider, TcpEvent, TcpProvider};

const COUNTS: &[usize] = &[1, 64, 256, 512];
const SETUP_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_BATCH: usize = 32;

struct ReadySet {
    provider: StdTcpProvider,
    peers: Vec<TcpStream>,
}

fn readiness_poll(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp/readiness_poll");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));

    for &count in COUNTS {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            let mut ready = establish(count);
            b.iter(|| poll_ready(&mut ready, count));
        });
    }
    group.finish();
}

fn establish(count: usize) -> ReadySet {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind peer listener");
    listener
        .set_nonblocking(true)
        .expect("make peer listener nonblocking");
    let address: Multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}",
        listener.local_addr().expect("peer listener address").port()
    )
    .parse()
    .expect("benchmark address");
    let mut provider = StdTcpProvider::new().expect("create provider");

    let mut peers = Vec::with_capacity(count);
    let mut connected = 0;
    let mut started_connections = 0;
    let started = Instant::now();
    while started_connections != count {
        for _ in 0..(count - started_connections).min(CONNECT_BATCH) {
            provider
                .connect(&address)
                .expect("start provider connection");
            started_connections += 1;
        }
        connected += accept_and_poll(&listener, &mut peers, &mut provider);
        assert!(
            started.elapsed() < SETUP_TIMEOUT,
            "only started {started_connections}/{count}, established {connected}/{count} provider connections, and accepted {}/{} peer streams",
            peers.len(),
            count
        );
    }
    while connected != count || peers.len() != count {
        connected += accept_and_poll(&listener, &mut peers, &mut provider);
        assert!(
            started.elapsed() < SETUP_TIMEOUT,
            "only established {connected}/{count} provider connections and accepted {}/{} peer streams",
            peers.len(),
            count
        );
        thread::sleep(Duration::from_micros(100));
    }
    ReadySet { provider, peers }
}

fn accept_and_poll(
    listener: &TcpListener,
    peers: &mut Vec<TcpStream>,
    provider: &mut StdTcpProvider,
) -> usize {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nodelay(true).expect("disable Nagle");
                peers.push(stream);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => {
                assert_eq!(error.kind(), ErrorKind::WouldBlock, "accept peer: {error}");
                break;
            }
        }
    }
    provider
        .poll(Now::from_millis(0))
        .expect("finish provider connection")
        .into_iter()
        .filter(|event| matches!(event, TcpEvent::Connected { .. }))
        .count()
}

fn poll_ready(ready: &mut ReadySet, count: usize) {
    for peer in &mut ready.peers {
        peer.write_all(&[1]).expect("write readiness byte");
    }

    let mut received = 0;
    while received != count {
        for event in ready
            .provider
            .poll(Now::from_millis(0))
            .expect("poll ready sockets")
        {
            if let TcpEvent::Received { data, .. } = event {
                assert!(data.iter().all(|byte| *byte == 1), "unexpected payload");
                received += data.len();
                assert!(received <= count, "received more bytes than were sent");
            }
        }
    }
    black_box(received);
}

criterion_group!(benches, readiness_poll);
criterion_main!(benches);
