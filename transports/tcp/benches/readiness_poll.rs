use std::hint::black_box;
use std::io::{ErrorKind, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use minip2p_core::{Multiaddr, PeerAddr};
use minip2p_identity::Ed25519Keypair;
use minip2p_platform::{Now, StdEntropy};
use minip2p_tcp::{StdTcpProvider, TcpEvent, TcpProvider, TcpTransport};
use minip2p_transport::{Bytes, ConnectionId, SharedPoll, StreamId, Transport, TransportEvent};

type Node = TcpTransport<StdTcpProvider, StdEntropy>;

// The locked 512-connection provider sweeps need at least 1,027 open file
// descriptors, and the transport sweeps, which hold both ends, about 1,040.
const COUNTS: &[usize] = &[1, 64, 256, 512];
const CONNECT_BATCH: usize = 32;
/// Failure backstop for one measured delivery, so a regression reports which
/// iteration stalled instead of hanging the bench.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

fn setup_timeout() -> Duration {
    std::env::var("MINIP2P_BENCH_SETUP_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(20))
}

// Every measured poll is driven as a std host drives it (ADR 0013): the
// polled side is attached to a shared poll once setup is done, and each poll
// follows a zero-timeout harvest. Unattached, a provider treats every open
// socket as possibly ready and reads each one on every poll.

struct ReadySet {
    provider: StdTcpProvider,
    readiness: SharedPoll,
    peers: Vec<TcpStream>,
}

/// A shared poll with `source` attached.
fn attached<S: minip2p_transport::PollSource>(source: &mut S) -> SharedPoll {
    let mut readiness = SharedPoll::new().expect("open readiness poll");
    readiness.attach(source).expect("attach to readiness poll");
    readiness
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

    // Many connections, one of them ready: the cost of finding it.
    let mut group = c.benchmark_group("tcp/readiness_poll_sparse");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    for &count in COUNTS {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            let mut ready = establish(count);
            let mut next = 0;
            b.iter(|| {
                poll_one_ready(&mut ready, next);
                next = (next + 1) % count;
            });
        });
    }
    group.finish();
}

/// Per-poll overhead of `TcpTransport` itself over many upgraded connections.
fn transport_poll(c: &mut Criterion) {
    // Nothing is ready: what a poll costs before it finds any work.
    let mut group = c.benchmark_group("tcp/transport_poll_idle");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    for &count in COUNTS {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            let mut pair = upgraded(count);
            b.iter(|| {
                pair.client_readiness
                    .harvest(&mut pair.client, Duration::ZERO)
                    .expect("harvest readiness");
                black_box(pair.client.poll(Now::from_millis(0)).expect("idle poll"))
            });
        });
    }
    group.finish();

    // One connection carries a byte per iteration, rotating across them.
    let mut group = c.benchmark_group("tcp/transport_poll_sparse");
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    for &count in COUNTS {
        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            let mut pair = upgraded(count);
            let mut next = 0;
            b.iter(|| {
                deliver_one(&mut pair, next);
                next = (next + 1) % count;
            });
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
    let mut provider = StdTcpProvider::new();

    let mut peers = Vec::with_capacity(count);
    let mut connected = 0;
    let mut started_connections = 0;
    let started = Instant::now();
    let setup_timeout = setup_timeout();
    while started_connections != count {
        for _ in 0..(count - started_connections).min(CONNECT_BATCH) {
            provider
                .connect(&address)
                .expect("start provider connection");
            started_connections += 1;
        }
        connected += accept_and_poll(&listener, &mut peers, &mut provider);
        assert!(
            started.elapsed() < setup_timeout,
            "only started {started_connections}/{count}, established {connected}/{count} provider connections, and accepted {}/{} peer streams",
            peers.len(),
            count
        );
    }
    while connected != count || peers.len() != count {
        connected += accept_and_poll(&listener, &mut peers, &mut provider);
        assert!(
            started.elapsed() < setup_timeout,
            "only established {connected}/{count} provider connections and accepted {}/{} peer streams",
            peers.len(),
            count
        );
        thread::sleep(Duration::from_micros(100));
    }
    let readiness = attached(&mut provider);
    ReadySet {
        provider,
        readiness,
        peers,
    }
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
        ready
            .readiness
            .harvest(&mut ready.provider, Duration::ZERO)
            .expect("harvest readiness");
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

#[expect(
    clippy::panic,
    reason = "a lost delivery is a bench invariant failure, reported where it happened"
)]
fn poll_one_ready(ready: &mut ReadySet, index: usize) {
    ready
        .peers
        .get_mut(index)
        .expect("peer index in range")
        .write_all(&[1])
        .expect("write readiness byte");
    let deadline = Instant::now() + DELIVERY_TIMEOUT;
    loop {
        ready
            .readiness
            .harvest(&mut ready.provider, Duration::ZERO)
            .expect("harvest readiness");
        for event in ready
            .provider
            .poll(Now::from_millis(0))
            .expect("poll ready sockets")
        {
            match event {
                TcpEvent::Received { data, .. } => {
                    assert_eq!(data, [1], "unexpected payload");
                    black_box(data);
                    return;
                }
                TcpEvent::Closed { socket, reason } => {
                    panic!("{socket} closed while waiting on peer {index}: {reason:?}")
                }
                _ => {}
            }
        }
        assert!(
            Instant::now() < deadline,
            "byte from peer {index} never arrived"
        );
    }
}

/// `count` upgraded connections from `client` to `server`, each with one
/// server-opened stream the client has seen.
struct UpgradedSet {
    client: Node,
    server: Node,
    client_readiness: SharedPoll,
    server_readiness: SharedPoll,
    /// The server's (connection, stream) for each connection.
    streams: Vec<(ConnectionId, StreamId)>,
}

fn node(seed: u8) -> Node {
    TcpTransport::new(
        StdTcpProvider::new(),
        Ed25519Keypair::from_secret_key_bytes([seed; 32]),
        StdEntropy::new(),
    )
}

fn upgraded(count: usize) -> UpgradedSet {
    let mut client = node(1);
    let mut server = node(2);
    let bound = server
        .listen(&"/ip4/127.0.0.1/tcp/0".parse().expect("listen address"))
        .expect("server listens");
    let target = PeerAddr::new(bound, server.local_peer_id()).expect("dial target");

    let started = Instant::now();
    let setup_timeout = setup_timeout();
    let mut dialed = 0;
    let mut connected = 0;
    let mut incoming = 0;
    let mut streams = Vec::with_capacity(count);
    while connected != count || incoming != count || streams.len() != count {
        // Batched, so the listen backlog never overflows.
        while dialed < count && dialed < connected + CONNECT_BATCH {
            client.dial(&target).expect("dial");
            dialed += 1;
        }
        for event in client.poll(Now::from_millis(0)).expect("poll client") {
            match event {
                TransportEvent::Connected { .. } => connected += 1,
                TransportEvent::IncomingStream { .. } => incoming += 1,
                _ => {}
            }
        }
        for event in server.poll(Now::from_millis(0)).expect("poll server") {
            match event {
                TransportEvent::Connected { id, .. } => {
                    server.open_stream(id).expect("open stream");
                }
                TransportEvent::StreamOpened { id, stream_id } => streams.push((id, stream_id)),
                _ => {}
            }
        }
        assert!(
            started.elapsed() < setup_timeout,
            "only upgraded {connected}/{count} connections with {incoming}/{count} streams"
        );
    }
    let mut client_readiness = attached(&mut client);
    let mut server_readiness = attached(&mut server);
    // Settle both sides so the first measured poll starts idle.
    for _ in 0..4 {
        client_readiness
            .harvest(&mut client, Duration::ZERO)
            .expect("harvest readiness");
        client.poll(Now::from_millis(0)).expect("settle client");
        server_readiness
            .harvest(&mut server, Duration::ZERO)
            .expect("harvest readiness");
        server.poll(Now::from_millis(0)).expect("settle server");
    }
    UpgradedSet {
        client,
        server,
        client_readiness,
        server_readiness,
        streams,
    }
}

#[expect(
    clippy::panic,
    reason = "a lost delivery is a bench invariant failure, reported where it happened"
)]
fn deliver_one(pair: &mut UpgradedSet, index: usize) {
    let (id, stream) = *pair.streams.get(index).expect("stream index in range");
    pair.server
        .send_stream(id, stream, Bytes::from_static(&[1]))
        .expect("send");
    let deadline = Instant::now() + DELIVERY_TIMEOUT;
    loop {
        pair.client_readiness
            .harvest(&mut pair.client, Duration::ZERO)
            .expect("harvest readiness");
        for event in pair.client.poll(Now::from_millis(0)).expect("poll client") {
            match event {
                TransportEvent::StreamData {
                    id,
                    stream_id,
                    data,
                    ..
                } => {
                    assert_eq!(&data[..], [1], "unexpected payload");
                    pair.client
                        .ack_stream(id, stream_id, data.len())
                        .expect("ack");
                    // Lets the server take the window update back.
                    pair.server_readiness
                        .harvest(&mut pair.server, Duration::ZERO)
                        .expect("harvest readiness");
                    pair.server.poll(Now::from_millis(0)).expect("poll server");
                    return;
                }
                TransportEvent::Error { id, message } => {
                    panic!("connection {id} failed while waiting on stream {index}: {message}")
                }
                TransportEvent::Closed { id } => {
                    panic!("connection {id} closed while waiting on stream {index}")
                }
                _ => {}
            }
        }
        assert!(
            Instant::now() < deadline,
            "byte on stream {index} never arrived"
        );
    }
}

criterion_group!(benches, readiness_poll, transport_poll);
criterion_main!(benches);
