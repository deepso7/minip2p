use std::collections::{HashMap, HashSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use minip2p::{Deadline, Endpoint, EndpointEvent, EndpointWaitOutcome, PeerAddr, PeerId, StreamId};

const ECHO: &str = "/minip2p/bench/echo/1";
const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
enum Kind {
    Tcp,
    Quic,
}

fn bind(kind: Kind) -> Endpoint {
    let builder = Endpoint::builder()
        .agent_version("minip2p-bench")
        .protocol(ECHO);
    match kind {
        Kind::Tcp => builder
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind(),
        Kind::Quic => builder
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind(),
    }
    .expect("bind endpoint")
}

/// The next Endpoint event, or `None` once `deadline` passes.
fn next_event(endpoint: &mut Endpoint, deadline: impl Into<Deadline>) -> Option<EndpointEvent> {
    let deadline = deadline.into();
    loop {
        match endpoint.wait(deadline).expect("endpoint wait") {
            EndpointWaitOutcome::Event(event) => return Some(event),
            EndpointWaitOutcome::Deadline => return None,
            EndpointWaitOutcome::Interrupted => {}
        }
    }
}

/// Drives `endpoint` until `wanted` accepts an event, dispatching (here:
/// dropping) everything else, as an application event loop would.
fn wait_for(endpoint: &mut Endpoint, what: &str, wanted: impl Fn(&EndpointEvent) -> bool) {
    let deadline = Deadline::from(Instant::now() + TIMEOUT);
    loop {
        let event = next_event(endpoint, deadline).expect(what);
        if wanted(&event) {
            return;
        }
    }
}

/// Starts one Connection attempt and waits until Identify completes.
fn connect_ready(client: &mut Endpoint, server: &PeerAddr) {
    client.connect(server).expect("connect");
    let peer = server.peer_id();
    wait_for(
        client,
        "ready",
        |event| matches!(event, EndpointEvent::PeerReady { peer_id, .. } if peer_id == peer),
    );
}

struct EchoServer {
    address: PeerAddr,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl EchoServer {
    fn start(kind: Kind) -> Self {
        let mut endpoint = bind(kind);
        let address = endpoint.listen().expect("listen");
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut streams = HashSet::<(PeerId, StreamId)>::new();
            while !worker_stop.load(Ordering::Relaxed) {
                let event = next_event(&mut endpoint, Duration::from_millis(5));
                match event {
                    Some(EndpointEvent::StreamReady {
                        peer_id,
                        stream_id,
                        protocol_id,
                        initiated_locally: false,
                        ..
                    }) if protocol_id == ECHO => {
                        streams.insert((peer_id, stream_id));
                    }
                    Some(EndpointEvent::StreamData {
                        peer_id,
                        stream_id,
                        data,
                        ..
                    }) if streams.contains(&(peer_id.clone(), stream_id)) => {
                        endpoint
                            .send_stream(&peer_id, stream_id, data)
                            .expect("echo");
                    }
                    Some(EndpointEvent::StreamRemoteWriteClosed {
                        peer_id, stream_id, ..
                    }) if streams.contains(&(peer_id.clone(), stream_id)) => {
                        endpoint
                            .close_stream_write(&peer_id, stream_id)
                            .expect("close echo");
                    }
                    Some(EndpointEvent::StreamClosed {
                        peer_id, stream_id, ..
                    }) => {
                        streams.remove(&(peer_id, stream_id));
                    }
                    _ => {}
                }
            }
        });
        Self {
            address,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("server thread");
        }
    }
}

struct Pair {
    _server: EchoServer,
    client: Endpoint,
    peer: PeerId,
}

struct Crossed {
    _server: EchoServer,
    clients: Vec<(Endpoint, PeerId)>,
}

impl Crossed {
    fn connected(kind: Kind) -> Self {
        let server = EchoServer::start(kind);
        let peer = server.address.peer_id().clone();
        let mut clients = Vec::new();
        for _ in 0..4 {
            let mut client = bind(kind);
            connect_ready(&mut client, &server.address);
            clients.push((client, peer.clone()));
        }
        Self {
            _server: server,
            clients,
        }
    }

    fn echo_4x4(&mut self) {
        let payload = vec![0x5a; 64];
        let mut pending = Vec::new();
        for (client, peer) in &mut self.clients {
            let mut streams = HashSet::new();
            for _ in 0..4 {
                streams.insert(client.open_stream(peer, ECHO).expect("open stream"));
            }
            pending.push(streams);
        }
        let deadline = Instant::now() + TIMEOUT;
        let mut received = vec![HashMap::<StreamId, Vec<u8>>::new(); self.clients.len()];
        while pending.iter().any(|streams| !streams.is_empty()) {
            assert!(Instant::now() < deadline, "crossed echo timeout");
            for (index, (client, peer)) in self.clients.iter_mut().enumerate() {
                let Some(event) = next_event(client, Duration::from_millis(1)) else {
                    continue;
                };
                match event {
                    EndpointEvent::StreamReady {
                        stream_id,
                        protocol_id,
                        initiated_locally: true,
                        ..
                    } if protocol_id == ECHO
                        && pending
                            .get(index)
                            .is_some_and(|streams| streams.contains(&stream_id)) =>
                    {
                        client
                            .send_stream(peer, stream_id, payload.clone())
                            .expect("send");
                        client
                            .close_stream_write(peer, stream_id)
                            .expect("close write");
                    }
                    EndpointEvent::StreamData {
                        stream_id, data, ..
                    } if pending
                        .get(index)
                        .is_some_and(|streams| streams.contains(&stream_id)) =>
                    {
                        let bytes = received
                            .get_mut(index)
                            .expect("client receive map")
                            .entry(stream_id)
                            .or_default();
                        bytes.extend_from_slice(&data);
                        assert!(
                            bytes.len() <= payload.len(),
                            "crossed echo exceeded payload"
                        );
                        if bytes.len() == payload.len() {
                            assert_eq!(bytes, &payload);
                            pending
                                .get_mut(index)
                                .expect("client pending set")
                                .remove(&stream_id);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

impl Pair {
    fn disconnected(kind: Kind) -> Self {
        let server = EchoServer::start(kind);
        let peer = server.address.peer_id().clone();
        Self {
            _server: server,
            client: bind(kind),
            peer,
        }
    }

    fn connected(kind: Kind) -> Self {
        let mut pair = Self::disconnected(kind);
        pair.connect();
        pair
    }

    fn connect(&mut self) {
        connect_ready(&mut self.client, &self._server.address);
    }

    fn ping(&mut self) {
        self.client.ping(&self.peer).expect("ping");
        let peer = &self.peer;
        wait_for(
            &mut self.client,
            "ping",
            |event| matches!(event, EndpointEvent::PingRttMeasured { peer_id, .. } if peer_id == peer),
        );
    }

    fn echo(&mut self, payload: Vec<u8>, streams: usize) {
        let mut pending = HashMap::new();
        for _ in 0..streams {
            let stream = self
                .client
                .open_stream(&self.peer, ECHO)
                .expect("open stream");
            pending.insert(stream, (0usize, Vec::with_capacity(payload.len())));
        }
        let deadline = Deadline::from(Instant::now() + TIMEOUT);
        while !pending.is_empty() {
            match next_event(&mut self.client, deadline).expect("echo timeout") {
                EndpointEvent::StreamReady {
                    peer_id,
                    stream_id,
                    protocol_id,
                    initiated_locally: true,
                    ..
                } if peer_id == self.peer
                    && protocol_id == ECHO
                    && pending.contains_key(&stream_id) =>
                {
                    let end = payload.len().min(32 * 1024);
                    self.client
                        .send_stream(
                            &self.peer,
                            stream_id,
                            payload.get(..end).expect("first payload chunk").to_vec(),
                        )
                        .expect("send");
                    pending.get_mut(&stream_id).expect("pending stream").0 = end;
                }
                EndpointEvent::StreamData {
                    peer_id,
                    stream_id,
                    data,
                    ..
                } if peer_id == self.peer && pending.contains_key(&stream_id) => {
                    let (sent, response) = pending.get_mut(&stream_id).expect("pending stream");
                    response.extend_from_slice(&data);
                    if response.len() == *sent && *sent < payload.len() {
                        let end = payload.len().min(*sent + 32 * 1024);
                        self.client
                            .send_stream(
                                &self.peer,
                                stream_id,
                                payload
                                    .get(*sent..end)
                                    .expect("next payload chunk")
                                    .to_vec(),
                            )
                            .expect("send");
                        *sent = end;
                    }
                    if response.len() == payload.len() {
                        assert_eq!(*response, payload);
                        self.client
                            .close_stream_write(&self.peer, stream_id)
                            .expect("close write");
                        pending.remove(&stream_id);
                    }
                }
                _ => {}
            }
        }
    }
}

fn suite(c: &mut Criterion, kind: Kind, transport: &str) {
    let mut group = c.benchmark_group(format!("e2e/{transport}"));
    group.bench_function("setup", |b| {
        b.iter_batched_ref(
            || Pair::disconnected(kind),
            Pair::connect,
            BatchSize::SmallInput,
        )
    });
    let mut ping = Pair::connected(kind);
    group.bench_function("ping", |b| b.iter(|| ping.ping()));
    let mut echo = Pair::connected(kind);
    group.bench_function("echo_64b", |b| b.iter(|| echo.echo(vec![0x5a; 64], 1)));
    let mut crossed = Crossed::connected(kind);
    group.bench_function("echo_64b_crossed_4x4", |b| b.iter(|| crossed.echo_4x4()));
    let mut transfer = Pair::connected(kind);
    group.bench_function("transfer_1mib", |b| {
        b.iter(|| transfer.echo(vec![0x5a; 1024 * 1024], 1))
    });
    group.finish();
}

fn endpoint_e2e(c: &mut Criterion) {
    suite(c, Kind::Tcp, "tcp");
    suite(c, Kind::Quic, "quic");
}

criterion_group!(benches, endpoint_e2e);
criterion_main!(benches);
