//! Real std Endpoint relay-server integration coverage.

#![cfg(all(feature = "relay-server", feature = "relay", feature = "quic"))]
#![expect(
    clippy::unwrap_used,
    reason = "the relay integration harness uses fixed local operations that must succeed"
)]

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use minip2p::{
    Endpoint, EndpointBuilder, EndpointEvent, NatConfig, NatEvent, Path, PeerAddr, PeerId,
    RelayServerEvent, ReservationPolicy,
};

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
use endpoint_support::NextEvent;

const ECHO_PROTOCOL: &str = "/minip2p/tests/endpoint-relay-echo/1.0.0";
const HOP_PROTOCOL: &str = "/libp2p/circuit/relay/0.2.0/hop";

/// Two clients connected through `relay`, with the relay driven on its own
/// thread until [`RelayedPair::finish`].
struct RelayedPair {
    initiator: Endpoint,
    responder: Endpoint,
    initiator_peer: PeerId,
    responder_peer: PeerId,
    relay_addr: PeerAddr,
    /// The relay's events, as it produces them.
    relay_events: mpsc::Receiver<RelayServerEvent>,
    stop_tx: mpsc::Sender<()>,
    relay_thread: thread::JoinHandle<()>,
}

impl RelayedPair {
    /// Drops both clients, lets the relay see them go, then stops it and
    /// returns the relay events not yet taken from `relay_events`.
    fn finish(self) -> Vec<RelayServerEvent> {
        drop(self.initiator);
        drop(self.responder);
        thread::sleep(Duration::from_millis(50));
        self.stop_tx.send(()).unwrap();
        self.relay_thread.join().expect("relay driver thread");
        self.relay_events.try_iter().collect()
    }
}

/// Reserves on `relay` for a responder, then connects an initiator to it
/// over a relayed circuit and waits for Identify on both ends.
fn relayed_pair(
    relay: Endpoint,
    relay_addr: PeerAddr,
    bind_client: impl Fn(EndpointBuilder) -> Endpoint,
) -> RelayedPair {
    relayed_pair_via(relay, relay_addr.clone(), relay_addr, bind_client)
}

/// [`relayed_pair`], with the initiator reaching the relay at
/// `initiator_relay_addr` (a proxy in front of it, say).
fn relayed_pair_via(
    mut relay: Endpoint,
    relay_addr: PeerAddr,
    initiator_relay_addr: PeerAddr,
    bind_client: impl Fn(EndpointBuilder) -> Endpoint,
) -> RelayedPair {
    let (stop_tx, stop_rx) = mpsc::channel();
    let (events_tx, relay_events) = mpsc::channel();
    let relay_thread = thread::spawn(move || {
        while stop_rx.try_recv().is_err() {
            if let Some(EndpointEvent::RelayServer(event)) = relay
                .next_event(Duration::from_millis(10))
                .expect("drive relay server")
            {
                events_tx.send(event).unwrap();
            }
        }
    });

    let config = NatConfig {
        force_relay: true,
        reservation_policy: ReservationPolicy::Always,
        ..NatConfig::default()
    };
    let mut responder = bind_client(
        Endpoint::builder()
            .protocol(ECHO_PROTOCOL)
            .relay(relay_addr.clone())
            .nat_config(config),
    );
    responder.listen().expect("responder listens");
    let responder_peer = *responder.peer_id();

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "reservation timed out");
        if let Some(EndpointEvent::Nat(NatEvent::RelayReserved { relay, .. })) =
            responder.next_event(Duration::from_millis(20)).unwrap()
            && &relay == relay_addr.peer_id()
        {
            break;
        }
    }

    let mut initiator = bind_client(
        Endpoint::builder()
            .protocol(ECHO_PROTOCOL)
            .relay(initiator_relay_addr)
            .nat_config(NatConfig {
                force_relay: true,
                reservation_policy: ReservationPolicy::Never,
                ..NatConfig::default()
            }),
    );
    initiator.listen().expect("initiator listens");
    let initiator_peer = *initiator.peer_id();
    let connect_id = initiator.connect(responder_peer).expect("connect starts");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut connected = false;
    let mut trace = Vec::new();
    while !connected {
        assert!(
            Instant::now() < deadline,
            "relayed connect timed out: {trace:#?}"
        );
        if let Some(event) = initiator.next_event(Duration::from_millis(20)).unwrap() {
            trace.push(format!("initiator: {event:?}"));
            connected = matches!(
                event,
                EndpointEvent::Nat(NatEvent::PathEstablished { connect_id: found, path: Path::Relayed { .. }, .. })
                    if found == connect_id
            );
        }
        if let Some(event) = responder.next_event(Duration::from_millis(20)).unwrap() {
            trace.push(format!("responder: {event:?}"));
        }
    }
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    while initiator.peer_info(&responder_peer).is_none()
        || responder.peer_info(&initiator_peer).is_none()
    {
        assert!(
            Instant::now() < ready_deadline,
            "circuit identify timed out"
        );
        let _ = initiator.next_event(Duration::from_millis(20)).unwrap();
        let _ = responder.next_event(Duration::from_millis(20)).unwrap();
    }
    RelayedPair {
        initiator,
        responder,
        initiator_peer,
        responder_peer,
        relay_addr,
        relay_events,
        stop_tx,
        relay_thread,
    }
}

fn exercise_relay(
    relay: Endpoint,
    relay_addr: PeerAddr,
    bind_client: impl Fn(EndpointBuilder) -> Endpoint,
) {
    let mut pair = relayed_pair(relay, relay_addr, bind_client);
    let initiator_peer = pair.initiator_peer;
    let responder_peer = pair.responder_peer;
    let relay_addr = pair.relay_addr.clone();
    let initiator = &mut pair.initiator;
    let responder = &mut pair.responder;
    assert!(
        responder
            .peer_info(relay_addr.peer_id())
            .expect("relay identify")
            .protocols
            .iter()
            .any(|protocol| protocol == HOP_PROTOCOL),
        "relay-only server must advertise HOP"
    );
    assert!(
        !initiator
            .peer_info(&responder_peer)
            .expect("responder identify over circuit")
            .protocols
            .iter()
            .any(|protocol| protocol == HOP_PROTOCOL),
        "NAT-only client must not advertise HOP"
    );

    let stream = initiator
        .open_stream(&responder_peer, ECHO_PROTOCOL)
        .expect("open echo stream");
    let payload = b"bidirectional payload through Endpoint relay server".to_vec();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut responder_stream = None;
    let mut echoed = None;
    while echoed.is_none() {
        assert!(Instant::now() < deadline, "relay payload timed out");
        if let Some(event) = initiator.next_event(Duration::from_millis(20)).unwrap() {
            match event {
                EndpointEvent::StreamReady {
                    peer_id,
                    stream: ready,
                    initiated_locally: true,
                    ..
                } if peer_id == responder_peer && ready == stream => {
                    initiator.send_stream(stream, payload.clone()).unwrap();
                }
                EndpointEvent::StreamData {
                    peer_id,
                    stream: from,
                    data,
                } if peer_id == responder_peer && from == stream => {
                    echoed = Some(data);
                }
                _ => {}
            }
        }
        if let Some(event) = responder.next_event(Duration::from_millis(20)).unwrap() {
            match event {
                EndpointEvent::StreamReady {
                    peer_id,
                    stream,
                    initiated_locally: false,
                    protocol_id,
                    ..
                } if peer_id == initiator_peer && protocol_id == ECHO_PROTOCOL => {
                    responder_stream = Some(stream);
                }
                EndpointEvent::StreamData {
                    peer_id,
                    stream,
                    data,
                } if peer_id == initiator_peer && Some(stream) == responder_stream => {
                    responder.send_stream(stream, data).unwrap();
                }
                _ => {}
            }
        }
    }
    assert_eq!(echoed.as_deref(), Some(payload.as_slice()));

    let relay_events = pair.finish();
    assert!(relay_events.iter().any(|event| matches!(event, RelayServerEvent::ReservationAccepted { peer_id, .. } if peer_id == &responder_peer)));
    assert!(relay_events.iter().any(|event| matches!(event, RelayServerEvent::CircuitOpened { source_peer_id, destination_peer_id, via: None } if source_peer_id == &initiator_peer && destination_peer_id == &responder_peer)));
}

/// Built exactly as the README hosts a relay: `bind()` alone, no `listen()`.
/// The relay must accept clients all the same.
#[cfg(feature = "quic")]
#[test]
fn quic_clients_exchange_payload_through_quic_relay_endpoint() {
    let relay = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay");
    let bound = relay.bound_addresses().pop().expect("bound address");
    let relay_addr = PeerAddr::new(bound, *relay.peer_id()).unwrap();
    exercise_relay(relay, relay_addr, |builder| {
        builder
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind client")
    });
}

/// A relay bound only to a wildcard, with nothing announced, has no address
/// to advertise: it grants reservations with an empty address list, and
/// clients build circuit addresses from the address they dialed it at.
#[cfg(feature = "quic")]
#[test]
fn a_wildcard_only_relay_grants_reservations_and_relays_circuits() {
    let relay = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/0.0.0.0/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay");
    let bound = relay.bound_addresses().pop().expect("bound address");
    let port = bound
        .iter()
        .find_map(|protocol| match protocol {
            minip2p::Protocol::Udp(port) => Some(*port),
            _ => None,
        })
        .expect("bound UDP port");
    let dialed = format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
        .parse()
        .unwrap();
    let relay_addr = PeerAddr::new(dialed, *relay.peer_id()).unwrap();
    exercise_relay(relay, relay_addr, |builder| {
        builder
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind client")
    });
}

#[cfg(feature = "tcp")]
#[test]
fn tcp_clients_exchange_payload_through_tcp_relay_endpoint() {
    let mut relay = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind relay");
    let relay_addr = relay.listen().expect("relay listens");
    exercise_relay(relay, relay_addr, |builder| {
        builder
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("bind client")
    });
}

/// A slow reader behind a relayed circuit pauses the relay instead of
/// making it close the circuit (ADR 0012).
///
/// The Endpoint does not expose the relay's sends, so the test relies on
/// sizing: the parallel streams carry more than the relay's destination leg
/// can hold, so its forwards come back Full. Reporting the relay's Full as a
/// failed send (the behaviour before #257) fails this test every time.
#[cfg(feature = "tcp")]
mod bulk {
    use std::collections::BTreeMap;

    use minip2p::{Bytes, CircuitCloseReason, RelayServerConfig, SendOutcome, StreamKey};

    use super::endpoint_support::is_stranger_handshake_failure;
    use super::*;

    /// Inner streams sending at once. Each holds at most one 256 KiB Yamux
    /// window in the circuit, and a relay leg over TCP holds about 512 KiB (its
    /// Yamux window plus its send buffer), so together they fill the leg.
    const BULK_STREAMS: usize = 6;
    /// Bytes sent on each inner stream.
    const BULK_PER_STREAM: usize = 1024 * 1024;
    /// The reader is driven only once per this many writer turns.
    const READER_EVERY: usize = 8;

    /// One inner stream's sender, holding its unsent tail across a Full.
    struct BulkSender {
        stream: StreamKey,
        offset: usize,
        tail: Option<Bytes>,
        writable: bool,
        closed: bool,
    }

    #[test]
    fn a_bulk_transfer_to_a_slow_reader_over_a_relayed_circuit_completes() {
        let mut relay = Endpoint::builder()
            .relay_server_config(RelayServerConfig {
                max_circuit_bytes: 1 << 40,
                ..RelayServerConfig::default()
            })
            .listen_on("/ip4/127.0.0.1/tcp/0")
            .expect("tcp listen address")
            .bind()
            .expect("bind relay");
        let relay_addr = relay.listen().expect("relay listens");
        let mut pair = relayed_pair(relay, relay_addr, |builder| {
            builder
                .listen_on("/ip4/127.0.0.1/tcp/0")
                .expect("tcp listen address")
                .bind()
                .expect("bind client")
        });
        let writer = &mut pair.initiator;
        let reader = &mut pair.responder;
        let reader_peer = pair.responder_peer;

        let payload = Bytes::from(
            (0..BULK_PER_STREAM)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<u8>>(),
        );
        let mut senders = Vec::new();
        for _ in 0..BULK_STREAMS {
            let stream = writer
                .open_stream(&reader_peer, ECHO_PROTOCOL)
                .expect("open bulk stream");
            senders.push(BulkSender {
                stream,
                offset: 0,
                tail: None,
                writable: false,
                closed: false,
            });
        }

        let mut received: BTreeMap<StreamKey, Vec<u8>> = BTreeMap::new();
        let mut finished = 0;
        let deadline = Instant::now() + Duration::from_secs(60);
        for turn in 0.. {
            assert!(
                Instant::now() < deadline,
                "transfer stalled: {:?}",
                received.values().map(Vec::len).collect::<Vec<_>>()
            );
            for sender in senders.iter_mut().filter(|sender| sender.writable) {
                let data = sender.tail.take().or_else(|| {
                    (sender.offset < BULK_PER_STREAM).then(|| {
                        let chunk = payload.slice(sender.offset..);
                        sender.offset = BULK_PER_STREAM;
                        chunk
                    })
                });
                match data {
                    Some(data) => match writer
                        .try_send_stream(sender.stream, data)
                        .expect("send failed")
                    {
                        SendOutcome::Accepted => {}
                        SendOutcome::Full { unsent } => {
                            sender.tail = Some(unsent);
                            sender.writable = false;
                        }
                    },
                    None if !sender.closed => {
                        writer
                            .close_stream_write(sender.stream)
                            .expect("close write");
                        sender.closed = true;
                    }
                    None => {}
                }
            }
            while let Some(event) = writer.next_event(Duration::from_millis(1)).unwrap() {
                match event {
                    EndpointEvent::StreamReady { stream, .. }
                    | EndpointEvent::StreamWritable { stream, .. } => {
                        if let Some(sender) = senders.iter_mut().find(|s| s.stream == stream) {
                            sender.writable = true;
                        }
                    }
                    EndpointEvent::Error(error) if is_stranger_handshake_failure(&error) => {}
                    EndpointEvent::StreamClosed { .. }
                    | EndpointEvent::ConnectionClosed { .. }
                    | EndpointEvent::Error(_) => panic!("writer saw a teardown: {event:?}"),
                    _ => {}
                }
            }
            if turn % READER_EVERY == 0 {
                while let Some(event) = reader.next_event(Duration::ZERO).unwrap() {
                    match event {
                        EndpointEvent::StreamData { stream, data, .. } => {
                            received.entry(stream).or_default().extend_from_slice(&data)
                        }
                        EndpointEvent::StreamRemoteWriteClosed { stream, .. } => {
                            let bytes = received.get(&stream).map_or(0, Vec::len);
                            assert_eq!(bytes, BULK_PER_STREAM, "the FIN follows the last byte");
                            finished += 1;
                        }
                        EndpointEvent::Error(error) if is_stranger_handshake_failure(&error) => {}
                        EndpointEvent::StreamClosed { .. }
                        | EndpointEvent::ConnectionClosed { .. }
                        | EndpointEvent::Error(_) => panic!("reader saw a teardown: {event:?}"),
                        _ => {}
                    }
                }
            }
            if finished == BULK_STREAMS {
                break;
            }
        }
        for data in received.values() {
            assert!(data[..] == payload[..], "every byte, once, in order");
        }

        let relay_events: Vec<_> = pair.relay_events.try_iter().collect();
        let failure = relay_events.iter().find(|event| {
            matches!(
                event,
                RelayServerEvent::Error(_)
                    | RelayServerEvent::CircuitClosed {
                        reason: CircuitCloseReason::ForwardFailed { .. }
                            | CircuitCloseReason::InternalFailure
                            | CircuitCloseReason::ByteLimit { .. }
                            | CircuitCloseReason::DurationLimit,
                        ..
                    }
            )
        });
        assert!(
            failure.is_none(),
            "the relay tore the circuit down: {failure:?}"
        );
        pair.finish();
    }
}

/// Closing an endpoint over a relayed circuit drains the circuit's bridge
/// stream before it closes the relay connection, so a lost final packet is
/// retransmitted instead of dying with the connection (#565).
#[cfg(feature = "quic")]
mod relayed_close {
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use minip2p::{CloseOutcome, Multiaddr, Protocol};

    use super::*;

    fn take_drop_budget(counter: &AtomicUsize) -> bool {
        let mut left = counter.load(Ordering::SeqCst);
        while let Some(next) = left.checked_sub(1) {
            match counter.compare_exchange_weak(left, next, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return true,
                Err(observed) => left = observed,
            }
        }
        false
    }

    /// A UDP proxy in front of a relay that can drop what passes through it.
    struct LossyProxy {
        addr: SocketAddr,
        /// Client-to-relay datagrams still to drop.
        drop_upstream: Arc<AtomicUsize>,
        /// Drops every datagram, both ways.
        blackhole: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        threads: Vec<thread::JoinHandle<()>>,
    }

    impl LossyProxy {
        fn start(relay: SocketAddr) -> Self {
            let front = UdpSocket::bind("127.0.0.1:0").unwrap();
            let back = UdpSocket::bind("127.0.0.1:0").unwrap();
            let tick = Some(Duration::from_millis(5));
            front.set_read_timeout(tick).unwrap();
            back.set_read_timeout(tick).unwrap();
            let addr = front.local_addr().unwrap();
            let drop_upstream = Arc::new(AtomicUsize::new(0));
            let blackhole = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let client = Arc::new(std::sync::Mutex::new(None));
            let upstream = {
                let (front, back) = (front.try_clone().unwrap(), back.try_clone().unwrap());
                let (drop_upstream, blackhole, stop, client) = (
                    Arc::clone(&drop_upstream),
                    Arc::clone(&blackhole),
                    Arc::clone(&stop),
                    Arc::clone(&client),
                );
                thread::spawn(move || {
                    let mut buf = [0u8; 65_536];
                    while !stop.load(Ordering::SeqCst) {
                        let Ok((len, from)) = front.recv_from(&mut buf) else {
                            continue;
                        };
                        *client.lock().unwrap() = Some(from);
                        let dropped =
                            blackhole.load(Ordering::SeqCst) || take_drop_budget(&drop_upstream);
                        if !dropped && let Some(datagram) = buf.get(..len) {
                            drop(back.send_to(datagram, relay));
                        }
                    }
                })
            };
            let downstream = {
                let (blackhole, stop) = (Arc::clone(&blackhole), Arc::clone(&stop));
                thread::spawn(move || {
                    let mut buf = [0u8; 65_536];
                    while !stop.load(Ordering::SeqCst) {
                        let Ok((len, _)) = back.recv_from(&mut buf) else {
                            continue;
                        };
                        let to = *client.lock().unwrap();
                        if let Some(to) = to
                            && !blackhole.load(Ordering::SeqCst)
                            && let Some(datagram) = buf.get(..len)
                        {
                            drop(front.send_to(datagram, to));
                        }
                    }
                })
            };
            Self {
                addr,
                drop_upstream,
                blackhole,
                stop,
                threads: vec![upstream, downstream],
            }
        }

        fn multiaddr(&self) -> Multiaddr {
            format!("/ip4/127.0.0.1/udp/{}/quic-v1", self.addr.port())
                .parse()
                .unwrap()
        }
    }

    impl Drop for LossyProxy {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            for thread in self.threads.drain(..) {
                thread.join().unwrap();
            }
        }
    }

    /// A QUIC relay, an initiator reaching it only through a [`LossyProxy`],
    /// and a responder reaching it directly, connected over a circuit.
    fn proxied_pair() -> (RelayedPair, LossyProxy) {
        let relay = Endpoint::builder()
            .relay_server()
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
            .expect("quic listen address")
            .bind()
            .expect("bind relay");
        let bound = relay.bound_addresses().pop().expect("bound address");
        let port = bound
            .iter()
            .find_map(|protocol| match protocol {
                Protocol::Udp(port) => Some(*port),
                _ => None,
            })
            .expect("bound UDP port");
        let proxy = LossyProxy::start(SocketAddr::from(([127, 0, 0, 1], port)));
        let relay_addr = PeerAddr::new(bound, *relay.peer_id()).unwrap();
        let via_proxy = PeerAddr::new(proxy.multiaddr(), *relay.peer_id()).unwrap();
        let pair = relayed_pair_via(relay, relay_addr, via_proxy, |builder| {
            builder
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
                .expect("quic listen address")
                .bind()
                .expect("bind client")
        });
        (pair, proxy)
    }

    fn stop_relay(stop_tx: mpsc::Sender<()>, relay_thread: thread::JoinHandle<()>) {
        stop_tx.send(()).unwrap();
        relay_thread.join().expect("relay driver thread");
    }

    /// Every client datagram from the payload on, through the circuit's
    /// close, until the retransmissions after it.
    const DROPPED: usize = 8;

    #[test]
    fn a_lost_final_bridge_packet_is_retransmitted_before_close_returns() {
        let (pair, proxy) = proxied_pair();
        let RelayedPair {
            mut initiator,
            mut responder,
            responder_peer,
            stop_tx,
            relay_thread,
            ..
        } = pair;
        let stream = initiator
            .open_stream(&responder_peer, ECHO_PROTOCOL)
            .expect("open stream");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline, "stream never became ready");
            if let Some(EndpointEvent::StreamReady { stream: ready, .. }) =
                initiator.next_event(Duration::from_millis(20)).unwrap()
                && ready == stream
            {
                break;
            }
            let _ = responder.next_event(Duration::ZERO).unwrap();
        }
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        proxy.drop_upstream.store(DROPPED, Ordering::SeqCst);
        initiator.send_stream(stream, payload.clone()).unwrap();
        initiator.close_stream_write(stream).unwrap();
        let closer = thread::spawn(move || initiator.close_within(Duration::from_secs(5)));

        let mut received = Vec::new();
        let mut finished = false;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !finished && Instant::now() < deadline {
            match responder.next_event(Duration::from_millis(20)).unwrap() {
                Some(EndpointEvent::StreamData { data, .. }) => received.extend_from_slice(&data),
                Some(EndpointEvent::StreamRemoteWriteClosed { .. }) => finished = true,
                _ => {}
            }
        }
        let report = closer.join().expect("close thread");
        assert_eq!(received, payload, "the responder gets every byte");
        assert!(finished, "the responder gets the stream FIN");
        assert_eq!(proxy.drop_upstream.load(Ordering::SeqCst), 0);
        assert_eq!(report.outcome, CloseOutcome::Drained, "{report:?}");
        drop(responder);
        stop_relay(stop_tx, relay_thread);
    }

    #[test]
    fn an_unreachable_relay_bounds_the_close_by_its_deadline() {
        let (pair, proxy) = proxied_pair();
        let RelayedPair {
            initiator,
            responder,
            stop_tx,
            relay_thread,
            ..
        } = pair;
        proxy.blackhole.store(true, Ordering::SeqCst);
        let timeout = Duration::from_millis(300);
        let started = Instant::now();
        let report = initiator.close_within(timeout);
        let elapsed = started.elapsed();
        assert!(elapsed < timeout + Duration::from_secs(1), "{elapsed:?}");
        assert_eq!(report.outcome, CloseOutcome::DeadlineExpired, "{report:?}");
        drop(responder);
        stop_relay(stop_tx, relay_thread);
    }
}
