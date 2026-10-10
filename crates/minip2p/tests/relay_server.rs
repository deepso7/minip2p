//! Real std Endpoint relay-server integration coverage.

#![cfg(all(feature = "relay-server", feature = "nat"))]
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
    mut relay: Endpoint,
    relay_addr: PeerAddr,
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
    let responder_peer = responder.peer_id().clone();

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
            .relay(relay_addr.clone())
            .nat_config(NatConfig {
                force_relay: true,
                reservation_policy: ReservationPolicy::Never,
                ..NatConfig::default()
            }),
    );
    initiator.listen().expect("initiator listens");
    let initiator_peer = initiator.peer_id().clone();
    let connect_id = initiator.connect(&responder_peer).expect("connect starts");

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
    let initiator_peer = pair.initiator_peer.clone();
    let responder_peer = pair.responder_peer.clone();
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

    let (conn, stream) = initiator
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
                    stream_id,
                    initiated_locally: true,
                    ..
                } if peer_id == responder_peer && stream_id == stream => {
                    initiator
                        .send_stream(&responder_peer, conn, stream, payload.clone())
                        .unwrap();
                }
                EndpointEvent::StreamData {
                    peer_id,
                    stream_id,
                    data,
                    ..
                } if peer_id == responder_peer && stream_id == stream => {
                    echoed = Some(data);
                }
                _ => {}
            }
        }
        if let Some(event) = responder.next_event(Duration::from_millis(20)).unwrap() {
            match event {
                EndpointEvent::StreamReady {
                    peer_id,
                    conn_id,
                    stream_id,
                    initiated_locally: false,
                    protocol_id,
                } if peer_id == initiator_peer && protocol_id == ECHO_PROTOCOL => {
                    responder_stream = Some((conn_id, stream_id));
                }
                EndpointEvent::StreamData {
                    peer_id,
                    conn_id,
                    stream_id,
                    data,
                } if peer_id == initiator_peer
                    && Some((conn_id, stream_id)) == responder_stream =>
                {
                    responder
                        .send_stream(&initiator_peer, conn_id, stream_id, data)
                        .unwrap();
                }
                _ => {}
            }
        }
    }
    assert_eq!(echoed.as_deref(), Some(payload.as_slice()));

    let relay_events = pair.finish();
    assert!(relay_events.iter().any(|event| matches!(event, RelayServerEvent::ReservationAccepted { peer_id, .. } if peer_id == &responder_peer)));
    assert!(relay_events.iter().any(|event| matches!(event, RelayServerEvent::CircuitOpened { source_peer_id, destination_peer_id } if source_peer_id == &initiator_peer && destination_peer_id == &responder_peer)));
}

#[cfg(feature = "quic")]
#[test]
fn quic_clients_exchange_payload_through_quic_relay_endpoint() {
    let mut relay = Endpoint::builder()
        .relay_server()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind relay");
    let relay_addr = relay.listen().expect("relay listens");
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

    use minip2p::{Bytes, CircuitCloseReason, Error, RelayServerConfig, StreamId};

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
        stream: StreamId,
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
            .expect("relay config")
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
        let reader_peer = pair.responder_peer.clone();

        let payload = Bytes::from(
            (0..BULK_PER_STREAM)
                .map(|i| (i % 251) as u8)
                .collect::<Vec<u8>>(),
        );
        let mut senders = Vec::new();
        let mut conn_id = None;
        for _ in 0..BULK_STREAMS {
            let (conn, stream) = writer
                .open_stream(&reader_peer, ECHO_PROTOCOL)
                .expect("open bulk stream");
            conn_id = Some(conn);
            senders.push(BulkSender {
                stream,
                offset: 0,
                tail: None,
                writable: false,
                closed: false,
            });
        }
        let conn_id = conn_id.unwrap();

        let mut received: BTreeMap<StreamId, Vec<u8>> = BTreeMap::new();
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
                    Some(data) => {
                        match writer.send_stream(&reader_peer, conn_id, sender.stream, data) {
                            Ok(()) => {}
                            Err(Error::Full { unsent, .. }) => {
                                sender.tail = Some(unsent);
                                sender.writable = false;
                            }
                            other => other.expect("send failed"),
                        }
                    }
                    None if !sender.closed => {
                        writer
                            .close_stream_write(&reader_peer, conn_id, sender.stream)
                            .expect("close write");
                        sender.closed = true;
                    }
                    None => {}
                }
            }
            while let Some(event) = writer.next_event(Duration::from_millis(1)).unwrap() {
                match event {
                    EndpointEvent::StreamReady { stream_id, .. }
                    | EndpointEvent::StreamWritable { stream_id, .. } => {
                        if let Some(sender) = senders.iter_mut().find(|s| s.stream == stream_id) {
                            sender.writable = true;
                        }
                    }
                    EndpointEvent::StreamClosed { .. }
                    | EndpointEvent::ConnectionClosed { .. }
                    | EndpointEvent::Error(_) => panic!("writer saw a teardown: {event:?}"),
                    _ => {}
                }
            }
            if turn % READER_EVERY == 0 {
                while let Some(event) = reader.next_event(Duration::ZERO).unwrap() {
                    match event {
                        EndpointEvent::StreamData {
                            stream_id, data, ..
                        } => received
                            .entry(stream_id)
                            .or_default()
                            .extend_from_slice(&data),
                        EndpointEvent::StreamRemoteWriteClosed { stream_id, .. } => {
                            let bytes = received.get(&stream_id).map_or(0, Vec::len);
                            assert_eq!(bytes, BULK_PER_STREAM, "the FIN follows the last byte");
                            finished += 1;
                        }
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

        // Judged before the clients go: their teardown can race a last forward.
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
