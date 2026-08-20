//! Real std Endpoint relay-server integration coverage.

#![cfg(all(feature = "relay-server", feature = "nat"))]

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use minip2p::{
    Endpoint, EndpointBuilder, Event, NatConfig, NatEvent, Path, PeerAddr, RelayServerEvent,
    ReservationPolicy,
};

const ECHO_PROTOCOL: &str = "/minip2p/tests/endpoint-relay-echo/1.0.0";
const HOP_PROTOCOL: &str = "/libp2p/circuit/relay/0.2.0/hop";

fn exercise_relay(
    mut relay: Endpoint,
    relay_addr: PeerAddr,
    bind_client: impl Fn(EndpointBuilder) -> Endpoint,
) {
    let (stop_tx, stop_rx) = mpsc::channel();
    let relay_thread = thread::spawn(move || {
        while stop_rx.try_recv().is_err() {
            relay
                .next_event(Duration::from_millis(10))
                .expect("drive relay server");
        }
        relay.take_relay_server_events()
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
        let _ = responder.next_event(Duration::from_millis(20)).unwrap();
        if responder.take_nat_events().iter().any(|event| {
            matches!(event, NatEvent::RelayReserved { relay, .. } if relay == relay_addr.peer_id())
        }) {
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
            trace.push(format!("initiator swarm: {event:?}"));
        }
        if let Some(event) = responder.next_event(Duration::from_millis(20)).unwrap() {
            trace.push(format!("responder swarm: {event:?}"));
        }
        let initiator_events = initiator.take_nat_events();
        trace.extend(
            initiator_events
                .iter()
                .map(|event| format!("initiator nat: {event:?}")),
        );
        connected = initiator_events.iter().any(|event| {
            matches!(event, NatEvent::PathEstablished { connect_id: found, path: Path::Relayed { .. }, .. } if *found == connect_id)
        });
        trace.extend(
            responder
                .take_nat_events()
                .iter()
                .map(|event| format!("responder nat: {event:?}")),
        );
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
                Event::StreamReady {
                    peer_id,
                    stream_id,
                    initiated_locally: true,
                    ..
                } if peer_id == responder_peer && stream_id == stream => {
                    initiator
                        .send_stream(&responder_peer, stream, payload.clone())
                        .unwrap();
                }
                Event::StreamData {
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
                Event::StreamReady {
                    peer_id,
                    stream_id,
                    initiated_locally: false,
                    protocol_id,
                    ..
                } if peer_id == initiator_peer && protocol_id == ECHO_PROTOCOL => {
                    responder_stream = Some(stream_id);
                }
                Event::StreamData {
                    peer_id,
                    stream_id,
                    data,
                    ..
                } if peer_id == initiator_peer && Some(stream_id) == responder_stream => {
                    responder
                        .send_stream(&initiator_peer, stream_id, data)
                        .unwrap();
                }
                _ => {}
            }
        }
    }
    assert_eq!(echoed, Some(payload));

    drop(initiator);
    drop(responder);
    thread::sleep(Duration::from_millis(50));
    stop_tx.send(()).unwrap();
    let relay_events = relay_thread.join().expect("relay driver thread");
    assert!(relay_events.iter().any(|event| matches!(event, RelayServerEvent::ReservationAccepted { peer_id, .. } if peer_id == &responder_peer)));
    assert!(relay_events.iter().any(|event| matches!(event, RelayServerEvent::CircuitOpened { source_peer_id, destination_peer_id } if source_peer_id == &initiator_peer && destination_peer_id == &responder_peer)));
}

#[cfg(feature = "quic")]
#[test]
fn quic_clients_exchange_payload_through_quic_relay_endpoint() {
    let mut relay = Endpoint::builder()
        .relay_server()
        .bind_quic("127.0.0.1:0")
        .expect("bind relay");
    let relay_addr = relay.listen().expect("relay listens");
    exercise_relay(relay, relay_addr, |builder| {
        builder.bind_quic("127.0.0.1:0").expect("bind client")
    });
}

#[cfg(feature = "tcp")]
#[test]
fn tcp_clients_exchange_payload_through_tcp_relay_endpoint() {
    let mut relay = Endpoint::builder()
        .relay_server()
        .bind_tcp("127.0.0.1:0")
        .expect("bind relay");
    let relay_addr = relay.listen().expect("relay listens");
    exercise_relay(relay, relay_addr, |builder| {
        builder.bind_tcp("127.0.0.1:0").expect("bind client")
    });
}
