//! End-to-end coverage for the `nat` facade over direct QUIC and a real
//! loopback Circuit Relay v2 bridge.

#![cfg(feature = "nat")]

use std::time::{Duration, Instant};

use minip2p::{
    ConnectionId, Endpoint, Event, NatConfig, NatError, NatEvent, Path, PeerId, ReservationPolicy,
};

#[path = "../../../tests/support/relay.rs"]
mod relay_support;

const ECHO_PROTOCOL: &str = "/minip2p/tests/nat-echo/1.0.0";

fn nat_endpoint() -> Endpoint {
    Endpoint::builder()
        .nat_config(NatConfig::default())
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint")
}

#[test]
fn direct_candidate_wins_over_loopback() {
    let mut a = nat_endpoint();
    let mut b = Endpoint::builder()
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint");

    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    let id = a.connect_addr(&b_addr).expect("connect starts");

    // Drive both endpoints; no relay is configured, so the only leg is the
    // direct dial of the provided candidate.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut path = None;
    while path.is_none() {
        assert!(Instant::now() < deadline, "direct connect timed out");
        let _ = a.next_event(Duration::from_millis(20)).expect("a drives");
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
        for event in a.take_nat_events() {
            if let NatEvent::PathEstablished {
                connect_id,
                path: found,
                ..
            } = event
                && connect_id == id
            {
                path = Some(found);
            }
        }
    }
    assert!(matches!(path, Some(Path::DirectDialed)));
    assert!(a.connected_peers().contains(b_addr.peer_id()));
}

#[test]
fn connect_without_candidates_or_relay_fails_fast() {
    let mut a = nat_endpoint();
    a.listen().expect("a listens");

    let stranger = minip2p::Ed25519Keypair::generate().peer_id();
    let id = a.connect(&stranger).expect("connect starts");

    let path = a
        .wait_path(id, Duration::from_secs(2))
        .expect("wait_path drives");
    assert!(path.is_none(), "no path can exist");
    // The failure detail stays inspectable.
    let events = a.take_nat_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            NatEvent::ConnectFailed { connect_id, error: NatError::NoPathAvailable, .. }
                if *connect_id == id
        )),
        "expected ConnectFailed, got {events:?}"
    );
}

#[test]
fn wait_path_buffers_application_events() {
    let mut a = nat_endpoint();
    let mut b = Endpoint::builder()
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint");
    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    let id = a.connect_addr(&b_addr).expect("connect starts");
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut path = None;
    while path.is_none() {
        assert!(Instant::now() < deadline, "direct connect timed out");
        path = a.wait_path(id, Duration::from_millis(20)).expect("a waits");
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
    }
    assert!(matches!(path, Some(Path::DirectDialed)));

    // The swarm events observed during the wait (ConnectionEstablished,
    // PeerReady, ...) were buffered, not swallowed.
    let mut saw_connection = false;
    while let Some(event) = a.next_event(Duration::from_millis(50)).expect("drain") {
        if matches!(event, minip2p::Event::ConnectionEstablished { .. }) {
            saw_connection = true;
            break;
        }
    }
    assert!(saw_connection, "application events must survive wait_path");
}

#[test]
fn wait_peer_ready_drives_nat_agent() {
    let mut a = nat_endpoint();
    let mut b = Endpoint::builder()
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint");
    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    // The facade wait drives only `a`, so keep the remote's socket serviced
    // concurrently. `wait_peer_ready` must feed ConnectionEstablished to
    // the NAT agent on the way to the matching PeerReady event.
    let (stop_remote, remote_stop) = std::sync::mpsc::channel();
    let remote = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if remote_stop.try_recv().is_ok() {
                break;
            }
            let _ = b.next_event(Duration::from_millis(10));
        }
    });

    let id = a.connect_addr(&b_addr).expect("connect starts");
    let ready = a
        .wait_peer_ready(b_addr.peer_id(), Duration::from_secs(10))
        .expect("wait succeeds");
    assert!(
        matches!(ready, Some(minip2p::Event::PeerReady { peer_id, .. }) if peer_id == *b_addr.peer_id())
    );

    let events = a.take_nat_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                NatEvent::PathEstablished { connect_id, path: Path::DirectDialed, .. }
                    if *connect_id == id
            )
        }),
        "wait_peer_ready must deliver ConnectionEstablished to NAT: {events:?}"
    );
    let _ = stop_remote.send(());
    remote.join().expect("remote driver thread");
}

#[test]
fn relay_promotion_runs_identify_ping_and_protocol_then_closes_on_relay_cut() {
    let relay = relay_support::RelayServer::spawn();
    let relay_addr = relay.addr().clone();

    let mut responder = Endpoint::builder()
        .protocol(ECHO_PROTOCOL)
        .relay(relay_addr.clone())
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Always,
            ..NatConfig::default()
        })
        .bind_quic("127.0.0.1:0")
        .expect("bind responder");
    responder.listen().expect("responder listens");
    let responder_peer = responder.peer_id().clone();

    let reservation_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            Instant::now() < reservation_deadline,
            "responder did not reserve on relay"
        );
        let _ = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder reservation");
        if responder.take_nat_events().iter().any(
            |event| matches!(event, NatEvent::RelayReserved { relay, .. } if relay == relay_addr.peer_id()),
        ) {
            break;
        }
        relay.assert_healthy();
    }

    let mut initiator = Endpoint::builder()
        .protocol(ECHO_PROTOCOL)
        .relay(relay_addr)
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Never,
            ..NatConfig::default()
        })
        .bind_quic("127.0.0.1:0")
        .expect("bind initiator");
    initiator.listen().expect("initiator listens");
    let initiator_peer = initiator.peer_id().clone();
    let connect_id = initiator
        .connect(&responder_peer)
        .expect("start relay-only connect");

    let deadline = Instant::now() + Duration::from_secs(15);
    let mut path = None;
    let mut initiator_circuit = None;
    let mut responder_circuit = None;
    let mut initiator_ready = false;
    let mut responder_ready = false;
    let mut trace = Vec::new();
    while path.is_none() || !initiator_ready || !responder_ready {
        assert!(
            Instant::now() < deadline,
            "circuit did not become ready:\npeers={trace:#?}\nrelay={:#?}\ninitiator circuits={:?}\nresponder circuits={:?}",
            relay.trace(),
            initiator.swarm().transport().circuit_ids(),
            responder.swarm().transport().circuit_ids(),
        );
        if let Some(event) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator")
        {
            trace.push(format!("initiator swarm: {event:?}"));
            observe_circuit_event(
                event,
                &responder_peer,
                &mut initiator_circuit,
                &mut initiator_ready,
            );
        }
        if let Some(event) = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder")
        {
            trace.push(format!("responder swarm: {event:?}"));
            observe_circuit_event(
                event,
                &initiator_peer,
                &mut responder_circuit,
                &mut responder_ready,
            );
        }
        for event in initiator.take_nat_events() {
            trace.push(format!("initiator nat: {event:?}"));
            if let NatEvent::PathEstablished {
                connect_id: found,
                peer,
                path: found_path,
            } = event
                && found == connect_id
                && peer == responder_peer
            {
                path = Some(found_path);
            }
        }
        for event in responder.take_nat_events() {
            trace.push(format!("responder nat: {event:?}"));
        }
        relay.assert_healthy();
    }

    assert_eq!(
        path,
        Some(Path::Relayed {
            relay: relay.addr().peer_id().clone()
        })
    );
    let initiator_circuit = initiator_circuit.expect("initiator circuit id");
    let responder_circuit = responder_circuit.expect("responder circuit id");
    assert_ne!(initiator_circuit.as_u64() & (1 << 63), 0);
    assert_ne!(responder_circuit.as_u64() & (1 << 63), 0);
    assert!(initiator.peer_info(&responder_peer).is_some());
    assert!(responder.peer_info(&initiator_peer).is_some());

    initiator.ping(&responder_peer).expect("ping over circuit");
    let ping_deadline = Instant::now() + Duration::from_secs(5);
    let mut ping_rtt = None;
    while ping_rtt.is_none() {
        assert!(Instant::now() < ping_deadline, "circuit ping timed out");
        if let Some(Event::PingRttMeasured { peer_id, rtt_ms }) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator ping")
            && peer_id == responder_peer
        {
            ping_rtt = Some(rtt_ms);
        }
        let _ = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder ping");
        relay.assert_healthy();
    }

    let stream = initiator
        .open_stream(&responder_peer, ECHO_PROTOCOL)
        .expect("open echo stream over circuit");
    let payload = b"echo across the promoted circuit".to_vec();
    let echo_deadline = Instant::now() + Duration::from_secs(5);
    let mut initiator_stream_ready = false;
    let mut responder_stream = None;
    let mut echoed = None;
    while echoed.is_none() {
        assert!(Instant::now() < echo_deadline, "circuit echo timed out");
        if let Some(event) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator echo")
        {
            match event {
                Event::StreamReady {
                    peer_id,
                    stream_id,
                    initiated_locally: true,
                    ..
                } if peer_id == responder_peer && stream_id == stream => {
                    initiator_stream_ready = true;
                    initiator
                        .send_stream(&responder_peer, stream, payload.clone())
                        .expect("send echo payload");
                }
                Event::StreamData {
                    peer_id,
                    stream_id,
                    data,
                    ..
                } if peer_id == responder_peer && stream_id == stream => echoed = Some(data),
                _ => {}
            }
        }
        if let Some(event) = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder echo")
        {
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
                        .expect("echo payload");
                }
                _ => {}
            }
        }
        relay.assert_healthy();
    }
    assert!(initiator_stream_ready);
    assert_eq!(echoed, Some(payload));

    relay.cut_all();
    let close_deadline = Instant::now() + Duration::from_secs(5);
    let mut initiator_closed = false;
    let mut responder_closed = false;
    while !initiator_closed || !responder_closed {
        assert!(
            Instant::now() < close_deadline,
            "circuit did not close after relay cut"
        );
        if let Some(Event::ConnectionClosed { peer_id, conn_id }) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator close")
            && peer_id == responder_peer
            && conn_id == initiator_circuit
        {
            initiator_closed = true;
        }
        if let Some(Event::ConnectionClosed { peer_id, conn_id }) = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder close")
            && peer_id == initiator_peer
            && conn_id == responder_circuit
        {
            responder_closed = true;
        }
        relay.assert_healthy();
    }
}

fn observe_circuit_event(
    event: Event,
    remote: &PeerId,
    circuit: &mut Option<ConnectionId>,
    ready: &mut bool,
) {
    match event {
        Event::ConnectionEstablished { peer_id, conn_id } if peer_id == *remote => {
            *circuit = Some(conn_id);
        }
        Event::PeerReady { peer_id, protocols } if peer_id == *remote => {
            assert!(protocols.iter().any(|protocol| protocol == ECHO_PROTOCOL));
            *ready = true;
        }
        _ => {}
    }
}
