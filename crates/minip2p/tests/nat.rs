//! End-to-end coverage for the `nat` endpoint API over direct QUIC and a real
//! loopback Circuit Relay v2 bridge.

#![cfg(feature = "nat")]

use std::time::{Duration, Instant};

use minip2p::{
    ConnectFailure, ConnectId, ConnectOutcome, ConnectionId, Endpoint, EndpointEvent, NatConfig,
    NatEvent, Path, PeerId, ReservationPolicy,
};

#[path = "../../../tests/support/endpoint.rs"]
mod endpoint_support;
use endpoint_support::NextEvent;

#[path = "../../../tests/support/relay.rs"]
mod relay_support;

const ECHO_PROTOCOL: &str = "/minip2p/tests/nat-echo/1.0.0";

fn nat_endpoint() -> Endpoint {
    Endpoint::builder()
        .nat_config(NatConfig::default())
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint")
}

#[test]
fn direct_candidate_wins_over_loopback() {
    let mut a = nat_endpoint();
    let mut b = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");

    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    let id = a.connect(&b_addr).expect("connect starts");

    // Drive both endpoints; no relay is configured, so the only leg is the
    // direct dial of the provided candidate.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut path = None;
    let mut settled = None;
    while path.is_none() || settled.is_none() {
        assert!(Instant::now() < deadline, "direct connect timed out");
        let event = a.next_event(Duration::from_millis(20)).expect("a drives");
        if let Some(EndpointEvent::ConnectSettled {
            connect_id,
            outcome,
            ..
        }) = &event
            && *connect_id == id
        {
            settled = Some(outcome.clone());
        }
        if let Some(event) = &event {
            observe_path_event(event, id, b_addr.peer_id(), &mut path);
        }
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
    }
    assert!(matches!(path, Some(Path::DirectDialed)));
    assert!(
        matches!(settled, Some(ConnectOutcome::Connected { conn_id }) if !conn_id.is_circuit())
    );
    assert!(a.connected_peers().contains(b_addr.peer_id()));
    assert!(
        matches!(a.path(b_addr.peer_id()), Some(Path::DirectDialed)),
        "the path query must survive PathEstablished event consumption"
    );

    a.cancel_connect(id);
    assert!(
        a.connected_peers().contains(b_addr.peer_id()),
        "cancel after Connected must not disconnect"
    );

    a.disconnect(b_addr.peer_id()).expect("disconnect starts");
    while a.connected_peers().contains(b_addr.peer_id()) {
        assert!(Instant::now() < deadline, "disconnect timed out");
        let _ = a.next_event(Duration::from_millis(20)).expect("a drives");
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
    }
    assert!(
        a.path(b_addr.peer_id()).is_none(),
        "the path query must clear after the final connection closes"
    );
}

#[test]
fn connect_without_candidates_or_relay_fails_fast() {
    let mut a = nat_endpoint();
    a.listen().expect("a listens");

    let stranger = minip2p::Ed25519Keypair::generate().peer_id();
    let id = a.connect(&stranger).expect("connect starts");

    let event = a
        .next_event(Duration::from_secs(1))
        .expect("connect settles without I/O");
    match event {
        Some(EndpointEvent::ConnectSettled {
            connect_id,
            outcome: ConnectOutcome::Failed(failure),
            ..
        }) if connect_id == id => {
            assert!(
                matches!(failure, ConnectFailure::NoUsableRoute { relay: None, .. }),
                "expected NoUsableRoute, got {failure:?}"
            );
            let text = failure.to_string();
            assert!(
                text.contains("no known addresses and no relay configured"),
                "expected both missing sources, got {text}"
            );
        }
        other => panic!("expected NoUsableRoute ConnectSettled, got {other:?}"),
    }
}

#[test]
fn waiting_for_peer_ready_drives_the_nat_agent() {
    let mut a = nat_endpoint();
    let mut b = Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind loopback endpoint");
    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    // The endpoint wait drives only `a`, so keep the remote's socket serviced
    // concurrently.
    let (stop_remote, remote_stop) = std::sync::mpsc::channel();
    let remote = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if remote_stop.try_recv().is_ok() {
                break;
            }
            match b.next_event(Duration::from_millis(10)) {
                Ok(_) | Err(_) => {}
            }
        }
    });

    let id = a.connect(&b_addr).expect("connect starts");
    // Waiting for PeerReady must feed ConnectionEstablished to the NAT agent
    // on the way; its path event arrives on the same stream.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = Vec::new();
    loop {
        assert!(Instant::now() < deadline, "no PeerReady: {events:?}");
        match a.next_event(deadline).expect("a waits") {
            Some(EndpointEvent::PeerReady { peer_id, .. }) if peer_id == *b_addr.peer_id() => break,
            Some(event) => events.push(event),
            None => {}
        }
    }
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                EndpointEvent::Nat(NatEvent::PathEstablished { connect_id, path: Path::DirectDialed, .. })
                    if *connect_id == id
            )
        }),
        "the endpoint must deliver ConnectionEstablished to NAT: {events:?}"
    );
    match stop_remote.send(()) {
        Ok(()) | Err(_) => {}
    }
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
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind responder");
    responder.listen().expect("responder listens");
    let responder_peer = responder.peer_id().clone();

    let reservation_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            Instant::now() < reservation_deadline,
            "responder did not reserve on relay"
        );
        if let Some(EndpointEvent::Nat(NatEvent::RelayReserved { relay, .. })) = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder reservation")
            && &relay == relay_addr.peer_id()
        {
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
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
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
    let mut settled = None;
    let mut trace = Vec::new();
    while path.is_none() || settled.is_none() || !initiator_ready || !responder_ready {
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
            if let EndpointEvent::ConnectSettled {
                connect_id: found,
                outcome,
                ..
            } = &event
                && *found == connect_id
            {
                settled = Some(outcome.clone());
            }
            observe_path_event(&event, connect_id, &responder_peer, &mut path);
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
        relay.assert_healthy();
    }

    assert_eq!(
        path,
        Some(Path::Relayed {
            relay: relay.addr().peer_id().clone()
        })
    );
    match settled {
        Some(ConnectOutcome::Connected { conn_id }) => {
            assert!(conn_id.is_circuit());
            assert_eq!(Some(conn_id), initiator_circuit);
        }
        other => panic!("expected ConnectSettled Connected circuit, got {other:?}"),
    }
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
        if let Some(EndpointEvent::PingRttMeasured { peer_id, rtt_ms }) = initiator
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
                EndpointEvent::StreamReady {
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
                EndpointEvent::StreamData {
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
                EndpointEvent::StreamReady {
                    peer_id,
                    stream_id,
                    initiated_locally: false,
                    protocol_id,
                    ..
                } if peer_id == initiator_peer && protocol_id == ECHO_PROTOCOL => {
                    responder_stream = Some(stream_id);
                }
                EndpointEvent::StreamData {
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
        if let Some(EndpointEvent::ConnectionClosed {
            peer_id, conn_id, ..
        }) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator close")
            && peer_id == responder_peer
            && conn_id == initiator_circuit
        {
            initiator_closed = true;
        }
        if let Some(EndpointEvent::ConnectionClosed {
            peer_id, conn_id, ..
        }) = responder
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

#[cfg(feature = "tcp")]
#[test]
fn a_tcp_relay_carries_a_circuit_and_the_traffic_on_it() {
    // Everything above the transport is the same code: HOP and STOP are
    // ordinary streams on an established connection to the relay, and the
    // circuit rides that connection. A device with no operating system has
    // only TCP, so if relaying were QUIC-shaped anywhere above the dial, it
    // would be out of reach of every one of them.
    let relay = relay_support::RelayServer::spawn_tcp();
    let relay_addr = relay.addr().clone();
    assert!(
        relay_addr.transport().is_tcp_transport(),
        "the relay itself is reached over TCP: {relay_addr}"
    );

    let mut responder = Endpoint::builder()
        .protocol(ECHO_PROTOCOL)
        .relay(relay_addr.clone())
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Always,
            ..NatConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
        .expect("bind responder");
    responder.listen().expect("responder listens");
    let responder_peer = responder.peer_id().clone();

    let reservation_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            Instant::now() < reservation_deadline,
            "responder did not reserve on the TCP relay"
        );
        if let Some(EndpointEvent::Nat(NatEvent::RelayReserved { relay, .. })) = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder reservation")
            && &relay == relay_addr.peer_id()
        {
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
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("tcp listen address")
        .bind()
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
    let mut settled = false;
    while path.is_none() || !settled || !initiator_ready || !responder_ready {
        assert!(
            Instant::now() < deadline,
            "circuit over a TCP relay did not become ready:\nrelay={:#?}",
            relay.trace(),
        );
        if let Some(event) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator")
        {
            if let EndpointEvent::ConnectSettled {
                connect_id: found,
                outcome: ConnectOutcome::Connected { conn_id },
                ..
            } = &event
                && *found == connect_id
            {
                assert!(conn_id.is_circuit());
                settled = true;
            }
            observe_path_event(&event, connect_id, &responder_peer, &mut path);
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
            observe_circuit_event(
                event,
                &initiator_peer,
                &mut responder_circuit,
                &mut responder_ready,
            );
        }
        relay.assert_healthy();
    }

    assert_eq!(
        path,
        Some(Path::Relayed {
            relay: relay.addr().peer_id().clone()
        })
    );
    assert!(
        initiator_circuit
            .expect("initiator circuit id")
            .is_circuit()
    );
    assert!(
        responder_circuit
            .expect("responder circuit id")
            .is_circuit()
    );

    // The responder advertises the reservation as a circuit through a TCP
    // relay, and it crossed the wire in identify -- the address shape that
    // was rejected outright before this stage, on the leg that was the whole
    // reason for rejecting it.
    let advertised: Vec<_> = initiator
        .peer_info(&responder_peer)
        .expect("identify completed over the circuit")
        .listen_addrs
        .iter()
        .filter_map(|bytes| minip2p::Multiaddr::from_bytes(bytes).ok())
        .filter(|addr| addr.is_relay_circuit_transport())
        .collect();
    assert!(
        advertised
            .iter()
            .any(|addr| addr.to_string().contains("/tcp/")),
        "expected a circuit through a TCP relay, got {advertised:?}"
    );

    // Ping over the circuit, because identify and ping are what the default
    // swarm runs on every connection: if the stack above the dial were not
    // shared, this is where it would show.
    initiator
        .ping(&responder_peer)
        .expect("ping over a circuit on a TCP relay");
    let ping_deadline = Instant::now() + Duration::from_secs(5);
    let mut ping_rtt = None;
    while ping_rtt.is_none() {
        assert!(Instant::now() < ping_deadline, "circuit ping timed out");
        if let Some(EndpointEvent::PingRttMeasured { peer_id, .. }) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator ping")
            && peer_id == responder_peer
        {
            ping_rtt = Some(());
        }
        let _ = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder ping");
        relay.assert_healthy();
    }

    // And it carries application traffic, which is the only thing that
    // proves the whole stack negotiated over it rather than merely opened.
    let stream = initiator
        .open_stream(&responder_peer, ECHO_PROTOCOL)
        .expect("open echo stream over circuit");
    let payload = b"echo across a circuit on a TCP relay".to_vec();
    let echo_deadline = Instant::now() + Duration::from_secs(5);
    let mut responder_stream = None;
    let mut echoed = None;
    while echoed.is_none() {
        assert!(Instant::now() < echo_deadline, "circuit echo timed out");
        if let Some(event) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator echo")
        {
            match event {
                EndpointEvent::StreamReady {
                    peer_id,
                    stream_id,
                    initiated_locally: true,
                    ..
                } if peer_id == responder_peer && stream_id == stream => {
                    initiator
                        .send_stream(&responder_peer, stream, payload.clone())
                        .expect("send echo payload");
                }
                EndpointEvent::StreamData {
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
                EndpointEvent::StreamReady {
                    peer_id,
                    stream_id,
                    initiated_locally: false,
                    protocol_id,
                    ..
                } if peer_id == initiator_peer && protocol_id == ECHO_PROTOCOL => {
                    responder_stream = Some(stream_id);
                }
                EndpointEvent::StreamData {
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
    assert_eq!(echoed, Some(payload));

    // A circuit is only as alive as the connection carrying it, and on a TCP
    // relay that connection is a TCP one. Cutting it has to close the circuit
    // on both sides rather than leave either holding a connection to a peer
    // it can no longer reach.
    relay.cut_all();
    let close_deadline = Instant::now() + Duration::from_secs(5);
    let mut initiator_closed = false;
    let mut responder_closed = false;
    while !initiator_closed || !responder_closed {
        assert!(
            Instant::now() < close_deadline,
            "circuit did not close after the TCP relay was cut"
        );
        if let Some(EndpointEvent::ConnectionClosed {
            peer_id, conn_id, ..
        }) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator close")
            && peer_id == responder_peer
            && Some(conn_id) == initiator_circuit
        {
            initiator_closed = true;
        }
        if let Some(EndpointEvent::ConnectionClosed {
            peer_id, conn_id, ..
        }) = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder close")
            && peer_id == initiator_peer
            && Some(conn_id) == responder_circuit
        {
            responder_closed = true;
        }
        relay.assert_healthy();
    }
}

#[test]
fn cancel_mid_relay_leg_emits_cancelled_and_closes_circuits() {
    let relay = relay_support::RelayServer::spawn();
    let relay_addr = relay.addr().clone();

    let mut responder = Endpoint::builder()
        .relay(relay_addr.clone())
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Always,
            ..NatConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind responder");
    responder.listen().expect("responder listens");
    let responder_peer = responder.peer_id().clone();

    let reservation_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            Instant::now() < reservation_deadline,
            "responder did not reserve on relay"
        );
        if let Some(EndpointEvent::Nat(NatEvent::RelayReserved { relay, .. })) = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder reservation")
            && &relay == relay_addr.peer_id()
        {
            break;
        }
        relay.assert_healthy();
    }

    let mut initiator = Endpoint::builder()
        .relay(relay_addr)
        .nat_config(NatConfig {
            force_relay: true,
            reservation_policy: ReservationPolicy::Never,
            ..NatConfig::default()
        })
        .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
        .expect("quic listen address")
        .bind()
        .expect("bind initiator");
    initiator.listen().expect("initiator listens");
    let id = initiator
        .connect(&responder_peer)
        .expect("start relay-only connect");
    initiator.cancel_connect(id);

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut cancelled = false;
    while !cancelled {
        assert!(Instant::now() < deadline, "cancel did not settle");
        if let Some(EndpointEvent::ConnectSettled {
            connect_id,
            outcome: ConnectOutcome::Cancelled,
            ..
        }) = initiator
            .next_event(Duration::from_millis(20))
            .expect("drive initiator cancel")
            && connect_id == id
        {
            cancelled = true;
        }
        let _ = responder
            .next_event(Duration::from_millis(20))
            .expect("drive responder");
        relay.assert_healthy();
    }

    assert!(initiator.swarm().transport().circuit_ids().is_empty());
    assert!(!initiator.connected_peers().contains(&responder_peer));
}

/// Records the first NAT path the Endpoint event stream reports for `id`.
fn observe_path_event(
    event: &EndpointEvent,
    id: ConnectId,
    remote: &PeerId,
    path: &mut Option<Path>,
) {
    if let EndpointEvent::Nat(NatEvent::PathEstablished {
        connect_id,
        peer,
        path: found,
    }) = event
        && *connect_id == id
        && peer == remote
        && path.is_none()
    {
        *path = Some(found.clone());
    }
}

fn observe_circuit_event(
    event: EndpointEvent,
    remote: &PeerId,
    circuit: &mut Option<ConnectionId>,
    ready: &mut bool,
) {
    match event {
        EndpointEvent::ConnectionEstablished { peer_id, conn_id } if peer_id == *remote => {
            *circuit = Some(conn_id);
        }
        EndpointEvent::PeerReady { peer_id, protocols } if peer_id == *remote => {
            assert!(protocols.iter().any(|protocol| protocol == ECHO_PROTOCOL));
            *ready = true;
        }
        _ => {}
    }
}
