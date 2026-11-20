use super::*;

fn noted_dial_addr(label: &[u8]) -> (PeerId, PeerAddr, ConnectionId) {
    let peer = PeerId::from_public_key_protobuf(label);
    let addr = PeerAddr::new(loopback_transport(), peer).expect("valid peer addr");
    (peer, addr, ConnectionId::new(81))
}

#[test]
fn noted_dial_closed_before_established_emits_dial_failed() {
    let mut core = test_core();
    let (_, addr, conn_id) = noted_dial_addr(b"noted-dial-closed");
    core.note_dial(conn_id, addr.clone());
    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Local,
        },
    );

    assert!(matches!(
        drain_events(&mut core).as_slice(),
        [SwarmEvent::DialFailed {
            conn_id: failed,
            addr: failed_addr,
            reason,
        }] if *failed == conn_id
            && failed_addr == &addr
            && reason == "connection closed before establishment: closed locally"
    ));
}

#[test]
fn noted_dial_uses_close_reason_as_dial_failed_reason() {
    let mut core = test_core();
    let (_, addr, conn_id) = noted_dial_addr(b"noted-dial-error");
    core.note_dial(conn_id, addr.clone());
    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Error("refused".into()),
        },
    );

    let events = drain_events(&mut core);
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, SwarmEvent::Error(_))),
        "pending-dial transport errors stay on DialFailed; got {events:?}"
    );
    assert!(matches!(
        events.last(),
        Some(SwarmEvent::DialFailed {
            conn_id: failed,
            addr: failed_addr,
            reason,
        }) if *failed == conn_id
            && failed_addr == &addr
            && reason == "connection closed before establishment: refused"
    ));
}

#[test]
fn noted_dial_that_establishes_does_not_emit_dial_failed() {
    let mut core = test_core();
    let (peer, addr, conn_id) = noted_dial_addr(b"noted-dial-established");
    core.note_dial(conn_id, addr);
    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(loopback_transport(), peer)),
        },
    );

    let established = drain_events(&mut core);
    assert!(
        established
            .iter()
            .any(|event| matches!(event, SwarmEvent::ConnectionEstablished { .. })),
        "got {established:?}"
    );
    assert!(
        established
            .iter()
            .all(|event| !matches!(event, SwarmEvent::DialFailed { .. })),
        "got {established:?}"
    );

    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Local,
        },
    );
    assert!(matches!(
        drain_events(&mut core).as_slice(),
        [SwarmEvent::ConnectionClosed { conn_id: closed, .. }] if *closed == conn_id
    ));
}

#[test]
fn noted_dial_connected_without_identity_then_closed_emits_dial_failed() {
    let mut core = test_core();
    let (_, addr, conn_id) = noted_dial_addr(b"noted-dial-anonymous");
    core.note_dial(conn_id, addr.clone());
    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Local,
        },
    );
    assert!(matches!(
        drain_events(&mut core).as_slice(),
        [SwarmEvent::DialFailed {
            conn_id: failed,
            addr: failed_addr,
            ..
        }] if *failed == conn_id && failed_addr == &addr
    ));
}

#[test]
fn taken_pending_dial_after_anonymous_connected_then_closed_is_silent() {
    let mut core = test_core();
    let (_, addr, conn_id) = noted_dial_addr(b"forget-after-anon");
    core.note_dial(conn_id, addr);
    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    assert!(core.take_pending_dial(conn_id).is_some());
    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Local,
        },
    );
    let events = drain_events(&mut core);
    assert!(
        events.is_empty(),
        "forgotten pre-identity dial must not emit ConnectionClosed; got {events:?}"
    );
}

#[test]
fn taken_pending_dial_then_closed_is_silent() {
    let mut core = test_core();
    let (_, addr, conn_id) = noted_dial_addr(b"forget-dial-closed");
    core.note_dial(conn_id, addr);
    assert!(core.take_pending_dial(conn_id).is_some());
    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Local,
        },
    );
    assert!(
        drain_events(&mut core).is_empty(),
        "forgotten dials must not emit DialFailed"
    );
}

#[test]
fn a_connection_that_fails_before_establishing_reports_a_transport_error() {
    let mut core = test_core();
    let conn_id = ConnectionId::new(91);
    feed(
        &mut core,
        TransportEvent::IncomingConnection {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::TimedOut,
        },
    );
    assert!(matches!(
        drain_events(&mut core).as_slice(),
        [SwarmEvent::Error(SwarmRuntimeError {
            kind: SwarmErrorKind::Transport,
            peer_id: None,
            conn_id: Some(failed),
            detail,
            ..
        })] if *failed == conn_id && detail.ends_with("timed out")
    ));

    let closed = ConnectionId::new(92);
    feed(
        &mut core,
        TransportEvent::IncomingConnection {
            id: closed,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    feed(
        &mut core,
        TransportEvent::Closed {
            id: closed,
            reason: ConnectionCloseReason::Local,
        },
    );
    assert!(drain_events(&mut core).is_empty());
}

#[test]
fn an_aborted_dial_that_fails_anyway_stays_silent() {
    let mut core = test_core();
    let (_, addr, conn_id) = noted_dial_addr(b"aborted-dial-failed");
    core.note_dial(conn_id, addr);
    assert!(core.take_pending_dial(conn_id).is_some());
    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Error("refused".into()),
        },
    );
    assert!(drain_events(&mut core).is_empty());
}

#[test]
fn veto_survives_connected_then_peer_identity_verified() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"veto-two-stage-peer");
    let existing = ConnectionId::new(41);
    let late = ConnectionId::new(42);
    let late_addr = PeerAddr::new(loopback_transport(), peer).expect("peer addr");

    feed(
        &mut core,
        TransportEvent::Connected {
            id: existing,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(loopback_transport(), peer)),
        },
    );
    let _ = drain_events(&mut core);
    assert_eq!(core.connection_id(&peer), Some(existing));

    core.note_dial(late, late_addr);
    core.veto_establish(late);
    feed(
        &mut core,
        TransportEvent::Connected {
            id: late,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    let after_connected = drain_events(&mut core);
    assert!(
        after_connected.iter().any(|event| {
            matches!(
                event,
                SwarmEvent::DialFailed { conn_id, .. } if *conn_id == late
            )
        }),
        "vetoed Connected should DialFailed; got {after_connected:?}"
    );
    assert!(
        after_connected.iter().all(|event| {
            !matches!(
                event,
                SwarmEvent::ConnectionEstablished { conn_id, .. } if *conn_id == late
            )
        }),
        "vetoed Connected must not establish; got {after_connected:?}"
    );

    feed(
        &mut core,
        TransportEvent::PeerIdentityVerified {
            id: late,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(loopback_transport(), peer)),
            previous_peer_id: None,
        },
    );
    let after_identity = drain_events(&mut core);
    assert!(
        after_identity.iter().all(|event| {
            !matches!(
                event,
                SwarmEvent::ConnectionEstablished { conn_id, .. } if *conn_id == late
            )
        }),
        "veto must still block PeerIdentityVerified; got {after_identity:?}"
    );
    assert_eq!(core.connection_id(&peer), Some(existing));
    assert!(core.connected_peers().contains(&peer));
}

#[test]
fn vetoed_establish_suppresses_transport_error_after_dial_failed() {
    let mut core = test_core();
    let (_, addr, conn_id) = noted_dial_addr(b"veto-error-after-reject");
    core.note_dial(conn_id, addr);
    core.veto_establish(conn_id);
    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    let after_reject = drain_events(&mut core);
    assert!(
        after_reject.iter().any(|event| {
            matches!(
                event,
                SwarmEvent::DialFailed { conn_id: failed, .. } if *failed == conn_id
            )
        }),
        "reject should DialFailed; got {after_reject:?}"
    );

    feed(
        &mut core,
        TransportEvent::Error {
            id: conn_id,
            message: "reset after veto".into(),
        },
    );
    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Local,
        },
    );
    let trailing = drain_events(&mut core);
    assert!(
        trailing
            .iter()
            .all(|event| !matches!(event, SwarmEvent::Error(_))),
        "vetoed dial must not emit Error after DialFailed; got {trailing:?}"
    );
}

#[test]
fn incoming_connection_closed_does_not_emit_dial_failed() {
    let mut core = test_core();
    let conn_id = ConnectionId::new(22);
    feed(
        &mut core,
        TransportEvent::IncomingConnection {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Local,
        },
    );
    assert!(
        drain_events(&mut core)
            .iter()
            .all(|event| !matches!(event, SwarmEvent::DialFailed { .. })),
    );
}

#[test]
fn ping_deadline_runs_from_the_ping_call_not_the_deferred_send() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let conn_id = ConnectionId::new(2);
    let stream_id = StreamId::new(9);

    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    core.ping(&peer_id, [7u8; PING_PAYLOAD_LEN], 1_000)
        .expect("queue ping");

    core.on_outbound_negotiated(conn_id, stream_id, ProtocolKind::Ping, 2_000);
    assert_eq!(
        core.next_deadline(Now::from_millis(4_000)),
        Some(Deadline::from_millis(11_000))
    );
}

#[test]
fn established_connections_lists_each_connected_peers_current_connection() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"multi-connection-peer");
    let circuit = ConnectionId::new(1);
    let direct = ConnectionId::new(2);
    let unverified = ConnectionId::new(3);
    assert_eq!(core.established_connections().count(), 0);

    feed(
        &mut core,
        TransportEvent::Connected {
            id: circuit,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(loopback_transport(), peer)),
        },
    );
    feed(
        &mut core,
        TransportEvent::Connected {
            id: direct,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    feed(
        &mut core,
        TransportEvent::PeerIdentityVerified {
            id: direct,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(loopback_transport(), peer)),
            previous_peer_id: None,
        },
    );
    feed(
        &mut core,
        TransportEvent::Connected {
            id: unverified,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    assert_eq!(
        core.established_connections().collect::<Vec<_>>(),
        vec![(direct, &peer)]
    );
    assert_eq!(core.connection_peer(direct), Some(&peer));
    assert_eq!(core.connection_peer(circuit), None, "replaced");
    assert_eq!(core.connection_peer(unverified), None, "not established");

    feed(
        &mut core,
        TransportEvent::Closed {
            id: direct,
            reason: ConnectionCloseReason::Local,
        },
    );
    assert_eq!(core.established_connections().count(), 0);
    assert_eq!(core.connection_peer(direct), None);
}
