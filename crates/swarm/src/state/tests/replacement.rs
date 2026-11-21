use super::*;

#[test]
fn closing_one_connection_keeps_same_stream_id_on_another() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"two-connection-peer");
    let closed = ConnectionId::new(1);
    let surviving = ConnectionId::new(2);
    let stream_id = StreamId::new(4);
    core.conn_to_peer.insert(closed, peer_id);
    core.conn_to_peer.insert(surviving, peer_id);
    core.peer_to_conn.insert(peer_id, surviving);
    for conn_id in [closed, surviving] {
        core.insert_stream_owner(conn_id, stream_id, ProtocolKind::User("/test/1".into()));
    }

    feed(
        &mut core,
        TransportEvent::Closed {
            id: closed,
            reason: ConnectionCloseReason::Local,
        },
    );
    drain_actions(&mut core);
    core.send_stream(&peer_id, surviving, stream_id, Bytes::from_static(b"ok"))
        .expect("stream on the surviving connection should remain");
    assert!(matches!(
        drain_actions(&mut core).as_slice(),
        [Action::SendStream { conn_id, .. }] if *conn_id == surviving
    ));

    feed(
        &mut core,
        TransportEvent::Closed {
            id: surviving,
            reason: ConnectionCloseReason::Local,
        },
    );
    assert!(matches!(
        core.reset_stream(&peer_id, surviving, stream_id),
        Err(SwarmError::StreamNotFound { .. })
    ));
}

#[test]
fn identity_upgrade_moves_streams_to_verified_peer() {
    let mut core = test_core();
    let conn_id = ConnectionId::new(7);
    let stream_id = StreamId::new(4);
    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    let placeholder = core.conn_to_peer[&conn_id];
    core.insert_stream_owner(conn_id, stream_id, ProtocolKind::User("/test/1".into()));

    let verified = PeerId::from_public_key_protobuf(b"verified-peer");
    feed(
        &mut core,
        TransportEvent::PeerIdentityVerified {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                verified,
            )),
            previous_peer_id: None,
        },
    );
    drain_actions(&mut core);

    core.close_stream_write(&verified, conn_id, stream_id)
        .expect("stream should follow the connection to its verified peer");
    assert!(matches!(
        core.close_stream_write(&placeholder, conn_id, stream_id),
        Err(SwarmError::StreamNotFound { .. })
    ));
}

#[test]
fn replacement_discards_undrained_old_actions() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"undrained-replaced-peer");
    let original = ConnectionId::new(12);
    let replacement = ConnectionId::new(13);
    let stream = StreamId::new(8);

    feed(
        &mut core,
        TransportEvent::Connected {
            id: original,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
    );
    core.insert_stream_owner(
        original,
        stream,
        ProtocolKind::User("/minip2p/test/1.0.0".into()),
    );
    core.send_stream(&peer_id, original, stream, Bytes::from_static(b"stale"))
        .expect("old connection stream should initially be active");
    core.reset_stream(&peer_id, original, stream)
        .expect("old connection stream should initially be active");

    feed(
        &mut core,
        TransportEvent::Connected {
            id: replacement,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
    );

    assert!(
        core.actions
            .iter()
            .all(|action| !connection_action_matches(action, original)),
        "no ordinary action for the replaced connection may reach the driver"
    );
    assert!(matches!(
        core.deferred_closes.as_slices(),
        ([conn_id], []) if *conn_id == original
    ));
    assert!(matches!(
        core.send_stream(&peer_id, original, stream, Bytes::from_static(b"lost")),
        Err(SwarmError::StreamNotFound { .. })
    ));
}

/// A peer whose stream 3 lived on `old` and now lives on `new`, after
/// `old` was replaced (or closed, then reconnected as `new`).
fn peer_with_stream_on_two_generations(
    replace: bool,
) -> (SwarmState, PeerId, ConnectionId, ConnectionId, StreamId) {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"two-generation-peer");
    let (old, new, stream) = (
        ConnectionId::new(40),
        ConnectionId::new(41),
        StreamId::new(3),
    );
    let user = || ProtocolKind::User("/test/1".into());
    connect_again(&mut core, &peer_id, old, false);
    core.insert_stream_owner(old, stream, user());
    if !replace {
        feed(
            &mut core,
            TransportEvent::Closed {
                id: old,
                reason: ConnectionCloseReason::Local,
            },
        );
    }
    connect_again(&mut core, &peer_id, new, false);
    core.insert_stream_owner(new, stream, user());
    while core.poll_output().is_some() {}
    (core, peer_id, old, new, stream)
}

/// Runs every user-stream operation against `conn_id`.
fn stream_ops(
    core: &mut SwarmState,
    peer_id: &PeerId,
    conn_id: ConnectionId,
    stream_id: StreamId,
) -> [Result<(), SwarmError>; 4] {
    [
        core.send_stream(peer_id, conn_id, stream_id, Bytes::from_static(b"x")),
        core.close_stream_write(peer_id, conn_id, stream_id),
        core.reset_stream(peer_id, conn_id, stream_id),
        core.abandon_stream(peer_id, conn_id, stream_id),
    ]
}

#[test]
fn stream_ops_for_an_old_connection_never_reach_its_successor() {
    for replace in [true, false] {
        let (mut core, peer_id, old, new, stream) = peer_with_stream_on_two_generations(replace);

        let [send, close, reset, abandon] = stream_ops(&mut core, &peer_id, old, stream);
        for result in [send, close, reset] {
            assert!(
                matches!(
                    result,
                    Err(SwarmError::StreamNotFound { conn_id, .. }) if conn_id == old
                ),
                "replace={replace}"
            );
        }
        abandon.expect("abandoning after the connection ended succeeds");
        assert!(
            matches!(
                drain_actions(&mut core).as_slice(),
                [Action::SettleStream { conn_id, stream_id }]
                    if *conn_id == old && *stream_id == stream
            ),
            "replace={replace}"
        );
        assert!(core.poll_output().is_none(), "replace={replace}");

        for result in stream_ops(&mut core, &peer_id, new, stream) {
            result.expect("the live connection's stream accepts every op");
        }
        let actions = drain_actions(&mut core);
        assert_eq!(
            actions.len(),
            3,
            "send, close, one reset; replace={replace}"
        );
        assert!(
            actions
                .iter()
                .all(|action| connection_action_matches(action, new)),
            "replace={replace}"
        );
    }
}

#[test]
fn abandoning_an_old_connection_stream_keeps_the_successors_events() {
    let (mut core, peer_id, old, new, stream) = peer_with_stream_on_two_generations(true);
    let data = |conn_id| SwarmEvent::StreamData {
        peer_id,
        conn_id,
        stream_id: stream,
        data: Bytes::from(vec![1]),
    };
    core.events.push_back(data(old));
    core.events.push_back(data(new));

    core.abandon_stream(&peer_id, old, stream)
        .expect("abandoning after the connection ended succeeds");
    assert!(matches!(
        drain_events(&mut core).as_slice(),
        [SwarmEvent::StreamData { conn_id, .. }] if *conn_id == new
    ));
}

#[test]
fn abandoning_after_the_close_was_delivered_settles_the_stream_in_the_transport() {
    let (mut core, peer_id, old, new, stream) = peer_with_stream_on_two_generations(false);
    core.abandon_stream(&peer_id, old, stream)
        .expect("no terminal event is needed as proof");
    assert!(matches!(
        drain_actions(&mut core).as_slice(),
        [Action::SettleStream { conn_id, stream_id }]
            if *conn_id == old && *stream_id == stream
    ));
    core.abandon_ended_stream(old, stream)
        .expect("an ended connection");
    assert!(matches!(
        drain_actions(&mut core).as_slice(),
        [Action::SettleStream { conn_id, .. }] if *conn_id == old
    ));
    assert!(matches!(
        core.abandon_stream(&peer_id, new, StreamId::new(99)),
        Err(SwarmError::StreamNotFound { .. })
    ));
    assert!(matches!(
        core.abandon_ended_stream(new, StreamId::new(99)),
        Err(SwarmError::StreamNotFound { .. })
    ));
}

#[test]
fn data_from_a_replaced_connection_is_acknowledged_and_queued_acks_survive() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"acked-replaced-peer");
    let (old, new) = (ConnectionId::new(50), ConnectionId::new(51));
    connect_again(&mut core, &peer_id, old, false);
    drain_actions(&mut core);
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: old,
            stream_id: StreamId::new(7),
            data: Bytes::from_static(b"stray"),
        },
    );
    connect_again(&mut core, &peer_id, new, false);
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: old,
            stream_id: StreamId::new(9),
            data: Bytes::from_static(b"late"),
        },
    );
    let acks: Vec<_> = drain_actions(&mut core)
        .into_iter()
        .filter_map(|action| match action {
            Action::AckStream {
                conn_id,
                stream_id,
                bytes,
            } if conn_id == old => Some((stream_id.as_u64(), bytes)),
            _ => None,
        })
        .collect();
    assert_eq!(acks, [(7, 5), (9, 4)]);
}

#[test]
fn replacement_on_dial_and_listen_side_reports_only_connection_replaced() {
    for inbound in [false, true] {
        let mut core = test_core();
        let peer_id = PeerId::from_public_key_protobuf(b"replaced-peer");
        let original = ConnectionId::new(20);
        let replacement = ConnectionId::new(21);
        connect_again(&mut core, &peer_id, original, false);
        let _ = drain_events(&mut core);

        connect_again(&mut core, &peer_id, replacement, inbound);
        assert!(core.is_peer_connected(&peer_id), "inbound={inbound}");
        assert_eq!(core.connection_id(&peer_id), Some(replacement));
        let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
        assert_eq!(
            lifecycle(&outputs),
            ["replaced 20->21", "close 20"],
            "inbound={inbound}"
        );
        assert!(
            outputs.iter().any(|output| matches!(
                output,
                Output::Action(Action::OpenStream { conn_id, .. }) if *conn_id == replacement
            )),
            "the new connection is re-identified (inbound={inbound})"
        );

        feed(
            &mut core,
            TransportEvent::Closed {
                id: original,
                reason: ConnectionCloseReason::Local,
            },
        );
        assert!(drain_events(&mut core).is_empty(), "inbound={inbound}");
        assert!(core.is_peer_connected(&peer_id));
    }
}

#[test]
fn replacement_chain_reports_each_hand_over_then_closes_in_order() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"chained-peer");
    let (old, new, newer) = (
        ConnectionId::new(1),
        ConnectionId::new(2),
        ConnectionId::new(3),
    );
    for conn_id in [old, new, newer] {
        connect_again(&mut core, &peer_id, conn_id, false);
    }

    let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
    assert_eq!(
        lifecycle(&outputs),
        [
            "established 1",
            "replaced 1->2",
            "replaced 2->3",
            "close 1",
            "close 2"
        ]
    );
    let retired: Vec<_> = outputs
        .iter()
        .filter_map(|output| match output {
            Output::Action(action)
                if connection_action_matches(action, old)
                    || connection_action_matches(action, new) =>
            {
                Some(action)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        retired.len(),
        2,
        "only the closes target retired ids: {retired:?}"
    );
    assert_eq!(core.connection_id(&peer_id), Some(newer));
}

#[test]
fn identity_upgrade_onto_connected_peer_replaces_without_orphan() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"upgrade-replaced-peer");
    let original = ConnectionId::new(30);
    let upgraded = ConnectionId::new(31);
    connect_again(&mut core, &peer_id, original, false);
    let _ = drain_events(&mut core);

    feed(
        &mut core,
        TransportEvent::Connected {
            id: upgraded,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    feed(
        &mut core,
        TransportEvent::PeerIdentityVerified {
            id: upgraded,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
            previous_peer_id: None,
        },
    );
    let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
    assert_eq!(lifecycle(&outputs), ["replaced 30->31", "close 30"]);
    assert_eq!(
        core.established_connections().collect::<Vec<_>>(),
        [(upgraded, &peer_id)],
        "the old connection must not linger as an orphan"
    );

    feed(
        &mut core,
        TransportEvent::PeerIdentityVerified {
            id: original,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
            previous_peer_id: None,
        },
    );
    feed(
        &mut core,
        TransportEvent::IncomingStream {
            id: original,
            stream_id: StreamId::new(3),
        },
    );
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: original,
            stream_id: StreamId::new(3),
            data: Bytes::from(multistream_frame(MULTISTREAM_PROTOCOL_ID)),
        },
    );
    assert!(matches!(
        core::iter::from_fn(|| core.poll_output()).collect::<Vec<_>>().as_slice(),
        [Output::Action(Action::AckStream { conn_id, .. })] if *conn_id == original
    ));
    assert_eq!(core.connection_id(&peer_id), Some(upgraded));
    feed(
        &mut core,
        TransportEvent::Closed {
            id: original,
            reason: ConnectionCloseReason::Local,
        },
    );
    assert!(drain_events(&mut core).is_empty());
    assert!(core.is_peer_connected(&peer_id));
}

#[test]
fn readiness_belongs_to_the_current_connection() {
    let mut core = test_core();
    core.add_protocol("/app/1").expect("register");
    let peer_id = PeerId::from_public_key_protobuf(b"per-connection-ready-peer");
    let original = ConnectionId::new(40);
    let replacement = ConnectionId::new(41);
    connect_again(&mut core, &peer_id, original, false);
    identify_on(&mut core, original, StreamId::new(1), &[]);
    assert_eq!(ready_conns(&drain_events(&mut core)), [original]);

    connect_again(&mut core, &peer_id, replacement, false);
    assert!(core.is_peer_connected(&peer_id));
    assert!(!core.is_peer_ready(&peer_id), "readiness ends with `old`");
    assert!(core.peer_readiness(&peer_id).is_none());
    assert!(core.peer_info(&peer_id).is_none());
    core.open_stream(&peer_id, "/app/1")
        .expect("not ready yet, so no protocol rejection");

    identify_on(&mut core, replacement, StreamId::new(1), &["/app/1"]);
    let events = drain_events(&mut core);
    assert_eq!(ready_conns(&events), [replacement]);
    assert!(
        events.iter().any(|event| matches!(
            event,
            SwarmEvent::IdentifyReceived { conn_id, .. } if *conn_id == replacement
        )),
        "Identify names the connection it arrived on: {events:?}"
    );
    assert_eq!(
        core.peer_readiness(&peer_id).map(|(conn, _)| conn),
        Some(replacement)
    );
}

#[test]
fn replacement_before_first_readiness_identifies_the_new_connection() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"early-replaced-peer");
    let original = ConnectionId::new(50);
    let replacement = ConnectionId::new(51);
    connect_again(&mut core, &peer_id, original, false);
    let _ = drain_actions(&mut core);
    connect_again(&mut core, &peer_id, replacement, false);

    identify_on(&mut core, replacement, StreamId::new(1), &[]);
    let events = drain_events(&mut core);
    assert_eq!(ready_conns(&events), [replacement]);
    assert!(
        !events.iter().any(|event| matches!(
            event,
            SwarmEvent::ConnectionEstablished { .. } | SwarmEvent::ConnectionClosed { .. }
        )),
        "a hand-over is never a disconnect: {events:?}"
    );
}

#[test]
fn peer_ready_queued_before_a_replacement_is_stale() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"stale-ready-peer");
    let original = ConnectionId::new(56);
    let replacement = ConnectionId::new(57);
    connect_again(&mut core, &peer_id, original, false);
    identify_on(&mut core, original, StreamId::new(1), &[]);
    connect_again(&mut core, &peer_id, replacement, false);

    let events = drain_events(&mut core);
    assert_eq!(ready_conns(&events), [original]);
    let ready = events
        .iter()
        .find(|event| matches!(event, SwarmEvent::PeerReady { .. }))
        .expect("PeerReady(original) stays queued");
    assert!(core.is_stale_peer_ready(ready));
    assert!(!core.is_stale_peer_ready(&SwarmEvent::PeerReady {
        peer_id,
        conn_id: replacement,
        protocols: Vec::new(),
    }));
}

#[test]
fn in_flight_ping_is_resent_on_the_new_connection_without_timeout() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"ping-replaced-peer");
    let original = ConnectionId::new(60);
    let replacement = ConnectionId::new(61);
    let payload = [9; PING_PAYLOAD_LEN];
    setup_outbound_ping_stream(&mut core, &peer_id, original, StreamId::new(4));
    core.ping(&peer_id, payload, 0).expect("ping in flight");
    let _ = drain_actions(&mut core);

    core.handle_transport_event(
        TransportEvent::Connected {
            id: replacement,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
        6_000,
    );
    core.first_identify.clear();
    let actions = drain_actions(&mut core);
    assert_eq!(
        core.next_deadline(Now::from_millis(6_000)),
        Some(Deadline::from_millis(16_000)),
        "the deadline restarts at the hand-over"
    );

    core.handle_tick(12_000);
    assert!(
        !drain_events(&mut core)
            .iter()
            .any(|event| matches!(event, SwarmEvent::PingFailed { .. }))
    );

    let stream_id = StreamId::new(8);
    core.opened(actions, replacement, PING_PROTOCOL_ID, stream_id);
    let _ = drain_actions(&mut core);
    let mut accept = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    accept.extend_from_slice(&multistream_frame(PING_PROTOCOL_ID));
    core.handle_transport_event(
        TransportEvent::StreamData {
            id: replacement,
            stream_id,
            data: Bytes::from(accept),
        },
        12_000,
    );
    assert!(drain_actions(&mut core).iter().any(|action| matches!(
        action,
        Action::SendStream { conn_id, data, .. }
            if *conn_id == replacement && data[..] == payload[..]
    )));
    assert_eq!(
        core.next_deadline(Now::from_millis(12_000)),
        Some(Deadline::from_millis(16_000)),
        "the re-send stays inside the restarted attempt"
    );
}

#[test]
fn overdue_ping_times_out_instead_of_being_resent_on_replacement() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"ping-overdue-peer");
    let other = PeerId::from_public_key_protobuf(b"ping-other-peer");
    let replacement = ConnectionId::new(63);
    setup_outbound_ping_stream(&mut core, &peer_id, ConnectionId::new(62), StreamId::new(4));
    setup_outbound_ping_stream(&mut core, &other, ConnectionId::new(64), StreamId::new(4));
    core.ping(&peer_id, [7; PING_PAYLOAD_LEN], 0)
        .expect("ping in flight");
    core.ping(&other, [8; PING_PAYLOAD_LEN], 0)
        .expect("ping in flight");
    let _ = drain_actions(&mut core);

    core.handle_transport_event(
        TransportEvent::Connected {
            id: replacement,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
        12_000,
    );
    let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
    let timed_out: Vec<_> = outputs
        .iter()
        .filter_map(|output| match output {
            Output::Event(SwarmEvent::PingFailed { peer_id, .. }) => Some(peer_id),
            _ => None,
        })
        .collect();
    assert_eq!(
        timed_out,
        [&peer_id],
        "only the replaced peer's due ping times out; the other's reply may follow"
    );
    let opens = outputs
        .iter()
        .filter(|output| {
            matches!(
                output,
                Output::Action(Action::OpenStream { conn_id, .. })
                    if *conn_id == replacement
            )
        })
        .count();
    assert_eq!(
        opens, 1,
        "only Identify opens; a timed-out ping is not re-sent"
    );
    assert!(
        core.next_deadline(Now::from_millis(12_000)).is_some(),
        "the other peer's timer is still armed"
    );
}
