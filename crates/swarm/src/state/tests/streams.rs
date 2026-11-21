use super::*;

#[test]
fn is_idle_reflects_pending_actions_and_events() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let conn_id = ConnectionId::new(1);

    assert!(core.is_idle());

    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
    );
    assert!(!core.is_idle());

    while core.poll_output().is_some() {}
    assert!(core.is_idle());
}

#[test]
fn outbound_ping_registration_without_payload_leaves_protocol_idle() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let conn_id = ConnectionId::new(2);
    let stream_id = StreamId::new(9);

    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);

    core.on_outbound_negotiated(conn_id, stream_id, ProtocolKind::Ping, 0);

    assert!(core.ping.poll_output().is_none());
    assert!(core.poll_output().is_none());
}

#[test]
fn abandon_stream_is_reset_idempotent_and_suppresses_queued_and_future_events() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"abandoned-peer");
    let conn = ConnectionId::new(44);
    let stream = StreamId::new(9);
    core.conn_to_peer.insert(conn, peer);
    core.peer_to_conn.insert(peer, conn);
    core.insert_stream_owner(conn, stream, ProtocolKind::User("/test/1".into()));
    core.events.push_back(SwarmEvent::StreamData {
        peer_id: peer,
        conn_id: conn,
        stream_id: stream,
        data: Bytes::from(vec![1]),
    });

    core.reset_stream(&peer, conn, stream).unwrap();
    core.abandon_stream(&peer, conn, stream).unwrap();
    core.abandon_stream(&peer, conn, stream).unwrap();
    let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
    assert_eq!(
        outputs
            .iter()
            .filter(|output| matches!(output, Output::Action(Action::ResetStream { stream_id, .. }) if *stream_id == stream))
            .count(),
        1
    );
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, Output::Event(_)))
    );

    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn,
            stream_id: stream,
            data: Bytes::from(vec![2]),
        },
    );
    feed(
        &mut core,
        TransportEvent::StreamRemoteWriteClosed {
            id: conn,
            stream_id: stream,
        },
    );
    feed(
        &mut core,
        TransportEvent::StreamClosed {
            id: conn,
            stream_id: stream,
        },
    );
    assert!(drain_events(&mut core).is_empty());
    assert!(!core.abandoned_streams.contains(&(conn, stream)));
}

#[test]
fn abandoning_a_peer_closed_stream_acknowledges_the_data_it_drops() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"closed-abandon-peer");
    let conn = ConnectionId::new(61);
    let stream = StreamId::new(7);
    core.conn_to_peer.insert(conn, peer);
    core.peer_to_conn.insert(peer, conn);
    core.insert_stream_owner(conn, stream, ProtocolKind::User("/test/1".into()));

    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn,
            stream_id: stream,
            data: Bytes::from(vec![1, 2, 3]),
        },
    );
    feed(
        &mut core,
        TransportEvent::StreamClosed {
            id: conn,
            stream_id: stream,
        },
    );

    core.abandon_stream(&peer, conn, stream).unwrap();

    let acked: usize = core::iter::from_fn(|| core.poll_output())
        .filter_map(|output| match output {
            Output::Action(Action::AckStream {
                conn_id,
                stream_id,
                bytes,
            }) if conn_id == conn && stream_id == stream => Some(bytes),
            _ => None,
        })
        .sum();
    assert_eq!(acked, 3);

    assert!(matches!(
        core.abandon_stream(&peer, conn, stream),
        Err(SwarmError::StreamNotFound { .. })
    ));
}

#[test]
fn abandon_stream_reclaims_an_outbound_negotiator_before_ready() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"pending-outbound-peer");
    let conn = ConnectionId::new(47);
    let stream = StreamId::new(12);
    let key = (conn, stream);
    core.conn_to_peer.insert(conn, peer);
    core.peer_to_conn.insert(peer, conn);
    core.outbound_negotiators.insert(
        key,
        PendingOutbound {
            negotiator: MultistreamSelect::dialer("/test/1"),
            target: ProtocolKind::User("/test/1".into()),
            deadline_ms: Some(OUTBOUND_NEGOTIATION_TIMEOUT_MS),
            write_stopped: None,
        },
    );

    core.abandon_stream(&peer, conn, stream).unwrap();

    assert!(!core.outbound_negotiators.contains_key(&key));
    assert!(core.abandoned_streams.contains(&key));
    assert!(matches!(
        core.poll_output(),
        Some(Output::Action(Action::ResetStream {
            conn_id,
            stream_id
        })) if conn_id == conn && stream_id == stream
    ));
}

/// A stream `open_stream` handed out is not ready, not gone, until its
/// negotiation finishes.
#[test]
fn a_negotiating_stream_is_not_ready_until_negotiated() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"not-ready-peer");
    let (conn, stream) = (ConnectionId::new(48), StreamId::new(14));
    core.conn_to_peer.insert(conn, peer);
    core.peer_to_conn.insert(peer, conn);
    core.outbound_negotiators.insert(
        (conn, stream),
        PendingOutbound {
            negotiator: MultistreamSelect::dialer("/test/1"),
            target: ProtocolKind::User("/test/1".into()),
            deadline_ms: Some(OUTBOUND_NEGOTIATION_TIMEOUT_MS),
            write_stopped: None,
        },
    );
    let not_ready = Err(SwarmError::StreamNotReady {
        conn_id: conn,
        stream_id: stream,
    });
    assert_eq!(
        core.admit_user_write(&peer, conn, stream, Bytes::from_static(b"x"))
            .map(drop),
        not_ready
    );
    assert_eq!(core.close_stream_write(&peer, conn, stream), not_ready);
    assert_eq!(core.reset_stream(&peer, conn, stream), not_ready);

    core.outbound_negotiators.remove(&(conn, stream));
    core.insert_stream_owner(conn, stream, ProtocolKind::User("/test/1".into()));
    core.admit_user_write(&peer, conn, stream, Bytes::from_static(b"x"))
        .expect("a negotiated stream takes writes");
}

#[test]
fn failed_reset_can_be_retried_before_and_after_abandonment() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"reset-retry-peer");
    let conn = ConnectionId::new(45);
    let stream = StreamId::new(10);
    core.conn_to_peer.insert(conn, peer);
    core.peer_to_conn.insert(peer, conn);
    core.insert_stream_owner(conn, stream, ProtocolKind::User("/test/1".into()));

    core.reset_stream(&peer, conn, stream).unwrap();
    assert!(matches!(
        core.poll_output(),
        Some(Output::Action(Action::ResetStream { .. }))
    ));
    core.reset_stream_failed(conn, stream);
    core.reset_stream(&peer, conn, stream).unwrap();
    assert!(matches!(
        core.poll_output(),
        Some(Output::Action(Action::ResetStream { .. }))
    ));
    core.reset_stream_failed(conn, stream);
    core.abandon_stream(&peer, conn, stream).unwrap();
    assert!(matches!(
        core.poll_output(),
        Some(Output::Action(Action::ResetStream { .. }))
    ));
    core.reset_stream_failed(conn, stream);
    core.abandon_stream(&peer, conn, stream).unwrap();
    assert!(matches!(
        core.poll_output(),
        Some(Output::Action(Action::ResetStream { .. }))
    ));
}

#[test]
fn abandon_purges_a_terminal_event_after_the_stream_was_forgotten() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"closed-before-abandon-peer");
    let conn = ConnectionId::new(46);
    let stream = StreamId::new(11);
    core.conn_to_peer.insert(conn, peer);
    core.peer_to_conn.insert(peer, conn);
    core.insert_stream_owner(conn, stream, ProtocolKind::User("/test/1".into()));

    feed(
        &mut core,
        TransportEvent::StreamClosed {
            id: conn,
            stream_id: stream,
        },
    );
    core.abandon_stream(&peer, conn, stream).unwrap();
    assert!(core.poll_output().is_none());
}

#[test]
fn transport_error_does_not_surface_synthetic_peer_id() {
    let mut core = test_core();
    let conn_id = ConnectionId::new(7);

    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );
    feed(
        &mut core,
        TransportEvent::Error {
            id: conn_id,
            message: "boom".into(),
        },
    );

    let events = drain_events(&mut core);
    let error = events
        .iter()
        .find_map(|event| match event {
            SwarmEvent::Error(error) => Some(error),
            _ => None,
        })
        .expect("transport error should surface");
    assert_eq!(error.peer_id, None);
    assert_eq!(error.conn_id, Some(conn_id));
}

#[test]
fn transport_error_keeps_established_peer_id() {
    let mut core = test_core();
    let conn_id = ConnectionId::new(8);
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");

    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
    );
    feed(
        &mut core,
        TransportEvent::Error {
            id: conn_id,
            message: "boom".into(),
        },
    );

    let events = drain_events(&mut core);
    let error = events
        .iter()
        .find_map(|event| match event {
            SwarmEvent::Error(error) if error.kind == SwarmErrorKind::Transport => Some(error),
            _ => None,
        })
        .expect("transport error should surface");
    assert_eq!(error.peer_id.as_ref(), Some(&peer_id));
    assert_eq!(error.conn_id, Some(conn_id));
}

#[test]
fn stream_send_uses_connection_that_owns_stream() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let original_conn = ConnectionId::new(1);
    let newer_conn = ConnectionId::new(2);
    let stream_id = StreamId::new(4);

    core.conn_to_peer.insert(original_conn, peer_id);
    core.conn_to_peer.insert(newer_conn, peer_id);
    core.peer_to_conn.insert(peer_id, newer_conn);
    core.insert_stream_owner(
        original_conn,
        stream_id,
        ProtocolKind::User("/minip2p/test/1.0.0".into()),
    );

    core.send_stream(
        &peer_id,
        original_conn,
        stream_id,
        Bytes::from_static(b"ok"),
    )
    .expect("user stream should be active on original connection");
    let actions = drain_actions(&mut core);

    assert!(matches!(
        actions.as_slice(),
        [Action::SendStream { conn_id, stream_id: sid, data }]
            if *conn_id == original_conn && *sid == stream_id && data[..] == b"ok"[..]
    ));
}

#[test]
fn write_stop_surfaces_on_user_streams_and_resets_internal_ones() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"write-stop-peer");
    let conn_id = ConnectionId::new(12);
    let user = StreamId::new(4);
    let ping = StreamId::new(8);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    core.insert_stream_owner(
        conn_id,
        user,
        ProtocolKind::User("/minip2p/test/1.0.0".into()),
    );
    core.insert_stream_owner(conn_id, ping, ProtocolKind::Ping);

    for stream_id in [user, ping] {
        feed(
            &mut core,
            TransportEvent::StreamWriteStopped {
                id: conn_id,
                stream_id,
                error_code: 7,
            },
        );
    }

    let mut actions = Vec::new();
    let mut events = Vec::new();
    while let Some(output) = core.poll_output() {
        match output {
            Output::Action(action) => actions.push(action),
            Output::Event(event) => events.push(event),
        }
    }
    assert!(matches!(
        events.as_slice(),
        [SwarmEvent::StreamWriteStopped { peer_id: stopped_peer, conn_id: stopped_conn, stream_id, error_code: 7 }]
            if *stopped_peer == peer_id && *stopped_conn == conn_id && *stream_id == user
    ));
    assert!(matches!(
        actions.as_slice(),
        [Action::ResetStream { conn_id: reset_conn, stream_id }]
            if *reset_conn == conn_id && *stream_id == ping
    ));
}

/// A multistream-select line: its varint length, then the text.
fn ms_line(text: &str) -> Bytes {
    let mut line = vec![u8::try_from(text.len()).expect("a short line")];
    line.extend_from_slice(text.as_bytes());
    Bytes::from(line)
}

/// go-libp2p's WebTransport `Close` stops our sending as it answers, so
/// a write stop can overtake the reply to a proposal already sent. The
/// proposal leaves with the header, so the stop can even beat the
/// listener's header.
#[test]
fn a_write_stop_after_the_proposal_waits_for_the_reply() {
    let (mut core, conn, stream) = negotiating_user_stream(0);
    let data = |text: &str| TransportEvent::StreamData {
        id: conn,
        stream_id: stream,
        data: ms_line(text),
    };
    feed(
        &mut core,
        TransportEvent::StreamWriteStopped {
            id: conn,
            stream_id: stream,
            error_code: 3,
        },
    );
    let actions = drain_actions(&mut core);
    assert!(
        !actions
            .iter()
            .any(|action| matches!(action, Action::ResetStream { .. })),
        "{actions:?}"
    );

    feed(&mut core, data("/multistream/1.0.0\n"));
    feed(&mut core, data("/app/1\n"));
    let events: Vec<_> = drain_events(&mut core)
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                SwarmEvent::StreamReady { .. } | SwarmEvent::StreamWriteStopped { .. }
            )
        })
        .collect();
    assert!(
        matches!(
            events.as_slice(),
            [
                SwarmEvent::StreamReady { stream_id: ready, .. },
                SwarmEvent::StreamWriteStopped { stream_id: stopped, error_code: 3, .. },
            ] if *ready == stream && *stopped == stream
        ),
        "{events:?}"
    );
}

/// A proposal the transport answered Full is still unsent, so no reply
/// can come: a write stop resets the stream.
#[test]
fn a_write_stop_while_the_proposal_is_held_resets() {
    let (mut core, conn, stream) = negotiating_user_stream(0);
    core.handle_send_full(conn, stream, Bytes::from_static(b"held"), 4);
    feed(
        &mut core,
        TransportEvent::StreamWriteStopped {
            id: conn,
            stream_id: stream,
            error_code: 3,
        },
    );
    let actions = drain_actions(&mut core);
    assert!(
        actions.iter().any(|action| matches!(
            action,
            Action::ResetStream { conn_id, stream_id } if *conn_id == conn && *stream_id == stream
        )),
        "{actions:?}"
    );
}

#[test]
fn a_write_stop_on_an_identify_request_lets_the_reply_arrive() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"identify-stop-peer");
    let conn_id = ConnectionId::new(13);
    let stream_id = StreamId::new(4);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    core.insert_stream_owner(conn_id, stream_id, ProtocolKind::IdentifyInitiator);

    feed(
        &mut core,
        TransportEvent::StreamWriteStopped {
            id: conn_id,
            stream_id,
            error_code: 0,
        },
    );

    assert_eq!(drain_actions(&mut core), Vec::new());
}
