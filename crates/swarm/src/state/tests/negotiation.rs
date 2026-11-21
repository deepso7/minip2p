use super::*;

/// The terminal events (`StreamReady`, `StreamClosed`, or an error naming
/// the stream) for `stream` among `events`.
fn stream_terminals(events: &[SwarmEvent], stream: StreamId) -> usize {
    events
        .iter()
        .filter(|event| match event {
            SwarmEvent::StreamReady { stream_id, .. }
            | SwarmEvent::StreamClosed { stream_id, .. } => *stream_id == stream,
            SwarmEvent::Error(error) => error.stream_id == Some(stream),
            _ => false,
        })
        .count()
}

#[test]
fn a_peer_reset_during_outbound_negotiation_is_one_terminal_event() {
    let (mut core, conn, stream) = negotiating_user_stream(0);
    feed(
        &mut core,
        TransportEvent::StreamClosed {
            id: conn,
            stream_id: stream,
        },
    );
    let events = drain_events(&mut core);
    assert_eq!(stream_terminals(&events, stream), 1, "{events:?}");
    assert!(events.iter().any(|event| matches!(
        event,
        SwarmEvent::Error(SwarmRuntimeError {
            kind: SwarmErrorKind::OpenStreamFailed,
            ..
        })
    )));
}

#[test]
fn timers_armed_near_the_end_of_time_saturate() {
    let start = u64::MAX - 5;
    let (mut core, _, _) = negotiating_user_stream(start);
    let now = Now::from_millis(start);
    assert_eq!(core.next_deadline(now), Some(Deadline::NEVER));

    let peer = PeerId::from_public_key_protobuf(b"late-ping-peer");
    setup_outbound_ping_stream(&mut core, &peer, ConnectionId::new(90), StreamId::new(4));
    core.ping(&peer, [7; PING_PAYLOAD_LEN], start)
        .expect("ping in flight");
    assert_eq!(
        core.pings.get(&peer).map(|attempt| attempt.deadline_ms),
        Some(u64::MAX),
        "a saturated ping deadline must not wrap to the past"
    );
}

#[test]
fn an_unanswered_outbound_negotiation_fails_at_its_deadline() {
    let start = 1_000;
    let (mut core, conn, stream) = negotiating_user_stream(start);
    let due = start + OUTBOUND_NEGOTIATION_TIMEOUT_MS;
    assert_eq!(
        core.next_deadline(Now::from_millis(start)),
        Some(Deadline::from_millis(due))
    );

    core.handle_tick(due - 1);
    assert_eq!(stream_terminals(&drain_events(&mut core), stream), 0);

    core.handle_tick(due);
    let mut events = Vec::new();
    let mut actions = Vec::new();
    while let Some(output) = core.poll_output() {
        match output {
            Output::Action(action) => actions.push(action),
            Output::Event(event) => events.push(event),
        }
    }
    assert_eq!(stream_terminals(&events, stream), 1, "{events:?}");
    assert!(
        actions.contains(&Action::ResetStream {
            conn_id: conn,
            stream_id: stream
        }),
        "the abandoned negotiation's stream is reset: {actions:?}"
    );
    assert_eq!(core.next_deadline(Now::from_millis(due)), None);

    feed(
        &mut core,
        TransportEvent::StreamClosed {
            id: conn,
            stream_id: stream,
        },
    );
    assert_eq!(stream_terminals(&drain_events(&mut core), stream), 0);
}

/// A connection to a known peer with one inbound stream that arrived at
/// `start` and has not negotiated.
fn negotiating_inbound_stream(start: u64) -> (SwarmState, ConnectionId, StreamId) {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"stalled-inbound-peer");
    let conn = ConnectionId::new(91);
    let stream = StreamId::new(3);
    core.conn_to_peer.insert(conn, peer);
    core.peer_to_conn.insert(peer, conn);
    core.handle_transport_event(
        TransportEvent::IncomingStream {
            id: conn,
            stream_id: stream,
        },
        start,
    );
    core.actions.clear();
    (core, conn, stream)
}

#[test]
fn an_unfinished_inbound_negotiation_is_reset_at_its_deadline() {
    let start = 1_000;
    let (mut core, conn, stream) = negotiating_inbound_stream(start);
    let due = start + OUTBOUND_NEGOTIATION_TIMEOUT_MS;
    assert_eq!(
        core.next_deadline(Now::from_millis(start)),
        Some(Deadline::from_millis(due))
    );

    core.handle_tick(due - 1);
    assert!(core.inbound_negotiators.contains_key(&(conn, stream)));
    assert!(core.actions.is_empty());

    core.handle_tick(due);
    assert!(!core.inbound_negotiators.contains_key(&(conn, stream)));
    assert_eq!(
        core.actions.pop_front(),
        Some(Action::ResetStream {
            conn_id: conn,
            stream_id: stream
        })
    );
    assert!(
        drain_events(&mut core).iter().any(|event| matches!(
            event,
            SwarmEvent::Error(SwarmRuntimeError {
                kind: SwarmErrorKind::Multistream,
                stream_id: Some(s),
                ..
            }) if *s == stream
        )),
        "a stalled inbound negotiation is reported like a failed one"
    );
    assert_eq!(core.next_deadline(Now::from_millis(due)), None);
}

#[test]
fn a_finished_inbound_negotiation_clears_its_deadline() {
    const PROTOCOL: &str = "/minip2p/inbound-deadline/1.0.0";
    let mut core = test_core();
    core.add_inbound_protocol(PROTOCOL)
        .expect("service protocol is not reserved");
    let conn = ConnectionId::new(92);
    let stream = StreamId::new(1);
    let peer = PeerId::from_public_key_protobuf(b"finished-inbound-peer");
    core.conn_to_peer.insert(conn, peer);
    core.peer_to_conn.insert(peer, conn);
    feed(
        &mut core,
        TransportEvent::IncomingStream {
            id: conn,
            stream_id: stream,
        },
    );
    assert!(core.next_deadline(Now::from_millis(0)).is_some());

    let mut offer = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    offer.extend_from_slice(&multistream_frame(PROTOCOL));
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn,
            stream_id: stream,
            data: Bytes::from(offer),
        },
    );
    assert_eq!(
        core.stream_protocol(conn, stream),
        Some(&ProtocolKind::User(PROTOCOL.to_string()))
    );
    assert_eq!(core.next_deadline(Now::from_millis(0)), None);
}

#[test]
fn an_inbound_negotiation_deadline_clears_when_its_connection_closes() {
    let (mut core, conn, _) = negotiating_inbound_stream(0);
    assert!(core.next_deadline(Now::from_millis(0)).is_some());
    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn,
            reason: ConnectionCloseReason::Local,
        },
    );
    assert_eq!(core.next_deadline(Now::from_millis(0)), None);
}

#[test]
fn outbound_not_available_error_preserves_stream_id() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"unsupported-peer");
    let conn = ConnectionId::new(48);
    let stream = StreamId::new(13);
    core.conn_to_peer.insert(conn, peer);
    core.peer_to_conn.insert(peer, conn);
    let mut negotiator = MultistreamSelect::dialer("/test/1");
    negotiator.start();
    while negotiator.poll_output().is_some() {}
    core.outbound_negotiators.insert(
        (conn, stream),
        PendingOutbound {
            negotiator,
            target: ProtocolKind::User("/test/1".into()),
            deadline_ms: Some(OUTBOUND_NEGOTIATION_TIMEOUT_MS),
            write_stopped: None,
        },
    );

    core.feed_outbound_negotiator(conn, stream, &multistream_frame(MULTISTREAM_PROTOCOL_ID), 0);
    while core.poll_output().is_some() {}
    core.feed_outbound_negotiator(conn, stream, &multistream_frame("na"), 0);

    assert!(drain_events(&mut core).iter().any(|event| matches!(
        event,
        SwarmEvent::Error(SwarmRuntimeError {
            kind: SwarmErrorKind::UnsupportedProtocol,
            stream_id: Some(id),
            ..
        }) if *id == stream
    )));
}

#[test]
fn add_protocol_rejects_reserved_builtin_ids() {
    let mut core = test_core();
    for reserved in RESERVED_PROTOCOL_IDS {
        let error = core
            .add_protocol(reserved)
            .expect_err("built-in ids must be rejected");
        assert_eq!(
            error,
            SwarmError::ReservedProtocol {
                protocol_id: reserved.into()
            }
        );
    }
    core.add_protocol("/myapp/1.0.0")
        .expect("application ids must be accepted");
    assert!(core.outbound_protocols.iter().any(|p| p == "/myapp/1.0.0"));
}

#[test]
fn outbound_only_protocol_can_open_without_being_accepted_inbound() {
    const OUTBOUND_ONLY: &str = "/minip2p/outbound-only/1.0.0";

    let mut core = test_core();
    core.add_outbound_protocol(OUTBOUND_ONLY)
        .expect("service protocol is not reserved");
    let peer_id = PeerId::from_public_key_protobuf(b"outbound-only-peer");
    let conn_id = ConnectionId::new(70);
    let inbound_stream = StreamId::new(1);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);

    core.open_stream(&peer_id, OUTBOUND_ONLY)
        .expect("outbound membership permits opening");
    assert!(matches!(
        core.actions.pop_front(),
        Some(Action::OpenStream { conn_id: opened, .. }) if opened == conn_id
    ));

    feed(
        &mut core,
        TransportEvent::IncomingStream {
            id: conn_id,
            stream_id: inbound_stream,
        },
    );
    core.actions.clear();
    let mut offer = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    offer.extend_from_slice(&multistream_frame(OUTBOUND_ONLY));
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id: inbound_stream,
            data: Bytes::from(offer),
        },
    );

    assert!(matches!(
        core.actions.pop_front(),
        Some(Action::SendStream { data, .. }) if data == multistream_frame("na")
    ));
    assert!(
        drain_events(&mut core)
            .iter()
            .all(|event| !matches!(event, SwarmEvent::StreamReady { protocol_id, initiated_locally: false, .. } if protocol_id == OUTBOUND_ONLY))
    );
}

#[test]
fn inbound_negotiation_uses_membership_snapshot_from_stream_arrival() {
    const LATE_PROTOCOL: &str = "/minip2p/late-inbound/1.0.0";

    let mut core = test_core();
    let conn_id = ConnectionId::new(75);
    let stream_id = StreamId::new(1);
    let peer_id = PeerId::from_public_key_protobuf(b"inbound-snapshot-peer");
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    feed(
        &mut core,
        TransportEvent::IncomingStream {
            id: conn_id,
            stream_id,
        },
    );
    core.actions.clear();
    core.add_inbound_protocol(LATE_PROTOCOL)
        .expect("service protocol is not reserved");

    let mut offer = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    offer.extend_from_slice(&multistream_frame(LATE_PROTOCOL));
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(offer),
        },
    );

    assert!(matches!(
        core.actions.pop_front(),
        Some(Action::SendStream { data, .. }) if data == multistream_frame("na")
    ));
}

#[test]
fn advertised_only_protocol_appears_only_in_future_identify_responses() {
    const ADVERTISED_ONLY: &str = "/minip2p/advertised-only/1.0.0";

    let mut core = test_core();
    let conn_id = ConnectionId::new(76);
    let stream_id = StreamId::new(2);
    let peer_id = PeerId::from_public_key_protobuf(b"advertised-only-peer");
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    core.add_advertised_protocol(ADVERTISED_ONLY)
        .expect("service protocol is not reserved");

    core.on_inbound_negotiated(conn_id, stream_id, IDENTIFY_PROTOCOL_ID);
    let data = core
        .actions
        .iter()
        .find_map(|action| match action {
            Action::SendStream { data, .. } => Some(data),
            _ => None,
        })
        .expect("Identify responder sends its current snapshot");
    let minip2p_core::FrameDecode::Complete { payload, .. } =
        minip2p_core::decode_frame(data, 8 * 1024)
    else {
        panic!("Identify response must be framed");
    };
    let message = IdentifyMessage::decode(payload).expect("Identify response decodes");

    assert!(
        message
            .protocols
            .iter()
            .any(|protocol| protocol == ADVERTISED_ONLY)
    );
    assert!(matches!(
        core.open_stream(
            &PeerId::from_public_key_protobuf(b"advertised-only-peer"),
            ADVERTISED_ONLY
        ),
        Err(SwarmError::ProtocolNotRegistered { .. })
    ));

    let inbound_stream = StreamId::new(3);
    feed(
        &mut core,
        TransportEvent::IncomingStream {
            id: conn_id,
            stream_id: inbound_stream,
        },
    );
    core.actions.clear();
    let mut offer = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    offer.extend_from_slice(&multistream_frame(ADVERTISED_ONLY));
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id: inbound_stream,
            data: Bytes::from(offer),
        },
    );

    assert!(matches!(
        core.actions.pop_front(),
        Some(Action::SendStream { data, .. }) if data == multistream_frame("na")
    ));
    assert!(drain_events(&mut core).iter().all(|event| {
        !matches!(
            event,
            SwarmEvent::StreamReady {
                peer_id: ready_peer,
                protocol_id,
                initiated_locally: false,
                ..
            } if ready_peer == &peer_id && protocol_id == ADVERTISED_ONLY
        )
    }));
}

#[test]
fn the_core_acks_what_it_consumes_and_leaves_application_bytes_unacked() {
    const PROTOCOL: &str = "/test/1";
    let mut core = test_core();
    core.add_protocol(PROTOCOL).expect("register protocol");
    let peer_id = PeerId::from_public_key_protobuf(b"ack-peer");
    let conn_id = ConnectionId::new(7);
    let stream_id = StreamId::new(3);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    feed(
        &mut core,
        TransportEvent::IncomingStream {
            id: conn_id,
            stream_id,
        },
    );
    drain_actions(&mut core);

    let mut chunk = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    chunk.extend_from_slice(&multistream_frame(PROTOCOL));
    let negotiation = chunk.len();
    chunk.extend_from_slice(b"app bytes");
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(chunk),
        },
    );
    let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
    assert!(outputs.iter().any(|output| matches!(
        output,
        Output::Action(Action::AckStream { bytes, .. }) if *bytes == negotiation
    )));
    assert!(outputs.iter().any(|output| matches!(
        output,
        Output::Event(SwarmEvent::StreamData { data, .. }) if &data[..] == b"app bytes"
    )));

    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from_static(b"more"),
        },
    );
    assert!(
        !drain_actions(&mut core)
            .iter()
            .any(|action| matches!(action, Action::AckStream { .. }))
    );
}

#[test]
fn inbound_streams_are_control_until_they_negotiate_an_application_protocol() {
    const PROTOCOL: &str = "/test/1";
    let mut core = test_core();
    core.add_protocol(PROTOCOL).expect("register protocol");
    let peer_id = PeerId::from_public_key_protobuf(b"control-peer");
    let conn_id = ConnectionId::new(7);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);

    for (stream_id, protocol, marks) in [
        (StreamId::new(3), PROTOCOL, [true, false].as_slice()),
        (StreamId::new(7), PING_PROTOCOL_ID, [true].as_slice()),
        (StreamId::new(11), IDENTIFY_PROTOCOL_ID, [true].as_slice()),
    ] {
        feed(
            &mut core,
            TransportEvent::IncomingStream {
                id: conn_id,
                stream_id,
            },
        );
        let actions = drain_actions(&mut core);
        assert!(matches!(
            actions.first(),
            Some(Action::SetControlStream { control: true, .. })
        ));
        let mut chunk = multistream_frame(MULTISTREAM_PROTOCOL_ID);
        chunk.extend_from_slice(&multistream_frame(protocol));
        feed(
            &mut core,
            TransportEvent::StreamData {
                id: conn_id,
                stream_id,
                data: Bytes::from(chunk),
            },
        );
        let mut all = actions;
        all.extend(drain_actions(&mut core));
        assert_eq!(control_marks(&all, stream_id), marks, "{protocol}");
    }
}

#[test]
fn an_outbound_application_stream_is_control_only_while_it_negotiates() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"outbound-control-peer");
    let (conn_id, stream_id) = (ConnectionId::new(61), StreamId::new(7));
    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(loopback_transport(), peer)),
        },
    );
    drain_actions(&mut core);
    core.add_protocol("/app/1").expect("register");
    core.open_stream(&peer, "/app/1").expect("admit open");
    let opens = drain_actions(&mut core);
    core.opened(opens, conn_id, "/app/1", stream_id);
    let mut actions = drain_actions(&mut core);
    assert!(matches!(
        actions.first(),
        Some(Action::SetControlStream { control: true, .. })
    ));
    assert_eq!(control_marks(&actions, stream_id), [true]);

    let mut answer = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    answer.extend_from_slice(&multistream_frame("/app/1"));
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(answer),
        },
    );
    actions.extend(drain_actions(&mut core));
    assert_eq!(control_marks(&actions, stream_id), [true, false]);
}

#[test]
fn inbound_multistream_accepts_fallback_after_na_on_same_stream() {
    const MESHSUB_V1_2: &str = "/meshsub/1.2.0";
    const MESHSUB_V1_1: &str = "/meshsub/1.1.0";

    let mut core = test_core();
    core.add_protocol(MESHSUB_V1_1)
        .expect("register meshsub 1.1");
    let peer_id = PeerId::from_public_key_protobuf(b"fallback-peer");
    let conn_id = ConnectionId::new(7);
    let stream_id = StreamId::new(3);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);

    feed(
        &mut core,
        TransportEvent::IncomingStream {
            id: conn_id,
            stream_id,
        },
    );
    core.actions.clear();

    let mut first_offer = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    first_offer.extend_from_slice(&multistream_frame(MESHSUB_V1_2));
    let first_offer_len = first_offer.len();
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(first_offer),
        },
    );

    assert!(core.inbound_negotiators.contains_key(&(conn_id, stream_id)));
    assert!(matches!(
        core.actions.pop_front(),
        Some(Action::SendStream {
            conn_id: action_conn,
            stream_id: action_stream,
            data,
        }) if action_conn == conn_id
            && action_stream == stream_id
            && data == multistream_frame("na")
    ));
    assert_eq!(
        core.actions.pop_front(),
        Some(Action::AckStream {
            conn_id,
            stream_id,
            bytes: first_offer_len,
        }),
        "the core consumed the offer"
    );
    assert!(core.actions.is_empty(), "unsupported offer must not reset");

    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(multistream_frame(MESHSUB_V1_1)),
        },
    );

    assert!(!core.inbound_negotiators.contains_key(&(conn_id, stream_id)));
    assert_eq!(
        core.stream_protocol(conn_id, stream_id),
        Some(&ProtocolKind::User(MESHSUB_V1_1.to_string()))
    );
    assert!(matches!(
        core.actions.pop_front(),
        Some(Action::SendStream {
            conn_id: action_conn,
            stream_id: action_stream,
            data,
        }) if action_conn == conn_id
            && action_stream == stream_id
            && data == multistream_frame(MESHSUB_V1_1)
    ));
    assert!(matches!(
        core.actions.pop_front(),
        Some(Action::SetControlStream { control: false, .. })
    ));
    assert!(matches!(
        core.actions.pop_front(),
        Some(Action::AckStream { .. })
    ));
    assert!(core.actions.is_empty());
    assert!(matches!(
        core.events.pop_front(),
        Some(SwarmEvent::StreamReady {
            peer_id: ready_peer,
            conn_id: ready_conn,
            stream_id: ready_stream,
            protocol_id,
            initiated_locally: false,
        }) if ready_peer == peer_id
            && ready_conn == conn_id
            && ready_stream == stream_id
            && protocol_id == MESHSUB_V1_1
    ));
}
