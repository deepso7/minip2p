use alloc::boxed::Box;
use core::str::FromStr;

use minip2p_identify::IdentifyConfig;
use minip2p_multistream_select::MULTISTREAM_PROTOCOL_ID;
use minip2p_transport::{
    ConnectionCloseReason, ConnectionEndpoint, ConnectionId, StreamId, TransportEvent,
};

use super::*;

fn test_core() -> SwarmState {
    SwarmState::new(
        IdentifyConfig {
            protocol_version: "minip2p-test/0.1.0".into(),
            agent_version: "minip2p-test/0.1.0".into(),
            protocols: Vec::new(),
            public_key: Vec::new(),
        },
        SwarmTimeouts::default(),
    )
}

fn loopback_transport() -> Multiaddr {
    Multiaddr::from_str("/ip4/127.0.0.1/udp/4001/quic-v1").expect("valid multiaddr")
}

fn feed(core: &mut SwarmState, event: TransportEvent) {
    core.handle_transport_event(event, 0);
}

/// One step of the state's queues in delivery order: ordinary actions,
/// then events, then deferred closes.
#[derive(Debug)]
#[expect(clippy::large_enum_variant, reason = "test-only queue view")]
enum Output {
    Action(Action),
    Event(SwarmEvent),
}

impl SwarmState {
    fn poll_output(&mut self) -> Option<Output> {
        if !self.actions.is_empty()
            && let Some(action) = self.next_action()
        {
            return Some(Output::Action(action));
        }
        if let Some(event) = self.next_event() {
            return Some(Output::Event(event));
        }
        self.next_action().map(Output::Action)
    }

    /// What `SwarmCore::open_stream` does before its transport call,
    /// queued instead so tests can observe it.
    fn open_stream(&mut self, peer_id: &PeerId, protocol_id: &str) -> Result<(), SwarmError> {
        let conn_id = self.admit_user_open(peer_id, protocol_id)?;
        self.actions.push_back(Action::OpenStream {
            conn_id,
            protocol: protocol_id.into(),
            target: ProtocolKind::User(protocol_id.into()),
        });
        Ok(())
    }

    /// What `SwarmCore::send_stream` does before its transport call,
    /// queued instead so tests can observe it.
    fn send_stream(
        &mut self,
        peer_id: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
    ) -> Result<(), SwarmError> {
        let data = self.admit_user_write(peer_id, conn_id, stream_id, data)?;
        self.actions.push_back(Action::SendStream {
            conn_id,
            stream_id,
            data,
        });
        Ok(())
    }

    /// Reports `stream_id` opened for the open of `protocol_id` on
    /// `conn_id` in `actions`, as `SwarmCore` does once the transport
    /// answers.
    fn opened(
        &mut self,
        actions: Vec<Action>,
        conn_id: ConnectionId,
        protocol_id: &str,
        stream_id: StreamId,
    ) {
        let target = actions
            .into_iter()
            .find_map(|action| match action {
                Action::OpenStream {
                    conn_id: open_conn,
                    protocol,
                    target,
                } if open_conn == conn_id && protocol == protocol_id => Some(target),
                _ => None,
            })
            .expect("an OpenStream for the protocol on the connection");
        self.start_outbound(conn_id, stream_id, protocol_id, target);
    }
}

fn drain_actions(core: &mut SwarmState) -> Vec<Action> {
    let mut actions = Vec::new();
    while let Some(output) = core.poll_output() {
        match output {
            Output::Action(action) => actions.push(action),
            Output::Event(_) => {}
        }
    }
    actions
}

fn drain_events(core: &mut SwarmState) -> Vec<SwarmEvent> {
    let mut events = Vec::new();
    while let Some(output) = core.poll_output() {
        match output {
            Output::Action(_) => {}
            Output::Event(event) => events.push(event),
        }
    }
    events
}

fn multistream_frame(protocol: &str) -> Vec<u8> {
    let payload_len = protocol.len() + 1;
    assert!(
        payload_len < 128,
        "test helper only encodes one-byte lengths"
    );
    let mut frame = vec![payload_len as u8];
    frame.extend_from_slice(protocol.as_bytes());
    frame.push(b'\n');
    frame
}

#[test]
fn default_timeouts_are_30_s_negotiation_and_identify_and_10_s_ping() {
    assert_eq!(
        SwarmTimeouts::default(),
        SwarmTimeouts {
            negotiation_ms: 30_000,
            identify_ms: 30_000,
            ping_ms: 10_000,
        }
    );
}

#[test]
fn connection_state_updates_before_establishment_event_is_queued() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"state-before-event-peer");
    let conn_id = ConnectionId::new(91);
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

    // State must reflect the transition before any application drain.
    assert!(
        core.connected_peers().contains(&peer_id),
        "connected_peers reflects the peer before the event is drained"
    );
    assert_eq!(core.connection_id(&peer_id), Some(conn_id));
    // The event is still sitting in the output queue — state was updated
    // before queueing, so getters are never behind an already-emitted event.
    assert!(
        !core.events.is_empty(),
        "the matching event remains queued after state was updated"
    );
    assert!(
        core.events.front().is_some_and(|event| {
            matches!(
                event,
                SwarmEvent::ConnectionEstablished {
                    peer_id: established,
                    conn_id: established_conn,
                } if *established == peer_id && *established_conn == conn_id
            )
        }),
        "ConnectionEstablished is the queued transition for this state change"
    );
}

#[test]
fn peer_ready_state_updates_before_event_is_queued() {
    use minip2p_core::encode_frame;
    use minip2p_identify::IDENTIFY_PROTOCOL_ID;

    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"ready-before-event-peer");
    let conn_id = ConnectionId::new(92);
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

    // Connected auto-opens identify. Complete the outbound initiator path.
    let actions = drain_actions(&mut core);
    let stream_id = StreamId::new(1);
    core.opened(actions, conn_id, IDENTIFY_PROTOCOL_ID, stream_id);
    let _ = drain_actions(&mut core);

    let mut accept = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    accept.extend_from_slice(&multistream_frame(IDENTIFY_PROTOCOL_ID));
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(accept),
        },
    );
    let _ = drain_actions(&mut core);

    let info = IdentifyMessage {
        protocol_version: Some("ipfs/0.1.0".into()),
        agent_version: Some("test".into()),
        public_key: None,
        listen_addrs: Vec::new(),
        observed_addr: None,
        protocols: alloc::vec!["/test/1.0.0".into()],
    };
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(encode_frame(&info.encode())),
        },
    );
    feed(
        &mut core,
        TransportEvent::StreamRemoteWriteClosed {
            id: conn_id,
            stream_id,
        },
    );

    assert!(
        core.is_peer_ready(&peer_id),
        "ready state is set before the event is drained"
    );
    assert!(
        drain_events(&mut core).iter().any(|event| {
            matches!(
                event,
                SwarmEvent::PeerReady { peer_id: ready, .. } if *ready == peer_id
            )
        }),
        "PeerReady is queued after ready state was updated"
    );
}

/// A connected peer with a user stream for `/app/1` opened on stream 7,
/// still negotiating, opened at `now_ms`.
fn negotiating_user_stream(now_ms: u64) -> (SwarmState, ConnectionId, StreamId) {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"negotiating-peer");
    let conn = ConnectionId::new(61);
    let stream = StreamId::new(7);
    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(loopback_transport(), peer)),
        },
    );
    drain_actions(&mut core);
    drain_events(&mut core);
    // Only the user stream's timer is under test.
    core.first_identify.clear();
    core.add_protocol("/app/1").expect("register");
    core.open_stream(&peer, "/app/1").expect("admit open");
    let actions = drain_actions(&mut core);
    let target = actions
        .into_iter()
        .find_map(|action| match action {
            Action::OpenStream { target, .. } => Some(target),
            _ => None,
        })
        .expect("an open");
    core.start_outbound(conn, stream, "/app/1", target);
    core.handle_transport_event(
        TransportEvent::StreamOpened {
            id: conn,
            stream_id: stream,
        },
        now_ms,
    );
    drain_actions(&mut core);
    (core, conn, stream)
}

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

    // The reset's own close adds nothing.
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

    // Negotiation and the first application bytes arrive in one chunk.
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

    // Later application bytes are the application's to acknowledge.
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

/// The `control` values of the control-stream marks in `actions` for
/// `stream_id`, in order.
fn control_marks(actions: &[Action], stream_id: StreamId) -> Vec<bool> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::SetControlStream {
                stream_id: marked,
                control,
                ..
            } if *marked == stream_id => Some(*control),
            _ => None,
        })
        .collect()
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
        // Marked before negotiation writes anything on it.
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
    // Marked before the negotiation's first write.
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
    core.actions.clear(); // listener's multistream header

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

#[test]
fn the_core_holds_its_own_full_writes_and_replays_them_in_order_on_writable() {
    const PROTOCOL: &str = "/test/1";
    let mut core = test_core();
    core.add_protocol(PROTOCOL).expect("register protocol");
    let peer_id = PeerId::from_public_key_protobuf(b"slow-reader");
    let conn_id = ConnectionId::new(7);
    let stream_id = StreamId::new(3);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    let send = |data: &[u8]| Action::SendStream {
        conn_id,
        stream_id,
        data: Bytes::copy_from_slice(data),
    };

    // The listener's multistream header comes back Full after 3 bytes.
    feed(
        &mut core,
        TransportEvent::IncomingStream {
            id: conn_id,
            stream_id,
        },
    );
    let header = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    assert_eq!(
        drain_actions(&mut core),
        [
            Action::SetControlStream {
                conn_id,
                stream_id,
                control: true,
            },
            send(&header),
        ]
    );
    core.handle_send_full(
        conn_id,
        stream_id,
        Bytes::copy_from_slice(&header[3..]),
        header.len(),
    );

    // The protocol echo queues behind the held tail instead of going out.
    let mut offer = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    offer.extend_from_slice(&multistream_frame(PROTOCOL));
    let offer_len = offer.len();
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(offer),
        },
    );
    // The stream stays a control stream while the core holds its reply,
    // so the held bytes keep the control reserve.
    assert_eq!(
        drain_actions(&mut core),
        [Action::AckStream {
            conn_id,
            stream_id,
            bytes: offer_len,
        }],
        "only the offer's ack goes out"
    );

    // The application cannot overtake it either, and its close waits.
    let payload = Bytes::from_static(b"app");
    assert_eq!(
        core.send_stream(&peer_id, conn_id, stream_id, payload.clone()),
        Err(SwarmError::Full {
            conn_id,
            stream_id,
            unsent: payload,
        })
    );
    core.close_stream_write(&peer_id, conn_id, stream_id)
        .expect("close is accepted");
    assert!(drain_actions(&mut core).is_empty());
    assert_eq!(
        core.send_stream(&peer_id, conn_id, stream_id, Bytes::from_static(b"late")),
        Err(SwarmError::WriteClosed { conn_id, stream_id }),
        "writes after the close request are rejected"
    );

    feed(
        &mut core,
        TransportEvent::StreamWritable {
            id: conn_id,
            stream_id,
        },
    );
    let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
    let actions: Vec<_> = outputs
        .iter()
        .filter_map(|output| match output {
            Output::Action(action) => Some(action.clone()),
            Output::Event(_) => None,
        })
        .collect();
    assert_eq!(
        actions,
        [
            send(&header[3..]),
            send(&multistream_frame(PROTOCOL)),
            Action::SetControlStream {
                conn_id,
                stream_id,
                control: false,
            },
            Action::CloseStreamWrite { conn_id, stream_id },
        ],
        "the tail, then the queued echo, then the demotion, then the FIN"
    );
    assert!(
        !outputs
            .iter()
            .any(|output| matches!(output, Output::Event(SwarmEvent::StreamWritable { .. }))),
        "no Writable after the write side closed"
    );
}

#[test]
fn forgetting_a_stream_hands_back_the_bytes_the_core_still_owes() {
    const PROTOCOL: &str = "/test/1";
    // Whether the demotion is still queued or already held behind the
    // tail when the stream changes hands.
    for demotion_held in [false, true] {
        let mut core = test_core();
        core.add_protocol(PROTOCOL).expect("register protocol");
        let peer_id = PeerId::from_public_key_protobuf(b"bridge-relay");
        let conn_id = ConnectionId::new(7);
        let stream_id = StreamId::new(3);
        core.conn_to_peer.insert(conn_id, peer_id);
        core.peer_to_conn.insert(peer_id, conn_id);

        // The negotiation header comes back Full, and the echo queues
        // behind it.
        feed(
            &mut core,
            TransportEvent::IncomingStream {
                id: conn_id,
                stream_id,
            },
        );
        let header = multistream_frame(MULTISTREAM_PROTOCOL_ID);
        drain_actions(&mut core);
        core.handle_send_full(
            conn_id,
            stream_id,
            Bytes::copy_from_slice(&header[3..]),
            header.len(),
        );
        let mut offer = multistream_frame(MULTISTREAM_PROTOCOL_ID);
        offer.extend_from_slice(&multistream_frame(PROTOCOL));
        feed(
            &mut core,
            TransportEvent::StreamData {
                id: conn_id,
                stream_id,
                data: Bytes::from(offer),
            },
        );
        if demotion_held {
            drain_actions(&mut core);
        }

        let owed: Vec<u8> = core
            .forget_stream(conn_id, stream_id)
            .into_iter()
            .flatten()
            .collect();
        let mut expected = header[3..].to_vec();
        expected.extend_from_slice(&multistream_frame(PROTOCOL));
        assert_eq!(owed, expected, "the held tail, then the queued echo");
        assert!(!core.held.is_held(conn_id, stream_id));
        // The new owner writes application data, so the stream must not
        // keep the control reserve.
        assert_eq!(
            control_marks(&drain_actions(&mut core), stream_id),
            [false],
            "demotion held: {demotion_held}"
        );
    }
}

#[test]
fn a_writable_waits_while_the_replayed_tail_comes_back_full() {
    const PROTOCOL: &str = "/test/1";
    let mut core = test_core();
    core.add_protocol(PROTOCOL).expect("register protocol");
    let peer_id = PeerId::from_public_key_protobuf(b"slow-reader");
    let conn_id = ConnectionId::new(7);
    let stream_id = StreamId::new(3);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    core.insert_stream_owner(conn_id, stream_id, ProtocolKind::User(PROTOCOL.to_string()));
    let tail = Bytes::from_static(b"tail");
    core.handle_send_full(conn_id, stream_id, tail.clone(), 4);
    let payload = Bytes::from_static(b"app");
    assert!(matches!(
        core.send_stream(&peer_id, conn_id, stream_id, payload),
        Err(SwarmError::Full { .. })
    ));
    let writable = TransportEvent::StreamWritable {
        id: conn_id,
        stream_id,
    };

    // The replay is Full again: the user is not woken yet.
    feed(&mut core, writable.clone());
    assert!(matches!(
        core.poll_output(),
        Some(Output::Action(Action::SendStream { .. }))
    ));
    core.handle_send_full(conn_id, stream_id, tail, 4);
    assert!(core.poll_output().is_none());

    // The next replay goes through, and then the user is woken.
    feed(&mut core, writable);
    let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
    assert!(matches!(
        outputs.as_slice(),
        [
            Output::Action(Action::SendStream { .. }),
            Output::Event(SwarmEvent::StreamWritable { .. }),
        ]
    ));
}

#[test]
fn a_stale_writable_behind_a_queued_close_wakes_no_one() {
    const PROTOCOL: &str = "/test/1";
    let mut core = test_core();
    core.add_protocol(PROTOCOL).expect("register protocol");
    let peer_id = PeerId::from_public_key_protobuf(b"slow-reader");
    let conn_id = ConnectionId::new(7);
    let stream_id = StreamId::new(3);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    core.insert_stream_owner(conn_id, stream_id, ProtocolKind::User(PROTOCOL.to_string()));
    core.handle_send_full(conn_id, stream_id, Bytes::from_static(b"tail"), 4);
    core.close_stream_write(&peer_id, conn_id, stream_id)
        .expect("close is accepted");
    assert!(drain_actions(&mut core).is_empty());

    core.events.push_back(SwarmEvent::StreamWritable {
        peer_id,
        conn_id,
        stream_id,
    });
    assert!(core.poll_output().is_none());
    assert!(
        !core.user_writable_wanted.contains(&(conn_id, stream_id)),
        "a closing stream never waits for a Writable"
    );
}

#[test]
fn closing_or_resetting_a_stream_ends_its_writable_notices() {
    const PROTOCOL: &str = "/test/1";
    let mut core = test_core();
    core.add_protocol(PROTOCOL).expect("register protocol");
    let peer_id = PeerId::from_public_key_protobuf(b"slow-reader");
    let conn_id = ConnectionId::new(7);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    let closed = StreamId::new(3);
    let reset = StreamId::new(5);
    for stream_id in [closed, reset] {
        core.insert_stream_owner(conn_id, stream_id, ProtocolKind::User(PROTOCOL.to_string()));
        // One notice already queued, and one still in the transport.
        feed(
            &mut core,
            TransportEvent::StreamWritable {
                id: conn_id,
                stream_id,
            },
        );
    }

    core.close_stream_write(&peer_id, conn_id, closed)
        .expect("close is accepted");
    core.reset_stream(&peer_id, conn_id, reset)
        .expect("reset is accepted");
    for stream_id in [closed, reset] {
        feed(
            &mut core,
            TransportEvent::StreamWritable {
                id: conn_id,
                stream_id,
            },
        );
    }

    assert!(
        drain_events(&mut core).is_empty(),
        "no Writable reaches a stream the app closed or reset"
    );
}

#[test]
fn a_peer_that_never_reads_cannot_grow_the_core_hold_past_its_bound() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"flooder");
    let conn_id = ConnectionId::new(7);
    let stream_id = StreamId::new(3);
    core.conn_to_peer.insert(conn_id, peer_id);
    core.peer_to_conn.insert(peer_id, conn_id);
    core.handle_send_full(conn_id, stream_id, Bytes::from_static(b"x"), 1);
    for _ in 0..=MAX_HELD_PER_STREAM / 32 {
        core.actions.push_back(Action::SendStream {
            conn_id,
            stream_id,
            data: Bytes::from(vec![0; 32]),
        });
    }
    assert_eq!(
        drain_actions(&mut core),
        [Action::ResetStream { conn_id, stream_id }],
        "past the bound the stream is reset and the hold dropped"
    );
    assert!(!core.held.is_held(conn_id, stream_id));
}

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

    // The peer sends, then closes. Both events queue undelivered, and the
    // data counts against the stream's receive budget until acknowledged.
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

    // The consumer gives up before pulling either event.
    core.abandon_stream(&peer, conn, stream).unwrap();

    // Those bytes are gone, so nobody will ever acknowledge them: the
    // state owes the acknowledgement itself, or the muxer holds the
    // stream's slot against `max_streams` for good.
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

    // The queued terminal was this stream's only remaining trace, so a
    // second call cannot tell it from a stream that never existed. The
    // documented success is scoped to the first call for that reason.
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

    // Negotiated: the same stream takes writes.
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
    // Abandoning a stream the transport already closed succeeds: the
    // consumer's intent is met, and there is nothing left to reset.
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

    // Replace before draining the original connection's automatic
    // Identify open or the application-requested stream actions.
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

/// Feeds a second connection to an already connected peer, as the
/// dialer (`Connected`) or the listener (`IncomingConnection` first).
fn connect_again(core: &mut SwarmState, peer_id: &PeerId, conn_id: ConnectionId, inbound: bool) {
    if inbound {
        feed(
            core,
            TransportEvent::IncomingConnection {
                id: conn_id,
                endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
            },
        );
    }
    feed(
        core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                *peer_id,
            )),
        },
    );
}

/// The lifecycle events and the `old` close action among `outputs`, in order.
fn lifecycle(outputs: &[Output]) -> Vec<String> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::Event(SwarmEvent::ConnectionEstablished { conn_id, .. }) => {
                Some(format!("established {conn_id}"))
            }
            Output::Event(SwarmEvent::ConnectionClosed { conn_id, .. }) => {
                Some(format!("closed {conn_id}"))
            }
            Output::Event(SwarmEvent::ConnectionReplaced { old, new, .. }) => {
                Some(format!("replaced {old}->{new}"))
            }
            Output::Action(Action::CloseConnection { conn_id }) => Some(format!("close {conn_id}")),
            _ => None,
        })
        .collect()
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
        // Abandoning settles the old stream in the transport, never the
        // successor's.
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
    // ADR 0012 (#356): abandonment goes top-down. With the connection's
    // terminal event long delivered, the swarm drops what it still holds
    // and the transport settles the stream outright.
    let (mut core, peer_id, old, new, stream) = peer_with_stream_on_two_generations(false);
    core.abandon_stream(&peer_id, old, stream)
        .expect("no terminal event is needed as proof");
    assert!(matches!(
        drain_actions(&mut core).as_slice(),
        [Action::SettleStream { conn_id, stream_id }]
            if *conn_id == old && *stream_id == stream
    ));
    // A caller that no longer knows the peer gets the same.
    core.abandon_ended_stream(old, stream)
        .expect("an ended connection");
    assert!(matches!(
        drain_actions(&mut core).as_slice(),
        [Action::SettleStream { conn_id, .. }] if *conn_id == old
    ));
    // A connection the swarm still routes keeps the strict rules.
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
    // Bytes for a stream nobody owns are the state's to acknowledge.
    feed(
        &mut core,
        TransportEvent::StreamData {
            id: old,
            stream_id: StreamId::new(7),
            data: Bytes::from_static(b"stray"),
        },
    );
    connect_again(&mut core, &peer_id, new, false);
    // The replaced connection's late data is dropped, and acknowledged.
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

        // The transport's close of the retired connection is silent.
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

    // Late events on the retired id never re-register it, and its close
    // is not reported a second time.
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
    // Only the acknowledgement of the data it drops.
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

/// Completes the Identify exchange the core opened on `conn_id`,
/// advertising `protocols`.
fn identify_on(
    core: &mut SwarmState,
    conn_id: ConnectionId,
    stream_id: StreamId,
    protocols: &[&str],
) {
    use minip2p_core::encode_frame;

    let actions = drain_actions(core);
    core.opened(actions, conn_id, IDENTIFY_PROTOCOL_ID, stream_id);
    let mut accept = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    accept.extend_from_slice(&multistream_frame(IDENTIFY_PROTOCOL_ID));
    feed(
        core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(accept),
        },
    );
    let info = IdentifyMessage {
        protocol_version: Some("ipfs/0.1.0".into()),
        agent_version: Some("test".into()),
        public_key: None,
        listen_addrs: Vec::new(),
        observed_addr: None,
        protocols: protocols.iter().map(|p| (*p).into()).collect(),
    };
    feed(
        core,
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(encode_frame(&info.encode())),
        },
    );
    feed(
        core,
        TransportEvent::StreamRemoteWriteClosed {
            id: conn_id,
            stream_id,
        },
    );
}

fn ready_conns(events: &[SwarmEvent]) -> Vec<ConnectionId> {
    events
        .iter()
        .filter_map(|event| match event {
            SwarmEvent::PeerReady { conn_id, .. } => Some(*conn_id),
            _ => None,
        })
        .collect()
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
    // Stale Identify data from `old` must not reject the open.
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

    // Both events are still delivered; only the first is stale by the
    // time a host sees the batch.
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
    let mut core = test_core(); // default ping_ms = 10_000
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

    // Past the original deadline: no failure for the hand-over.
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
    let mut core = test_core(); // default request_timeout_ms = 10_000
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

    // The replacement arrives in the same poll as the overdue tick, ahead
    // of it.
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

#[test]
fn transport_loss_reports_connection_closed_with_its_reason() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"transport-closed-peer");
    let conn_id = ConnectionId::new(71);
    connect_again(&mut core, &peer_id, conn_id, false);
    let _ = drain_events(&mut core);

    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Error("boom".into()),
        },
    );

    // The failure is the close's reason, with no separate error event.
    assert!(matches!(
        drain_events(&mut core).as_slice(),
        [SwarmEvent::ConnectionClosed { conn_id: closed, reason, .. }]
            if *closed == conn_id && *reason == ConnectionCloseReason::Error("boom".into())
    ));
}

#[test]
fn connection_remote_addr_is_scoped_to_exact_connection() {
    let mut core = test_core();
    let first = ConnectionId::new(72);
    let second = ConnectionId::new(73);
    let first_addr = Multiaddr::from_str("/ip4/192.0.2.1/tcp/4001").unwrap();
    let second_addr = Multiaddr::from_str("/ip4/192.0.2.2/tcp/4002").unwrap();
    feed(
        &mut core,
        TransportEvent::IncomingConnection {
            id: first,
            endpoint: Box::new(ConnectionEndpoint::new(first_addr.clone())),
        },
    );
    feed(
        &mut core,
        TransportEvent::IncomingConnection {
            id: second,
            endpoint: Box::new(ConnectionEndpoint::new(second_addr.clone())),
        },
    );

    assert_eq!(core.connection_remote_addr(first), Some(&first_addr));
    assert_eq!(core.connection_remote_addr(second), Some(&second_addr));
    assert_eq!(core.connection_remote_addr(ConnectionId::new(74)), None);
}

#[test]
fn incoming_connection_is_tracked_before_it_is_established() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"pending-handshake-peer");
    let incoming = ConnectionId::new(22);

    feed(
        &mut core,
        TransportEvent::IncomingConnection {
            id: incoming,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        },
    );

    assert!(core.has_tracked_connections());
    assert!(core.connected_peers().is_empty());

    feed(
        &mut core,
        TransportEvent::Connected {
            id: incoming,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
    );
    let _ = drain_events(&mut core);
    assert!(core.connected_peers().contains(&peer_id));
    assert!(core.has_tracked_connections());

    feed(
        &mut core,
        TransportEvent::Closed {
            id: incoming,
            reason: ConnectionCloseReason::Local,
        },
    );
    let _ = drain_events(&mut core);
    assert!(core.connected_peers().is_empty());
    assert!(!core.has_tracked_connections());
}

#[test]
fn forget_stream_drops_bookkeeping_without_reset_or_event_purge() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(b"transferred-stream-peer");
    let conn = ConnectionId::new(30);
    let stream = StreamId::new(7);
    let key = (conn, stream);
    core.conn_to_peer.insert(conn, peer);
    core.peer_to_conn.insert(peer, conn);
    core.insert_stream_owner(conn, stream, ProtocolKind::User("/test/1".into()));
    core.inbound_negotiators.insert(
        key,
        PendingInbound {
            negotiator: MultistreamSelect::listener(["/test/1".to_string()]),
            deadline_ms: OUTBOUND_NEGOTIATION_TIMEOUT_MS,
        },
    );
    core.outbound_negotiators.insert(
        key,
        PendingOutbound {
            negotiator: MultistreamSelect::dialer("/test/1"),
            target: ProtocolKind::User("/test/1".into()),
            deadline_ms: Some(OUTBOUND_NEGOTIATION_TIMEOUT_MS),
            write_stopped: None,
        },
    );
    core.reset_stream(&peer, conn, stream)
        .expect("active user stream can be reset");
    core.abandoned_streams.insert(key);
    core.actions.push_back(Action::SendStream {
        conn_id: conn,
        stream_id: stream,
        data: Bytes::from(vec![2]),
    });
    core.actions.push_back(Action::CloseStreamWrite {
        conn_id: conn,
        stream_id: stream,
    });
    let other_stream = StreamId::new(8);
    core.actions.push_back(Action::ResetStream {
        conn_id: conn,
        stream_id: other_stream,
    });
    core.events.push_back(SwarmEvent::StreamData {
        peer_id: peer,
        conn_id: conn,
        stream_id: stream,
        data: Bytes::from(vec![1]),
    });

    assert_eq!(
        core.forget_stream(conn, stream),
        [Bytes::from(vec![2])],
        "the queued send is handed back"
    );

    assert!(core.stream_protocol(conn, stream).is_none());
    assert!(!core.inbound_negotiators.contains_key(&key));
    assert!(!core.outbound_negotiators.contains_key(&key));
    assert!(!core.reset_pending.contains(&key));
    assert!(!core.abandoned_streams.contains(&key));
    assert_eq!(core.actions.len(), 1);
    assert!(matches!(
        core.actions.front(),
        Some(Action::ResetStream { conn_id, stream_id })
            if *conn_id == conn && *stream_id == other_stream
    ));
    assert!(matches!(
        core.events.front(),
        Some(SwarmEvent::StreamData { conn_id, stream_id, .. })
            if *conn_id == conn && *stream_id == stream
    ));
}

#[test]
fn replacement_resets_stale_ping_stream() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let original_conn = ConnectionId::new(10);
    let newer_conn = ConnectionId::new(11);
    let stale_stream = StreamId::new(8);

    feed(
        &mut core,
        TransportEvent::Connected {
            id: original_conn,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
    );
    core.insert_stream_owner(original_conn, stale_stream, ProtocolKind::Ping);
    core.ping
        .register_outbound_stream(peer_id, stale_stream)
        .expect("register ping stream");
    while core.ping.poll_output().is_some() {}

    feed(
        &mut core,
        TransportEvent::Connected {
            id: newer_conn,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
    );
    while core.poll_output().is_some() {}

    core.ping(&peer_id, [7; PING_PAYLOAD_LEN], 42)
        .expect("ping should open a fresh stream on the newer connection");
    let actions = drain_actions(&mut core);

    assert!(
        actions.iter().any(
            |action| matches!(action, Action::OpenStream { conn_id, .. } if *conn_id == newer_conn)
        ),
        "ping should negotiate a fresh stream on the active connection, got {actions:?}"
    );
    assert!(
        !actions.iter().any(|action| matches!(
            action,
            Action::SendStream {
                conn_id,
                stream_id,
                ..
            } if *conn_id == newer_conn && *stream_id == stale_stream
        )),
        "ping must not send on a stream id from the replaced connection"
    );
}

#[test]
fn replacement_requeues_pending_ping_open() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let original_conn = ConnectionId::new(10);
    let newer_conn = ConnectionId::new(11);

    feed(
        &mut core,
        TransportEvent::Connected {
            id: original_conn,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
    );
    while core.poll_output().is_some() {}
    core.ping(&peer_id, [7; PING_PAYLOAD_LEN], 42)
        .expect("ping should queue an open on the original connection");

    feed(
        &mut core,
        TransportEvent::Connected {
            id: newer_conn,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                peer_id,
            )),
        },
    );
    let actions = drain_actions(&mut core);

    assert!(
        actions.iter().any(
            |action| matches!(action, Action::OpenStream { conn_id, .. } if *conn_id == newer_conn)
        ),
        "pending ping should be re-opened on the active connection, got {actions:?}"
    );
}

#[test]
fn inbound_ping_response_uses_stream_owner_connection() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let original_conn = ConnectionId::new(10);
    let newer_conn = ConnectionId::new(11);
    let inbound_stream = StreamId::new(8);

    core.conn_to_peer.insert(original_conn, peer_id);
    core.conn_to_peer.insert(newer_conn, peer_id);
    core.peer_to_conn.insert(peer_id, newer_conn);
    core.insert_stream_owner(original_conn, inbound_stream, ProtocolKind::Ping);
    core.ping.register_inbound_stream(peer_id, inbound_stream);
    while core.ping.poll_output().is_some() {}

    core.ping
        .on_stream_data(&peer_id, inbound_stream, &[7; PING_PAYLOAD_LEN], 42);
    core.drain_ping_outputs();
    let actions = drain_actions(&mut core);

    assert!(matches!(
        actions.as_slice(),
        [Action::SendStream {
            conn_id,
            stream_id,
            data
        }] if *conn_id == original_conn
            && *stream_id == inbound_stream
            && data[..] == [7; PING_PAYLOAD_LEN][..]
    ));
}

/// Identify's refusal resets the stream on the connection that owns it.
#[test]
fn refused_identify_bytes_reset_the_owned_stream() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let original_conn = ConnectionId::new(10);
    let newer_conn = ConnectionId::new(11);
    let stream_id = StreamId::new(8);

    core.conn_to_peer.insert(original_conn, peer_id);
    core.conn_to_peer.insert(newer_conn, peer_id);
    core.peer_to_conn.insert(peer_id, newer_conn);
    core.insert_stream_owner(original_conn, stream_id, ProtocolKind::IdentifyInitiator);
    core.identify.register_inbound_stream(peer_id, stream_id);

    // A header declaring a frame far beyond identify's limit.
    let mut data = Vec::new();
    minip2p_core::write_uvarint(u64::from(u32::MAX), &mut data);
    core.identify.on_stream_data(peer_id, stream_id, &data);
    core.drain_identify_outputs();

    assert!(matches!(
        drain_actions(&mut core).as_slice(),
        [Action::ResetStream { conn_id, stream_id: sid }]
            if *conn_id == original_conn && *sid == stream_id
    ));
}

/// Registers `peer_id` as connected on `conn_id` with a fully
/// negotiated outbound ping stream, draining all setup outputs.
fn setup_outbound_ping_stream(
    core: &mut SwarmState,
    peer_id: &PeerId,
    conn_id: ConnectionId,
    stream_id: StreamId,
) {
    feed(
        core,
        TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(
                loopback_transport(),
                *peer_id,
            )),
        },
    );
    while core.poll_output().is_some() {}
    // Only ping's timer is under test.
    core.first_identify.clear();
    core.insert_stream_owner(conn_id, stream_id, ProtocolKind::Ping);
    core.ping
        .register_outbound_stream(*peer_id, stream_id)
        .expect("register outbound ping stream");
    while core.ping.poll_output().is_some() {}
}

#[test]
fn next_deadline_arms_on_ping_and_clears_on_rtt() {
    let mut core = test_core(); // default request_timeout_ms = 10_000
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let conn_id = ConnectionId::new(1);
    let stream_id = StreamId::new(4);
    setup_outbound_ping_stream(&mut core, &peer_id, conn_id, stream_id);

    assert_eq!(
        core.next_deadline(Now::from_millis(0)),
        None,
        "no timer armed before a ping is in flight"
    );

    let payload = [7u8; PING_PAYLOAD_LEN];
    core.ping(&peer_id, payload, 1_000).expect("send ping");

    // The attempt is due ping_ms after the ping call.
    let due = Deadline::from_millis(11_000);
    assert_eq!(core.next_deadline(Now::from_millis(1_000)), Some(due));
    assert_eq!(
        core.next_deadline(Now::from_millis(5_000)),
        Some(due),
        "the deadline is absolute, not relative to now"
    );
    assert!(!due.is_expired_at(Now::from_millis(10_999)));
    assert!(
        due.is_expired_at(Now::from_millis(11_000)),
        "due exactly now"
    );
    assert_eq!(
        core.next_deadline(Now::from_millis(20_000)),
        Some(due),
        "an overdue timer keeps its past due time"
    );

    // The echoed payload resolves the ping and disarms the timer.
    core.handle_transport_event(
        TransportEvent::StreamData {
            id: conn_id,
            stream_id,
            data: Bytes::from(payload.to_vec()),
        },
        1_500,
    );
    assert_eq!(core.next_deadline(Now::from_millis(1_500)), None);
    let events = drain_events(&mut core);
    assert!(
        events.iter().any(|event| matches!(
            event,
            SwarmEvent::PingRttMeasured { conn_id: id, .. } if *id == conn_id
        )),
        "the RTT names the connection it was measured on: {events:?}"
    );
}

#[test]
fn next_deadline_disarms_after_timeout_tick() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let conn_id = ConnectionId::new(1);
    let stream_id = StreamId::new(4);
    setup_outbound_ping_stream(&mut core, &peer_id, conn_id, stream_id);

    core.ping(&peer_id, [7u8; PING_PAYLOAD_LEN], 1_000)
        .expect("send ping");

    // An early tick must not disarm the timer.
    core.handle_tick(5_000);
    assert_eq!(
        core.next_deadline(Now::from_millis(5_000)),
        Some(Deadline::from_millis(11_000))
    );

    // A tick at the deadline fires the timeout and disarms the timer.
    core.handle_tick(11_000);
    let events = drain_events(&mut core);
    assert!(
        events.iter().any(|event| matches!(
            event,
            SwarmEvent::PingFailed { conn_id: id, cause: PingFailure::TimedOut, .. }
                if *id == conn_id
        )),
        "the timeout names the connection the ping was sent on: {events:?}"
    );
    assert_eq!(core.next_deadline(Now::from_millis(11_000)), None);
}

#[test]
fn next_deadline_cleared_when_connection_closes() {
    let mut core = test_core();
    let peer_id = PeerId::from_public_key_protobuf(b"known-peer");
    let conn_id = ConnectionId::new(1);
    let stream_id = StreamId::new(4);
    setup_outbound_ping_stream(&mut core, &peer_id, conn_id, stream_id);

    core.ping(&peer_id, [7u8; PING_PAYLOAD_LEN], 0)
        .expect("send ping");
    assert_eq!(
        core.next_deadline(Now::from_millis(0)),
        Some(Deadline::from_millis(10_000))
    );

    feed(
        &mut core,
        TransportEvent::Closed {
            id: conn_id,
            reason: ConnectionCloseReason::Local,
        },
    );
    assert_eq!(core.next_deadline(Now::from_millis(0)), None);
    assert!(
        !drain_events(&mut core)
            .iter()
            .any(|event| matches!(event, SwarmEvent::PingFailed { .. })),
        "ConnectionClosed alone ends the ping"
    );
}

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

    // Closing it ourselves is no failure.
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

    // Identity arrives after Connected already consumed the first veto check.
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

    // reject_pending_establish already reported the dial; a trailing
    // Error before Closed must not leak a second SwarmEvent::Error.
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

    // Negotiation completing at 2_000 fires the queued payload; the
    // timer still runs from the ping call.
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
    // A late identity upgrade replaces the first connection; an
    // unverified connection is not the peer's.
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

/// Peer ids that sort below and above [`tie_break_core`]'s own.
const LOWER_PEER: &[u8] = b"a";
const HIGHER_PEER: &[u8] = b"z";

/// A core whose own peer id sorts between `LOWER_PEER` and `HIGHER_PEER`.
fn tie_break_core() -> SwarmState {
    SwarmState::new(
        IdentifyConfig {
            protocol_version: "minip2p-test/0.1.0".into(),
            agent_version: "minip2p-test/0.1.0".into(),
            protocols: Vec::new(),
            public_key: b"m".to_vec(),
        },
        SwarmTimeouts::default(),
    )
}

/// Feeds `conn_id` to `peer` at `now_ms`, as our dial (`outbound`) or the
/// peer's, with its identity on `Connected` or, when `upgrade`, through a
/// later `PeerIdentityVerified`.
fn register(
    core: &mut SwarmState,
    peer: &PeerId,
    conn_id: ConnectionId,
    outbound: bool,
    upgrade: bool,
    now_ms: u64,
) {
    register_with_token(core, peer, conn_id, outbound, upgrade, None, now_ms);
}

/// [`register`], with `token` (if any) as the connection's token.
fn register_with_token(
    core: &mut SwarmState,
    peer: &PeerId,
    conn_id: ConnectionId,
    outbound: bool,
    upgrade: bool,
    token: Option<u8>,
    now_ms: u64,
) {
    let mut endpoint = ConnectionEndpoint::with_peer_id(loopback_transport(), *peer);
    if let Some(token) = token {
        endpoint.set_token(ConnectionToken::new([token; 32]));
    }
    let mut events = Vec::new();
    if outbound {
        let addr = PeerAddr::new(loopback_transport(), *peer).expect("peer addr");
        core.note_dial(conn_id, addr);
    } else {
        events.push(TransportEvent::IncomingConnection {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        });
    }
    if upgrade {
        events.push(TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(ConnectionEndpoint::new(loopback_transport())),
        });
        events.push(TransportEvent::PeerIdentityVerified {
            id: conn_id,
            endpoint: Box::new(endpoint),
            previous_peer_id: None,
        });
    } else {
        events.push(TransportEvent::Connected {
            id: conn_id,
            endpoint: Box::new(endpoint),
        });
    }
    for event in events {
        core.handle_transport_event(event, now_ms);
    }
}

#[test]
fn simultaneous_dial_closes_the_higher_peers_dial_unannounced() {
    let current = ConnectionId::new(1);
    let new = ConnectionId::new(2);
    // The current connection is the lower peer's dial: ours when we are
    // lower, the peer's when it is.
    for (peer, current_outbound) in [(HIGHER_PEER, true), (LOWER_PEER, false)] {
        for upgrade in [false, true] {
            let case = format!("current_outbound={current_outbound} upgrade={upgrade}");
            let mut core = tie_break_core();
            let peer = PeerId::from_public_key_protobuf(peer);
            register(&mut core, &peer, current, current_outbound, false, 0);
            let _ = drain_events(&mut core);

            register(&mut core, &peer, new, !current_outbound, upgrade, 4_999);
            let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
            assert_eq!(lifecycle(&outputs), ["close 2"], "{case}");
            // Only our own losing dial reports anything: it completes as
            // DialFailed. The peer's losing dial closes with no event.
            let events: Vec<_> = outputs
                .iter()
                .filter_map(|output| match output {
                    Output::Event(event) => Some(event),
                    Output::Action(_) => None,
                })
                .collect();
            if current_outbound {
                assert!(events.is_empty(), "{case}: {events:?}");
            } else {
                assert!(
                    matches!(
                        events.as_slice(),
                        [SwarmEvent::DialFailed { conn_id, .. }] if *conn_id == new
                    ),
                    "{case}: {events:?}"
                );
            }
            assert_eq!(core.connection_id(&peer), Some(current), "{case}");

            // Data the loser still delivers is dropped and acknowledged.
            feed(
                &mut core,
                TransportEvent::StreamData {
                    id: new,
                    stream_id: StreamId::new(3),
                    data: Bytes::from_static(b"lost"),
                },
            );
            assert!(
                drain_actions(&mut core).contains(&Action::AckStream {
                    conn_id: new,
                    stream_id: StreamId::new(3),
                    bytes: 4,
                }),
                "{case}"
            );

            // Its transport close is bookkeeping only.
            feed(
                &mut core,
                TransportEvent::Closed {
                    id: new,
                    reason: ConnectionCloseReason::Local,
                },
            );
            assert!(drain_events(&mut core).is_empty(), "{case}");
            assert_eq!(core.connection_id(&peer), Some(current), "{case}");
        }
    }
}

#[test]
fn same_direction_race_keeps_the_lower_token_in_either_order() {
    let low = (ConnectionId::new(1), 1);
    let high = (ConnectionId::new(2), 2);
    // Our two dials, or two of the peer's: the two ends of the race see
    // the same pair, possibly in opposite orders, and must agree.
    for outbound in [true, false] {
        for upgrade in [false, true] {
            for (first, second) in [(low, high), (high, low)] {
                let case = format!("outbound={outbound} upgrade={upgrade} first={}", first.0);
                let mut core = tie_break_core();
                let peer = PeerId::from_public_key_protobuf(HIGHER_PEER);
                register_with_token(&mut core, &peer, first.0, outbound, false, Some(first.1), 0);
                let _ = drain_events(&mut core);

                register_with_token(
                    &mut core,
                    &peer,
                    second.0,
                    outbound,
                    upgrade,
                    Some(second.1),
                    4_999,
                );
                let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
                assert_eq!(core.connection_id(&peer), Some(low.0), "{case}");
                if second == low {
                    assert_eq!(
                        lifecycle(&outputs),
                        [
                            format!("replaced {}->{}", high.0, low.0),
                            format!("close {}", high.0)
                        ],
                        "{case}"
                    );
                } else {
                    // Unannounced; our own losing dial completes as
                    // DialFailed, which a settled attempt consumes.
                    assert_eq!(lifecycle(&outputs), [format!("close {}", high.0)]);
                    let dial_failed = outputs.iter().any(|output| {
                        matches!(
                            output,
                            Output::Event(SwarmEvent::DialFailed { conn_id, .. })
                                if *conn_id == high.0
                        )
                    });
                    assert_eq!(dial_failed, outbound, "{case}");
                }
            }
        }
    }
}

#[test]
fn newest_connection_wins_outside_a_simultaneous_dial() {
    let direct = ConnectionId::new(1);
    let circuit = ConnectionId::namespaced(minip2p_transport::ConnectionNamespace::CIRCUIT, 1)
        .expect("circuit id");
    let new = ConnectionId::new(2);
    // (case, current, current_outbound, new_outbound, tokens, new_at_ms).
    // We are the lower peer, so our own dial wins a simultaneous dial;
    // a same-direction race needs a token on both to keep the older.
    let cases = [
        (
            "new is the lower peer's dial",
            direct,
            false,
            true,
            (None, None),
            0,
        ),
        (
            "same direction without tokens",
            direct,
            true,
            true,
            (None, None),
            0,
        ),
        (
            "same direction, new has no token",
            direct,
            true,
            true,
            (Some(1), None),
            0,
        ),
        (
            "same direction, current has no token",
            direct,
            false,
            false,
            (None, Some(2)),
            0,
        ),
        (
            "current is older than the window",
            direct,
            true,
            false,
            (None, None),
            SIMULTANEOUS_DIAL_WINDOW_MS,
        ),
        (
            "same direction, current is older than the window",
            direct,
            true,
            true,
            (Some(1), Some(2)),
            SIMULTANEOUS_DIAL_WINDOW_MS,
        ),
        ("circuit to direct", circuit, true, false, (None, None), 0),
    ];
    for (case, current, current_outbound, new_outbound, tokens, new_at_ms) in cases {
        for upgrade in [false, true] {
            let mut core = tie_break_core();
            let peer = PeerId::from_public_key_protobuf(HIGHER_PEER);
            register_with_token(
                &mut core,
                &peer,
                current,
                current_outbound,
                false,
                tokens.0,
                0,
            );
            let _ = drain_events(&mut core);

            register_with_token(
                &mut core,
                &peer,
                new,
                new_outbound,
                upgrade,
                tokens.1,
                new_at_ms,
            );
            let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
            assert_eq!(
                lifecycle(&outputs),
                [
                    format!("replaced {current}->{new}"),
                    format!("close {current}")
                ],
                "{case} (upgrade={upgrade})"
            );
            assert_eq!(core.connection_id(&peer), Some(new), "{case}");
        }
    }
}

#[test]
fn a_configured_window_bounds_the_race() {
    let current = ConnectionId::new(1);
    let new = ConnectionId::new(2);
    // Our dial to the higher peer is the one both sides keep, until the
    // window ends.
    for (new_at_ms, expected) in [
        (199, ["close 2"].as_slice()),
        (200, &["replaced 1->2", "close 1"]),
    ] {
        let mut core = tie_break_core();
        core.simultaneous_dial_window_ms = 200;
        let peer = PeerId::from_public_key_protobuf(HIGHER_PEER);
        register(&mut core, &peer, current, true, false, 0);
        let _ = drain_events(&mut core);

        register(&mut core, &peer, new, false, false, new_at_ms);
        let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
        assert_eq!(lifecycle(&outputs), expected, "new at {new_at_ms}ms");
    }
}

// --- A connection's first Identify fails (#470) ---

/// How a test scenario breaks the first Identify exchange on a connection.
#[derive(Clone, Copy, Debug)]
enum IdentifyBreak {
    /// The peer never answers the negotiation.
    Silent,
    /// The peer negotiates Identify, then never replies.
    NegotiatedThenSilent,
    /// The transport refuses to open the stream.
    OpenFails,
    /// The peer answers `na`.
    Rejected,
    /// The peer resets the stream mid-negotiation.
    ClosedNegotiating,
    /// The peer closes its write side mid-negotiation.
    FinNegotiating,
    /// The peer resets the stream after negotiating, before replying.
    ClosedNegotiated,
    /// The peer sends a frame Identify refuses.
    Malformed,
    /// The peer's negotiation reply breaks multistream-select.
    BadNegotiation,
}

const FIRST_IDENTIFY_PEER: &[u8] = b"first-identify-peer";

/// A peer connected at time 0 whose first Identify is broken as `how`.
/// Returns the core, peer, and connection.
fn break_first_identify(how: IdentifyBreak) -> (SwarmState, PeerId, ConnectionId) {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(FIRST_IDENTIFY_PEER);
    let conn = ConnectionId::new(70);
    let stream = StreamId::new(1);
    feed(
        &mut core,
        TransportEvent::Connected {
            id: conn,
            endpoint: Box::new(ConnectionEndpoint::with_peer_id(loopback_transport(), peer)),
        },
    );
    let actions = drain_actions(&mut core);
    if let IdentifyBreak::OpenFails = how {
        core.open_failed(conn, IDENTIFY_PROTOCOL_ID, "stream limit reached");
        return (core, peer, conn);
    }
    core.opened(actions, conn, IDENTIFY_PROTOCOL_ID, stream);
    feed(
        &mut core,
        TransportEvent::StreamOpened {
            id: conn,
            stream_id: stream,
        },
    );
    let data = |core: &mut SwarmState, bytes: Vec<u8>| {
        feed(
            core,
            TransportEvent::StreamData {
                id: conn,
                stream_id: stream,
                data: Bytes::from(bytes),
            },
        )
    };
    let mut accept = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    accept.extend_from_slice(&multistream_frame(IDENTIFY_PROTOCOL_ID));
    let closed = |core: &mut SwarmState| {
        feed(
            core,
            TransportEvent::StreamClosed {
                id: conn,
                stream_id: stream,
            },
        )
    };
    match how {
        IdentifyBreak::Silent | IdentifyBreak::OpenFails => {}
        IdentifyBreak::NegotiatedThenSilent => data(&mut core, accept),
        IdentifyBreak::Rejected => {
            let mut na = multistream_frame(MULTISTREAM_PROTOCOL_ID);
            na.extend_from_slice(&multistream_frame("na"));
            data(&mut core, na);
        }
        IdentifyBreak::ClosedNegotiating => closed(&mut core),
        IdentifyBreak::FinNegotiating => feed(
            &mut core,
            TransportEvent::StreamRemoteWriteClosed {
                id: conn,
                stream_id: stream,
            },
        ),
        IdentifyBreak::ClosedNegotiated => {
            data(&mut core, accept);
            closed(&mut core);
        }
        IdentifyBreak::BadNegotiation => data(&mut core, b"\x05nope\n".to_vec()),
        IdentifyBreak::Malformed => {
            data(&mut core, accept);
            // A header declaring a frame far beyond Identify's limit.
            let mut frame = Vec::new();
            minip2p_core::write_uvarint(u64::from(u32::MAX), &mut frame);
            data(&mut core, frame);
        }
    }
    (core, peer, conn)
}

#[test]
fn a_failed_first_identify_is_reported_and_closes_its_connection() {
    use IdentifyBreak::*;
    let cases = [
        (Silent, IdentifyFailure::TimedOut),
        (NegotiatedThenSilent, IdentifyFailure::TimedOut),
        (OpenFails, IdentifyFailure::OpenFailed),
        (Rejected, IdentifyFailure::Rejected),
        (ClosedNegotiating, IdentifyFailure::ClosedEarly),
        (FinNegotiating, IdentifyFailure::ClosedEarly),
        (ClosedNegotiated, IdentifyFailure::ClosedEarly),
        (Malformed, IdentifyFailure::Malformed),
        (BadNegotiation, IdentifyFailure::Malformed),
    ];
    for (how, cause) in cases {
        let (mut core, peer, conn) = break_first_identify(how);
        if cause == IdentifyFailure::TimedOut {
            assert_eq!(
                core.next_deadline(Now::from_millis(0)),
                Some(Deadline::from_millis(IDENTIFY_TIMEOUT_MS)),
                "{how:?}"
            );
            core.handle_tick(IDENTIFY_TIMEOUT_MS - 1);
            assert!(drain_events(&mut core).is_empty(), "{how:?}: early");
            core.handle_tick(IDENTIFY_TIMEOUT_MS);
        }
        let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
        let failed: Vec<_> = outputs
            .iter()
            .filter_map(|output| match output {
                Output::Event(SwarmEvent::IdentifyFailed {
                    peer_id,
                    conn_id,
                    cause,
                }) => Some((*peer_id, *conn_id, *cause)),
                _ => None,
            })
            .collect();
        assert_eq!(failed, [(peer, conn, cause)], "{how:?}: {outputs:?}");
        assert!(
            outputs.iter().any(|output| matches!(
                output,
                Output::Action(Action::CloseConnection { conn_id }) if *conn_id == conn
            )),
            "{how:?}: the connection is closed: {outputs:?}"
        );
        assert!(
            !outputs.iter().any(|output| matches!(
                output,
                Output::Event(SwarmEvent::Error(SwarmRuntimeError {
                    kind: SwarmErrorKind::OpenStreamFailed
                        | SwarmErrorKind::UnsupportedProtocol
                        | SwarmErrorKind::Multistream
                        | SwarmErrorKind::Identify,
                    ..
                }))
            )),
            "{how:?}: IdentifyFailed is the one report: {outputs:?}"
        );
        assert_eq!(core.next_deadline(Now::from_millis(0)), None, "{how:?}");

        // Nothing more until the transport reports the close, which names
        // Identify; the peer never becomes ready.
        core.handle_tick(10 * IDENTIFY_TIMEOUT_MS);
        feed(
            &mut core,
            TransportEvent::Closed {
                id: conn,
                reason: ConnectionCloseReason::Local,
            },
        );
        let events = drain_events(&mut core);
        assert!(
            matches!(
                events.as_slice(),
                [SwarmEvent::ConnectionClosed {
                    reason: ConnectionCloseReason::Error(reason),
                    ..
                }] if reason.contains("identify")
            ),
            "{how:?}: {events:?}"
        );
        assert!(!core.is_peer_ready(&peer), "{how:?}");
    }
}

#[test]
fn a_failed_identify_blocks_a_late_reply_from_making_the_peer_ready() {
    let (mut core, peer, conn) = break_first_identify(IdentifyBreak::NegotiatedThenSilent);
    core.handle_tick(IDENTIFY_TIMEOUT_MS);
    drain_events(&mut core);
    // The reply arrives before the transport closes the connection.
    let info = IdentifyMessage {
        protocol_version: None,
        agent_version: None,
        public_key: None,
        listen_addrs: Vec::new(),
        observed_addr: None,
        protocols: Vec::new(),
    };
    let stream = StreamId::new(1);
    for event in [
        TransportEvent::StreamData {
            id: conn,
            stream_id: stream,
            data: Bytes::from(minip2p_core::encode_frame(&info.encode())),
        },
        TransportEvent::StreamRemoteWriteClosed {
            id: conn,
            stream_id: stream,
        },
    ] {
        feed(&mut core, event);
    }
    assert!(ready_conns(&drain_events(&mut core)).is_empty());
    assert!(!core.is_peer_ready(&peer));
}

#[test]
fn a_ready_connection_survives_later_identify_failures() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(FIRST_IDENTIFY_PEER);
    let conn = ConnectionId::new(71);
    connect_again(&mut core, &peer, conn, false);
    identify_on(&mut core, conn, StreamId::new(1), &[]);
    assert_eq!(ready_conns(&drain_events(&mut core)), [conn]);

    // Past the deadline, then a second Identify request the responder
    // refuses: neither ends the ready connection.
    core.handle_tick(10 * IDENTIFY_TIMEOUT_MS);
    for stream in [StreamId::new(2), StreamId::new(4)] {
        feed(
            &mut core,
            TransportEvent::IncomingStream {
                id: conn,
                stream_id: stream,
            },
        );
        let mut propose = multistream_frame(MULTISTREAM_PROTOCOL_ID);
        propose.extend_from_slice(&multistream_frame(IDENTIFY_PROTOCOL_ID));
        feed(
            &mut core,
            TransportEvent::StreamData {
                id: conn,
                stream_id: stream,
                data: Bytes::from(propose),
            },
        );
    }
    let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
    assert!(
        outputs.iter().any(|output| matches!(
            output,
            Output::Event(SwarmEvent::Error(SwarmRuntimeError {
                kind: SwarmErrorKind::IdentifyStreamRejected,
                ..
            }))
        )),
        "{outputs:?}"
    );
    assert!(
        !outputs.iter().any(|output| matches!(
            output,
            Output::Action(Action::CloseConnection { .. })
                | Output::Event(SwarmEvent::IdentifyFailed { .. })
        )),
        "{outputs:?}"
    );
    assert!(core.is_peer_ready(&peer));
}

// --- Every ping attempt ends in one ping event (#495) ---

/// How a test scenario breaks a ping attempt.
#[derive(Clone, Copy, Debug)]
enum PingBreak {
    /// An echo times out, and the retry's fresh stream never finishes
    /// negotiating.
    NegotiationAfterTimeout,
    /// The echo never arrives on a negotiated stream.
    EchoSilent,
    /// The transport refuses to open the ping stream.
    OpenFails,
    /// The peer answers `na` to `/ipfs/ping/1.0.0`.
    Rejected,
    /// The peer answers with malformed multistream framing.
    BadNegotiation,
    /// The peer resets the stream mid-negotiation.
    ClosedNegotiating,
    /// The peer closes its write side mid-negotiation.
    FinNegotiating,
    /// The peer resets the negotiated stream with the ping in flight.
    ClosedInFlight,
}

const PING_PEER: &[u8] = b"ping-attempt-peer";

/// The `PingFailed` and `PingRttMeasured` events among `outputs`.
fn ping_results(outputs: &[Output]) -> Vec<(ConnectionId, Option<PingFailure>)> {
    outputs
        .iter()
        .filter_map(|output| match output {
            Output::Event(SwarmEvent::PingFailed { conn_id, cause, .. }) => {
                Some((*conn_id, Some(*cause)))
            }
            Output::Event(SwarmEvent::PingRttMeasured { conn_id, .. }) => Some((*conn_id, None)),
            _ => None,
        })
        .collect()
}

/// Runs one broken attempt to a peer connected at time 0 and returns
/// every output from the attempt's `ping` on, the connection, and the
/// time by which it must have ended.
fn break_ping(how: PingBreak) -> (SwarmState, Vec<Output>, ConnectionId, u64) {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(PING_PEER);
    let conn = ConnectionId::new(90);
    let negotiated = StreamId::new(4);
    let fresh = StreamId::new(8);
    let mut outputs = Vec::new();
    let at = |core: &mut SwarmState, event, now_ms| core.handle_transport_event(event, now_ms);
    let reset = |stream_id| TransportEvent::StreamClosed {
        id: conn,
        stream_id,
    };
    // Opens a fresh ping stream for the attempt started at `start`, the
    // transport reporting it opened at `start + 2_000`.
    let open_fresh = |core: &mut SwarmState, start: u64| {
        core.ping(&peer, [3; PING_PAYLOAD_LEN], start)
            .expect("ping");
        let actions = drain_actions(core);
        core.opened(actions, conn, PING_PROTOCOL_ID, fresh);
        core.handle_transport_event(
            TransportEvent::StreamOpened {
                id: conn,
                stream_id: fresh,
            },
            start + 2_000,
        );
    };
    let ends_by = match how {
        PingBreak::NegotiationAfterTimeout => {
            setup_outbound_ping_stream(&mut core, &peer, conn, negotiated);
            core.ping(&peer, [2; PING_PAYLOAD_LEN], 0).expect("ping");
            core.handle_tick(PING_TIMEOUT);
            let first: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
            assert_eq!(
                ping_results(&first),
                [(conn, Some(PingFailure::TimedOut))],
                "the first echo times out: {first:?}"
            );
            at(&mut core, reset(negotiated), PING_TIMEOUT);
            open_fresh(&mut core, PING_TIMEOUT);
            2 * PING_TIMEOUT
        }
        PingBreak::EchoSilent => {
            setup_outbound_ping_stream(&mut core, &peer, conn, negotiated);
            core.ping(&peer, [2; PING_PAYLOAD_LEN], 0).expect("ping");
            PING_TIMEOUT
        }
        PingBreak::OpenFails => {
            setup_outbound_ping_stream(&mut core, &peer, conn, negotiated);
            at(&mut core, reset(negotiated), 0);
            core.ping(&peer, [2; PING_PAYLOAD_LEN], 0).expect("ping");
            outputs.extend(core::iter::from_fn(|| core.poll_output()));
            core.open_failed(conn, PING_PROTOCOL_ID, "stream limit reached");
            0
        }
        PingBreak::Rejected
        | PingBreak::BadNegotiation
        | PingBreak::ClosedNegotiating
        | PingBreak::FinNegotiating => {
            setup_outbound_ping_stream(&mut core, &peer, conn, negotiated);
            at(&mut core, reset(negotiated), 0);
            open_fresh(&mut core, 0);
            if let PingBreak::Rejected = how {
                let mut na = multistream_frame(MULTISTREAM_PROTOCOL_ID);
                na.extend_from_slice(&multistream_frame("na"));
                at(
                    &mut core,
                    TransportEvent::StreamData {
                        id: conn,
                        stream_id: fresh,
                        data: Bytes::from(na),
                    },
                    3_000,
                );
            } else if let PingBreak::BadNegotiation = how {
                at(
                    &mut core,
                    TransportEvent::StreamData {
                        id: conn,
                        stream_id: fresh,
                        data: Bytes::from_static(b"\x05nope\n"),
                    },
                    3_000,
                );
            } else if let PingBreak::FinNegotiating = how {
                at(
                    &mut core,
                    TransportEvent::StreamRemoteWriteClosed {
                        id: conn,
                        stream_id: fresh,
                    },
                    3_000,
                );
            } else {
                at(&mut core, reset(fresh), 3_000);
            }
            3_000
        }
        PingBreak::ClosedInFlight => {
            setup_outbound_ping_stream(&mut core, &peer, conn, negotiated);
            core.ping(&peer, [2; PING_PAYLOAD_LEN], 0).expect("ping");
            at(&mut core, reset(negotiated), 3_000);
            3_000
        }
    };
    outputs.extend(core::iter::from_fn(|| core.poll_output()));
    (core, outputs, conn, ends_by)
}

/// The default ping deadline.
const PING_TIMEOUT: u64 = 10_000;

#[test]
fn a_failed_ping_attempt_ends_in_exactly_one_ping_failed() {
    use PingBreak::*;
    let cases = [
        (NegotiationAfterTimeout, PingFailure::TimedOut),
        (EchoSilent, PingFailure::TimedOut),
        (OpenFails, PingFailure::OpenFailed),
        (Rejected, PingFailure::Rejected),
        (BadNegotiation, PingFailure::Rejected),
        (ClosedNegotiating, PingFailure::StreamClosed),
        (FinNegotiating, PingFailure::StreamClosed),
        (ClosedInFlight, PingFailure::StreamClosed),
    ];
    for (how, cause) in cases {
        let (mut core, mut outputs, conn, ends_by) = break_ping(how);
        if cause == PingFailure::TimedOut {
            assert_eq!(
                core.next_deadline(Now::from_millis(0)),
                Some(Deadline::from_millis(ends_by)),
                "{how:?}: the ping deadline runs from the ping call"
            );
            core.handle_tick(ends_by - 1);
            assert!(ping_results(&outputs).is_empty(), "{how:?}: {outputs:?}");
            let early: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
            assert!(ping_results(&early).is_empty(), "{how:?}: early {early:?}");
            core.handle_tick(ends_by);
            outputs.extend(core::iter::from_fn(|| core.poll_output()));
        }
        // Long after: nothing more, whatever other deadline was running.
        core.handle_tick(ends_by + 10 * PING_TIMEOUT);
        outputs.extend(core::iter::from_fn(|| core.poll_output()));

        assert_eq!(
            ping_results(&outputs),
            [(conn, Some(cause))],
            "{how:?}: {outputs:?}"
        );
        assert!(
            !outputs.iter().any(|output| matches!(
                output,
                Output::Event(SwarmEvent::Error(SwarmRuntimeError {
                    kind: SwarmErrorKind::OpenStreamFailed
                        | SwarmErrorKind::UnsupportedProtocol
                        | SwarmErrorKind::Multistream,
                    ..
                }))
            )),
            "{how:?}: PingFailed is the report: {outputs:?}"
        );
        let mut resets: Vec<_> = outputs
            .iter()
            .filter_map(|output| match output {
                Output::Action(Action::ResetStream { stream_id, .. }) => Some(*stream_id),
                _ => None,
            })
            .collect();
        let all = resets.len();
        resets.sort_unstable();
        resets.dedup();
        assert_eq!(
            resets.len(),
            all,
            "{how:?}: one reset per stream: {outputs:?}"
        );
        assert!(core.pings.is_empty(), "{how:?}: attempt cleared");
        assert!(
            !core
                .outbound_negotiators
                .values()
                .any(|pending| pending.target == ProtocolKind::Ping),
            "{how:?}: no ping stream left negotiating"
        );
        assert_eq!(core.next_deadline(Now::from_millis(0)), None, "{how:?}");
    }
}

#[test]
fn a_retry_after_a_bad_echo_opens_a_fresh_stream() {
    let mut core = test_core();
    let peer = PeerId::from_public_key_protobuf(PING_PEER);
    let conn = ConnectionId::new(92);
    let stream = StreamId::new(4);
    setup_outbound_ping_stream(&mut core, &peer, conn, stream);
    core.ping(&peer, [2; PING_PAYLOAD_LEN], 0).expect("ping");
    let _ = drain_actions(&mut core);

    core.handle_transport_event(
        TransportEvent::StreamData {
            id: conn,
            stream_id: stream,
            data: Bytes::from(vec![9; PING_PAYLOAD_LEN]),
        },
        1_000,
    );
    let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
    assert_eq!(
        ping_results(&outputs),
        [(conn, Some(PingFailure::StreamClosed))],
        "{outputs:?}"
    );

    // Before the transport reports the reset stream closed.
    core.ping(&peer, [3; PING_PAYLOAD_LEN], 1_000)
        .expect("retry");
    let actions = drain_actions(&mut core);
    assert!(
        actions.iter().any(|action| matches!(
            action,
            Action::OpenStream {
                target: ProtocolKind::Ping,
                ..
            }
        )),
        "{actions:?}"
    );
    assert!(
        !actions.iter().any(|action| matches!(
            action,
            Action::SendStream { stream_id, .. } if *stream_id == stream
        )),
        "the reset stream is not reused: {actions:?}"
    );
}

#[test]
fn a_ping_stream_has_no_negotiation_deadline_of_its_own() {
    let mut core = SwarmState::new(
        IdentifyConfig {
            protocol_version: "minip2p-test/0.1.0".into(),
            agent_version: "minip2p-test/0.1.0".into(),
            protocols: Vec::new(),
            public_key: Vec::new(),
        },
        SwarmTimeouts {
            negotiation_ms: 10_000,
            ping_ms: 25_000,
            ..SwarmTimeouts::default()
        },
    );
    let peer = PeerId::from_public_key_protobuf(PING_PEER);
    let conn = ConnectionId::new(91);
    let stream = StreamId::new(8);
    connect_again(&mut core, &peer, conn, false);
    core.first_identify.clear();
    let _ = drain_actions(&mut core);
    let payload = [5; PING_PAYLOAD_LEN];
    core.ping(&peer, payload, 0).expect("ping");
    let actions = drain_actions(&mut core);
    core.opened(actions, conn, PING_PROTOCOL_ID, stream);
    feed(
        &mut core,
        TransportEvent::StreamOpened {
            id: conn,
            stream_id: stream,
        },
    );
    // Past the 10 s negotiation deadline, inside the 25 s ping deadline.
    core.handle_tick(15_000);
    let mut accept = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    accept.extend_from_slice(&multistream_frame(PING_PROTOCOL_ID));
    for (data, now_ms) in [(accept, 15_000), (payload.to_vec(), 20_000)] {
        core.handle_transport_event(
            TransportEvent::StreamData {
                id: conn,
                stream_id: stream,
                data: Bytes::from(data),
            },
            now_ms,
        );
    }
    let outputs: Vec<_> = core::iter::from_fn(|| core.poll_output()).collect();
    assert_eq!(ping_results(&outputs), [(conn, None)], "{outputs:?}");
}
