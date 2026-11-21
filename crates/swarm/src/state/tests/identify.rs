use super::*;

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
