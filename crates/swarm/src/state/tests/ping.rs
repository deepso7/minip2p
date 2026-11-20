use super::*;

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
