use super::*;

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
