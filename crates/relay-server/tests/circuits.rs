//! CONNECT admission, the STOP exchange, and how a pending circuit commits,
//! fails, or is abandoned.

mod common;

use common::{
    Call, DESTINATION_CONN, Fixture, Node, SOURCE_CONN, acked, at, connect_request,
    connected_circuit, key, opening_stop, peer, pending_stop, resets, sends_on, stop_status,
    unlimited_rates, without_acks,
};
use minip2p_relay::{HopMessage, MAX_PENDING_BRIDGE_SIZE, Status, decode_frame};
use minip2p_relay_server::{
    CircuitCloseReason, CircuitDirection, CircuitLeg, RateLimit, RelayServerConfig,
    RelayServerEvent, RelayServerRuntimeError, RelayServerRuntimeErrorKind, ReservationCloseReason,
    StreamKey,
};
use minip2p_swarm::{SwarmErrorKind, SwarmEvent, SwarmRuntimeError};
use minip2p_transport::ConnectionId;

fn timeout_5ms() -> RelayServerConfig {
    RelayServerConfig {
        control_stream_timeout_ms: 5,
        ..RelayServerConfig::default()
    }
}

/// The status of the one HOP reply written on `stream`.
#[expect(clippy::panic, reason = "the helper requires one framed HOP reply")]
fn hop_reply_status(calls: &[Call], stream: StreamKey) -> Option<Status> {
    let sends = sends_on(calls, stream);
    let [send] = &sends[..] else {
        panic!("one reply on {stream:?}: {calls:?}");
    };
    let minip2p_relay::FrameDecode::Complete { payload, .. } = decode_frame(send) else {
        panic!("a framed HOP reply");
    };
    HopMessage::decode(payload).expect("a HOP message").status
}

fn denied(events: &[RelayServerEvent]) -> Vec<Status> {
    events
        .iter()
        .filter_map(|event| match event {
            RelayServerEvent::CircuitDenied { status, .. } => Some(*status),
            _ => None,
        })
        .collect()
}

fn negotiation_failed(stream: StreamKey) -> SwarmEvent {
    SwarmEvent::Error(SwarmRuntimeError {
        kind: SwarmErrorKind::OpenStreamFailed,
        peer_id: None,
        conn_id: Some(stream.conn_id),
        stream_id: Some(stream.stream_id),
        detail: "timed out".into(),
    })
}

#[test]
fn admitted_connect_opens_stop_on_the_reserved_exact_connection() {
    let source = peer(b"source");
    let destination = peer(b"destination");
    let mut node = Node::new(RelayServerConfig {
        max_circuit_bytes: 3,
        ..unlimited_rates()
    });
    let destination_stream = key(10, 1);
    node.reserve(&destination, destination_stream);
    node.establish(&source, ConnectionId::new(20));
    let source_stream = key(20, 2);
    node.feed_hop(
        &source,
        source_stream,
        connect_request(&destination),
        b"pipelined-source",
    );

    let calls = node.calls();
    let [
        Call::Open {
            peer: opened_for,
            protocol_id,
            opened: Some(stop_stream),
        },
    ] = &without_acks(calls)[..]
    else {
        panic!("an admitted CONNECT opens STOP and nothing else");
    };
    assert_eq!(*opened_for, destination);
    assert_eq!(protocol_id, minip2p_relay::STOP_PROTOCOL_ID);
    assert_eq!(stop_stream.conn_id, destination_stream.conn_id);
    let stop_stream = *stop_stream;
    assert!(node.events().is_empty());

    assert!(node.stop_ready(&destination, stop_stream, at(1)));
    assert_eq!(
        sends_on(&node.calls(), stop_stream).len(),
        1,
        "STOP CONNECT"
    );
    node.stop_status(&destination, stop_stream, Status::Ok, at(2));
    let calls = node.calls();
    assert_eq!(hop_reply_status(&calls, source_stream), Some(Status::Ok));
    // The pipelined payload is released after commit, and crosses the limit.
    assert_eq!(
        sends_on(&calls, stop_stream),
        [b"pipelined-source".to_vec()]
    );
    let events = node.events();
    assert!(
        matches!(
            events[..],
            [
                RelayServerEvent::CircuitOpened {
                    ref source_peer_id,
                    ref destination_peer_id,
                },
                RelayServerEvent::CircuitClosed {
                    bytes,
                    reason: CircuitCloseReason::ByteLimit {
                        direction: CircuitDirection::SourceToDestination,
                    },
                    ..
                },
            ] if *source_peer_id == source
                && *destination_peer_id == destination
                && bytes.source_to_destination == 16
                && bytes.destination_to_source == 0
        ),
        "{events:?}"
    );
}

#[test]
fn paused_connect_is_permission_denied_without_reserving_capacity() {
    let mut node = Node::new(RelayServerConfig::default());
    let destination = peer(b"paused-connect-destination");
    let source = peer(b"paused-connect-source");
    node.reserve(&destination, key(331, 1));
    node.establish(&source, ConnectionId::new(332));
    node.set_accepting(false);
    node.feed_hop(&source, key(332, 1), connect_request(&destination), &[]);
    assert_eq!(denied(&node.events()), [Status::PermissionDenied]);
    assert_eq!(node.circuit_count(), 0);
    assert_eq!(common::opened(&node.calls()), None);
}

/// A CONNECT refused for a reason other than its rate limit spends no
/// token: the source is admitted once the destination has reserved.
#[test]
fn a_refused_connect_spends_no_rate_token() {
    let mut node = Node::new(RelayServerConfig {
        circuit_rate_limit_per_peer: Some(RateLimit {
            capacity: 1,
            refill_interval_ms: 1_000_000,
        }),
        circuit_rate_limit_per_ip: None,
        reservation_rate_limit_per_peer: None,
        reservation_rate_limit_per_ip: None,
        ..RelayServerConfig::default()
    });
    let source = peer(b"source-connect-token");
    let destination = peer(b"destination-connect-token");
    node.establish(&source, ConnectionId::new(361));

    node.feed_hop(&source, key(361, 1), connect_request(&destination), &[]);
    assert_eq!(denied(&node.events()), [Status::NoReservation]);

    node.reserve(&destination, key(360, 1));
    node.feed_hop(&source, key(361, 2), connect_request(&destination), &[]);
    assert!(
        common::opened(&node.calls()).is_some(),
        "the source still holds its token: {:?}",
        node.events()
    );
}

#[test]
fn a_pending_circuit_leg_does_not_hold_a_hop_slot() {
    // The CONNECT took the source connection's only HOP slot, and its worker
    // is now a pending circuit leg.
    let Fixture {
        mut node, source, ..
    } = pending_stop(
        RelayServerConfig {
            max_pending_hop_requests_per_connection: 1,
            ..RelayServerConfig::default()
        },
        0,
    );
    let second = key(SOURCE_CONN.as_u64(), 3);
    node.hop_ready(&source, second, at(0));
    assert!(
        resets(&node.calls()).is_empty(),
        "a pending circuit leg must not hold a HOP slot"
    );

    // That second stream is an ordinary HOP worker, so it fills the slot: the
    // exclusion is for circuit legs, not a blanket opt-out.
    let third = key(SOURCE_CONN.as_u64(), 4);
    node.hop_ready(&source, third, at(0));
    assert_eq!(
        resets(&node.calls()),
        [third],
        "an ordinary HOP worker still holds the slot"
    );
}

#[test]
fn a_committed_circuit_leg_does_not_hold_a_hop_slot() {
    let Fixture {
        mut node,
        source,
        source_stream,
        ..
    } = connected_circuit(
        RelayServerConfig {
            max_pending_hop_requests_per_connection: 1,
            ..RelayServerConfig::default()
        },
        0,
    );
    assert!(node.owns_stream(source_stream));
    node.hop_ready(&source, key(SOURCE_CONN.as_u64(), 3), at(0));
    assert!(
        resets(&node.calls()).is_empty(),
        "a committed circuit leg must not hold a HOP slot"
    );
}

#[test]
fn a_failed_circuit_leg_holds_a_hop_slot_while_its_stream_stays_open() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = pending_stop(
        RelayServerConfig {
            max_pending_hop_requests_per_connection: 1,
            ..RelayServerConfig::default()
        },
        0,
    );

    // The destination refuses, so the circuit never commits. The HOP denial
    // completes, but the worker stays until the source closes its stream,
    // and with no circuit to exclude it, it must count again.
    node.stop_status(&destination, stop_stream, Status::PermissionDenied, at(0));
    assert!(node.owns_stream(source_stream));
    node.calls();

    let next = key(SOURCE_CONN.as_u64(), 3);
    node.hop_ready(&source, next, at(0));
    assert_eq!(
        resets(&node.calls()),
        [next],
        "a failed circuit's finished HOP worker must count again"
    );
}

#[test]
fn control_timeouts_release_hop_and_stop_ownership() {
    let remote = peer(b"peer-timeouts");
    let mut node = Node::new(timeout_5ms());
    let hop = key(80, 1);
    node.establish(&remote, hop.conn_id);
    node.hop_ready(&remote, hop, at(0));
    node.handle_tick(at(5));
    assert!(!node.owns_stream(hop));
    assert_eq!(resets(&node.calls()), [hop]);

    let Fixture {
        mut node,
        destination,
        stop_stream,
        ..
    } = pending_stop(timeout_5ms(), 0);
    node.handle_tick(at(5));
    assert_eq!(node.circuit_count(), 0);
    assert_eq!(denied(&node.events()), [Status::ConnectionFailed]);
    assert!(resets(&node.calls()).contains(&stop_stream));
    // The reset STOP stream is claimed until it closes.
    assert!(node.owns_stream(stop_stream));
    assert!(node.stream_closed(&destination, stop_stream, at(6)));
    assert!(!node.owns_stream(stop_stream));
}

#[test]
fn stop_refusal_statuses_map_exactly_to_hop() {
    for status in [Status::ResourceLimitExceeded, Status::PermissionDenied] {
        let Fixture {
            mut node,
            destination,
            stop_stream,
            ..
        } = pending_stop(RelayServerConfig::default(), 0);
        node.stop_status(&destination, stop_stream, status, at(1));
        assert_eq!(denied(&node.events()), [status]);
        assert_eq!(node.circuit_count(), 0);
    }
}

#[test]
fn self_and_global_circuit_capacity_are_enforced() {
    let config = RelayServerConfig {
        max_circuits: 4,
        max_circuits_per_peer: 2,
        ..unlimited_rates()
    };
    let remote = peer(b"self-circuit-peer");
    let mut node = Node::new(config.clone());
    node.reserve(&remote, key(110, 1));
    for stream_id in [2, 3, 4] {
        node.feed_hop(&remote, key(110, stream_id), connect_request(&remote), &[]);
        if stream_id <= 3 {
            assert!(common::opened(&node.calls()).is_some());
        } else {
            assert_eq!(denied(&node.events()), [Status::ResourceLimitExceeded]);
        }
    }

    let mut zero = Node::new(RelayServerConfig {
        max_circuits: 0,
        ..config
    });
    let destination = peer(b"zero-global-destination");
    let source = peer(b"zero-global-source");
    zero.reserve(&destination, key(120, 1));
    zero.establish(&source, ConnectionId::new(121));
    zero.feed_hop(&source, key(121, 1), connect_request(&destination), &[]);
    assert_eq!(denied(&zero.events()), [Status::ResourceLimitExceeded]);
}

#[test]
fn zero_stop_cap_denies_without_opening_a_stream() {
    let source = peer(b"source-stop-cap");
    let destination = peer(b"destination-stop-cap");
    let mut node = Node::new(RelayServerConfig {
        max_pending_stop_requests_per_connection: 0,
        ..unlimited_rates()
    });
    node.reserve(&destination, key(70, 1));
    node.establish(&source, ConnectionId::new(71));
    let source_stream = key(71, 2);
    node.feed_hop(&source, source_stream, connect_request(&destination), &[]);

    assert_eq!(denied(&node.events()), [Status::ResourceLimitExceeded]);
    let calls = node.calls();
    assert_eq!(common::opened(&calls), None);
    assert_eq!(
        hop_reply_status(&calls, source_stream),
        Some(Status::ResourceLimitExceeded)
    );
}

#[test]
fn failed_hop_success_delivery_cleans_both_precommit_legs() {
    let Fixture {
        mut node,
        destination,
        source_stream,
        stop_stream,
        ..
    } = pending_stop(RelayServerConfig::default(), 0);
    node.swarm.failing_sends.insert(source_stream);

    node.stop_status(&destination, stop_stream, Status::Ok, at(0));

    assert!(!node.owns_stream(source_stream));
    let reset = resets(&node.calls());
    assert!(reset.contains(&source_stream));
    assert!(reset.contains(&stop_stream));
    assert!(
        matches!(
            node.events()[..],
            [RelayServerEvent::Error(RelayServerRuntimeError {
                kind: RelayServerRuntimeErrorKind::SendStream,
                ..
            })]
        ),
        "no uncommitted lifecycle"
    );
}

#[test]
fn source_payload_arriving_during_stop_rtt_is_forwarded_after_commit() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = pending_stop(RelayServerConfig::default(), 0);
    node.data(&source, source_stream, b"during-stop-rtt", at(1));
    assert!(sends_on(&node.calls(), stop_stream).is_empty());
    node.stop_status(&destination, stop_stream, Status::Ok, at(1));
    assert_eq!(
        sends_on(&node.calls(), stop_stream),
        [b"during-stop-rtt".to_vec()]
    );
}

#[test]
fn precommit_payload_is_bounded_in_both_directions() {
    for direction in [
        CircuitDirection::SourceToDestination,
        CircuitDirection::DestinationToSource,
    ] {
        let Fixture {
            mut node,
            source,
            destination,
            source_stream,
            stop_stream,
        } = pending_stop(RelayServerConfig::default(), 0);
        let (peer_id, stream) = match direction {
            CircuitDirection::SourceToDestination => (source, source_stream),
            // The STATUS accepts, and the payload behind it overflows.
            CircuitDirection::DestinationToSource => (destination, stop_stream),
        };
        let mut data = match direction {
            CircuitDirection::SourceToDestination => Vec::new(),
            CircuitDirection::DestinationToSource => stop_status(Status::Ok),
        };
        data.resize(data.len() + MAX_PENDING_BRIDGE_SIZE + 1, 0);
        node.data(&peer_id, stream, &data, at(1));

        assert!(!node.owns_stream(source_stream), "{direction:?}");
        assert_eq!(node.circuit_count(), 0, "{direction:?}");
        let events = node.events();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, RelayServerEvent::CircuitOpened { .. })),
            "{direction:?}: {events:?}"
        );
    }
}

#[test]
fn source_reset_while_connect_is_pending_cleans_the_stop_leg() {
    let Fixture {
        mut node,
        source,
        source_stream,
        stop_stream,
        ..
    } = pending_stop(RelayServerConfig::default(), 0);

    assert!(node.stream_closed(&source, source_stream, at(1)));

    assert_eq!(node.circuit_count(), 0);
    assert!(!node.owns_stream(source_stream));
    assert_eq!(resets(&node.calls()), [stop_stream]);
    assert!(node.events().is_empty(), "no uncommitted lifecycle");
}

/// The source's half-close while STOP is pending reaches the destination
/// after commit, behind the payload it sent first.
#[test]
fn source_eof_while_connect_is_pending_follows_its_payload_after_commit() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = pending_stop(RelayServerConfig::default(), 0);
    node.data(&source, source_stream, b"buffered", at(1));
    node.half_close(&source, source_stream, at(1));
    assert_eq!(acked(&node.calls(), source_stream), 0, "payload waits");

    // The destination is full at commit: the FIN waits behind the payload.
    node.swarm.credit.insert(stop_stream, 0);
    node.stop_status(&destination, stop_stream, Status::Ok, at(1));
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::CircuitOpened { .. }]
    ));
    let committed = node.calls();
    assert!(common::closes(&committed).is_empty(), "{committed:?}");

    node.swarm.credit.remove(&stop_stream);
    node.writable(&destination, stop_stream, at(1));
    let drained = without_acks(node.calls());
    assert!(
        matches!(
            &drained[..],
            [Call::Send { stream: sent, data, .. }, Call::Close { stream: closed, .. }]
                if *sent == stop_stream && data == b"buffered" && *closed == stop_stream
        ),
        "{drained:?}"
    );
}

#[test]
fn replacing_a_leg_connection_closes_its_circuit() {
    for leg in [CircuitLeg::Source, CircuitLeg::Destination] {
        let Fixture {
            mut node,
            source,
            destination,
            source_stream,
            stop_stream,
        } = connected_circuit(RelayServerConfig::default(), 0);
        let (peer_id, old, other_stream) = match leg {
            CircuitLeg::Source => (&source, source_stream.conn_id, stop_stream),
            CircuitLeg::Destination => (&destination, stop_stream.conn_id, source_stream),
        };
        node.replace(peer_id, old, ConnectionId::new(62), false, 1);

        assert!(
            matches!(
                node.events()[..],
                [RelayServerEvent::CircuitClosed {
                    reason: CircuitCloseReason::ConnectionClosed { leg: closed },
                    ..
                }] if closed == leg
            ),
            "{leg:?}"
        );
        assert_eq!(node.circuit_count(), 0, "{leg:?}");
        assert_eq!(
            resets(&node.calls()),
            [other_stream],
            "{leg:?}: the surviving leg's stream is reset"
        );
        // Only the destination's own reservation follows its connection.
        let reservation_conn = match leg {
            CircuitLeg::Source => stop_stream.conn_id,
            CircuitLeg::Destination => ConnectionId::new(62),
        };
        assert_eq!(
            node.reservation_connection(&destination),
            Some(reservation_conn),
            "{leg:?}"
        );
    }
}

#[test]
fn replacing_the_destination_fails_a_pending_connect() {
    let Fixture {
        mut node,
        destination,
        source_stream,
        stop_stream,
        ..
    } = pending_stop(RelayServerConfig::default(), 0);
    node.replace(
        &destination,
        stop_stream.conn_id,
        ConnectionId::new(62),
        false,
        1,
    );

    assert_eq!(denied(&node.events()), [Status::ConnectionFailed]);
    let calls = node.calls();
    assert_eq!(
        hop_reply_status(&calls, source_stream),
        Some(Status::ConnectionFailed),
        "the source hears the failure"
    );
    assert!(
        resets(&calls).is_empty(),
        "the STOP stream went with its connection"
    );
    assert!(!node.owns_stream(stop_stream));
}

/// Closing a connection that carries one circuit's source leg, another's
/// destination leg, and a pending circuit's destination tears each down
/// through the indexes, leaving none of them pointing at it.
#[test]
fn closing_a_connection_with_both_circuit_legs_keeps_indexes_consistent() {
    // `relay` (connection 60) is the destination of a committed circuit from
    // `source` (connection 61).
    let Fixture {
        mut node,
        source,
        destination: relay,
        source_stream,
        stop_stream,
    } = connected_circuit(RelayServerConfig::default(), 0);
    let now = at(0);

    // `relay` is also the source of a committed circuit to `far`.
    let far = peer(b"far-both-legs");
    node.reserve(&far, key(70, 1));
    let outbound = key(DESTINATION_CONN.as_u64(), 5);
    let far_stop = key(70, 6);
    node.swarm.next_open = Some(far_stop);
    node.feed_hop(&relay, outbound, connect_request(&far), &[]);
    node.stop_ready(&far, far_stop, now);
    node.stop_status(&far, far_stop, Status::Ok, now);
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::CircuitOpened { .. }]
    ));

    node.calls();

    // A third peer's CONNECT to `relay` is still opening its STOP stream.
    let late = peer(b"late-both-legs");
    node.establish(&late, ConnectionId::new(71));
    node.feed_hop(&late, key(71, 7), connect_request(&relay), &[]);
    let late_stop = common::opened(&node.calls()).expect("STOP open");
    assert_eq!(late_stop.conn_id, DESTINATION_CONN);
    assert_eq!(node.circuit_count(), 3);

    node.close_connection(&relay, DESTINATION_CONN, 0);

    // Circuits close in source-stream order: the outbound one on connection
    // 60 first, then the inbound one from connection 61.
    let mut closed = Vec::new();
    let mut denied = 0;
    let mut open_failed = 0;
    let mut reservation_closed = false;
    for event in node.events() {
        match event {
            RelayServerEvent::CircuitClosed {
                reason: CircuitCloseReason::ConnectionClosed { leg },
                ..
            } => closed.push(leg),
            RelayServerEvent::CircuitDenied {
                source_peer_id,
                status: Status::ConnectionFailed,
                ..
            } if source_peer_id == late => denied += 1,
            RelayServerEvent::Error(RelayServerRuntimeError {
                kind: RelayServerRuntimeErrorKind::OpenStream,
                ..
            }) => open_failed += 1,
            RelayServerEvent::ReservationClosed {
                peer_id,
                reason: ReservationCloseReason::ConnectionClosed,
            } if peer_id == relay => reservation_closed = true,
            other => panic!("unexpected event {other:?}"),
        }
    }
    assert_eq!(closed, [CircuitLeg::Source, CircuitLeg::Destination]);
    assert_eq!((denied, open_failed), (1, 1));
    assert!(reservation_closed);

    assert_eq!(node.circuit_count(), 0);
    for stream in [stop_stream, outbound, late_stop] {
        assert!(!node.owns_stream(stream), "{stream:?}");
    }
    // The surviving legs were reset; `far`'s and `source`'s streams are
    // only claimed until they close.
    let reset = resets(&node.calls());
    assert!(reset.contains(&far_stop) && reset.contains(&source_stream));
    let _ = source;
}

#[test]
fn circuits_per_ip_count_either_end_and_a_shared_key_once() {
    let mut node = Node::new(RelayServerConfig {
        max_circuits_per_ip: 2,
        ..unlimited_rates()
    });
    let mut next_conn: u64 = 0;
    let mut destination = |node: &mut Node, name: &[u8], address: &str| {
        let remote = peer(name);
        next_conn += 1;
        node.swarm
            .remote_addrs
            .insert(ConnectionId::new(next_conn), common::maddr(address));
        node.reserve(&remote, key(next_conn, 1));
        remote
    };
    let d1 = destination(&mut node, b"d1", "/ip4/198.51.100.1/tcp/1");
    let d2 = destination(&mut node, b"d2", "/ip4/198.51.100.2/tcp/1");
    let d3 = destination(&mut node, b"d3", "/ip4/198.51.100.3/tcp/1");
    let shared = destination(&mut node, b"d4", "/ip4/192.0.2.50/tcp/1");

    let mut next_conn: u64 = 100;
    let mut connect = |node: &mut Node, address: &str, to: &minip2p_core::PeerId| {
        next_conn += 1;
        let source = peer(&next_conn.to_be_bytes());
        node.establish_from(&source, ConnectionId::new(next_conn), address);
        node.feed_hop(&source, key(next_conn, 1), connect_request(to), &[]);
        node.calls();
        match denied(&node.events())[..] {
            [status] => Err(status),
            [] => Ok(()),
            ref other => panic!("unexpected {other:?}"),
        }
    };
    let refused = Err(Status::ResourceLimitExceeded);

    // Two sources on one key fill it; their pending circuits count.
    let source_key = "/ip4/203.0.113.9/tcp/1";
    assert_eq!(connect(&mut node, source_key, &d1), Ok(()));
    assert_eq!(connect(&mut node, source_key, &d2), Ok(()));
    assert_eq!(connect(&mut node, source_key, &d3), refused);
    // The destination end counts too: d1's key holds one circuit.
    assert_eq!(connect(&mut node, "/ip4/203.0.113.10/tcp/1", &d1), Ok(()));
    assert_eq!(connect(&mut node, "/ip4/203.0.113.11/tcp/1", &d1), refused);
    // Both ends on one key count once, so two such circuits fit.
    let shared_key = "/ip4/192.0.2.50/tcp/2";
    assert_eq!(connect(&mut node, shared_key, &shared), Ok(()));
    assert_eq!(connect(&mut node, shared_key, &shared), Ok(()));
    assert_eq!(connect(&mut node, shared_key, &shared), refused);
}

// --- The STOP open: the one command whose result arrives later ---------------

/// A circuit abandoned while its STOP stream still negotiates cannot reset
/// that stream yet. Its late `StreamReady` resets it, and the relay claims
/// the stream's events until its terminal event.
#[test]
fn a_late_stop_readiness_after_a_timeout_or_source_close_resets_the_stream() {
    for cause in ["timeout", "source close"] {
        let Fixture {
            mut node,
            source,
            destination,
            source_stream,
            stop_stream,
        } = opening_stop(timeout_5ms());
        match cause {
            "timeout" => {
                node.handle_tick(at(5));
                assert_eq!(denied(&node.events()), [Status::ConnectionFailed]);
            }
            _ => {
                node.stream_closed(&source, source_stream, at(1));
                assert!(node.events().is_empty());
            }
        }
        assert!(
            !resets(&node.calls()).contains(&stop_stream),
            "{cause}: a negotiating stream cannot be reset"
        );
        assert!(node.owns_stream(stop_stream), "{cause}");

        assert!(node.stop_ready(&destination, stop_stream, at(6)), "{cause}");
        assert_eq!(
            node.calls(),
            [Call::Reset {
                peer: destination.clone(),
                stream: stop_stream,
            }],
            "{cause}"
        );
        assert!(node.data(&destination, stop_stream, b"late", at(6)));
        assert_eq!(acked(&node.calls(), stop_stream), 4, "{cause}");
        assert!(node.stream_closed(&destination, stop_stream, at(7)));
        assert!(
            !node.owns_stream(stop_stream),
            "{cause}: the record is gone"
        );
        assert!(!node.data(&destination, stop_stream, b"after", at(7)));
        assert!(node.events().is_empty(), "{cause}");
    }
}

/// An abandoned STOP stream whose negotiation fails, or whose connection
/// closes, needs no reset and is forgotten.
#[test]
fn an_abandoned_stop_open_is_forgotten_at_its_failure_or_connection_close() {
    for terminal in ["negotiation failure", "connection close"] {
        let Fixture {
            mut node,
            source,
            destination,
            source_stream,
            stop_stream,
        } = opening_stop(RelayServerConfig::default());
        node.stream_closed(&source, source_stream, at(1));
        match terminal {
            "negotiation failure" => {
                assert!(node.handle_event(&negotiation_failed(stop_stream), false, at(2)));
            }
            _ => node.close_connection(&destination, DESTINATION_CONN, 2),
        }
        assert!(!node.owns_stream(stop_stream), "{terminal}");
        assert!(resets(&node.calls()).is_empty(), "{terminal}");
    }
}

/// Settlement runs behind the event's deadline sweep: readiness at the
/// deadline finds the circuit already timed out, and resets the stream.
#[test]
fn stop_readiness_at_the_deadline_times_the_circuit_out() {
    let Fixture {
        mut node,
        destination,
        source_stream,
        stop_stream,
        ..
    } = opening_stop(timeout_5ms());

    assert!(node.stop_ready(&destination, stop_stream, at(5)));

    assert_eq!(denied(&node.events()), [Status::ConnectionFailed]);
    let calls = node.calls();
    assert_eq!(
        hop_reply_status(&calls, source_stream),
        Some(Status::ConnectionFailed)
    );
    assert!(sends_on(&calls, stop_stream).is_empty(), "no STOP CONNECT");
    assert_eq!(resets(&calls), [stop_stream]);
}

#[test]
fn stop_acceptance_at_the_deadline_times_the_circuit_out() {
    let Fixture {
        mut node,
        destination,
        stop_stream,
        ..
    } = pending_stop(timeout_5ms(), 0);
    let status = stop_status(Status::Ok);

    assert!(node.data(&destination, stop_stream, &status, at(5)));

    assert_eq!(denied(&node.events()), [Status::ConnectionFailed]);
    assert_eq!(node.circuit_count(), 0);
    let calls = node.calls();
    assert_eq!(resets(&calls), [stop_stream]);
    assert_eq!(
        acked(&calls, stop_stream),
        status.len(),
        "claimed and consumed"
    );
}

/// Opens are peer-scoped, so one can land on a connection that replaced the
/// reservation's before the relay heard of it. That stream is not the
/// reserved destination's: it is reset once it negotiates.
#[test]
fn an_open_on_another_connection_is_reset_and_the_circuit_fails() {
    let source = peer(b"source-wrong-connection");
    let destination = peer(b"destination-wrong-connection");
    let mut node = Node::new(unlimited_rates());
    node.reserve(&destination, key(60, 1));
    node.establish(&source, ConnectionId::new(61));
    let elsewhere = key(62, 9);
    node.swarm.next_open = Some(elsewhere);
    node.feed_hop(&source, key(61, 2), connect_request(&destination), &[]);

    assert_eq!(denied(&node.events()), [Status::NoReservation]);
    assert_eq!(node.circuit_count(), 0);
    assert!(resets(&node.calls()).is_empty());
    assert!(node.stop_ready(&destination, elsewhere, at(1)));
    assert_eq!(resets(&node.calls()), [elsewhere]);
}

#[test]
fn a_stop_open_that_fails_fails_the_circuit() {
    for failure in ["refused", "negotiation failure", "closed while negotiating"] {
        let Fixture {
            mut node,
            destination,
            source_stream,
            stop_stream,
            ..
        } = match failure {
            "refused" => {
                let mut node = Node::new(unlimited_rates());
                let source = peer(b"source");
                let destination = peer(b"destination");
                node.reserve(&destination, key(60, 1));
                node.establish(&source, SOURCE_CONN);
                node.swarm.refuse_opens = true;
                node.feed_hop(&source, key(61, 2), connect_request(&destination), &[]);
                Fixture {
                    node,
                    source,
                    destination,
                    source_stream: key(61, 2),
                    stop_stream: key(60, 3),
                }
            }
            _ => opening_stop(RelayServerConfig::default()),
        };
        match failure {
            "negotiation failure" => {
                assert!(node.handle_event(&negotiation_failed(stop_stream), false, at(1)));
            }
            "closed while negotiating" => {
                assert!(node.stream_closed(&destination, stop_stream, at(1)));
            }
            _ => {}
        }
        let events = node.events();
        assert!(
            matches!(
                events[..],
                [
                    RelayServerEvent::Error(RelayServerRuntimeError {
                        kind: RelayServerRuntimeErrorKind::OpenStream,
                        ..
                    }),
                    RelayServerEvent::CircuitDenied {
                        status: Status::ConnectionFailed,
                        ..
                    },
                ]
            ),
            "{failure}: {events:?}"
        );
        assert_eq!(node.circuit_count(), 0, "{failure}");
        assert!(!node.owns_stream(stop_stream), "{failure}");
        let calls = node.calls();
        assert_eq!(
            hop_reply_status(&calls, source_stream),
            Some(Status::ConnectionFailed),
            "{failure}"
        );
        assert!(resets(&calls).is_empty(), "{failure}: the stream is gone");
    }
}

#[test]
fn an_unrelated_swarm_error_is_not_claimed() {
    let Fixture {
        mut node,
        stop_stream,
        ..
    } = opening_stop(RelayServerConfig::default());
    let unrelated = SwarmEvent::Error(SwarmRuntimeError {
        kind: SwarmErrorKind::Ping,
        peer_id: None,
        conn_id: Some(stop_stream.conn_id),
        stream_id: Some(stop_stream.stream_id),
        detail: "ping".into(),
    });
    assert!(!node.handle_event(&unrelated, false, at(1)));
    assert_eq!(node.circuit_count(), 1);
}

/// A STOP CONNECT the destination's stream takes only part of fails the
/// circuit, and the stream is reset rather than left with a truncated
/// request.
#[test]
fn a_truncated_stop_request_fails_the_circuit_and_resets_the_stream() {
    let Fixture {
        mut node,
        destination,
        source_stream,
        stop_stream,
        ..
    } = opening_stop(RelayServerConfig::default());
    node.swarm.credit.insert(stop_stream, 1);

    assert!(node.stop_ready(&destination, stop_stream, at(1)));

    let events = node.events();
    assert!(
        matches!(
            events[..],
            [
                RelayServerEvent::CircuitDenied {
                    status: Status::ConnectionFailed,
                    ..
                },
                RelayServerEvent::Error(RelayServerRuntimeError {
                    kind: RelayServerRuntimeErrorKind::SendStream,
                    ..
                }),
            ]
        ),
        "{events:?}"
    );
    let calls = node.calls();
    assert_eq!(resets(&calls), [stop_stream]);
    assert!(
        common::closes(&calls)
            .iter()
            .all(|stream| *stream == source_stream)
    );
}
