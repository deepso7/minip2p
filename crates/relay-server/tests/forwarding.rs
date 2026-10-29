//! Committed-circuit forwarding: ADR 0012 backpressure, read credit,
//! half-close propagation, and the byte and duration limits.

mod common;

use common::{
    Call, Fixture, acked, at, closes, connect_request, connected_circuit, pending_stop,
    pending_stop_with_payload, resets, sends_on, stop_status, without_acks,
};
use minip2p_relay::{Status, encode_frame};
use minip2p_relay_server::{
    CircuitByteCounts, CircuitCloseReason, CircuitDirection, RelayServerConfig, RelayServerEvent,
    RelayServerRuntimeError, RelayServerRuntimeErrorKind,
};
use minip2p_swarm::SwarmEvent;

fn closed_for(events: &[RelayServerEvent]) -> Vec<(CircuitCloseReason, CircuitByteCounts)> {
    events
        .iter()
        .filter_map(|event| match event {
            RelayServerEvent::CircuitClosed { reason, bytes, .. } => Some((*reason, *bytes)),
            _ => None,
        })
        .collect()
}

fn bytes(source_to_destination: u64, destination_to_source: u64) -> CircuitByteCounts {
    CircuitByteCounts {
        source_to_destination,
        destination_to_source,
    }
}

#[test]
fn directional_equality_stays_open_and_failed_send_counts_no_bytes() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = connected_circuit(
        RelayServerConfig {
            max_circuit_bytes: 3,
            ..RelayServerConfig::default()
        },
        10,
    );
    node.data(&source, source_stream, b"abc", at(11));
    assert_eq!(sends_on(&node.calls(), stop_stream), [b"abc".to_vec()]);
    assert!(node.events().is_empty(), "equality remains open");

    node.swarm.failing_sends.insert(source_stream);
    node.data(&destination, stop_stream, b"not-counted", at(12));
    let events = node.events();
    assert_eq!(
        closed_for(&events),
        [(
            CircuitCloseReason::ForwardFailed {
                direction: CircuitDirection::DestinationToSource,
            },
            bytes(3, 0),
        )]
    );
    assert!(matches!(
        events.last(),
        Some(RelayServerEvent::Error(RelayServerRuntimeError {
            kind: RelayServerRuntimeErrorKind::SendStream,
            ..
        }))
    ));
}

#[test]
fn circuit_duration_is_commit_relative_and_terminal_once() {
    let Fixture {
        mut node,
        source,
        source_stream,
        ..
    } = connected_circuit(
        RelayServerConfig {
            max_circuit_duration_secs: 1,
            ..RelayServerConfig::default()
        },
        10,
    );
    node.handle_tick(at(1_009));
    assert!(node.events().is_empty());
    node.handle_tick(at(1_010));
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::CircuitClosed {
            reason: CircuitCloseReason::DurationLimit,
            ..
        }]
    ));
    node.stream_closed(&source, source_stream, at(1_010));
    node.handle_tick(at(2_000));
    assert!(node.events().is_empty());
}

#[test]
fn write_stop_on_a_circuit_leg_resets_it_before_teardown() {
    let Fixture {
        mut node,
        destination,
        stop_stream,
        ..
    } = connected_circuit(RelayServerConfig::default(), 0);
    let claimed = node.handle_event(
        &SwarmEvent::StreamWriteStopped {
            peer_id: destination,
            conn_id: stop_stream.conn_id,
            stream_id: stop_stream.stream_id,
            error_code: 0,
        },
        false,
        at(1),
    );
    assert!(claimed);
    assert_eq!(resets(&node.calls()), [stop_stream]);
}

#[test]
fn bidirectional_eof_propagates_half_closes_and_finishes_cleanly() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = connected_circuit(RelayServerConfig::default(), 0);
    node.half_close(&source, source_stream, at(1));
    assert_eq!(closes(&node.calls()), [stop_stream]);
    assert!(node.events().is_empty());

    node.half_close(&destination, stop_stream, at(2));
    assert_eq!(closes(&node.calls()), [source_stream]);
    assert_eq!(
        closed_for(&node.events()),
        [(CircuitCloseReason::Eof, bytes(0, 0))]
    );
}

#[test]
fn a_full_destination_pauses_the_source_until_writable() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = connected_circuit(RelayServerConfig::default(), 0);
    let now = at(1);

    // The destination takes three bytes: only those are acknowledged, so the
    // source's credit stays withheld for the rest.
    node.swarm.credit.insert(stop_stream, 3);
    node.data(&source, source_stream, b"abcdef", now);
    let paused = node.calls();
    assert_eq!(sends_on(&paused, stop_stream), [b"abcdef".to_vec()]);
    assert_eq!(acked(&paused, source_stream), 3);
    assert!(node.events().is_empty(), "the circuit stays open");

    // More source bytes queue behind the held tail.
    node.data(&source, source_stream, b"gh", now);
    assert!(node.calls().is_empty());

    // The destination's Writable resumes forwarding, in order.
    node.swarm.credit.remove(&stop_stream);
    assert!(node.writable(&destination, stop_stream, now));
    let resumed = node.calls();
    assert_eq!(
        sends_on(&resumed, stop_stream),
        [b"def".to_vec(), b"gh".to_vec()]
    );
    assert_eq!(acked(&resumed, source_stream), 5);
    assert!(node.events().is_empty());
}

#[test]
fn a_source_fin_follows_the_last_held_byte() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = connected_circuit(RelayServerConfig::default(), 0);
    let now = at(1);
    node.swarm.credit.insert(stop_stream, 2);
    node.data(&source, source_stream, b"abcd", now);
    node.half_close(&source, source_stream, now);
    assert!(
        closes(&node.calls()).is_empty(),
        "no FIN while bytes are held"
    );

    node.swarm.credit.remove(&stop_stream);
    node.writable(&destination, stop_stream, now);
    let drained = without_acks(node.calls());
    assert!(
        matches!(
            &drained[..],
            [Call::Send { stream: sent, data, .. }, Call::Close { stream: closed, .. }]
                if *sent == stop_stream && data == b"cd" && *closed == stop_stream
        ),
        "{drained:?}"
    );
}

#[test]
fn a_leg_that_closes_gracefully_keeps_the_other_direction_draining() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = connected_circuit(RelayServerConfig::default(), 0);
    let now = at(1);
    // The source finishes first; its FIN reaches the destination.
    node.half_close(&source, source_stream, now);
    assert_eq!(closes(&node.calls()), [stop_stream]);

    // The destination answers, the source leg is full, then the destination
    // finishes and its stream closes cleanly.
    node.swarm.credit.insert(source_stream, 3);
    node.data(&destination, stop_stream, b"reply", now);
    node.half_close(&destination, stop_stream, now);
    node.stream_closed(&destination, stop_stream, now);
    assert!(node.events().is_empty(), "the circuit stays open");
    let closed = node.calls();
    assert!(resets(&closed).is_empty(), "nothing is reset: {closed:?}");

    // The held reply still reaches the source, then its FIN. The wakeup
    // that finishes the circuit is still the relay's, not the application's.
    node.swarm.credit.remove(&source_stream);
    assert!(node.writable(&source, source_stream, now));
    let drained = without_acks(node.calls());
    assert!(
        matches!(
            &drained[..],
            [Call::Send { stream: sent, data, .. }, Call::Close { stream: closed, .. }]
                if *sent == source_stream && data == b"ly" && *closed == source_stream
        ),
        "{drained:?}"
    );
    assert_eq!(
        closed_for(&node.events()),
        [(CircuitCloseReason::Eof, bytes(0, 5))]
    );
}

/// Both sides' payload pipelined with the handshake is held while STOP is
/// pending, forwarded with the commit, and each byte acknowledged exactly
/// once, as its target accepts it.
#[test]
fn pipelined_payload_from_both_sides_is_acknowledged_once_forwarded() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = pending_stop(RelayServerConfig::default(), 0);
    let now = at(1);
    node.data(&source, source_stream, b"abcd", now);
    assert_eq!(acked(&node.calls(), source_stream), 0);

    // The STOP response carries destination payload behind it; the
    // destination takes only half of what the source pipelined.
    node.swarm.credit.insert(stop_stream, 2);
    let status = stop_status(Status::Ok);
    let mut response = status.clone();
    response.extend_from_slice(b"xy");
    node.data(&destination, stop_stream, &response, now);
    let committed = node.calls();
    assert_eq!(sends_on(&committed, stop_stream), [b"abcd".to_vec()]);
    assert_eq!(
        sends_on(&committed, source_stream).len(),
        2,
        "HOP OK, then xy"
    );
    assert_eq!(sends_on(&committed, source_stream)[1], b"xy");
    assert_eq!(acked(&committed, source_stream), 2);
    assert_eq!(acked(&committed, stop_stream), status.len() + 2);

    node.swarm.credit.remove(&stop_stream);
    node.writable(&destination, stop_stream, now);
    let resumed = node.calls();
    assert_eq!(acked(&resumed, source_stream), 2);
    assert_eq!(acked(&resumed, stop_stream), 0);
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::CircuitOpened { .. }]
    ));
}

#[test]
fn payload_coalesced_with_connect_is_acknowledged_only_once_forwarded() {
    let source = common::peer(b"source-coalesced");
    let destination = common::peer(b"destination-coalesced");
    let mut node = common::Node::new(common::unlimited_rates());
    node.reserve(&destination, common::key(60, 1));
    node.establish(&source, common::SOURCE_CONN);
    let source_stream = common::key(61, 2);
    node.feed_hop(
        &source,
        source_stream,
        connect_request(&destination),
        b"abcd",
    );
    // The CONNECT read acknowledged only its own frame.
    let connect = encode_frame(&connect_request(&destination).encode());
    let opened = node.calls();
    assert_eq!(acked(&opened, source_stream), connect.len());
    let stop_stream = common::opened(&opened).expect("STOP open");
    node.stop_ready(&destination, stop_stream, at(1));
    node.calls();

    node.swarm.credit.insert(stop_stream, 2);
    let status = stop_status(Status::Ok);
    node.data(&destination, stop_stream, &status, at(1));
    let accepted = node.calls();
    assert_eq!(acked(&accepted, stop_stream), status.len());
    assert_eq!(sends_on(&accepted, stop_stream), [b"abcd".to_vec()]);
    assert_eq!(acked(&accepted, source_stream), 2);
}

#[test]
fn payload_held_with_connect_precedes_later_pipelined_reads() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = pending_stop_with_payload(RelayServerConfig::default(), 0, b"ab");
    let now = at(1);
    node.data(&source, source_stream, b"cd", now);
    node.stop_status(&destination, stop_stream, Status::Ok, now);
    let calls = node.calls();
    assert_eq!(sends_on(&calls, stop_stream), [b"abcd".to_vec()]);
    assert_eq!(acked(&calls, source_stream), 4);
}

#[test]
fn tiny_reads_to_a_paused_destination_are_coalesced_in_order() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = connected_circuit(RelayServerConfig::default(), 0);
    let now = at(1);
    node.swarm.credit.insert(stop_stream, 0);
    node.data(&source, source_stream, b"\xff", now);
    node.calls();

    // One-byte reads while the destination is full cost one queue entry per
    // coalesced run, not one per read.
    let expected: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
    for byte in &expected {
        node.data(&source, source_stream, &[*byte], now);
    }
    assert!(node.calls().is_empty());

    // Resuming delivers every byte in order, in a few coalesced writes, and
    // acknowledges each once.
    node.swarm.credit.remove(&stop_stream);
    node.writable(&destination, stop_stream, now);
    let resumed = node.calls();
    let delivered = sends_on(&resumed, stop_stream);
    assert!(delivered.len() <= 4, "{} writes", delivered.len());
    let delivered = delivered.concat();
    assert_eq!(delivered[0], 0xff);
    assert_eq!(&delivered[1..], &expected[..]);
    assert_eq!(acked(&resumed, source_stream), 1 + expected.len());
}

#[test]
fn a_failed_connect_releases_payload_held_with_the_connect() {
    let Fixture {
        mut node,
        destination,
        source_stream,
        stop_stream,
        ..
    } = pending_stop_with_payload(RelayServerConfig::default(), 0, b"abcd");
    node.stop_status(&destination, stop_stream, Status::PermissionDenied, at(1));
    assert_eq!(acked(&node.calls(), source_stream), 4);
}

#[test]
fn a_failed_connect_releases_the_credit_of_pipelined_payload() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = pending_stop(RelayServerConfig::default(), 0);
    let now = at(1);
    node.data(&source, source_stream, b"abcd", now);
    node.stop_status(&destination, stop_stream, Status::PermissionDenied, now);
    assert_eq!(acked(&node.calls(), source_stream), 4);
}

#[test]
fn an_accepted_prefix_counts_toward_the_byte_limit() {
    let Fixture {
        mut node,
        source,
        source_stream,
        stop_stream,
        ..
    } = connected_circuit(
        RelayServerConfig {
            max_circuit_bytes: 3,
            ..RelayServerConfig::default()
        },
        0,
    );
    node.swarm.credit.insert(stop_stream, 4);
    node.data(&source, source_stream, b"abcdef", at(1));
    assert_eq!(
        closed_for(&node.events()),
        [(
            CircuitCloseReason::ByteLimit {
                direction: CircuitDirection::SourceToDestination,
            },
            bytes(4, 0),
        )]
    );
    let closed = node.calls();
    assert_eq!(resets(&closed).len(), 2, "both legs reset: {closed:?}");
}

#[test]
fn the_duration_limit_closes_a_paused_circuit() {
    let Fixture {
        mut node,
        source,
        source_stream,
        stop_stream,
        ..
    } = connected_circuit(
        RelayServerConfig {
            max_circuit_duration_secs: 1,
            ..RelayServerConfig::default()
        },
        0,
    );
    node.swarm.credit.insert(stop_stream, 0);
    node.data(&source, source_stream, b"abcd", at(1));

    node.handle_tick(at(1_000));
    assert!(matches!(
        node.events()[..],
        [RelayServerEvent::CircuitClosed {
            reason: CircuitCloseReason::DurationLimit,
            ..
        }]
    ));
}

#[test]
fn closing_releases_the_credit_of_bytes_never_forwarded() {
    let Fixture {
        mut node,
        source,
        source_stream,
        stop_stream,
        ..
    } = connected_circuit(RelayServerConfig::default(), 0);
    let now = at(1);
    node.swarm.credit.insert(stop_stream, 2);
    node.data(&source, source_stream, b"abcd", now);
    node.data(&source, source_stream, b"ef", now);
    assert_eq!(acked(&node.calls(), source_stream), 2);

    // The source resets: its stream is not reset by the relay, so it stays
    // unsettled until the four held bytes are acknowledged.
    node.stream_closed(&source, source_stream, now);
    assert_eq!(acked(&node.calls(), source_stream), 4);
}

#[test]
fn failed_eof_half_close_terminates_the_committed_circuit() {
    let Fixture {
        mut node,
        source,
        source_stream,
        stop_stream,
        ..
    } = connected_circuit(RelayServerConfig::default(), 0);
    node.swarm.failing_closes.insert(stop_stream);
    node.half_close(&source, source_stream, at(1));

    let events = node.events();
    assert!(
        matches!(
            events[..],
            [
                RelayServerEvent::CircuitClosed {
                    reason: CircuitCloseReason::InternalFailure,
                    ..
                },
                RelayServerEvent::Error(RelayServerRuntimeError {
                    kind: RelayServerRuntimeErrorKind::CloseStream,
                    ..
                }),
            ]
        ),
        "{events:?}"
    );
}

#[test]
fn zero_circuit_limits_remain_unlimited() {
    let Fixture {
        mut node,
        source,
        destination,
        source_stream,
        stop_stream,
    } = connected_circuit(
        RelayServerConfig {
            max_circuit_duration_secs: 0,
            max_circuit_bytes: 0,
            ..RelayServerConfig::default()
        },
        0,
    );
    node.data(&source, source_stream, &[1; 256], at(1));
    node.data(&destination, stop_stream, &[2; 256], at(1));
    let calls = node.calls();
    assert_eq!(sends_on(&calls, stop_stream).len(), 1);
    assert_eq!(sends_on(&calls, source_stream).len(), 1);
    node.handle_tick(at(1_000_000));
    assert!(node.owns_stream(source_stream));
    assert!(node.owns_stream(stop_stream));
    assert!(node.events().is_empty());
}
