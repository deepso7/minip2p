use super::*;

const LIMITED: &str = "/limited/1";
const FREE: &str = "/free/1";

fn setup() -> (SwarmState, ConnectionId, PeerId) {
    let mut state = test_core();
    state.add_protocol(LIMITED).unwrap();
    state.add_protocol(FREE).unwrap();
    state
        .inbound_limits
        .insert(LIMITED.into(), NonZeroUsize::new(1).unwrap());
    let conn = ConnectionId::new(1);
    let peer = PeerId::from_public_key_protobuf(b"admission");
    state.conn_to_peer.insert(conn, peer);
    state.peer_to_conn.insert(peer, conn);
    state.established_peers.insert(peer);
    (state, conn, peer)
}

fn incoming(
    state: &mut SwarmState,
    conn: ConnectionId,
    stream: StreamId,
    protocol: &str,
    tail: &[u8],
) {
    state.handle_incoming_stream(conn, stream, 0);
    let mut data = multistream_frame(MULTISTREAM_PROTOCOL_ID);
    data.extend(multistream_frame(protocol));
    data.extend(tail);
    state.handle_stream_data(conn, stream, Bytes::from(data), 0);
}

fn ready(events: &[SwarmEvent]) -> Vec<StreamId> {
    events
        .iter()
        .filter_map(|e| match e {
            SwarmEvent::StreamReady { stream_id, .. } => Some(*stream_id),
            _ => None,
        })
        .collect()
}

#[test]
fn inbound_limit_is_fifo_and_replays_unacknowledged_data_before_fin() {
    let (mut state, conn, _) = setup();
    let [a, b, c] = [1, 2, 3].map(StreamId::new);
    incoming(&mut state, conn, a, LIMITED, &[]);
    assert_eq!(ready(&drain_events(&mut state)), [a]);
    incoming(&mut state, conn, b, LIMITED, b"leftover");
    let negotiation_acked: usize = state
        .actions
        .iter()
        .filter_map(|action| match action {
            Action::AckStream {
                stream_id, bytes, ..
            } if *stream_id == b => Some(*bytes),
            _ => None,
        })
        .sum();
    assert_eq!(
        negotiation_acked,
        multistream_frame(MULTISTREAM_PROTOCOL_ID).len() + multistream_frame(LIMITED).len()
    );
    state.actions.clear();
    state.handle_stream_data(conn, b, Bytes::from_static(b"later"), 0);
    state.handle_stream_remote_write_closed(conn, b);
    incoming(&mut state, conn, c, LIMITED, &[]);
    assert!(!state.actions.iter().any(|action| matches!(action,
        Action::AckStream { stream_id, .. } if *stream_id == b)));
    assert!(drain_events(&mut state).is_empty());
    state.handle_stream_closed(conn, a);
    assert!(!state.actions.iter().any(|action| matches!(action,
        Action::AckStream { stream_id, .. } if *stream_id == b)));
    let events = drain_events(&mut state);
    assert!(matches!(&events[..], [
        SwarmEvent::StreamClosed { stream_id, .. },
        SwarmEvent::StreamReady { stream_id: next, .. },
        SwarmEvent::StreamData { data: first, .. },
        SwarmEvent::StreamData { data: second, .. },
        SwarmEvent::StreamRemoteWriteClosed { .. },
    ] if *stream_id == a && *next == b && first.as_ref() == b"leftover" && second.as_ref() == b"later"));
    assert!(!state.actions.iter().any(|action| matches!(action,
        Action::AckStream { stream_id, .. } if *stream_id == b)));
    state.handle_stream_closed(conn, b);
    assert_eq!(ready(&drain_events(&mut state)), [c]);
}

#[test]
fn queued_reset_is_silent_and_acknowledges_discarded_bytes() {
    let (mut state, conn, _) = setup();
    let [a, b, c] = [1, 2, 3].map(StreamId::new);
    incoming(&mut state, conn, a, LIMITED, &[]);
    drain_events(&mut state);
    incoming(&mut state, conn, b, LIMITED, b"discard");
    incoming(&mut state, conn, c, LIMITED, &[]);
    state.actions.clear();
    state.handle_stream_closed(conn, b);
    assert!(
        state
            .actions
            .iter()
            .any(|a| matches!(a, Action::AckStream { stream_id, bytes: 7, .. } if *stream_id == b))
    );
    assert!(drain_events(&mut state).is_empty());
    state.handle_stream_closed(conn, a);
    assert_eq!(ready(&drain_events(&mut state)), [c]);
}

#[test]
fn reset_and_abandon_release_active_slots() {
    for abandon in [false, true] {
        let (mut state, conn, peer) = setup();
        let [a, b] = [1, 2].map(StreamId::new);
        incoming(&mut state, conn, a, LIMITED, &[]);
        incoming(&mut state, conn, b, LIMITED, &[]);
        assert_eq!(ready(&drain_events(&mut state)), [a]);
        if abandon {
            state.abandon_stream(&peer, conn, a).unwrap();
        } else {
            state.reset_stream(&peer, conn, a).unwrap();
            state.handle_stream_closed(conn, a);
        }
        assert_eq!(ready(&drain_events(&mut state)), [b]);
    }
}

#[test]
fn connection_cleanup_drops_queued_streams_and_admits_other_peers() {
    let (mut state, conn, _) = setup();
    let other = ConnectionId::new(2);
    let peer = PeerId::from_public_key_protobuf(b"other");
    state.conn_to_peer.insert(other, peer);
    state.peer_to_conn.insert(peer, other);
    let [a, b, c] = [1, 2, 3].map(StreamId::new);
    incoming(&mut state, conn, a, LIMITED, &[]);
    incoming(&mut state, conn, b, LIMITED, b"discard");
    incoming(&mut state, other, c, LIMITED, &[]);
    assert_eq!(ready(&drain_events(&mut state)), [a]);
    state.actions.clear();
    state.handle_connection_closed(conn, ConnectionCloseReason::Local);
    assert!(state.actions.iter().any(
        |action| matches!(action, Action::AckStream { stream_id, bytes: 7, .. } if *stream_id == b)
    ));
    let events = drain_events(&mut state);
    assert!(matches!(
        events.first(),
        Some(SwarmEvent::ConnectionClosed { .. })
    ));
    assert_eq!(ready(&events), [c]);
}

#[test]
fn abandoning_a_queued_stream_discards_it_without_using_a_slot() {
    let (mut state, conn, peer) = setup();
    let [a, b, c] = [1, 2, 3].map(StreamId::new);
    incoming(&mut state, conn, a, LIMITED, &[]);
    incoming(&mut state, conn, b, LIMITED, b"discard");
    incoming(&mut state, conn, c, LIMITED, &[]);
    drain_events(&mut state);
    state.abandon_stream(&peer, conn, b).unwrap();
    assert!(drain_events(&mut state).is_empty());
    state.handle_stream_closed(conn, a);
    assert_eq!(ready(&drain_events(&mut state)), [c]);
    state.handle_stream_closed(conn, b);
    assert!(drain_events(&mut state).is_empty());
}

#[test]
fn replacement_releases_slots_and_preserves_discard_acknowledgements() {
    let (mut state, conn, peer) = setup();
    let other = ConnectionId::new(2);
    let other_peer = PeerId::from_public_key_protobuf(b"replacement-other");
    state.conn_to_peer.insert(other, other_peer);
    state.peer_to_conn.insert(other_peer, other);
    let [a, b, c] = [1, 2, 3].map(StreamId::new);
    incoming(&mut state, conn, a, LIMITED, &[]);
    incoming(&mut state, conn, b, LIMITED, b"discard");
    incoming(&mut state, other, c, LIMITED, &[]);
    drain_events(&mut state);
    state.register_connection(ConnectionId::new(3), peer, None, 10_000);
    assert!(state.actions.iter().any(|action| matches!(action, Action::AckStream { conn_id, stream_id, bytes: 7 } if *conn_id == conn && *stream_id == b)));
    let events = drain_events(&mut state);
    let replacement = events
        .iter()
        .position(|e| matches!(e, SwarmEvent::ConnectionReplaced { old, .. } if *old == conn))
        .unwrap();
    let admission = events
        .iter()
        .position(|e| matches!(e, SwarmEvent::StreamReady { stream_id, .. } if *stream_id == c))
        .unwrap();
    assert!(replacement < admission);
    assert_eq!(ready(&events), [c]);
}

#[test]
fn outbound_and_uncapped_streams_do_not_use_inbound_slots() {
    let (mut state, conn, _) = setup();
    let [a, b, c, d] = [1, 2, 3, 4].map(StreamId::new);
    state.on_outbound_negotiated(conn, a, ProtocolKind::User(LIMITED.into()), 0);
    incoming(&mut state, conn, b, LIMITED, &[]);
    incoming(&mut state, conn, c, FREE, b"free");
    incoming(&mut state, conn, d, FREE, &[]);
    assert_eq!(ready(&drain_events(&mut state)), [a, b, c, d]);
}

#[test]
fn admission_happens_before_the_next_transport_event() {
    let (mut state, conn, _) = setup();
    let [a, b] = [1, 2].map(StreamId::new);
    incoming(&mut state, conn, a, LIMITED, &[]);
    incoming(&mut state, conn, b, LIMITED, b"held");
    drain_events(&mut state);
    state.handle_stream_closed(conn, a);
    state.handle_stream_closed(conn, b);
    let events = drain_events(&mut state);
    assert!(matches!(&events[..], [
        SwarmEvent::StreamClosed { stream_id: first, .. },
        SwarmEvent::StreamReady { stream_id: admitted, .. },
        SwarmEvent::StreamData { data, .. },
        SwarmEvent::StreamClosed { stream_id: last, .. },
    ] if *first == a && *admitted == b && data.as_ref() == b"held" && *last == b));
}

#[test]
fn limits_are_independent_between_protocols() {
    let (mut state, conn, _) = setup();
    state
        .inbound_limits
        .insert(FREE.into(), NonZeroUsize::new(1).unwrap());
    let [a, b, c, d] = [1, 2, 3, 4].map(StreamId::new);
    incoming(&mut state, conn, a, LIMITED, &[]);
    incoming(&mut state, conn, b, LIMITED, &[]);
    incoming(&mut state, conn, c, FREE, &[]);
    incoming(&mut state, conn, d, FREE, &[]);
    assert_eq!(ready(&drain_events(&mut state)), [a, c]);
    state.handle_stream_closed(conn, c);
    assert_eq!(ready(&drain_events(&mut state)), [d]);
    state.handle_stream_closed(conn, a);
    assert_eq!(ready(&drain_events(&mut state)), [b]);
}
