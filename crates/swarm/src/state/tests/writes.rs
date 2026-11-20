use super::*;

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
