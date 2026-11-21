use super::*;

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

    assert!(
        core.connected_peers().contains(&peer_id),
        "connected_peers reflects the peer before the event is drained"
    );
    assert_eq!(core.connection_id(&peer_id), Some(conn_id));
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
        actions.iter().any(|action| matches!(
            action,
            Action::OpenStream { conn_id, target: ProtocolKind::Ping, .. }
                if *conn_id == newer_conn
        )),
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
        actions.iter().any(|action| matches!(
            action,
            Action::OpenStream { conn_id, target: ProtocolKind::Ping, .. }
                if *conn_id == newer_conn
        )),
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
