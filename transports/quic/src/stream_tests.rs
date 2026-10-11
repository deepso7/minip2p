//! Stream and connection behaviour the engine leaves to the adapter: scanning
//! new and gated streams, terminal-event order, releasing the other half on a
//! stop or reset, opens past peer credit, copied reads, close reporting,
//! keepalive, and what the transport advertises.

use std::time::{Duration, Instant};

use quinn_proto::{Dir, ReadError};

use super::*;
use crate::test_peer::{
    RawPeer, accept, allocation_len, drive_until, listening_server, loopback, now, peer_addr, sid,
    stream_bytes,
};

/// Events about `stream`, in order.
fn stream_events(events: &[TransportEvent], stream: u64) -> Vec<TransportEvent> {
    events
        .iter()
        .filter(|event| match event {
            TransportEvent::IncomingStream { stream_id, .. }
            | TransportEvent::StreamData { stream_id, .. }
            | TransportEvent::StreamRemoteWriteClosed { stream_id, .. }
            | TransportEvent::StreamWriteStopped { stream_id, .. }
            | TransportEvent::StreamWritable { stream_id, .. }
            | TransportEvent::StreamClosed { stream_id, .. } => stream_id.as_u64() == stream,
            _ => false,
        })
        .cloned()
        .collect()
}

/// Waits until a datagram is queued on the server's socket, then a moment
/// more for the rest of a flight.
fn await_input(server: &mut QuicTransport) {
    let start = Instant::now();
    while !socket::has_queued_input(&server.socket().udp) {
        assert!(start.elapsed() < Duration::from_secs(5), "nothing arrived");
        std::thread::sleep(Duration::from_millis(1));
    }
    std::thread::sleep(Duration::from_millis(5));
}

/// Whether the peer's read of `stream` ends in a reset.
fn peer_saw_reset(peer: &mut RawPeer, stream: u64) -> bool {
    let mut recv = peer.conn().recv_stream(sid(stream));
    let Ok(mut chunks) = recv.read(true) else {
        return false;
    };
    let reset = loop {
        match chunks.next(usize::MAX) {
            Ok(Some(_)) => {}
            Ok(None) | Err(ReadError::Blocked) => break false,
            Err(ReadError::Reset(_)) => break true,
        }
    };
    let _credit = chunks.finalize();
    reset
}

/// Pumps both sides until a RESET_STREAM reaches the peer. A peer that sent
/// STOP_SENDING can no longer read the stream, so this counts frames.
fn await_peer_reset(server: &mut QuicTransport, peer: &mut RawPeer) {
    let start = Instant::now();
    while peer.conn().stats().frame_rx.reset_stream == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the peer never saw RESET_STREAM"
        );
        std::thread::sleep(Duration::from_millis(1));
        server.poll(now()).expect("poll");
        peer.pump();
    }
}

/// Writes `len` bytes on `stream` as the peer's credit allows,
/// pumping both sides, and returns every server event seen until `done`.
fn send_window(
    server: &mut QuicTransport,
    peer: &mut RawPeer,
    stream: u64,
    len: usize,
    mut done: impl FnMut(&[TransportEvent]) -> bool,
) -> Vec<TransportEvent> {
    let payload = vec![7u8; len];
    let mut sent = 0;
    let mut events = Vec::new();
    let start = Instant::now();
    while !done(&events) {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "stalled after {sent} bytes: {:?}",
            stream_events(&events, stream).len()
        );
        if sent < len {
            sent += peer.write(stream, &payload[sent..]);
        }
        peer.pump();
        std::thread::sleep(Duration::from_millis(1));
        events.extend(server.poll(now()).expect("poll"));
    }
    events
}

fn delivered(events: &[TransportEvent], stream: u64) -> usize {
    stream_bytes(events, stream).len()
}

#[test]
fn a_one_packet_request_with_fin_is_delivered_without_further_traffic() {
    let mut server = listening_server(QuicLimits::default());
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});

    // Opening, data and FIN in one packet: the stream's first frame raises
    // only `Opened` in the engine, so the adapter has to scan it at once.
    let raw = peer.open();
    peer.write(raw, b"request");
    peer.finish(raw);
    peer.service();
    await_input(&mut server);
    let events = server.poll(now()).expect("poll");

    let stream = StreamId::new(raw);
    assert_eq!(
        stream_events(&events, raw),
        [
            TransportEvent::IncomingStream {
                id,
                stream_id: stream
            },
            TransportEvent::StreamData {
                id,
                stream_id: stream,
                data: Bytes::from_static(b"request"),
            },
            TransportEvent::StreamRemoteWriteClosed {
                id,
                stream_id: stream
            },
        ]
    );

    // Closing the local half then closes the stream.
    server.close_stream_write(id, stream).expect("close write");
    let events = server.poll(now()).expect("poll");
    assert_eq!(
        stream_events(&events, raw),
        [TransportEvent::StreamClosed {
            id,
            stream_id: stream
        }]
    );
}

#[test]
fn a_fin_at_the_budget_boundary_surfaces_while_gated() {
    let mut server = listening_server(QuicLimits::default());
    let (mut peer, _) = accept(&mut server, &mut [], |_| {});
    let raw = peer.open();

    // Exactly one window and then FIN, never acknowledged.
    let mut finished = false;
    let payload = vec![7u8; STREAM_RECEIVE_WINDOW];
    let mut sent = 0;
    let mut events = Vec::new();
    let start = Instant::now();
    while !events
        .iter()
        .any(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { .. }))
    {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "FIN never surfaced"
        );
        sent += peer.write(raw, &payload[sent..]);
        if sent == payload.len() && !finished {
            peer.finish(raw);
            finished = true;
        }
        peer.pump();
        std::thread::sleep(Duration::from_millis(1));
        events.extend(server.poll(now()).expect("poll"));
    }

    let stream_events = stream_events(&events, raw);
    assert_eq!(delivered(&events, raw), STREAM_RECEIVE_WINDOW);
    assert!(matches!(
        stream_events.last(),
        Some(TransportEvent::StreamRemoteWriteClosed { .. })
    ));
}

#[test]
fn a_reset_at_the_budget_boundary_surfaces_while_gated() {
    let mut server = listening_server(QuicLimits::default());
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});
    let raw = peer.open();
    let mut events = send_window(
        &mut server,
        &mut peer,
        raw,
        STREAM_RECEIVE_WINDOW,
        |events| delivered(events, raw) == STREAM_RECEIVE_WINDOW,
    );

    peer.reset(raw, 3);
    let stream = StreamId::new(raw);
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "reset",
        |events| {
            events.contains(&TransportEvent::StreamClosed {
                id,
                stream_id: stream,
            })
        },
    );
    let stream_events = stream_events(&events, raw);
    assert_eq!(delivered(&events, raw), STREAM_RECEIVE_WINDOW);
    assert!(matches!(
        stream_events.last(),
        Some(TransportEvent::StreamClosed { .. })
    ));
}

#[test]
fn an_exact_window_stays_gated_and_resumes_on_ack_without_a_packet() {
    let mut server = listening_server(QuicLimits::default());
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});
    let raw = peer.open();
    let stream = StreamId::new(raw);
    let mut events = send_window(
        &mut server,
        &mut peer,
        raw,
        STREAM_RECEIVE_WINDOW,
        |events| delivered(events, raw) == STREAM_RECEIVE_WINDOW,
    );
    // No FIN and nothing behind the window: the probe finds no data.
    assert!(server.connections[&id].is_gated(stream));

    // More arrives behind the spent budget and stays in the engine.
    let start = Instant::now();
    let mut more = 0;
    while more < 10 {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "no credit for more"
        );
        more += peer.write(raw, &[9u8; 10][more..]);
        peer.pump();
        std::thread::sleep(Duration::from_millis(1));
        events.extend(server.poll(now()).expect("poll"));
    }
    for _ in 0..20 {
        peer.pump();
        std::thread::sleep(Duration::from_millis(1));
        events.extend(server.poll(now()).expect("poll"));
    }
    assert_eq!(delivered(&events, raw), STREAM_RECEIVE_WINDOW);
    assert!(server.connections[&id].is_gated(stream));

    // The acknowledgement alone reads it: no packet, no engine event.
    server
        .ack_stream(id, stream, STREAM_RECEIVE_WINDOW)
        .expect("ack");
    assert_eq!(stream_bytes(&server.pending_events, raw), [9u8; 10]);
    assert!(!server.connections[&id].is_gated(stream));
}

#[test]
fn reset_and_stop_in_one_packet_report_the_stop_before_the_close() {
    let mut server = listening_server(QuicLimits::default());
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});
    let raw = peer.open();
    peer.write(raw, b"x");
    peer.stop(raw, 7);
    peer.reset(raw, 9);
    peer.service();

    let stream = StreamId::new(raw);
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "close",
        |events| {
            events.contains(&TransportEvent::StreamClosed {
                id,
                stream_id: stream,
            })
        },
    );
    for _ in 0..10 {
        peer.pump();
        std::thread::sleep(Duration::from_millis(1));
        events.extend(server.poll(now()).expect("poll"));
    }
    let stream_events = stream_events(&events, raw);
    // The reset may or may not overtake the byte; the stop always comes
    // first and nothing follows the close.
    assert_eq!(
        stream_events.first(),
        Some(&TransportEvent::IncomingStream {
            id,
            stream_id: stream
        })
    );
    let stopped = stream_events
        .iter()
        .position(|event| {
            *event
                == TransportEvent::StreamWriteStopped {
                    id,
                    stream_id: stream,
                    error_code: 7,
                }
        })
        .expect("stop reported");
    assert_eq!(
        stream_events.last(),
        Some(&TransportEvent::StreamClosed {
            id,
            stream_id: stream
        }),
        "{stream_events:?}"
    );
    assert!(stopped < stream_events.len() - 1);
}

/// One server stream slot, a peer granting 1,000 bytes per stream, and a
/// peer stream the server has read two bytes from and answered with more
/// than the peer's credit, so the engine holds some and the adapter queues
/// the rest.
fn one_slot_with_buffered_output() -> (QuicTransport, RawPeer, ConnectionId, u64) {
    let mut server = listening_server(QuicLimits {
        max_streams_per_connection: 1,
        ..QuicLimits::default()
    });
    let (mut peer, id) = accept(&mut server, &mut [], |config| {
        config.stream_receive_window(VarInt::from_u32(1_000));
    });
    let raw = peer.open();
    peer.write(raw, b"hi");
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "data",
        |events| delivered(events, raw) == 2,
    );
    server
        .send_stream(id, StreamId::new(raw), Bytes::from(vec![7; 10_000]))
        .expect("queued");
    assert!(server.connections[&id].pending_write_bytes() > 0);
    (server, peer, id, raw)
}

/// Waits until the peer may open another stream, then opens it and checks
/// that the server admits it.
fn reuse_the_slot(server: &mut QuicTransport, peer: &mut RawPeer) {
    let start = Instant::now();
    let next = loop {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the stream credit never came back"
        );
        if let Some(stream) = peer.conn().streams().open(Dir::Bi) {
            break u64::from(stream);
        }
        peer.pump();
        std::thread::sleep(Duration::from_millis(1));
        server.poll(now()).expect("poll");
    };
    peer.write(next, b"next");
    let mut events = Vec::new();
    drive_until(
        server,
        &mut [peer],
        &mut events,
        "the next stream",
        |events| delivered(events, next) == 4,
    );
    assert!(matches!(
        stream_events(&events, next).first(),
        Some(TransportEvent::IncomingStream { .. })
    ));
}

#[test]
fn a_peer_reset_releases_the_send_half_and_returns_stream_credit() {
    let (mut server, mut peer, id, raw) = one_slot_with_buffered_output();
    let stream = StreamId::new(raw);

    peer.reset(raw, 4);
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "reset",
        |events| {
            events.contains(&TransportEvent::StreamClosed {
                id,
                stream_id: stream,
            })
        },
    );
    assert_eq!(server.connections[&id].pending_write_bytes(), 0);
    // The engine reset its send half too, discarding what it buffered.
    await_peer_reset(&mut server, &mut peer);

    server.ack_stream(id, stream, 2).expect("settle");
    reuse_the_slot(&mut server, &mut peer);
}

#[test]
fn stop_sending_resets_the_send_half_keeps_the_read_half_and_frees_the_slot() {
    let (mut server, mut peer, id, raw) = one_slot_with_buffered_output();
    let stream = StreamId::new(raw);

    peer.stop(raw, 3);
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "stop",
        |events| {
            events.contains(&TransportEvent::StreamWriteStopped {
                id,
                stream_id: stream,
                error_code: 3,
            })
        },
    );
    assert_eq!(server.connections[&id].pending_write_bytes(), 0);
    // RESET_STREAM reaches the peer, so the engine dropped its buffer.
    await_peer_reset(&mut server, &mut peer);

    // The read half still works.
    peer.write(raw, b"more");
    peer.finish(raw);
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "FIN",
        |events| {
            events.contains(&TransportEvent::StreamClosed {
                id,
                stream_id: stream,
            })
        },
    );
    assert_eq!(stream_bytes(&events, raw), b"more");

    server.ack_stream(id, stream, 6).expect("settle");
    reuse_the_slot(&mut server, &mut peer);
}

#[test]
fn tiny_reads_are_copied_into_allocations_of_their_own_length() {
    let mut server = listening_server(QuicLimits::default());
    let (mut peer, _) = accept(&mut server, &mut [], |_| {});
    let raw = peer.open();

    let mut seen = 0;
    for round in 0..20u8 {
        // Each write leaves in its own packet, a slice of a much larger
        // receive buffer in the engine.
        peer.write(raw, &[round; 3]);
        peer.pump();
        std::thread::sleep(Duration::from_millis(2));
        for event in server.poll(now()).expect("poll") {
            if let TransportEvent::StreamData {
                id,
                stream_id,
                data,
            } = event
            {
                let len = data.len();
                seen += len;
                assert_eq!(allocation_len(data), len, "the copy is exactly sized");
                server.ack_stream(id, stream_id, len).expect("ack");
            }
        }
    }
    assert!(seen > 0);
}

#[test]
fn opens_past_peer_credit_keep_their_ids_and_a_reset_one_is_released_at_once() {
    let mut server = listening_server(QuicLimits {
        max_streams_per_connection: 3,
        max_pending_stream_bytes: 4_000,
        ..QuicLimits::default()
    });
    // The peer grants no streams until told to.
    let (mut peer, id) = accept(&mut server, &mut [], |config| {
        config.max_concurrent_bidi_streams(VarInt::from_u32(0));
    });

    let first = server.open_stream(id).expect("first");
    let second = server.open_stream(id).expect("second");
    server
        .send_stream(id, first, Bytes::from(vec![1; 4_000]))
        .expect("queued in full");
    server.close_stream_write(id, first).expect("queued FIN");
    let second_payload = Bytes::from(vec![2; 100]);
    let Err(TransportError::Full { unsent, .. }) =
        server.send_stream(id, second, second_payload.clone())
    else {
        panic!("the shared queue is full");
    };
    assert_eq!(unsent, second_payload);

    // Resetting the pending stream releases its queue now and wakes the
    // other writer, with one StreamClosed.
    server.reset_stream(id, first).expect("reset pending");
    assert_eq!(server.connections[&id].pending_write_bytes(), 0);
    let mut events = server.poll(now()).expect("poll");
    assert!(events.contains(&TransportEvent::StreamWritable {
        id,
        stream_id: second
    }));

    // Its reservation holds until it opens, so the cap still counts it.
    let third = server.open_stream(id).expect("third");
    assert_eq!(server.connections[&id].local_slots_used(), 3);
    assert!(matches!(
        server.open_stream(id),
        Err(TransportError::ResourceExhausted { .. })
    ));
    server
        .send_stream(id, second, second_payload.clone())
        .expect("resent");
    server.close_stream_write(id, second).expect("FIN");
    server
        .send_stream(id, third, Bytes::from_static(b"third"))
        .expect("third");
    server.close_stream_write(id, third).expect("FIN");

    peer.conn()
        .set_max_concurrent_streams(Dir::Bi, VarInt::from_u32(3));
    let mut received = [Vec::new(), Vec::new()];
    let mut finished = [false, false];
    let start = Instant::now();
    while finished != [true, true] {
        assert!(start.elapsed() < Duration::from_secs(10), "{received:?}");
        peer.pump();
        std::thread::sleep(Duration::from_millis(1));
        events.extend(server.poll(now()).expect("poll"));
        peer.pump();
        for (index, stream) in [second, third].into_iter().enumerate() {
            let (data, fin) = peer.read(stream.as_u64());
            received[index].extend(data);
            finished[index] |= fin;
        }
    }
    // Every stream bound to the id it was given.
    assert_eq!((first, second, third), (1.into(), 5.into(), 9.into()));
    assert_eq!(received[0], second_payload);
    assert_eq!(received[1], b"third");
    assert!(peer_saw_reset(&mut peer, first.as_u64()));
    assert_eq!(
        peer.conn().send_stream(sid(first.as_u64())).stopped(),
        Ok(Some(VarInt::from_u32(0))),
        "the reset stream is stopped on the wire too"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| **event
                == TransportEvent::StreamClosed {
                    id,
                    stream_id: first
                })
            .count(),
        1
    );
    assert_eq!(server.connections[&id].local_slots_used(), 2);
}

/// A connected pair of transports on loopback with `limits` on both.
fn connected_pair(
    limits: QuicLimits,
) -> (QuicTransport, QuicTransport, ConnectionId, ConnectionId) {
    let mut server = listening_server(limits.clone());
    let mut client = loopback(QuicNodeConfig::generate().with_limits(limits));
    let client_id = client.dial(&peer_addr(&server)).expect("dial");
    let mut server_id = None;
    let mut client_connected = false;
    let start = Instant::now();
    while server_id.is_none() || !client_connected {
        assert!(start.elapsed() < Duration::from_secs(5), "no handshake");
        std::thread::sleep(Duration::from_millis(1));
        for event in server.poll(now()).expect("server poll") {
            if let TransportEvent::Connected { id, .. } = event {
                server_id = Some(id);
            }
        }
        client_connected |= client
            .poll(now())
            .expect("client poll")
            .iter()
            .any(|event| matches!(event, TransportEvent::Connected { .. }));
    }
    (server, client, server_id.expect("server id"), client_id)
}

#[test]
fn an_orderly_peer_close_reports_closed_without_an_error() {
    let (mut server, mut client, server_id, client_id) = connected_pair(QuicLimits::default());
    client.close(client_id).expect("close");

    let mut events = Vec::new();
    let start = Instant::now();
    while !events.contains(&TransportEvent::Closed { id: server_id }) {
        assert!(start.elapsed() < Duration::from_secs(5), "{events:?}");
        std::thread::sleep(Duration::from_millis(1));
        client.poll(now()).expect("client poll");
        events.extend(server.poll(now()).expect("server poll"));
    }
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TransportEvent::Error { .. })),
        "{events:?}"
    );
}

#[test]
fn quic_datagrams_are_not_advertised() {
    let mut server = listening_server(QuicLimits::default());
    let (mut peer, _) = accept(&mut server, &mut [], |_| {});
    assert_eq!(peer.conn().datagrams().max_size(), None);
}

#[test]
fn keepalive_holds_a_live_idle_pair_and_a_dead_peer_still_times_out() {
    const IDLE_MS: u64 = 400;
    let (mut server, mut client, _, client_id) = connected_pair(QuicLimits {
        idle_timeout_ms: IDLE_MS,
        ..QuicLimits::default()
    });

    // Several idle periods, both sides polled as their deadlines ask.
    let until = Instant::now() + Duration::from_millis(4 * IDLE_MS);
    while Instant::now() < until {
        for node in [&mut server, &mut client] {
            let events = node.poll(now()).expect("poll");
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, TransportEvent::Closed { .. })),
                "a live idle connection closed: {events:?}"
            );
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    // The server goes silent; the client's keepalives go unanswered.
    let silent_from = Instant::now();
    let mut closed = false;
    while !closed {
        assert!(
            silent_from.elapsed() < Duration::from_secs(10),
            "a dead peer never timed out"
        );
        std::thread::sleep(Duration::from_millis(5));
        closed = client
            .poll(now())
            .expect("poll")
            .contains(&TransportEvent::Closed { id: client_id });
    }
}

#[test]
fn idle_polls_service_no_connection_and_traffic_services_only_its_own() {
    let mut server = listening_server(QuicLimits {
        idle_timeout_ms: 3_600_000,
        ..QuicLimits::default()
    });
    let mut peers: Vec<RawPeer> = Vec::new();
    for _ in 0..4 {
        let (peer, _) = accept(&mut server, &mut [], |_| {});
        peers.push(peer);
    }
    // Let every handshake's trailing packets and acknowledgements settle.
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(10));
        for peer in &mut peers {
            peer.pump();
        }
        server.poll(now()).expect("poll");
    }

    server.services = 0;
    for _ in 0..5 {
        assert!(server.poll(now()).expect("idle poll").is_empty());
    }
    assert_eq!(server.services, 0, "idle connections are not visited");
    assert!(
        server.next_deadline().is_some(),
        "the earliest timer still comes from the index"
    );

    let peer = &mut peers[0];
    let stream = peer.open();
    peer.write(stream, b"wake one");
    peer.service();
    await_input(&mut server);
    server.services = 0;
    let events = server.poll(now()).expect("poll");
    assert_eq!(stream_bytes(&events, stream), b"wake one");
    assert_eq!(server.services, 1, "only the connection with traffic");
}
