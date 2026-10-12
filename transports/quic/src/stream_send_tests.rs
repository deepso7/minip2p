//! How queued stream writes survive the engine's write errors and the peer's
//! stops and resets.
//!
//! The remote side is a bare quinn-proto peer rather than a second
//! `QuicTransport`, so a test can send STOP_SENDING without resetting the read
//! half and can shape the flow-control and stream credit it grants.

use std::time::{Duration, Instant};

use super::*;
use crate::test_peer::{
    RawPeer, accept, drive_until, listening_server, now, server_with_idle_timeout, sid,
    stream_bytes,
};

fn pending_write_bytes(server: &QuicTransport, id: ConnectionId) -> usize {
    server
        .connections
        .get(&id)
        .expect("connection")
        .pending_write_bytes()
}

/// A server whose write queue holds at most `bytes`.
fn server_with_queue(bytes: usize) -> QuicTransport {
    listening_server(QuicLimits {
        max_pending_bytes_per_stream: bytes,
        max_pending_connection_bytes: bytes,
        control_stream_reserve_bytes: 0,
        ..QuicLimits::default()
    })
}

/// Grants the server 1,000 bytes per stream, so most of a larger write queues.
fn small_stream_window(config: &mut quinn_proto::TransportConfig) {
    config.stream_receive_window(VarInt::from_u32(1_000));
}

/// Opens one stream from `peer` per payload and waits until the server has
/// read each.
fn open_streams(server: &mut QuicTransport, peer: &mut RawPeer, payloads: &[&[u8]]) -> Vec<u64> {
    let streams: Vec<u64> = payloads
        .iter()
        .map(|payload| {
            let stream = peer.open();
            assert_eq!(peer.write(stream, payload), payload.len());
            stream
        })
        .collect();
    let mut events = Vec::new();
    drive_until(
        server,
        &mut [peer],
        &mut events,
        "inbound streams",
        |events| {
            events
                .iter()
                .filter(|event| matches!(event, TransportEvent::StreamData { .. }))
                .count()
                >= payloads.len()
        },
    );
    streams
}

#[test]
fn stop_sending_drops_queued_writes_and_keeps_the_endpoint_polling() {
    let mut server = server_with_idle_timeout(1_000);
    let (mut stopper, stopper_id) = accept(&mut server, &mut [], small_stream_window);
    let (mut silent, silent_id) = accept(&mut server, &mut [&mut stopper], |_| {});

    let raw = open_streams(&mut server, &mut stopper, &[b"hi"])[0];
    let stream = StreamId::new(raw);
    server
        .send_stream(stopper_id, stream, Bytes::from(vec![7; 10_000]))
        .expect("send");
    assert!(pending_write_bytes(&server, stopper_id) > 0);

    stopper.stop(raw, 42);
    // The silent peer stops answering, so only its idle timer can close it.
    silent.mute = true;
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut stopper],
        &mut events,
        "write stop",
        |events| {
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamWriteStopped { .. }))
        },
    );
    assert_eq!(pending_write_bytes(&server, stopper_id), 0);

    // The read half is still open.
    assert_eq!(stopper.write(raw, b"more"), 4);
    stopper.finish(raw);
    drive_until(
        &mut server,
        &mut [&mut stopper],
        &mut events,
        "remote FIN",
        |events| {
            events.contains(&TransportEvent::StreamClosed {
                id: stopper_id,
                stream_id: stream,
            })
        },
    );
    assert_eq!(stream_bytes(&events, raw), b"more");
    assert!(events.contains(&TransportEvent::StreamRemoteWriteClosed {
        id: stopper_id,
        stream_id: stream,
    }));

    drive_until(
        &mut server,
        &mut [&mut stopper],
        &mut events,
        "idle timeout of the other connection",
        |events| events.contains(&TransportEvent::Closed { id: silent_id }),
    );
    let stops = events
        .iter()
        .filter(|event| matches!(event, TransportEvent::StreamWriteStopped { .. }))
        .collect::<Vec<_>>();
    assert_eq!(
        stops,
        [&TransportEvent::StreamWriteStopped {
            id: stopper_id,
            stream_id: stream,
            error_code: 42,
        }]
    );
}

#[test]
fn stop_sending_is_reported_when_nothing_is_queued() {
    let mut server = server_with_idle_timeout(30_000);
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});

    // STOP_SENDING and FIN leave together, before the server ever writes.
    let raw = peer.open();
    peer.write(raw, b"hi");
    peer.finish(raw);
    peer.stop(raw, 9);
    let stream = StreamId::new(raw);
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "stream close",
        |events| {
            events
                .iter()
                .any(|event| matches!(event, TransportEvent::StreamClosed { .. }))
        },
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, TransportEvent::StreamWriteStopped { .. }))
            .collect::<Vec<_>>(),
        [&TransportEvent::StreamWriteStopped {
            id,
            stream_id: stream,
            error_code: 9,
        }]
    );
    assert!(matches!(
        server.send_stream(id, stream, Bytes::from_static(b"late")),
        Err(TransportError::StreamSendFailed { .. } | TransportError::StreamNotFound { .. })
    ));
    assert_eq!(pending_write_bytes(&server, id), 0);
}

#[test]
fn stop_sending_is_reported_while_connection_credit_is_exhausted() {
    let mut server = server_with_idle_timeout(30_000);
    // The peer never reads, so it never raises this connection-level limit.
    let (mut peer, id) = accept(&mut server, &mut [], |config| {
        config.receive_window(VarInt::from_u32(2_000));
    });

    let first = open_streams(&mut server, &mut peer, &[b"hi"])[0];
    // Use up the connection's send credit.
    server
        .send_stream(id, StreamId::new(first), Bytes::from(vec![7; 10_000]))
        .expect("send");

    let raw = peer.open();
    peer.write(raw, b"hi");
    peer.finish(raw);
    peer.stop(raw, 5);
    let stream = StreamId::new(raw);
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "stream close",
        |events| {
            events.iter().any(|event| {
                matches!(event, TransportEvent::StreamClosed { stream_id, .. } if *stream_id == stream)
            })
        },
    );
    assert!(events.contains(&TransportEvent::StreamWriteStopped {
        id,
        stream_id: stream,
        error_code: 5,
    }));
}

/// Data spanning many packets must arrive whole and once, with nothing left
/// for idle polls to find.
#[test]
fn data_beyond_one_receive_buffer_arrives_once_and_idle_polls_stay_silent() {
    let mut server = server_with_idle_timeout(30_000);
    let (mut peer, id) = accept(&mut server, &mut [], |_| {});
    let payload: Vec<u8> = (0..3 * RECV_BUFFER_SIZE + 7).map(|i| i as u8).collect();
    let raw = peer.open();

    let mut sent = 0;
    let mut finished = false;
    let mut events = Vec::new();
    let start = Instant::now();
    while !events
        .iter()
        .any(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { .. }))
    {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out after {sent} bytes sent"
        );
        sent += peer.write(raw, &payload[sent..]);
        if sent == payload.len() && !finished {
            peer.finish(raw);
            finished = true;
        }
        peer.pump();
        events.extend(server.poll(now()).expect("poll"));
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(stream_bytes(&events, raw), payload);

    // Let the final acknowledgements settle, then go quiet.
    peer.pump();
    std::thread::sleep(Duration::from_millis(20));
    let mut idle = server.poll(now()).expect("poll");
    for _ in 0..5 {
        std::thread::sleep(Duration::from_millis(2));
        idle.extend(server.poll(now()).expect("idle poll"));
    }
    assert!(
        idle.iter().all(|event| !matches!(
            event,
            TransportEvent::StreamData { .. } | TransportEvent::StreamRemoteWriteClosed { .. }
        )),
        "idle polls repeated stream input on {id:?}: {idle:?}"
    );
}

#[test]
fn fin_waiting_for_stream_credit_stays_queued_until_granted() {
    let mut server = server_with_idle_timeout(30_000);
    let (mut peer, id) = accept(&mut server, &mut [], |config| {
        config.max_concurrent_bidi_streams(VarInt::from_u32(1));
    });

    let first = server.open_stream(id).expect("first stream");
    server
        .send_stream(id, first, Bytes::from_static(b"x"))
        .expect("send");
    server.close_stream_write(id, first).expect("fin first");
    // The peer has granted one server stream; this FIN has to wait.
    let second = server.open_stream(id).expect("second stream");
    server.close_stream_write(id, second).expect("queue fin");

    // Finishing the first stream lets the peer grant another.
    let mut events = Vec::new();
    let mut first_done = false;
    let mut second_fin = false;
    let start = Instant::now();
    while !second_fin {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "queued FIN never arrived; events: {events:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
        peer.pump();
        events.extend(server.poll(now()).expect("poll must not fail"));
        peer.pump();
        if !first_done && peer.read(first.as_u64()).1 {
            peer.finish(first.as_u64());
            first_done = true;
        }
        if first_done {
            second_fin = peer.read(second.as_u64()).1;
        }
    }
    assert!(
        !events.iter().any(|event| matches!(
            event,
            TransportEvent::Error { .. } | TransportEvent::Closed { .. }
        )),
        "{events:?}"
    );
}

#[test]
fn connection_fatal_send_error_closes_only_that_connection() {
    let mut server = server_with_idle_timeout(30_000);
    let (mut faulty, faulty_id) = accept(&mut server, &mut [], small_stream_window);
    let (mut healthy, healthy_id) = accept(&mut server, &mut [&mut faulty], |_| {});

    let raw = open_streams(&mut server, &mut faulty, &[b"hi"])[0];
    server
        .send_stream(faulty_id, StreamId::new(raw), Bytes::from(vec![7; 10_000]))
        .expect("most of the write queues");
    // The engine forgets the stream behind the adapter's back, so the next
    // drain of its queue meets a closed stream.
    server
        .connections
        .get_mut(&faulty_id)
        .expect("connection")
        .engine()
        .send_stream(sid(raw))
        .reset(VarInt::from_u32(0))
        .expect("reset");

    let stream = healthy.open();
    healthy.write(stream, b"still here");
    healthy.finish(stream);
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut faulty, &mut healthy],
        &mut events,
        "faulty connection close",
        |events| {
            events.contains(&TransportEvent::Closed { id: faulty_id })
                && events
                    .iter()
                    .any(|event| matches!(event, TransportEvent::StreamRemoteWriteClosed { id, .. } if *id == healthy_id))
        },
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, TransportEvent::Error { id, .. } if *id == faulty_id))
            .count(),
        1,
        "the failed write is dropped, not retried on every drain: {events:?}"
    );
    assert_eq!(stream_bytes(&events, stream), b"still here");
    assert!(!events.contains(&TransportEvent::Closed { id: healthy_id }));
    assert!(server.connections.contains_key(&healthy_id));
}

#[test]
fn partially_written_queue_drains_once_the_stream_is_writable() {
    let mut server = server_with_idle_timeout(30_000);
    let (mut peer, id) = accept(&mut server, &mut [], small_stream_window);

    let stream = server.open_stream(id).expect("open");
    server
        .send_stream(id, stream, Bytes::from(vec![7; 10_000]))
        .expect("send");
    server.close_stream_write(id, stream).expect("queue fin");
    let connection = server.connections.get(&id).expect("connection");
    assert!(connection.pending_write_bytes() > 0);
    assert_eq!(connection.queued_stream_count(), 1);

    let mut received = Vec::new();
    let mut fin = false;
    let start = Instant::now();
    while !fin {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "queued bytes never arrived; got {} bytes",
            received.len()
        );
        std::thread::sleep(Duration::from_millis(1));
        peer.pump();
        server.poll(now()).expect("poll must not fail");
        peer.pump();
        let (data, done) = peer.read(stream.as_u64());
        received.extend(data);
        fin = done;
    }
    assert_eq!(received, vec![7; 10_000]);
    let connection = server.connections.get(&id).expect("connection");
    assert_eq!(connection.pending_write_bytes(), 0);
    assert_eq!(connection.queued_stream_count(), 0);
}

/// Fills the server's whole 4,000-byte queue from stream `filler` and arms
/// the second stream too, neither able to drain: the peer grants 1,000 bytes
/// per stream and never reads.
fn two_full_streams() -> (QuicTransport, RawPeer, ConnectionId, StreamId, StreamId) {
    let mut server = server_with_queue(4_000);
    let (mut peer, id) = accept(&mut server, &mut [], small_stream_window);
    let streams = open_streams(&mut server, &mut peer, &[b"a", b"b"]);
    let (filler, other) = (StreamId::new(streams[0]), StreamId::new(streams[1]));
    for stream in [filler, other] {
        assert!(matches!(
            server.send_stream(id, stream, Bytes::from(vec![7; 10_000])),
            Err(TransportError::Full { .. })
        ));
    }
    (server, peer, id, filler, other)
}

#[test]
fn a_peer_reset_disarms_its_stream_while_the_queue_stays_full() {
    let (mut server, mut peer, id, _, reset) = two_full_streams();
    assert_eq!(server.connections[&id].writable_armed_count(), 2);

    // Resetting a stream that queued nothing frees no room, so no wake runs:
    // the reset itself must disarm it.
    peer.reset(reset.as_u64(), 5);
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "reset",
        |events| {
            events.contains(&TransportEvent::StreamClosed {
                id,
                stream_id: reset,
            })
        },
    );
    assert_eq!(server.connections[&id].writable_armed_count(), 1);
}

#[test]
fn a_peer_reset_retracts_a_writable_queued_before_the_poll() {
    let (mut server, mut peer, id, filler, reset) = two_full_streams();

    // The peer's reset is on the wire when the application resets the
    // filler, which frees the shared queue and queues a Writable for the
    // other stream before the next poll reads that reset.
    peer.reset(reset.as_u64(), 5);
    peer.service();
    // Wait until the reset is waiting on the server's socket (peeking leaves
    // it there), so the next poll is sure to read it.
    let start = Instant::now();
    while !socket::has_queued_input(&server.socket().udp) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "reset never arrived"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    server.reset_stream(id, filler).expect("local reset");
    let mut events = Vec::new();
    drive_until(
        &mut server,
        &mut [&mut peer],
        &mut events,
        "reset",
        |events| {
            events.contains(&TransportEvent::StreamClosed {
                id,
                stream_id: reset,
            })
        },
    );
    assert!(
        !events.contains(&TransportEvent::StreamWritable {
            id,
            stream_id: reset,
        }),
        "no Writable for a reset stream: {events:?}"
    );
}

#[test]
fn a_local_close_retracts_queued_writables() {
    let (mut server, _peer, id, filler, _) = two_full_streams();

    // Resetting the filler frees the shared queue and queues a Writable for
    // the other stream; closing the connection before the poll retracts it.
    server.reset_stream(id, filler).expect("local reset");
    server.close(id).expect("close");
    let events = server.poll(now()).expect("poll");
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, TransportEvent::StreamWritable { .. })),
        "no Writable after a local close: {events:?}"
    );
    assert_eq!(server.connections[&id].writable_armed_count(), 0);
}
