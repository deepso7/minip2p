//! Write fairness (ADR 0012, #327 finding 16): a stream stalled on peer
//! credit fills only its own share of the connection's send queue, queued
//! bytes enter the engine round-robin, and control streams keep a reserve
//! application streams cannot fill.

use std::time::{Duration, Instant};

use super::*;
use crate::test_peer::{RawPeer, accept, listening_server, now, server_with_idle_timeout};

/// Grants the server 1,000 bytes per stream, so most of a larger write queues.
fn small_stream_window(config: &mut quinn_proto::TransportConfig) {
    config.stream_receive_window(VarInt::from_u32(1_000));
}

/// Bytes of `data` the transport accepted, given its send result.
fn accepted(data: &Bytes, result: Result<(), TransportError>) -> usize {
    match result {
        Ok(()) => data.len(),
        Err(TransportError::Full { unsent, .. }) => data.len() - unsent.len(),
        Err(error) => panic!("send failed: {error}"),
    }
}

/// Polls the server and pumps the peer, reading `streams` on the peer each
/// turn, until `done` accepts the events and the bytes read per stream.
/// Returns the bytes read per stream.
fn drive_reading(
    server: &mut QuicTransport,
    peer: &mut RawPeer,
    streams: &[StreamId],
    what: &str,
    mut done: impl FnMut(&[TransportEvent], &[usize]) -> bool,
) -> Vec<usize> {
    let mut events = Vec::new();
    let mut read = vec![0; streams.len()];
    let start = Instant::now();
    while !done(&events, &read) {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for {what}; read {read:?}, events: {events:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
        peer.pump();
        events.extend(server.poll(now()).expect("poll must not fail"));
        peer.pump();
        for (stream, total) in streams.iter().zip(&mut read) {
            *total += peer.read(stream.as_u64()).0.len();
        }
    }
    read
}

#[test]
fn a_stream_without_peer_credit_cannot_keep_other_streams_from_writable() {
    let mut server = server_with_idle_timeout(30_000);
    let (mut peer, id) = accept(&mut server, &mut [], small_stream_window);
    let stuck = server.open_stream(id).expect("stuck stream");
    let other = server.open_stream(id).expect("other stream");

    // The peer never reads `stuck`, so it keeps its backlog for good.
    let payload = Bytes::from(vec![7; 9 * 1024 * 1024]);
    let taken = accepted(&payload, server.send_stream(id, stuck, payload.clone()));
    let stream_cap = QuicLimits::default().max_pending_bytes_per_stream;
    assert!(
        taken <= 1_000 + stream_cap,
        "a stream queues only its own share, took {taken}"
    );
    assert!(matches!(
        server.send_stream(id, other, payload),
        Err(TransportError::Full { .. })
    ));

    // Reading `other` frees its share; `stuck` keeps holding its own.
    drive_reading(&mut server, &mut peer, &[other], "Writable", |events, _| {
        events.contains(&TransportEvent::StreamWritable {
            id,
            stream_id: other,
        })
    });
}

#[test]
fn backlogged_streams_share_scarce_connection_credit() {
    let mut server = server_with_idle_timeout(30_000);
    // Generous stream credit but a 4,000-byte connection window, so the
    // two streams compete for every MAX_DATA the peer grants.
    let (mut peer, id) = accept(&mut server, &mut [], |config| {
        config.receive_window(VarInt::from_u32(4_000));
    });
    let first = server.open_stream(id).expect("first stream");
    let second = server.open_stream(id).expect("second stream");
    for stream in [first, second] {
        server
            .send_stream(id, stream, Bytes::from(vec![7; 200_000]))
            .expect("fits the stream cap");
    }

    let read = drive_reading(
        &mut server,
        &mut peer,
        &[first, second],
        "40,000 bytes delivered",
        |_, read| read.iter().sum::<usize>() >= 40_000,
    );
    // Draining in a fixed order would hand every grant to one stream.
    assert!(
        read.iter().all(|&bytes| bytes >= 10_000),
        "both streams progress: {read:?}"
    );
}

#[test]
fn control_streams_write_through_the_reserve_when_application_streams_fill_the_queue() {
    let mut server = listening_server(QuicLimits {
        max_pending_bytes_per_stream: 4_000,
        max_pending_connection_bytes: 12_000,
        control_stream_reserve_bytes: 4_000,
        ..QuicLimits::default()
    });
    let (_peer, id) = accept(&mut server, &mut [], small_stream_window);
    let streams: Vec<StreamId> = (0..4)
        .map(|_| server.open_stream(id).expect("open"))
        .collect();
    let control = streams[3];
    server.set_control_stream(id, control, true);

    // The peer never reads, so once each takes its stream credit, the
    // application streams fill everything but the reserve.
    let payload = Bytes::from(vec![7; 10_000]);
    for &stream in &streams[..3] {
        while accepted(&payload, server.send_stream(id, stream, payload.clone())) > 0 {}
    }
    assert_eq!(server.connections[&id].pending_write_bytes(), 8_000);

    server
        .send_stream(id, control, Bytes::from(vec![1; 3_000]))
        .expect("the reserve holds a control write");
}

#[test]
fn a_full_control_stream_wakes_once_a_small_reserve_frees() {
    let mut server = listening_server(QuicLimits {
        max_pending_bytes_per_stream: 4_000,
        max_pending_connection_bytes: 12_000,
        control_stream_reserve_bytes: 1_000,
        ..QuicLimits::default()
    });
    let (mut peer, id) = accept(&mut server, &mut [], small_stream_window);
    let apps: Vec<StreamId> = (0..3)
        .map(|_| server.open_stream(id).expect("open"))
        .collect();
    let control = server.open_stream(id).expect("open");
    server.set_control_stream(id, control, true);
    let payload = Bytes::from(vec![7; 10_000]);
    for &stream in &apps {
        while accepted(&payload, server.send_stream(id, stream, payload.clone())) > 0 {}
    }

    // Only the reserve is left. Once the engine takes the queued part, the
    // reserve is free again, which must be enough to wake the stream.
    assert!(matches!(
        server.send_stream(id, control, Bytes::from(vec![1; 3_000])),
        Err(TransportError::Full { .. })
    ));
    drive_reading(&mut server, &mut peer, &[], "Writable", |events, _| {
        events.contains(&TransportEvent::StreamWritable {
            id,
            stream_id: control,
        })
    });
}
