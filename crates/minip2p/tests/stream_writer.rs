//! The stream writer over real TCP endpoints, whose Yamux streams cap at
//! 256 KiB: it holds the tail a Full send left, finishes it on Writable,
//! defers the FIN behind it, and forgets it once the stream or its
//! connection ends.

#![cfg(all(feature = "std", feature = "tcp"))]

use std::time::{Duration, Instant};

use minip2p::{
    ConnectionId, Endpoint, EndpointEvent, EndpointWaitOutcome, StreamId, StreamWriteError,
    StreamWriter, WriteAccepted, WriteProgress,
};

const PROTOCOL: &str = "/minip2p/stream-writer/1";
/// Far past every per-stream send cap, so the first write is held.
const PAYLOAD: usize = 4 * 1024 * 1024;
const BACKSTOP: Duration = Duration::from_secs(30);

fn bind() -> Endpoint {
    Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("listen address")
        .protocol(PROTOCOL)
        .bind()
        .expect("bind endpoint")
}

fn next(endpoint: &mut Endpoint) -> Option<EndpointEvent> {
    match endpoint
        .wait(Duration::from_millis(2))
        .expect("drive endpoint")
    {
        EndpointWaitOutcome::Event(event) => Some(event),
        _ => None,
    }
}

/// Connects `writer` to `reader` and opens one negotiated stream.
fn open(writer: &mut Endpoint, reader: &mut Endpoint) -> (ConnectionId, StreamId) {
    let reader_addr = reader.listen().expect("reader listens");
    let reader_peer = reader.peer_id().clone();
    let writer_peer = writer.peer_id().clone();
    writer.connect(&reader_addr).expect("connect");
    let deadline = Instant::now() + BACKSTOP;
    while !writer.is_peer_ready(&reader_peer) || !reader.is_peer_ready(&writer_peer) {
        assert!(Instant::now() < deadline, "peers never became ready");
        let _ = next(writer);
        let _ = next(reader);
    }
    let (conn_id, stream_id) = writer
        .open_stream(&reader_peer, PROTOCOL)
        .expect("open stream");
    loop {
        assert!(Instant::now() < deadline, "stream never negotiated");
        let _ = next(reader);
        if let Some(EndpointEvent::StreamReady { stream_id: id, .. }) = next(writer)
            && id == stream_id
        {
            return (conn_id, stream_id);
        }
    }
}

fn payload() -> Vec<u8> {
    (0..PAYLOAD).map(|i| (i % 251) as u8).collect()
}

#[test]
fn a_held_write_completes_on_writable_and_the_fin_waits_for_it() {
    let mut reader = bind();
    let mut writer = bind();
    let (conn_id, stream_id) = open(&mut writer, &mut reader);
    let mut streams = StreamWriter::new(PAYLOAD);
    let payload = payload();

    assert_eq!(
        streams
            .write(&mut writer, conn_id, stream_id, payload.clone())
            .expect("write"),
        WriteProgress::Pending,
        "a write past the send caps is held"
    );
    assert!(streams.is_pending(conn_id, stream_id));
    assert!(streams.held_bytes() > 0);
    let overlapping = streams
        .write(&mut writer, conn_id, stream_id, vec![1])
        .expect_err("one pending write per stream");
    assert!(
        matches!(overlapping, StreamWriteError::Busy { ref unsent, .. } if unsent[..] == [1]),
        "{overlapping:?}"
    );
    assert!(overlapping.is_retryable() && !overlapping.is_stream_gone());

    // Requested behind the tail: the FIN must follow every byte.
    streams
        .close_write(&mut writer, conn_id, stream_id)
        .expect("close write");
    assert!(matches!(
        streams.write(&mut writer, conn_id, stream_id, vec![2]),
        Err(StreamWriteError::Closing { .. })
    ));

    let mut accepted = Vec::new();
    let mut received = Vec::new();
    let deadline = Instant::now() + BACKSTOP;
    loop {
        assert!(
            Instant::now() < deadline,
            "transfer stalled at {} bytes",
            received.len()
        );
        while let Some(event) = next(&mut writer) {
            accepted.extend(streams.observe(&mut writer, &event));
        }
        match next(&mut reader) {
            Some(EndpointEvent::StreamData { data, .. }) => received.extend_from_slice(&data),
            Some(EndpointEvent::StreamRemoteWriteClosed { .. }) => break,
            _ => {}
        }
    }
    assert_eq!(
        accepted,
        vec![WriteAccepted {
            peer_id: reader.peer_id().clone(),
            conn_id,
            stream_id,
        }],
        "the held write completes exactly once"
    );
    assert!(
        received == payload,
        "every byte arrives, in order, before the FIN"
    );
    assert!(!streams.is_pending(conn_id, stream_id));
    assert_eq!(streams.held_bytes(), 0);
}

#[test]
fn a_held_tail_is_dropped_when_its_stream_or_connection_ends() {
    let mut reader = bind();
    let mut writer = bind();
    let (conn_id, stream_id) = open(&mut writer, &mut reader);
    let mut streams = StreamWriter::new(PAYLOAD);

    // Replacement drops every tail held on the old connection.
    assert_eq!(
        streams
            .write(&mut writer, conn_id, stream_id, payload())
            .expect("write"),
        WriteProgress::Pending
    );
    let replaced = EndpointEvent::ConnectionReplaced {
        peer_id: reader.peer_id().clone(),
        old: conn_id,
        new: ConnectionId::new(u64::MAX),
    };
    assert_eq!(streams.observe(&mut writer, &replaced), None);
    assert!(!streams.is_pending(conn_id, stream_id));
    assert_eq!(streams.held_bytes(), 0, "the budget is released");

    // A stream end drops it too: the reader resets the stream.
    assert_eq!(
        streams
            .write(&mut writer, conn_id, stream_id, payload())
            .expect("write"),
        WriteProgress::Pending
    );
    let deadline = Instant::now() + BACKSTOP;
    let mut reset = false;
    while streams.is_pending(conn_id, stream_id) {
        assert!(Instant::now() < deadline, "the stream end never arrived");
        if let Some(EndpointEvent::StreamData {
            conn_id: c,
            stream_id: s,
            ..
        }) = next(&mut reader)
            && !reset
        {
            reader.reset_stream(c, s).expect("reader resets");
            reset = true;
        }
        if let Some(event) = next(&mut writer) {
            assert_eq!(streams.observe(&mut writer, &event), None);
        }
    }
    assert_eq!(streams.held_bytes(), 0);
}

#[test]
fn a_write_past_the_budget_is_refused_before_anything_is_sent() {
    let mut reader = bind();
    let mut writer = bind();
    let (conn_id, stream_id) = open(&mut writer, &mut reader);
    let mut streams = StreamWriter::new(16);

    let refused = streams
        .write(&mut writer, conn_id, stream_id, vec![0; 17])
        .expect_err("over budget");
    assert!(
        matches!(refused, StreamWriteError::OverBudget { ref unsent, available: 16 } if unsent.len() == 17),
        "{refused:?}"
    );
    assert_eq!(
        streams
            .write(&mut writer, conn_id, stream_id, vec![0; 16])
            .expect("fits"),
        WriteProgress::Accepted
    );

    // Errors from the endpoint keep their predicates.
    let gone = streams
        .write(&mut writer, ConnectionId::new(u64::MAX), stream_id, vec![0])
        .expect_err("unknown connection");
    assert!(gone.is_stream_gone() && !gone.is_retryable(), "{gone:?}");
}
