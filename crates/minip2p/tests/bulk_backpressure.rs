//! A bulk transfer to a reader that drains slowly completes without teardown
//! (ADR 0012): the writer sees `Full`, holds the unsent tail, resends it on
//! `StreamWritable`, and every byte arrives in order before the FIN.

#![cfg(feature = "std")]

use std::time::{Duration, Instant};

use minip2p::{
    Bytes, ConnectionId, Endpoint, EndpointEvent, EndpointWaitOutcome, Error, PeerId, StreamId,
};

const PROTOCOL: &str = "/minip2p/bulk-backpressure/1";
/// Larger than one stream's send window plus its queue cap.
const CHUNK: usize = 1024 * 1024;
/// The reader is driven only once per this many writer turns.
const READER_EVERY: usize = 8;
/// Failure backstop, not a budget the transfer has to fit in.
const BACKSTOP: Duration = Duration::from_secs(60);

fn bind(listen: &str) -> Endpoint {
    Endpoint::builder()
        .listen_on(listen)
        .expect("listen address")
        .protocol(PROTOCOL)
        .bind()
        .expect("bind endpoint")
}

/// One event, or `None` when the deadline passed first.
fn next(endpoint: &mut Endpoint, timeout: Duration) -> Option<EndpointEvent> {
    match endpoint.wait(timeout).expect("drive endpoint") {
        EndpointWaitOutcome::Event(event) => Some(event),
        EndpointWaitOutcome::Deadline | EndpointWaitOutcome::Interrupted => None,
    }
}

fn fail_on_teardown(event: &EndpointEvent) {
    assert!(
        !matches!(
            event,
            EndpointEvent::ConnectionClosed { .. }
                | EndpointEvent::StreamClosed { .. }
                | EndpointEvent::StreamWriteStopped { .. }
                | EndpointEvent::Error(_)
        ),
        "a slow reader must not tear anything down: {event:?}"
    );
}

/// Connects the two endpoints and opens one negotiated stream from `writer`.
fn open(writer: &mut Endpoint, reader: &mut Endpoint) -> (PeerId, ConnectionId, StreamId) {
    let reader_addr = reader.listen().expect("reader listens");
    let reader_peer = reader.peer_id().clone();
    let writer_peer = writer.peer_id().clone();
    writer.connect(&reader_addr).expect("connect");
    let deadline = Instant::now() + BACKSTOP;
    while !writer.is_peer_ready(&reader_peer) || !reader.is_peer_ready(&writer_peer) {
        assert!(Instant::now() < deadline, "peers never became ready");
        let _ = next(writer, Duration::from_millis(5));
        let _ = next(reader, Duration::from_millis(5));
    }
    let (conn_id, stream_id) = writer
        .open_stream(&reader_peer, PROTOCOL)
        .expect("open stream");
    loop {
        assert!(Instant::now() < deadline, "stream never negotiated");
        let _ = next(reader, Duration::from_millis(5));
        if let Some(EndpointEvent::StreamReady { stream_id: id, .. }) =
            next(writer, Duration::from_millis(5))
            && id == stream_id
        {
            return (reader_peer, conn_id, stream_id);
        }
    }
}

/// Moves `total` bytes, which must be several times every send cap on the
/// path so the writer has to hit Full.
fn bulk_transfer_to_slow_reader(listen: &str, total: usize) {
    let mut reader = bind(listen);
    let mut writer = bind(listen);
    let (reader_peer, conn_id, stream_id) = open(&mut writer, &mut reader);

    let payload = Bytes::from((0..total).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
    let mut offset = 0;
    let mut tail: Option<Bytes> = None;
    let mut writable = true;
    let mut fulls = 0;
    let mut closed_write = false;
    let mut received = Vec::with_capacity(total);
    let mut eof = false;
    let deadline = Instant::now() + BACKSTOP;

    for turn in 0.. {
        assert!(
            Instant::now() < deadline,
            "transfer stalled at {} of {total} bytes",
            received.len()
        );
        if writable {
            let data = match tail.take() {
                Some(tail) => Some(tail),
                None if offset < total => {
                    let end = (offset + CHUNK).min(total);
                    let chunk = payload.slice(offset..end);
                    offset = end;
                    Some(chunk)
                }
                None => None,
            };
            if let Some(data) = data {
                match writer.send_stream(&reader_peer, conn_id, stream_id, data) {
                    Ok(()) => {}
                    Err(Error::Full { unsent, .. }) => {
                        fulls += 1;
                        tail = Some(unsent);
                        writable = false;
                    }
                    other => other.expect("send failed"),
                }
            } else if !closed_write {
                // Every byte is accepted, so the FIN may follow.
                writer
                    .close_stream_write(&reader_peer, conn_id, stream_id)
                    .expect("close write");
                closed_write = true;
            }
        }
        while let Some(event) = next(&mut writer, Duration::from_millis(1)) {
            fail_on_teardown(&event);
            if let EndpointEvent::StreamWritable {
                conn_id: c,
                stream_id: s,
                ..
            } = event
                && (c, s) == (conn_id, stream_id)
            {
                assert!(!writable, "Writable without a preceding Full");
                writable = true;
            }
        }
        if turn % READER_EVERY == 0 {
            while let Some(event) = next(&mut reader, Duration::ZERO) {
                match event {
                    EndpointEvent::StreamData { data, .. } => received.extend_from_slice(&data),
                    EndpointEvent::StreamRemoteWriteClosed { .. } => eof = true,
                    other => fail_on_teardown(&other),
                }
            }
        }
        if eof {
            break;
        }
    }

    assert!(
        fulls > 0,
        "the reader was never slow enough to apply backpressure"
    );
    assert_eq!(received.len(), total, "every byte arrives before the FIN");
    assert!(received == payload, "bytes arrive in order and unchanged");
    assert!(writer.connected_peers().contains(&reader_peer));
}

#[cfg(feature = "quic")]
#[test]
fn a_bulk_transfer_to_a_slow_reader_over_quic_completes_without_teardown() {
    // Past QUIC's 8 MiB default connection queue.
    bulk_transfer_to_slow_reader("/ip4/127.0.0.1/udp/0/quic-v1", 24 * 1024 * 1024);
}

#[cfg(feature = "tcp")]
#[test]
fn a_bulk_transfer_to_a_slow_reader_over_tcp_completes_without_teardown() {
    // Past Yamux's 256 KiB stream cap and TCP's 1 MiB socket buffer.
    bulk_transfer_to_slow_reader("/ip4/127.0.0.1/tcp/0", 8 * 1024 * 1024);
}

/// Sends `payload` from `writer`, resending held tails on Writable, and
/// closes the write side once every byte is accepted. Call once per turn.
struct Sender {
    payload: Bytes,
    offset: usize,
    tail: Option<Bytes>,
    writable: bool,
    closed_write: bool,
}

impl Sender {
    fn new(payload: Bytes) -> Self {
        Self {
            payload,
            offset: 0,
            tail: None,
            writable: true,
            closed_write: false,
        }
    }

    fn turn(
        &mut self,
        writer: &mut Endpoint,
        peer: &PeerId,
        conn_id: ConnectionId,
        stream_id: StreamId,
    ) {
        if self.writable {
            let data = self.tail.take().or_else(|| {
                (self.offset < self.payload.len()).then(|| {
                    let end = (self.offset + CHUNK).min(self.payload.len());
                    let chunk = self.payload.slice(self.offset..end);
                    self.offset = end;
                    chunk
                })
            });
            match data {
                Some(data) => match writer.send_stream(peer, conn_id, stream_id, data) {
                    Ok(()) => {}
                    Err(Error::Full { unsent, .. }) => {
                        self.tail = Some(unsent);
                        self.writable = false;
                    }
                    other => other.expect("send failed"),
                },
                None if !self.closed_write => {
                    writer
                        .close_stream_write(peer, conn_id, stream_id)
                        .expect("close write");
                    self.closed_write = true;
                }
                None => {}
            }
        }
        while let Some(event) = next(writer, Duration::from_millis(1)) {
            fail_on_teardown(&event);
            if matches!(event, EndpointEvent::StreamWritable { stream_id: s, .. } if s == stream_id)
            {
                self.writable = true;
            }
        }
    }
}

/// A reader whose protocol takes manual acknowledgement holds its sender to
/// one receive window until it calls `stream_consumed`, which resumes it.
fn a_manual_ack_reader_stalls_its_sender_until_it_consumes(listen: &str, window: usize) {
    let mut reader = Endpoint::builder()
        .listen_on(listen)
        .expect("listen address")
        .manual_ack_protocol(PROTOCOL)
        .bind()
        .expect("bind reader");
    let mut writer = bind(listen);
    let (reader_peer, conn_id, stream_id) = open(&mut writer, &mut reader);
    let total = 3 * window;
    let payload = Bytes::from((0..total).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
    let mut sender = Sender::new(payload.clone());
    let mut received = Vec::with_capacity(total);
    let mut reader_stream = None;
    let deadline = Instant::now() + BACKSTOP;

    // Never acknowledging: delivery stops at exactly one window.
    let mut quiet_since = Instant::now();
    while quiet_since.elapsed() < Duration::from_millis(500) {
        assert!(Instant::now() < deadline, "the link never went quiet");
        sender.turn(&mut writer, &reader_peer, conn_id, stream_id);
        while let Some(event) = next(&mut reader, Duration::from_millis(1)) {
            if let EndpointEvent::StreamData {
                conn_id,
                stream_id,
                data,
                ..
            } = event
            {
                reader_stream = Some((conn_id, stream_id));
                received.extend_from_slice(&data);
                quiet_since = Instant::now();
            } else {
                fail_on_teardown(&event);
            }
        }
    }
    // The window also carried the negotiation, which the endpoint consumed
    // itself; Yamux returns credit in half windows, so that is not back yet.
    assert!(
        received.len() <= window && window - received.len() < 1024,
        "an unacknowledged reader gets one window, got {} of {window}",
        received.len()
    );

    let (reader_conn, reader_stream) = reader_stream.expect("data arrived");
    let over_ack = reader.stream_consumed(reader_conn, reader_stream, window + 1);
    assert!(
        matches!(
            over_ack,
            Err(Error::Transport(minip2p::TransportError::AckExceedsDelivered {
                acked,
                unacked,
                ..
            })) if (acked, unacked) == (window + 1, received.len())
        ),
        "an over-ack names both counts and fails: {over_ack:?}"
    );

    // Consuming resumes the sender, and the transfer completes.
    reader
        .stream_consumed(reader_conn, reader_stream, received.len())
        .expect("consume the window");
    let mut eof = false;
    while !eof {
        assert!(
            Instant::now() < deadline,
            "stalled at {} bytes",
            received.len()
        );
        sender.turn(&mut writer, &reader_peer, conn_id, stream_id);
        while let Some(event) = next(&mut reader, Duration::from_millis(1)) {
            match event {
                EndpointEvent::StreamData {
                    conn_id,
                    stream_id,
                    data,
                    ..
                } => {
                    received.extend_from_slice(&data);
                    reader
                        .stream_consumed(conn_id, stream_id, data.len())
                        .expect("consume");
                }
                EndpointEvent::StreamRemoteWriteClosed { .. } => eof = true,
                other => fail_on_teardown(&other),
            }
        }
    }
    assert!(received == payload, "every byte, once, in order");
}

#[cfg(feature = "quic")]
#[test]
fn a_manual_ack_reader_stalls_its_sender_until_it_consumes_over_quic() {
    a_manual_ack_reader_stalls_its_sender_until_it_consumes(
        "/ip4/127.0.0.1/udp/0/quic-v1",
        minip2p_quic::STREAM_RECEIVE_WINDOW,
    );
}

#[cfg(feature = "tcp")]
#[test]
fn a_manual_ack_reader_stalls_its_sender_until_it_consumes_over_tcp() {
    a_manual_ack_reader_stalls_its_sender_until_it_consumes(
        "/ip4/127.0.0.1/tcp/0",
        minip2p::TcpConfig::default().yamux.receive_window as usize,
    );
}
