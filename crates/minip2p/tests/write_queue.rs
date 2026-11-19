//! The endpoint's write queue over real TCP endpoints, std and portable,
//! whose Yamux streams cap at 256 KiB: `send_stream` queues the tail a Full
//! send left, finishes it on Writable, defers the FIN behind it, and aborts
//! it once the stream or its connection ends (ADR 0030).

#![cfg(all(feature = "std", feature = "tcp"))]

use std::time::{Duration, Instant};

use minip2p::{
    ConnectionId, Ed25519Keypair, Endpoint, EndpointEvent, EndpointWaitOutcome, ManualClock,
    PeerAddr, PortableEndpointBuilder, SendError, SendOutcome, StreamId, StreamKey,
};
use minip2p_core::platform::{Clock, StdClock, StdEntropy};

const PROTOCOL: &str = "/minip2p/write-queue/1";
/// Far past every per-stream send cap, so the first write is queued.
const PAYLOAD: usize = 4 * 1024 * 1024;
const BACKSTOP: Duration = Duration::from_secs(30);

fn bind(budget: usize) -> Endpoint {
    Endpoint::builder()
        .listen_on("/ip4/127.0.0.1/tcp/0")
        .expect("listen address")
        .protocol(PROTOCOL)
        .write_budget(budget)
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
fn open(writer: &mut Endpoint, reader: &mut Endpoint) -> StreamKey {
    let reader_addr = reader.listen().expect("reader listens");
    let reader_peer = *reader.peer_id();
    let writer_peer = *writer.peer_id();
    writer.connect(&reader_addr).expect("connect");
    let deadline = Instant::now() + BACKSTOP;
    while !writer.is_peer_ready(&reader_peer) || !reader.is_peer_ready(&writer_peer) {
        assert!(Instant::now() < deadline, "peers never became ready");
        let _ = next(writer);
        let _ = next(reader);
    }
    let stream = writer
        .open_stream(&reader_peer, PROTOCOL)
        .expect("open stream");
    loop {
        assert!(Instant::now() < deadline, "stream never negotiated");
        let _ = next(reader);
        if let Some(EndpointEvent::StreamReady { stream: ready, .. }) = next(writer)
            && ready == stream
        {
            return stream;
        }
    }
}

fn payload() -> Vec<u8> {
    (0..PAYLOAD).map(|i| (i % 251) as u8).collect()
}

#[test]
fn a_queued_write_completes_on_writable_and_the_fin_waits_for_it() {
    let mut reader = bind(0);
    let mut writer = bind(2 * PAYLOAD);
    let stream = open(&mut writer, &mut reader);
    let payload = payload();

    writer.send_stream(stream, payload.clone()).expect("write");
    assert!(
        writer.is_write_pending(stream),
        "a write past the send caps is queued"
    );
    assert!(writer.queued_write_bytes() > 0);
    // Behind queued bytes a write is queued whole, and a bare write accepts
    // nothing, so bytes stay in order.
    writer.send_stream(stream, vec![7]).expect("queued behind");
    assert_eq!(
        writer.try_send_stream(stream, vec![8]).expect("try"),
        SendOutcome::Full {
            unsent: vec![8].into()
        }
    );

    // Requested behind the queue: the FIN must follow every byte.
    writer.close_stream_write(stream).expect("close write");
    let closing = writer
        .send_stream(stream, vec![2])
        .expect_err("closing write side");
    assert!(
        matches!(closing, SendError::Closing { ref unsent, .. } if unsent[..] == [2]),
        "{closing:?}"
    );
    assert!(!closing.is_retryable() && !closing.is_stream_gone());

    let mut settled = Vec::new();
    let mut received = Vec::new();
    let deadline = Instant::now() + BACKSTOP;
    loop {
        assert!(
            Instant::now() < deadline,
            "transfer stalled at {} bytes",
            received.len()
        );
        while let Some(event) = next(&mut writer) {
            match event {
                EndpointEvent::StreamWritable { .. } => {
                    panic!("the queue, not the application, owns the tail")
                }
                event @ (EndpointEvent::StreamWriteAccepted { .. }
                | EndpointEvent::StreamWriteAborted { .. }) => settled.push(event),
                _ => {}
            }
        }
        match next(&mut reader) {
            Some(EndpointEvent::StreamData { data, .. }) => received.extend_from_slice(&data),
            Some(EndpointEvent::StreamRemoteWriteClosed { .. }) => break,
            _ => {}
        }
    }
    assert!(
        matches!(
            settled[..],
            [EndpointEvent::StreamWriteAccepted { peer_id, stream: s }]
                if peer_id == *reader.peer_id() && s == stream
        ),
        "the queued write completes exactly once: {settled:?}"
    );
    let mut expected = payload;
    expected.push(7);
    assert!(
        received == expected,
        "every byte arrives, in order, before the FIN"
    );
    assert!(!writer.is_write_pending(stream));
    assert_eq!(writer.queued_write_bytes(), 0);
}

/// Drives `writer` until its queue for `stream` aborts, returning the event
/// that ended it and the abort that followed.
fn until_aborted(
    writer: &mut Endpoint,
    reader: &mut Endpoint,
    stream: StreamKey,
) -> (Option<EndpointEvent>, EndpointEvent) {
    let deadline = Instant::now() + BACKSTOP;
    let mut previous = None;
    loop {
        assert!(Instant::now() < deadline, "the queue never aborted");
        let _ = next(reader);
        let Some(event) = next(writer) else { continue };
        assert!(
            !matches!(event, EndpointEvent::StreamWriteAccepted { .. }),
            "{event:?}"
        );
        if let EndpointEvent::StreamWriteAborted {
            stream: s, unsent, ..
        } = event
        {
            assert_eq!(s, stream);
            assert!(unsent > 0, "held bytes are counted");
            return (previous, event);
        }
        previous = Some(event);
    }
}

#[test]
fn a_queued_tail_is_aborted_when_its_stream_or_connection_ends() {
    let mut reader = bind(0);
    let mut writer = bind(PAYLOAD);
    let stream = open(&mut writer, &mut reader);

    writer.send_stream(stream, payload()).expect("write");
    assert!(writer.is_write_pending(stream));
    // The held tail is charged against the budget, so a write that only
    // fits the whole budget must wait for it (checked before any send).
    let other = StreamKey::new(stream.conn_id(), StreamId::new(u64::MAX));
    let waiting = writer
        .send_stream(other, payload())
        .expect_err("the held tail uses part of the budget");
    assert!(
        matches!(waiting, SendError::OverBudget { .. }) && waiting.is_retryable(),
        "{waiting:?}"
    );

    // A local reset aborts at once.
    writer.reset_stream(stream).expect("reset");
    assert!(!writer.is_write_pending(stream));
    assert_eq!(writer.queued_write_bytes(), 0, "the budget is released");
    until_aborted(&mut writer, &mut reader, stream);

    // The connection ending aborts it too, right after the close.
    let stream = open(&mut writer, &mut reader);
    writer.send_stream(stream, payload()).expect("write");
    assert!(writer.is_write_pending(stream));
    reader.disconnect(writer.peer_id()).expect("disconnect");
    let (ended, _) = until_aborted(&mut writer, &mut reader, stream);
    assert!(
        matches!(
            ended,
            Some(EndpointEvent::ConnectionClosed { conn_id, .. }) if conn_id == stream.conn_id()
        ) || matches!(ended, Some(EndpointEvent::StreamClosed { stream: s, .. }) if s == stream),
        "the abort follows the event that ended the stream: {ended:?}"
    );
    assert_eq!(writer.queued_write_bytes(), 0);
}

#[test]
fn a_write_past_the_budget_is_refused_before_anything_is_sent() {
    let mut reader = bind(0);
    let mut writer = bind(16);
    let stream = open(&mut writer, &mut reader);

    let refused = writer
        .send_stream(stream, vec![0; 17])
        .expect_err("larger than the whole budget");
    assert!(
        matches!(refused, SendError::TooLarge { ref unsent, budget: 16 } if unsent.len() == 17),
        "{refused:?}"
    );
    assert!(!refused.is_retryable(), "it can never be admitted");
    writer.send_stream(stream, vec![0; 16]).expect("fits");
    assert!(!writer.is_write_pending(stream));

    // Errors from the endpoint keep their predicates.
    let gone = writer
        .send_stream(
            StreamKey::new(ConnectionId::new(u64::MAX), stream.stream_id()),
            vec![0],
        )
        .expect_err("unknown connection");
    assert!(gone.is_stream_gone() && !gone.is_retryable(), "{gone:?}");
}

type Portable = minip2p::PortableEndpoint<
    minip2p::TcpTransport<minip2p_tcp::StdTcpProvider, StdEntropy>,
    StdEntropy,
    ManualClock,
>;

fn bind_portable() -> Portable {
    let key = Ed25519Keypair::generate();
    let transport =
        minip2p::TcpTransport::new(minip2p_tcp::StdTcpProvider::new(), key.clone(), StdEntropy);
    PortableEndpointBuilder::new(&key, StdEntropy, ManualClock::default())
        .protocol(PROTOCOL)
        .write_budget(PAYLOAD)
        .build(transport)
        .expect("build portable endpoint")
}

#[test]
fn a_portable_endpoint_finishes_a_queued_write_and_the_deferred_fin() {
    let mut clock = StdClock::new();
    let mut reader = bind_portable();
    let mut writer = bind_portable();
    let reader_addr = PeerAddr::new(
        reader
            .listen_on(&"/ip4/127.0.0.1/tcp/0".parse().expect("multiaddr"))
            .expect("reader listens"),
        *reader.peer_id(),
    )
    .expect("reader address");
    let (reader_peer, writer_peer) = (*reader.peer_id(), *writer.peer_id());
    writer
        .at(clock.now())
        .connect(reader_addr)
        .expect("connect");
    let deadline = Instant::now() + BACKSTOP;
    while !writer.is_peer_ready(&reader_peer) || !reader.is_peer_ready(&writer_peer) {
        assert!(Instant::now() < deadline, "peers never became ready");
        let now = clock.now();
        writer.at(now).poll().expect("writer polls");
        reader.at(now).poll().expect("reader polls");
    }
    let stream = writer
        .at(clock.now())
        .open_stream(&reader_peer, PROTOCOL)
        .expect("open stream");
    'negotiate: loop {
        assert!(Instant::now() < deadline, "stream never negotiated");
        let now = clock.now();
        reader.at(now).poll().expect("reader polls");
        for event in writer.at(now).poll().expect("writer polls") {
            if matches!(event, EndpointEvent::StreamReady { stream: ready, .. } if ready == stream)
            {
                break 'negotiate;
            }
        }
    }

    let payload = payload();
    writer
        .at(clock.now())
        .send_stream(stream, payload.clone())
        .expect("write");
    assert!(
        writer.is_write_pending(stream),
        "a write past the send caps is queued"
    );
    writer
        .at(clock.now())
        .close_stream_write(stream)
        .expect("close write");

    let (mut accepted, mut received) = (0, Vec::new());
    'transfer: loop {
        assert!(
            Instant::now() < deadline,
            "transfer stalled at {} bytes",
            received.len()
        );
        let now = clock.now();
        for event in writer.at(now).poll().expect("writer polls") {
            if matches!(event, EndpointEvent::StreamWriteAccepted { stream: s, .. } if s == stream)
            {
                accepted += 1;
            }
        }
        for event in reader.at(now).poll().expect("reader polls") {
            match event {
                EndpointEvent::StreamData { data, .. } => received.extend_from_slice(&data),
                EndpointEvent::StreamRemoteWriteClosed { .. } => break 'transfer,
                _ => {}
            }
        }
    }
    assert_eq!(accepted, 1, "the queued write completes exactly once");
    assert!(
        received == payload,
        "every byte arrives, in order, before the FIN"
    );
    assert_eq!(writer.queued_write_bytes(), 0);
}
