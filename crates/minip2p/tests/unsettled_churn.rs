//! A reader that holds delivered bytes across peer churn keeps them counted
//! (ADR 0012, #356): each closed connection keeps its slot until its bytes are
//! acknowledged or abandoned, so close-and-reconnect cannot grow what the
//! reader holds. With every slot held the transport refuses new connections;
//! acknowledging or abandoning after the close frees the slot again.

#![cfg(feature = "std")]

use std::time::{Duration, Instant};

use minip2p::{
    Bytes, ConnectOutcome, ConnectionId, Endpoint, EndpointBuilder, EndpointEvent,
    EndpointWaitOutcome, PeerAddr, StreamId,
};

const PROTOCOL: &str = "/minip2p/unsettled-churn/1";
/// Failure backstop, not a budget the test has to fit in.
const BACKSTOP: Duration = Duration::from_secs(30);

fn next(endpoint: &mut Endpoint) -> Option<EndpointEvent> {
    match endpoint
        .wait(Duration::from_millis(2))
        .expect("drive endpoint")
    {
        EndpointWaitOutcome::Event(event) => Some(event),
        _ => None,
    }
}

/// A fresh peer dials the reader. Returns the writer and, once the attempt
/// settles, whether it connected.
fn dial(
    reader: &mut Endpoint,
    reader_addr: &PeerAddr,
    writer: EndpointBuilder,
) -> (Endpoint, bool) {
    let mut writer = writer.protocol(PROTOCOL).bind().expect("bind writer");
    let attempt = writer.connect(reader_addr).expect("connect");
    let deadline = Instant::now() + BACKSTOP;
    loop {
        assert!(Instant::now() < deadline, "the attempt never settled");
        let _ = next(reader);
        if let Some(EndpointEvent::ConnectSettled {
            connect_id,
            outcome,
            ..
        }) = next(&mut writer)
            && connect_id == attempt
        {
            return (writer, matches!(outcome, ConnectOutcome::Connected { .. }));
        }
    }
}

/// A fresh peer connects, sends four bytes on a manual-ack stream, and
/// disconnects. Returns the reader's connection and stream, unacknowledged.
fn deliver_then_close(
    reader: &mut Endpoint,
    reader_addr: &PeerAddr,
    writer: EndpointBuilder,
) -> (ConnectionId, StreamId) {
    let (mut writer, connected) = dial(reader, reader_addr, writer);
    assert!(connected, "a free slot admits the peer");
    let reader_peer = reader.peer_id().clone();
    let deadline = Instant::now() + BACKSTOP;
    while !writer.is_peer_ready(&reader_peer) {
        assert!(Instant::now() < deadline, "never ready");
        let _ = next(reader);
        let _ = next(&mut writer);
    }
    let (conn_id, stream_id) = writer
        .open_stream(&reader_peer, PROTOCOL)
        .expect("open stream");
    let mut sent = false;
    let mut held = None;
    while held.is_none() {
        assert!(Instant::now() < deadline, "the bytes never arrived");
        match next(&mut writer) {
            Some(EndpointEvent::StreamReady { stream_id: id, .. }) if id == stream_id => {
                writer
                    .send_stream(conn_id, stream_id, Bytes::from_static(b"held"))
                    .expect("send");
                sent = true;
            }
            _ => {}
        }
        if let Some(EndpointEvent::StreamData {
            conn_id, stream_id, ..
        }) = next(reader)
        {
            assert!(sent);
            held = Some((conn_id, stream_id));
        }
    }
    let (held_conn, held_stream) = held.expect("delivered");
    writer.disconnect(&reader_peer).expect("disconnect");
    loop {
        assert!(Instant::now() < deadline, "the reader never saw the close");
        let _ = next(&mut writer);
        if let Some(EndpointEvent::ConnectionClosed { conn_id, .. }) = next(reader)
            && conn_id == held_conn
        {
            return (held_conn, held_stream);
        }
    }
}

fn churn(listen: &str, reader: EndpointBuilder, writer: impl Fn() -> EndpointBuilder) {
    let mut reader = reader
        .listen_on(listen)
        .expect("listen address")
        .manual_ack_protocol(PROTOCOL)
        .bind()
        .expect("bind reader");
    let reader_addr = reader.listen().expect("reader listens");

    // The reader never acknowledges, so the closed connection keeps its
    // only slot and every later peer is refused rather than delivered to.
    let (conn_id, stream_id) = deliver_then_close(&mut reader, &reader_addr, writer());
    for _ in 0..2 {
        assert!(!dial(&mut reader, &reader_addr, writer()).1, "refused");
    }

    // A partial acknowledgement after the close keeps the slot; the last
    // byte frees it.
    reader
        .stream_consumed(conn_id, stream_id, 2)
        .expect("partial ack after close");
    assert!(!dial(&mut reader, &reader_addr, writer()).1, "still held");
    reader
        .stream_consumed(conn_id, stream_id, 2)
        .expect("final ack after close");

    // Abandoning after the close frees it too.
    let (conn_id, stream_id) = deliver_then_close(&mut reader, &reader_addr, writer());
    assert!(!dial(&mut reader, &reader_addr, writer()).1, "held again");
    reader
        .abandon_stream(conn_id, stream_id)
        .expect("abandon after close");
    let _ = deliver_then_close(&mut reader, &reader_addr, writer());
}

#[cfg(feature = "quic")]
#[test]
fn a_reader_holding_bytes_across_quic_churn_stays_bounded() {
    let limits = || minip2p::QuicLimits {
        max_connections: 1,
        // A refused dial gives up quickly.
        idle_timeout_ms: 1_000,
        ..minip2p::QuicLimits::default()
    };
    churn(
        "/ip4/127.0.0.1/udp/0/quic-v1",
        Endpoint::builder().quic_limits(limits()),
        || {
            Endpoint::builder()
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1")
                .expect("listen address")
                .quic_limits(limits())
        },
    );
}

#[cfg(feature = "tcp")]
#[test]
fn a_reader_holding_bytes_across_tcp_churn_stays_bounded() {
    let config = || minip2p::TcpConfig {
        max_connections: 1,
        ..minip2p::TcpConfig::default()
    };
    churn(
        "/ip4/127.0.0.1/tcp/0",
        Endpoint::builder().tcp_config(config()),
        || {
            Endpoint::builder()
                .listen_on("/ip4/127.0.0.1/tcp/0")
                .expect("listen address")
                .tcp_config(config())
        },
    );
}
