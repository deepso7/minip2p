//! Stream lifecycle over real std endpoints: protocol handles on
//! `StreamReady` and `open_stream` (ADR 0031), and a short-lived sender's
//! `flush` and flush-before-close (ADR 0032), over QUIC and TCP.

#![cfg(feature = "quic")]

use std::thread;
use std::time::{Duration, Instant};

use minip2p::{
    CloseOutcome, ConnectOutcome, Endpoint, EndpointEvent, EndpointWaitOutcome, ProtocolId,
};

const CHAT: &str = "/minip2p/lifecycle/chat/1";
const FILE: &str = "/minip2p/lifecycle/file/1";
const BACKSTOP: Duration = Duration::from_secs(30);

fn bind(listen: &str) -> Endpoint {
    Endpoint::builder()
        .listen_on(listen)
        .expect("listen address")
        .protocol(CHAT)
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

/// Connects `a` to `b` and drives both until each has identified the other.
fn connect(a: &mut Endpoint, b: &mut Endpoint) {
    let (a_peer, b_peer) = (*a.peer_id(), *b.peer_id());
    a.connect(b.listen().expect("listen")).expect("connect");
    let deadline = Instant::now() + BACKSTOP;
    while !a.is_peer_ready(&b_peer) || !b.is_peer_ready(&a_peer) {
        assert!(Instant::now() < deadline, "peers never became ready");
        let _ = next(a);
        let _ = next(b);
    }
}

#[test]
fn stream_ready_carries_the_handle_open_stream_takes() {
    let (mut a, mut b) = (
        bind("/ip4/127.0.0.1/udp/0/quic-v1"),
        bind("/ip4/127.0.0.1/udp/0/quic-v1"),
    );
    let chat = a.protocol_id(CHAT).expect("builder protocol has a handle");
    let file = a.add_protocol(FILE).expect("register");
    assert_eq!(a.add_protocol(FILE).expect("again"), file);
    assert_ne!(chat, file);
    assert_eq!(a.protocol_name(file), Some(FILE));
    assert_eq!(a.protocol_id("/not/registered/1"), None);
    let b_file = b.add_protocol(FILE).expect("register");
    connect(&mut a, &mut b);

    let b_peer = *b.peer_id();
    let stream = a.open_stream(&b_peer, file).expect("open by handle");
    let deadline = Instant::now() + BACKSTOP;
    let (mut local, mut remote): (Option<ProtocolId>, Option<ProtocolId>) = (None, None);
    while local.is_none() || remote.is_none() {
        assert!(Instant::now() < deadline, "stream never negotiated");
        if let Some(EndpointEvent::StreamReady {
            stream: ready,
            protocol,
            protocol_id,
            ..
        }) = next(&mut a)
            && ready == stream
        {
            assert_eq!(protocol_id, FILE);
            local = Some(protocol);
        }
        if let Some(EndpointEvent::StreamReady {
            protocol,
            protocol_id,
            ..
        }) = next(&mut b)
        {
            assert_eq!(protocol_id, FILE);
            remote = Some(protocol);
        }
    }
    assert_eq!((local, remote), (Some(file), Some(b_file)));
}

/// Larger than the transports' per-stream send caps, so the endpoint and the
/// transport still hold most of it when the sender is done writing.
const PAYLOAD: usize = 2 * 1024 * 1024;

fn payload() -> Vec<u8> {
    (0..PAYLOAD).map(|i| (i % 251) as u8).collect()
}

/// How a short-lived sender ends after `send_stream` and `close_stream_write`.
#[derive(Clone, Copy)]
enum Ending {
    /// `flush`, then a teardown that waits at most this long. A flushed
    /// QUIC stream is acknowledged, so its teardown can wait for nothing;
    /// a TCP socket has to outlive the peer's reading, so its teardown
    /// waits for the peer to close too.
    FlushThenClose(Duration),
    /// `close_within` alone, which flushes first.
    CloseWithin,
}

/// A receiver on its own thread collects one inbound stream until its FIN,
/// while a sender connects, writes `PAYLOAD`, closes its write side, and
/// ends as `ending` says, at once. Returns what the receiver got, and
/// whether the FIN came behind it.
fn short_lived_sender(listen: &str, ending: Ending) -> (Vec<u8>, bool) {
    let mut receiver = bind(listen);
    let target = receiver.listen().expect("listen");
    let reader = thread::spawn(move || {
        let deadline = Instant::now() + BACKSTOP;
        let mut received = Vec::new();
        loop {
            assert!(
                Instant::now() < deadline,
                "no FIN after {} bytes",
                received.len()
            );
            match next(&mut receiver) {
                Some(EndpointEvent::StreamData { data, .. }) => received.extend_from_slice(&data),
                Some(EndpointEvent::StreamRemoteWriteClosed { .. }) => return (received, true),
                Some(EndpointEvent::ConnectionClosed { .. }) => return (received, false),
                _ => {}
            }
        }
    });

    let mut sender = bind(listen);
    let peer = *target.peer_id();
    let id = sender.connect(&target).expect("connect");
    let deadline = Instant::now() + BACKSTOP;
    let mut stream = None;
    loop {
        assert!(Instant::now() < deadline, "sender never got its stream");
        match next(&mut sender) {
            Some(EndpointEvent::ConnectSettled {
                connect_id,
                outcome,
                ..
            }) if connect_id == id => {
                assert!(
                    matches!(outcome, ConnectOutcome::Connected { .. }),
                    "{outcome:?}"
                );
                stream = Some(sender.open_stream(&peer, CHAT).expect("open"));
            }
            Some(EndpointEvent::StreamReady { stream: ready, .. }) if Some(ready) == stream => {
                break;
            }
            _ => {}
        }
    }
    let stream = stream.expect("opened");
    sender.send_stream(stream, payload()).expect("send");
    sender.close_stream_write(stream).expect("close write");
    assert!(
        sender.has_pending_writes(),
        "most of the payload is still held"
    );
    match ending {
        Ending::FlushThenClose(timeout) => {
            assert!(sender.flush(BACKSTOP).expect("flush"), "flush timed out");
            assert!(!sender.has_pending_writes());
            drop(sender.close_within(timeout));
        }
        Ending::CloseWithin => {
            let report = sender.close_within(BACKSTOP);
            assert_eq!(report.outcome, CloseOutcome::Drained, "{report:?}");
        }
    }
    reader.join().expect("receiver thread")
}

#[test]
fn a_flushed_quic_sender_delivers_every_byte_and_the_fin() {
    let (received, fin) = short_lived_sender(
        "/ip4/127.0.0.1/udp/0/quic-v1",
        Ending::FlushThenClose(Duration::ZERO),
    );
    assert!(fin, "the FIN never came");
    assert!(received == payload(), "received {} bytes", received.len());
}

#[test]
fn a_quic_close_within_flushes_before_tearing_down() {
    let (received, fin) = short_lived_sender("/ip4/127.0.0.1/udp/0/quic-v1", Ending::CloseWithin);
    assert!(fin, "the FIN never came");
    assert!(received == payload(), "received {} bytes", received.len());
}

#[cfg(feature = "tcp")]
#[test]
fn a_flushed_tcp_sender_delivers_every_byte_and_the_fin() {
    let (received, fin) =
        short_lived_sender("/ip4/127.0.0.1/tcp/0", Ending::FlushThenClose(BACKSTOP));
    assert!(fin, "the FIN never came");
    assert!(received == payload(), "received {} bytes", received.len());
}

#[cfg(feature = "tcp")]
#[test]
fn a_tcp_close_within_flushes_before_tearing_down() {
    let (received, fin) = short_lived_sender("/ip4/127.0.0.1/tcp/0", Ending::CloseWithin);
    assert!(fin, "the FIN never came");
    assert!(received == payload(), "received {} bytes", received.len());
}

/// A peer that is not driven never closes its side, so a TCP socket closed
/// gracefully is still waiting when the deadline passes: the close says so,
/// though no connection is tracked any more.
#[cfg(feature = "tcp")]
#[test]
fn a_tcp_close_cut_short_while_the_peer_has_not_closed_expires() {
    let (mut a, mut b) = (bind("/ip4/127.0.0.1/tcp/0"), bind("/ip4/127.0.0.1/tcp/0"));
    connect(&mut a, &mut b);
    let report = a.close_within(Duration::from_millis(200));
    assert_eq!(report.outcome, CloseOutcome::DeadlineExpired, "{report:?}");
    assert!(report.unfinished.is_empty(), "{report:?}");
    drop(b);
}
