//! Stream lifecycle over real std endpoints: protocol handles on
//! `StreamReady` and `open_stream` (ADR 0031).

#![cfg(feature = "quic")]

use std::time::{Duration, Instant};

use minip2p::{Endpoint, EndpointEvent, EndpointWaitOutcome, Error, ProtocolId, SwarmError};

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
    // The builder's protocol comes first; `add_protocol` numbers the next
    // one and returns the same handle for a protocol it already has.
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
    // Each side names it with its own handle.
    assert_eq!((local, remote), (Some(file), Some(b_file)));

    // A handle another endpoint issued names nothing here.
    let foreign = b
        .add_protocol("/minip2p/lifecycle/only-b/1")
        .expect("register");
    assert!(a.protocol_name(foreign).is_none());
    assert!(matches!(
        a.open_stream(&b_peer, foreign),
        Err(Error::Swarm(SwarmError::ProtocolNotRegistered { .. }))
    ));
}
