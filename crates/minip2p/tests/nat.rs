//! Loopback e2e for the `nat` feature: two real QUIC endpoints, no relay —
//! the direct leg of the race wins outright and the failure paths report
//! cleanly. (Relay-path coverage lives at the agent level in
//! `crates/nat/tests`; a full relay e2e needs an external relay server.)

#![cfg(feature = "nat")]

use std::time::{Duration, Instant};

use minip2p::{Endpoint, NatConfig, NatError, NatEvent, Path};

fn nat_endpoint() -> Endpoint {
    Endpoint::builder()
        .nat_config(NatConfig::default())
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint")
}

#[test]
fn direct_candidate_wins_over_loopback() {
    let mut a = nat_endpoint();
    let mut b = Endpoint::builder()
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint");

    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    let id = a.connect_addr(&b_addr).expect("connect starts");

    // Drive both endpoints; no relay is configured, so the only leg is the
    // direct dial of the provided candidate.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut path = None;
    while path.is_none() {
        assert!(Instant::now() < deadline, "direct connect timed out");
        let _ = a.next_event(Duration::from_millis(20)).expect("a drives");
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
        for event in a.take_nat_events() {
            if let NatEvent::PathEstablished {
                connect_id,
                path: found,
                ..
            } = event
                && connect_id == id
            {
                path = Some(found);
            }
        }
    }
    assert!(matches!(path, Some(Path::DirectDialed)));
    assert!(a.connected_peers().contains(b_addr.peer_id()));
}

#[test]
fn connect_without_candidates_or_relay_fails_fast() {
    let mut a = nat_endpoint();
    a.listen().expect("a listens");

    let stranger = minip2p::Ed25519Keypair::generate().peer_id();
    let id = a.connect(&stranger).expect("connect starts");

    let path = a
        .wait_path(id, Duration::from_secs(2))
        .expect("wait_path drives");
    assert!(path.is_none(), "no path can exist");
    // The failure detail stays inspectable.
    let events = a.take_nat_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            NatEvent::ConnectFailed { connect_id, error: NatError::NoPathAvailable, .. }
                if *connect_id == id
        )),
        "expected ConnectFailed, got {events:?}"
    );
}

#[test]
fn wait_path_buffers_application_events() {
    let mut a = nat_endpoint();
    let mut b = Endpoint::builder()
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint");
    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    let id = a.connect_addr(&b_addr).expect("connect starts");
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut path = None;
    while path.is_none() {
        assert!(Instant::now() < deadline, "direct connect timed out");
        path = a.wait_path(id, Duration::from_millis(20)).expect("a waits");
        let _ = b.next_event(Duration::from_millis(20)).expect("b drives");
    }
    assert!(matches!(path, Some(Path::DirectDialed)));

    // The swarm events observed during the wait (ConnectionEstablished,
    // PeerReady, ...) were buffered, not swallowed.
    let mut saw_connection = false;
    while let Some(event) = a.next_event(Duration::from_millis(50)).expect("drain") {
        if matches!(event, minip2p::Event::ConnectionEstablished { .. }) {
            saw_connection = true;
            break;
        }
    }
    assert!(saw_connection, "application events must survive wait_path");
}

#[test]
fn wait_peer_ready_drives_nat_agent() {
    let mut a = nat_endpoint();
    let mut b = Endpoint::builder()
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback endpoint");
    let b_addr = b.listen().expect("b listens");
    a.listen().expect("a listens");

    // The facade wait drives only `a`, so keep the remote's socket serviced
    // concurrently. `wait_peer_ready` must feed ConnectionEstablished to
    // the NAT agent on the way to the matching PeerReady event.
    let (stop_remote, remote_stop) = std::sync::mpsc::channel();
    let remote = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if remote_stop.try_recv().is_ok() {
                break;
            }
            let _ = b.next_event(Duration::from_millis(10));
        }
    });

    let id = a.connect_addr(&b_addr).expect("connect starts");
    let ready = a
        .wait_peer_ready(b_addr.peer_id(), Duration::from_secs(10))
        .expect("wait succeeds");
    assert!(
        matches!(ready, Some(minip2p::Event::PeerReady { peer_id, .. }) if peer_id == *b_addr.peer_id())
    );

    let events = a.take_nat_events();
    assert!(
        events.iter().any(|event| {
            matches!(
                event,
                NatEvent::PathEstablished { connect_id, path: Path::DirectDialed, .. }
                    if *connect_id == id
            )
        }),
        "wait_peer_ready must deliver ConnectionEstablished to NAT: {events:?}"
    );
    let _ = stop_remote.send(());
    remote.join().expect("remote driver thread");
}
