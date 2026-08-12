//! Regression coverage for listener state retention when dialers connect and
//! drop without an explicit `disconnect`.
//!
//! The listener advertises the default 30s QUIC idle timeout. After each
//! dialer is dropped (or `close`d), the listener must reclaim per-peer state
//! in well under that timeout. That is the spar reconnect-churn-200 failure
//! mode: missing `CONNECTION_CLOSE` left live quiche connections on the
//! listener until idle expiry (~40 KB/peer RSS).
//!
//! Out of scope: `kill -9` and hard partitions still wait for idle timeout.

#![cfg(feature = "quic")]

use std::time::{Duration, Instant};

use minip2p::{Endpoint, Event, PeerId};

const CHURN_ROUNDS: usize = 50;
/// Must stay ≪ default `QuicLimits::idle_timeout_ms` (30s).
const RECLAIM_WITHIN: Duration = Duration::from_millis(500);

fn wait_peer_ready(
    listener: &mut Endpoint,
    dialer: &mut Endpoint,
    listener_peer: &PeerId,
    dialer_peer: &PeerId,
) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !listener.is_peer_ready(dialer_peer) || !dialer.is_peer_ready(listener_peer) {
        assert!(Instant::now() < deadline, "peer ready timed out");
        let _ = listener
            .next_event(Duration::from_millis(10))
            .expect("drive listener toward ready");
        let _ = dialer
            .next_event(Duration::from_millis(10))
            .expect("drive dialer toward ready");
    }
}

fn ping_until_rtt(listener: &mut Endpoint, dialer: &mut Endpoint, listener_peer: &PeerId) {
    dialer.ping(listener_peer).expect("queue ping");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(Instant::now() < deadline, "ping rtt timed out");
        match dialer
            .next_event(Duration::from_millis(10))
            .expect("drive dialer ping")
        {
            Some(Event::PingRttMeasured { peer_id, .. }) if peer_id == *listener_peer => return,
            _ => {}
        }
        let _ = listener
            .next_event(Duration::from_millis(10))
            .expect("drive listener ping");
    }
}

fn assert_listener_reclaimed(listener: &mut Endpoint, dialer_peer: &PeerId, round: usize) {
    let deadline = Instant::now() + RECLAIM_WITHIN;
    while Instant::now() < deadline && !listener.connected_peers().is_empty() {
        let _ = listener
            .next_event(Duration::from_millis(10))
            .expect("drive listener reclaim");
    }

    assert!(
        listener.connected_peers().is_empty(),
        "round {round}: listener still tracks connected peers {:?} after {RECLAIM_WITHIN:?}",
        listener.connected_peers()
    );
    assert!(
        listener.peer_info(dialer_peer).is_none(),
        "round {round}: listener retained identify state for {dialer_peer}"
    );
}

fn bind_loopback() -> Endpoint {
    Endpoint::builder()
        .bind_quic("127.0.0.1:0")
        .expect("bind loopback")
}

#[test]
fn listener_reclaims_state_after_dialer_drop_without_disconnect() {
    let mut listener = bind_loopback();
    let listener_addr = listener.listen().expect("listener listens");
    let listener_peer = listener.peer_id().clone();

    for round in 0..CHURN_ROUNDS {
        let mut dialer = bind_loopback();
        let dialer_peer = dialer.peer_id().clone();
        dialer.dial(&listener_addr).expect("dial listener");

        wait_peer_ready(&mut listener, &mut dialer, &listener_peer, &dialer_peer);
        ping_until_rtt(&mut listener, &mut dialer, &listener_peer);

        // spar reconnect-churn: drop the dialer without `disconnect()`.
        drop(dialer);

        assert_listener_reclaimed(&mut listener, &dialer_peer, round);
    }
}

#[test]
fn listener_reclaims_state_after_dialer_close() {
    let mut listener = bind_loopback();
    let listener_addr = listener.listen().expect("listener listens");
    let listener_peer = listener.peer_id().clone();

    let mut dialer = bind_loopback();
    let dialer_peer = dialer.peer_id().clone();
    dialer.dial(&listener_addr).expect("dial listener");
    wait_peer_ready(&mut listener, &mut dialer, &listener_peer, &dialer_peer);
    ping_until_rtt(&mut listener, &mut dialer, &listener_peer);

    // QUIC close completes only when the peer is driven; otherwise
    // `close()` would return no events and Drop would do the real work.
    let (stop_remote, remote_stop) = std::sync::mpsc::channel();
    let remote = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if remote_stop.try_recv().is_ok() {
                break;
            }
            let _ = listener
                .next_event(Duration::from_millis(10))
                .expect("drive listener during close");
        }
        listener
    });

    let events = dialer.close().expect("close flushes disconnects");
    let _ = stop_remote.send(());
    let mut listener = remote.join().expect("listener driver thread");

    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::ConnectionClosed { peer_id, .. } if peer_id == &listener_peer
        )),
        "close must surface ConnectionClosed rather than relying on Drop: {events:?}"
    );
    assert_listener_reclaimed(&mut listener, &dialer_peer, 0);
}

#[test]
fn listener_reclaims_state_after_dialer_drop_during_handshake() {
    let mut listener = bind_loopback();
    let listener_addr = listener.listen().expect("listener listens");

    let mut dialer = bind_loopback();
    let dialer_peer = dialer.peer_id().clone();
    dialer.dial(&listener_addr).expect("dial listener");

    // Exchange a few packets so the listener is likely holding a QUIC
    // connection, but do not wait for Identify / PeerReady.
    for _ in 0..8 {
        let _ = listener
            .next_event(Duration::from_millis(10))
            .expect("drive listener handshake");
        let _ = dialer
            .next_event(Duration::from_millis(10))
            .expect("drive dialer handshake");
    }

    drop(dialer);
    assert_listener_reclaimed(&mut listener, &dialer_peer, 0);
}
