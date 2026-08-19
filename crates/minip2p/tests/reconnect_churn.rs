//! Listener must reclaim per-peer state well under the default 30s QUIC idle
//! timeout after a dialer is dropped or `close`d without `disconnect`.

#![cfg(feature = "quic")]

use std::time::{Duration, Instant};

use minip2p::{Ed25519Keypair, Endpoint, Event, PeerId};

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

    // Drive the listener so QUIC close can complete; otherwise Drop would
    // be the only path that notifies the peer.
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

    // Do not wait for Identify; the connection may still be handshaking.
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

#[test]
fn close_drains_replacement_connection() {
    let mut listener = bind_loopback();
    let listener_addr = listener.listen().expect("listener listens");
    let listener_peer = listener.peer_id().clone();

    let dialer_key = Ed25519Keypair::generate();
    let mut dialer = Endpoint::builder()
        .identity(dialer_key.clone())
        .bind_quic("127.0.0.1:0")
        .expect("bind first dialer");
    let dialer_peer = dialer.peer_id().clone();
    dialer.dial(&listener_addr).expect("dial listener");
    wait_peer_ready(&mut listener, &mut dialer, &listener_peer, &dialer_peer);

    // Queue a same-peer handshake without polling the listener, so close()
    // is the first drive that can supersede and establish the replacement.
    let mut replacement = Endpoint::builder()
        .identity(dialer_key)
        .bind_quic("127.0.0.1:0")
        .expect("bind replacement dialer");
    replacement.dial(&listener_addr).expect("redial listener");
    for _ in 0..8 {
        let _ = replacement
            .next_event(Duration::from_millis(10))
            .expect("send replacement handshake");
    }

    let (stop_remote, remote_stop) = std::sync::mpsc::channel();
    let remote = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if remote_stop.try_recv().is_ok() {
                break;
            }
            let _ = replacement
                .next_event(Duration::from_millis(10))
                .expect("drive replacement during close");
        }
        replacement
    });

    let events = listener.close().expect("close drains replacements");
    let _ = stop_remote.send(());
    let _replacement = remote.join().expect("replacement driver thread");

    let established: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::ConnectionEstablished { peer_id, conn_id } if peer_id == &dialer_peer => {
                Some(*conn_id)
            }
            _ => None,
        })
        .collect();
    assert!(
        !established.is_empty(),
        "close must observe the replacement ConnectionEstablished: {events:?}"
    );
    for conn_id in established {
        assert!(
            events.iter().any(|event| matches!(
                event,
                Event::ConnectionClosed { peer_id, conn_id: closed, .. }
                    if peer_id == &dialer_peer && *closed == conn_id
            )),
            "close must drain the replacement {conn_id:?}: {events:?}"
        );
    }
}

#[test]
fn close_drains_pending_replacement_handshake() {
    let mut listener = bind_loopback();
    let listener_addr = listener.listen().expect("listener listens");
    let listener_peer = listener.peer_id().clone();

    let dialer_key = Ed25519Keypair::generate();
    let mut dialer = Endpoint::builder()
        .identity(dialer_key.clone())
        .bind_quic("127.0.0.1:0")
        .expect("bind first dialer");
    let dialer_peer = dialer.peer_id().clone();
    dialer.dial(&listener_addr).expect("dial listener");
    wait_peer_ready(&mut listener, &mut dialer, &listener_peer, &dialer_peer);

    let mut replacement = Endpoint::builder()
        .identity(dialer_key)
        .bind_quic("127.0.0.1:0")
        .expect("bind replacement dialer");
    replacement.dial(&listener_addr).expect("redial listener");
    for _ in 0..4 {
        let _ = replacement
            .next_event(Duration::from_millis(10))
            .expect("send replacement initial");
    }
    // Accept the Initial without waiting for Connected; close() must keep
    // polling after the superseded peer leaves connected_peers.
    let _ = listener
        .next_event(Duration::from_millis(10))
        .expect("accept replacement initial");

    let (stop_remote, remote_stop) = std::sync::mpsc::channel();
    let remote = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if remote_stop.try_recv().is_ok() {
                break;
            }
            let _ = replacement
                .next_event(Duration::from_millis(10))
                .expect("drive replacement during close");
        }
        replacement
    });

    let events = listener.close().expect("close drains pending replacement");
    let _ = stop_remote.send(());
    let _replacement = remote.join().expect("replacement driver thread");

    let established: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::ConnectionEstablished { peer_id, conn_id } if peer_id == &dialer_peer => {
                Some(*conn_id)
            }
            _ => None,
        })
        .collect();
    assert!(
        !established.is_empty(),
        "close must observe the pending replacement ConnectionEstablished: {events:?}"
    );
    for conn_id in established {
        assert!(
            events.iter().any(|event| matches!(
                event,
                Event::ConnectionClosed { peer_id, conn_id: closed, .. }
                    if peer_id == &dialer_peer && *closed == conn_id
            )),
            "close must drain the pending replacement {conn_id:?}: {events:?}"
        );
    }
}
